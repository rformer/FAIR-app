# F-015 Security Posture & Configuration Profiles — Design
Status: **Approved** (Robert Former, 2026-10-24) | Requirements: Approved 2026-10-24 | Last updated: 2026-10-24
ADRs: 004, 005, 006 (Amendment 1), 007, 008

## 1. Overview
F-015 has four parts:
1. **`profilegen`** — a build-time tool. It turns OSCAL baselines plus binding files into signed **profile packages**.
2. **`posture` service (Go)** — owns:
   - the settings registry
   - profiles, custom profiles, and profile switches
   - setting changes and exceptions
   - application drift detection
   - OSCAL export
3. **`settings` library (Go)** — embedded in every service. Features use it to register settings and read effective values; it caches them and invalidates the cache on change events.
4. **`posture-scanner`** — a separately deployed, read-only Kubernetes checker for deployment drift. It is optional in self-hosted installs.

Two pieces are reused rather than rebuilt:
- **Approvals** come from the F-001 `approvals` module (generic dual approval).
- **Audit and SIEM** go through the F-002 emitter. Until F-002 exists, the F-001 T-00a stub is used.

## 2. Components

| Component | Runs | Responsibility |
|---|---|---|
| `profilegen` (Go) | CI / release pipeline only | Implements OSCAL profile resolution in Go (the subset needed: imports with include/exclude-controls, merge, `set-parameters`); resolves OSCAL profiles (800-53r5 catalog + FedRAMP Moderate baseline + in-repo CMMC L2 and Enterprise Baseline profiles), applies binding files, validates, and emits signed profile packages |
| `posture` service | In-cluster | Registry, profile catalog, change evaluator, exception lifecycle, switch state machine, app drift engine, Posture API, OSCAL Assessment Results / POA&M export |
| `settings` library | Embedded in every Go service | `Register()`, `Get(key, buID)`, `Set()` client; versioned cache; invalidation on `posture.setting.changed` |
| `posture-scanner` | Separate Deployment, own ServiceAccount | Read-only Kubernetes and TLS checks; reports findings to `posture` over mTLS gRPC |
| `fips-probe` (optional) | DaemonSet | Reads the node's FIPS kernel flag; reports through its readiness, which the scanner reads (see D-OQ2, T-29) |
| River jobs (in `posture`) | In-cluster | Expiry notices, automatic revert, scheduled drift scans, revert retries |

**Why the scanner is separate:** the scanner holds the only Kubernetes API permissions. Isolating it keeps those permissions off the main service. It also means declining Kubernetes access simply removes one Deployment.

## 3. Setting types and strictness
Every setting declares a **type** and a **direction**, which together give it a total "stricter-than" order.

| Type | Example | Order |
|---|---|---|
| `duration` / `int` | `session.idle_timeout`, `auth.lockout_threshold` | `lower_is_stricter` or `higher_is_stricter` |
| `bool` | `auth.jit_enabled` | Declared stricter value (`false` for jit) |
| `enum` | `session.network_binding` | Ordered list: `off < flag < reauthenticate` |
| `set` | `tls.allowed_versions` | Subset is stricter |

**Bounds** come in two forms, `{min, max}` or an `allowed` list, and are always expressed in the strict direction. A value is **out of bounds** when it is weaker than the bound. **Strictest-of** (R-09) uses the same comparator. Hard-floor settings carry an absolute `floor` that no profile can set weaker.

## 4. Profile packages and OSCAL binding

### 4.1 Binding file (YAML, in repo, one per setting)
```yaml
setting: session.idle_timeout
type: duration
direction: lower_is_stricter
bu_scopable: false
hard_floor: null
params:
  - catalog: nist-sp-800-53-r5
    param: ac-11_odp.02        # session lock: time period of inactivity
  - catalog: nist-sp-800-53-r5
    param: ac-12_odp.01        # session termination conditions (informational)
profiles:
  fedramp-moderate:
    default: 15m
    bound: { max: 15m }
    source:                    # what the value was transcribed from
      param: ac-11_odp.02
      constraint: "fifteen (15) minutes"
  cmmc-l2-r2:
    default: 15m
    bound: { max: 15m }
    platform_choice: "800-171 3.1.10 leaves the period open; matches FedRAMP Moderate"
  enterprise-baseline:
    default: 15m
    bound: { max: 30m }
    platform_choice: "Enterprise Baseline relaxation (see profile notes)"
```
- Published OSCAL baselines carry no machine-readable parameter values. FedRAMP's rev5 Moderate baseline sets 264 parameters, all as prose `constraints` (for example, AC-11 "fifteen (15) minutes"), and leaves some unset (for example, AC-7). Values are therefore **transcribed by a person and drift-checked by the build**:
  - `source.param` must exist in the resolved profile, and its constraint text must equal `source.constraint` exactly (whitespace normalized). Otherwise `profilegen` **fails the build**, and someone re-reviews the transcription against the new text.
  - Every profile entry states where its value comes from: `source` (drift-checked) or `platform_choice: <reason>`. A parameter the source leaves unconstrained, and any profile we author ourselves, therefore needs `platform_choice`, so no default is undocumented.
  - Bounds are written in the strict direction: `max` for `lower_is_stricter`, `min` for `higher_is_stricter`, and `allowed` for `bool` and `enum` (its weakest member is the bound). An omitted bound means the default itself. Durations accept Go units plus `d` for days.
  - Defaults are never derived from prose automatically.

### 4.2 Profile sources
- **FedRAMP Moderate:** NIST 800-53r5 OSCAL catalog plus the FedRAMP Moderate OSCAL baseline (pinned by digest).
- **CMMC L2:** an in-repo OSCAL profile built from the **revision of NIST SP 800-171 that the CMMC rule currently requires**. As of October 2026 that is **Rev 2 (110 requirements)**. Requirements are mapped onto the 800-53r5 parameters used by the bindings. The package ID carries the revision (`cmmc-l2-r2`). When a rule moving CMMC Level 2 to Rev 3 takes effect, a `cmmc-l2-r3` package is added alongside it, and customers move to it through the normal gated profile switch (§6.4). No code change is needed. Release checklist item: confirm the CMMC rule's current 800-171 revision before each release. This is automated (T-07): `profiles/release-checklist.yaml` records the confirmation, and the release gate re-checks it against the eCFR on every release tag.
- **Enterprise Baseline:** an in-repo OSCAL profile derived from 800-53r5 Moderate with documented relaxations.
- **Future (FedRAMP High, DoD IL4/IL5):** a new OSCAL source plus binding entries produces a new package with no runtime code change (AC-06).

### 4.3 Package format
`profile-<id>-<version>.json` contains:
- metadata: id, title, version, base, source OSCAL digests, `profilegen` version
- settings: key → `{default, bound, params[]}`
- the hard-floor manifest

The package is signed (ECDSA P-256, release signing key) with a detached signature. `posture` verifies the signature and schema on import and refuses unsigned or tampered packages. Packages are immutable: a new version gets a new file.

Build and release (T-06; proposed with T-06, pending approval):
- `profiles/packages.yaml` lists each package's id, title, family, version and base OSCAL profile. `profilegen packages` builds the packages deterministically and writes them, with a **package manifest** that pins each one by SHA-256, to `profiles/packages/`. Both are committed, so every change to a package shows up in review.
- Each setting entry also carries its type, direction, enum order, `bu_scopable` and origin (`source` or `platform_choice`), so an importer can validate the package with nothing else to hand. `bound` is the weakest value allowed without an exception. Metadata `sources` lists every input with its SHA-256: the base profile, every pinned file its resolution read, and every binding file.
- Packages are canonical JSON (sorted keys, durations as Go duration strings). Decoding refuses unknown fields, trailing data and non-canonical bytes.
- Immutability is enforced at build time. If a package that is already pinned would get different bytes, the build refuses and asks for a version bump in `packages.yaml`.
- `profilegen sign -key FILE -out DIR` (release pipeline) checks every package against its pin and signs each package and the package manifest (`<file>.sig`, base64 ASN.1 DER). The key is a PEM file, i.e. a mounted secret. `profilegen verify -pub FILE -dir DIR` verifies a signed release offline.
- The package manifest is the profile-package part of the release manifest. Wherever the release pipeline assembles the full release manifest (image digests, §6.8), it pins the package manifest by digest.

Loading and seeding (T-10; decisions by Robert Former, 2026-10-26):
- **Release packages** are embedded in the binary (`profiles/embed.go`). `iam migrate` checks them against their pinned manifest and loads them through `posture.sync_packages` as `fair_owner`. This is the trusted release path, like the permission catalog.
- **Later packages** (offline import, AC-05 and AC-06) go through `posture import -pub FILE -dir DIR`. The service verifies the manifest signature, each package's pin and signature, and its schema with the bundled public key, then calls `posture.import_package`. PostgreSQL cannot verify ECDSA, so on this path the database trusts `app_posture`. An imported profile is only `approved`, and it takes effect only through a dual-approved switch (T-21).
- **What the database checks on both paths:**
  - it computes the digest from the exact bytes it stores;
  - it loads insert-only, refusing an existing id and version with another digest;
  - it re-checks values and hard floors against registered setting definitions.
- **The install-time seed** is `posture seed [-profile ID]`, defaulting to `fedramp-moderate` (AC-09). The installer runs it once; F-014's UI wraps it. It makes the profile active, writes every instance value from its defaults with a row MAC, and emits `posture.seeded` (high severity) inside the transaction, so an audit failure seeds nothing (AC-10).

## 5. Data model (schema `posture`)
- `setting_def` (key PK, type, direction, bu_scopable, hard_floor jsonb, params text[], owner_feature, registered_version)
- `profile` (id, name, kind[builtin|custom], base_profile_id, version, package_digest, status[draft|pending_approval|approved|active|retired], label_deviates bool)
- `profile_value` (profile_id, version, key, default jsonb, bound jsonb, justification, loosened bool)
- `active_profile` (singleton: profile_id, version, activated_at, activated_by, switch_id)
- `setting_value` (key, bu_id NULL for instance, value jsonb, source[profile|change|exception|overlay|revert], change_id, exception_id, updated_at, **row_mac** bytea)
- `change` (id, key, bu_id, old_value, new_value, direction[tighten|neutral|loosen], explanation, requested_by, approval_request_id, state[applied|pending_approval|rejected], applied_at)
- `exception` (id, key, bu_id, value, bound_at_creation, justification, owner_id, approved_by, created_at, expires_at, renewed_from, state[active|renewed|expired|reverted|revert_failed])
- `profile_switch` (id, target_profile_id, target_version, state, requested_by, justification, approval_request_id, created_at, activated_at)
- `switch_conflict` (switch_id, key, bu_id, current_value, new_bound, resolution[conform|exception|unresolved], exception_id)
- `overlay_value` (key PK, value jsonb, source[change|exception], change_id, exception_id, updated_at, **row_mac** bytea) and `overlay_change`; the AC-33 defaults are `posture.overlay_defaults()` (changed 2026-10-27 from `overlay_def`; see the change log)
- `drift_finding` (id, kind[app|deployment], check_id, severity, controls text[], subject, detail jsonb, remediation, first_seen, last_seen, status[open|acknowledged|resolved], acknowledged_by)
- `k8s_access` (state[requested|granted|declined|revoked], decided_by, decided_at, reason)
- `export_record` (id, kind[assessment_results|poam], as_of, created_at, created_by, snapshot, snapshot_digest, document_digest, statement, signature, key_id); append-only (changed 2026-10-28 with T-35; see the change log)

### Access model (approved by Robert Former, 2026-10-26, with T-08)
- `bu_id` is nullable in posture tables (NULL = instance-wide). These rows are configuration, not BU-owned business records. Their main readers are system processes that act for no user: settings resolution for any BU, row-MAC drift checks, revert jobs. So they are not under F-001's user-scoped BU RLS (`authz.apply_bu_rls`, AC-24).
- Instead, application roles have **no privileges at all** on posture tables, reads included. Every read and write goes through SECURITY DEFINER functions owned by the NOLOGIN role `posture_definer`.
  - User-facing reads filter BU rows with `authz.visible_bus('settings', 'read')`.
  - System reads return effective values.
- Defence in depth: every posture table has RLS enabled and forced, with a single policy for `posture_definer` only. A mistaken grant to an application role still exposes no rows.
- The posture service connects as its own login role, `app_posture` (NOBYPASSRLS, owns nothing). It is created by `db/bootstrap` with its password read from a secret file.
  - Only `app_posture` may execute the posture write functions.
  - Other services read effective values through a read function granted to `app_rw` (T-11).

### Write protection (AC-02)
- `setting_value`, `exception`, and `active_profile` grant **no** INSERT, UPDATE, or DELETE to application roles.
- Writes go only through `posture.apply_change(change_id)` and `posture.apply_revert(exception_id)`, both SECURITY DEFINER functions. Each verifies that the referenced change, approval, or exception is in an applicable state.
- Every `setting_value` row carries a `row_mac`: an HMAC over (key, bu_id, value, source, ref id), keyed by a posture key that application roles cannot read. The app drift engine recomputes the MACs, so an out-of-band database edit (for example, by a DBA) is detected even when it bypasses the functions.

## 6. Key flows

### 6.1 Feature registration
At startup each service calls `settings.Register(defs...)`, and `posture` upserts `setting_def`. A registered key that is missing from the active profile package is a **startup error**. This forces every new setting to ship with bindings.

### 6.2 Change a setting (R-06)
`POST /settings/{key}` with `{value, bu_id?, explanation?}` goes to the evaluator:
1. **Hard-floor check.** Weaker than the floor → refuse with 422 and emit `setting.hard_floor_refused` (high severity).
2. **Direction check** against the current effective value:
   - **Tighten:** apply immediately via `apply_change`, then emit `setting.changed`.
   - **Within bounds:** apply and audit.
   - **Out of bounds:**
     - Require an explanation. The response includes a **warning payload** listing the affected controls and parameters.
     - Create an `approval_request`.
     - Once a *different* holder of `settings.approve` approves, `apply_change` runs and creates an `exception` (expiry defaults to 90 days, within bounds), and `setting.exception_created` is emitted (high severity).
     - In SaaS mode, vendor SecOps is notified (AC-23).
3. **Propagation.** After commit, `posture.setting.changed {key, bu_id, version}` is published on NATS. `settings` caches invalidate, with a 30 s TTL as a backstop, giving an SLA of ≤ 60 s.

### 6.3 Exception lifecycle (R-07)
- **Notices:** River schedules jobs at T-14 d, T-7 d, and T-1 d that notify the owner and admins.
- **Renewal:** allowed only while `state = active` and `now() < expires_at`. It requires a new justification and dual approval. Renewal creates a new exception with `renewed_from` set and marks the old one `renewed`.
- **Expiry job at `expires_at`:** calls `apply_revert(exception_id)` as the `system:posture` actor. The setting value becomes the active profile value (instance) or the inherited value (BU override). The exception moves to `reverted`, `setting.exception_reverted` is emitted (high severity), and notifications go out.
- **Session-affecting reverts:** the gateway re-evaluates on the next request with the new value, so no grace period applies (AC-28).
- **Failure:** retry with exponential backoff, capped at 5 minutes between attempts. Raise a **critical** `drift_finding` (`check_id = revert_failed`) that resolves automatically only when a revert succeeds. Escalation notices repeat hourly.
- **Clock:** all times come from database `now()`, never from client clocks.

### 6.4 Profile switch (R-05)
State machine:

`requested → conflicts_computed → resolving → (awaiting_approval) → activating → active` or `cancelled`

1. **Compute conflicts:** for each setting value (instance and BU overrides), compare it to the target profile's bounds. Every weaker value becomes a `switch_conflict(unresolved)`.
2. **Resolving:** an admin resolves each conflict, either:
   - `conform` — the setting will be set to the target default at activation, or
   - `exception` — dual-approved, with a reason and expiry; not allowed on the hard floor.

   Activation stays disabled while any conflict is unresolved (AC-17).
3. **Loosening check:** if the target profile is weaker than the current one on any bound, the switch is a loosening. It requires a justification, dual approval, and a high-severity audit event.
4. **Activation:** a single transaction that:
   - sets `active_profile`
   - applies the `conform` resolutions
   - attaches the approved exceptions
   - re-seeds settings whose `source = profile` to the new defaults
   - preserves explicit changes that are within the new bounds

   It then publishes `posture.profile.activated`.
5. **While pending:** the current profile stays in force, and the Posture page shows the pending switch (AC-18).

### 6.5 Custom profiles (R-04)
- **Create:** clone a built-in profile, giving a `draft`.
- **Edit:** the per-key editor shows the base value, the new value, its direction, and the affected controls. A loosened key requires a justification.
- **Validate:** the hard floor, types, and bounds coherence are checked.
- **Activate:** `profile.approve` by a different person sets `approved`, and the profile is then activated through the §6.4 switch flow.
- **Labeling:** deviations from the base are stored as `loosened = true` rows. The profile is labeled **"Deviates from <base>"** in the UI and in exports.
- **Base update:** when a base package is upgraded, the system diffs it against each derived profile. Any key where the new base is *weaker* than the custom profile's current effective value is **pinned** to the current value, so the custom profile never silently weakens (AC-15). Keys where the base gets stricter are proposed to the admin as updates.
- **Export/import:** JSON (native) and an OSCAL profile with `set-parameters`. Import validates the input and always creates a `draft`.

### 6.6 BU overrides and the Restricted BU overlay (R-09)
- **Resolution:** `effective(key, bu) = strictest(instance, override(a) for a on the path root→bu that is not blocked, override(bu), overlay if bu is restricted or below a restricted node)`. Path blocking reuses `iam.bu_closure.blocked` from F-001.
- **Overlay activation** (changed 2026-10-27; see the change log): the overlay is computed, not copied into rows. Every BU that is restricted or below a restricted BU gets it by construction, and loses it on unrestrict, which F-001 audits and already requires dual approval for.
- **Overlay edits:** the AC-33 defaults are the overlay's bound. Tightening, and moving back towards the default, apply at once. Anything weaker than the default follows R-06's out-of-bounds path (explanation, dual approval) and becomes an overlay exception under R-07.
- **Re-authentication freshness:** the overlay sets `bu.reauth_max_age = 15m`. `authz.Check()` (F-001 library) reads it for the target BU and returns `ErrStepUpRequired` when `session.auth_time` is older. The API then responds 401 with `WWW-Authenticate: step_up`, and the frontend re-runs the IdP flow (SAML `ForceAuthn=true` / OIDC `prompt=login` with `max_age`). *This adds a small change to the F-001 design; see §12.*
- **Export reason:** the overlay sets `export.reason_required = true`, which F-010 enforces.

### 6.7 Application drift (R-10)
The engine runs on every `posture.setting.changed`, every 15 minutes, and after each import or switch. For each setting value it:
1. recomputes the `row_mac` (detects tampering);
2. checks the value against the active profile bound, plus any active exception (detects an unapproved deviation);
3. checks exception expiry against the current state (detects a missed revert);
4. compares the effective value reported by each service (from the `settings` library heartbeat) with the expected value (detects a stale cache or rogue configuration).

Each check produces a `drift_finding` with `check_id`, severity, controls, and remediation. Events go to audit and SIEM. Target: ≤ 30 s at full scale.

### 6.8 Deployment drift (R-11)
**Access model:**
- **SaaS:** the scanner is always deployed by vendor operations.
- **Self-hosted:** the F-014 installer shows a *permission manifest* listing every verb and resource with its purpose. If the customer accepts, the scanner and its RBAC are deployed and `k8s_access = granted`. If the customer declines, nothing is deployed, `k8s_access = declined`, a persistent banner appears on the Posture page, the decision is audited, and deployment controls are exported as "Not assessed". Access can be granted later through a Helm value flip plus an admin acknowledgement in the UI.

**Permissions (read-only; Secrets are never read):**

| Scope | Resources (get/list/watch) | Purpose |
|---|---|---|
| Platform namespaces | pods, deployments, statefulsets, daemonsets, services, networkpolicies, serviceaccounts, roles, rolebindings, persistentvolumeclaims, externalsecrets (CRD, if present) | Workload hardening, NetworkPolicy presence, secret references, platform RBAC, storage classes of platform volumes (PVCs added 2026-10-28, T-28) |
| Cluster | namespaces (labels only), nodes (labels/annotations), storageclasses, clusterroles, clusterrolebindings (filtered to platform subjects), validatingadmissionpolicies / admission webhooks (metadata) | Pod security admission level, FIPS node labels, encryption, RBAC drift, presence of a signature-verification policy |

**Checks (initial catalog; each maps to controls):**

| Check | Method | Controls |
|---|---|---|
| Pod security admission = restricted on platform namespaces | Namespace labels | CM-6, CM-7 |
| NetworkPolicy default-deny + per-service allow | List and analyze | SC-7, AC-4 |
| TLS ≥ 1.2, approved cipher suites, certificate expiry > 30 d | Active TLS handshake to ingress and internal endpoints | SC-8, SC-13, SC-23 |
| Node FIPS mode (when the profile requires it) | `fips-probe` report or node label attested by the installer | SC-13 |
| Running image digests match the signed release manifest | Pod specs vs. the bundled manifest | CM-14, SI-7, SR-4 |
| Signature-verification admission policy present | Admission config metadata | CM-14 |
| Non-root and read-only root filesystem on all platform pods | Pod security contexts | CM-6, CM-7 |
| Encrypted storage classes for PVCs | StorageClass parameters (per provider) | SC-28 |
| No plaintext secrets in env/args | Pod spec analysis (secretKeyRef / ExternalSecret only; heuristics on literals) | IA-5, SC-28 |
| Platform RBAC unchanged from manifest | Role and binding hash comparison | AC-6, CM-5 |

Findings are reported over gRPC (mTLS) to `posture`, which de-duplicates them, sets their lifecycle, and emits events. The scanner runs every 15 minutes and on watch events. It is itself built as a non-root, read-only, signed image.

### 6.9 OSCAL export (R-13)
- **Assessment Results:**
  - `import-ap` references a generated assessment plan.
  - The `results` section holds:
    - **observations** for each setting/parameter (method `TEST`, type `finding` or `control-objective`), carrying the effective value
    - **findings** for each open drift finding, with a target status of `not-satisfied`
    - deployment controls with no access → `not-assessed`
  - Subjects reference the platform's **component definition** UUID (F-014).
- **POA&M:** one item per open exception or deviation, with justification, approver, expiry, related controls, and the linked observations.
- **Integrity:**
  - The export is generated from a consistent DB snapshot at `as_of`.
  - Its SHA-256 digest is stored in `export_record` and audited.
  - A detached ECDSA P-256 signature is produced.
  - The export is validated against the pinned OSCAL JSON schemas before release, and a failed validation means no export.
- **Reproducibility:** the same `as_of` produces an identical document (deterministic UUIDv5 and ordering).

## 7. API (`/api/v1/posture`)
- `GET /registry` · `GET /settings?bu=` · `POST /settings/{key}` · `GET /changes` · `GET /exceptions` · `POST /exceptions/{id}/renew`
- `GET /profiles` · `POST /profiles` (clone) · `PATCH /profiles/{id}` · `POST /profiles/{id}/submit` · `GET /profiles/{id}/diff?against=` · `POST /profiles/import` · `GET /profiles/{id}/export?format=json|oscal`
- `POST /switches` · `GET /switches/{id}` · `POST /switches/{id}/conflicts/{cid}/resolve` · `POST /switches/{id}/activate` · `POST /switches/{id}/cancel`
- `GET /overlay` · `PATCH /overlay`
- `GET /drift` · `POST /drift/{id}/acknowledge`
- `GET /k8s-access` · `POST /k8s-access/acknowledge-grant`
- `POST /exports` (`kind=assessment_results|poam`, `as_of`) · `GET /exports/{id}` (document + signature)
- Approvals are handled by F-001 `/approvals`. All mutations require `Idempotency-Key`, and loosening calls require `explanation`.

## 8. Security design (STRIDE)

| Threat | Example | Mitigations |
|---|---|---|
| Spoofing | Forged profile package | Signature + schema verification on import; packages pinned by digest in the release manifest |
| Tampering | DBA or attacker edits `setting_value` directly | No DML grants; definer-only writes; `row_mac` detection; critical drift finding |
| Tampering | Exception expiry extended by editing the DB | `exception` has no DML grants; expiry is checked against the audit trail; MAC on exception rows |
| Repudiation | "I didn't approve that loosening" | Dual-approval records both identities; every step goes to the F-002 hash-chained audit |
| Information disclosure | Scanner reads Secrets | RBAC excludes `secrets`; analysis covers pod specs only |
| Information disclosure | Posture page reveals restricted-BU overrides | BU overrides are filtered by the caller's F-001 scope; instance settings require `posture.view` |
| Denial of service | Revert job starved or blocked | Dedicated River queue; retry with backoff; critical finding + hourly escalation |
| Elevation of privilege | Collusion between two admins to loosen | Residual risk. Mitigated by SecOps notification (SaaS), Posture page visibility, the expiry and auto-revert ceiling, and OSCAL POA&M evidence for auditors |
| Elevation of privilege | Scanner ServiceAccount compromised | Read-only; no Secrets; isolated Deployment; NetworkPolicy allows egress only to `posture` and the probed endpoints |

**Crypto:** ECDSA P-256 for packages and exports, HMAC-SHA-256 for row MACs, and SHA-256 for digests, all through FIPS-validated modules. Signing keys come from KMS or Vault, or are generated at install for air-gapped use.

## 9. Secure defaults implementation
The install selects FedRAMP Moderate. The overlay is on. Drift scans run on change and every 15 minutes. Exceptions expire after 90 days and auto-revert. SaaS always deploys the scanner; self-hosted installs request it. The hard-floor manifest is compiled into the `posture` binary *and* carried in each package; the stricter of the two wins.

## 10. Requirements traceability

| Requirement | Satisfied by |
|---|---|
| R-01 Registry (AC-01–03) | §6.1, `setting_def`, definer-only writes + `row_mac` (§5) |
| R-02 OSCAL profiles (AC-04–08) | `profilegen`, binding files, signed packages (§4) |
| R-03 Install selection (AC-09–10) | F-014 installer → `posture` seed + audit |
| R-04 Custom profiles (AC-11–15) | §6.5 |
| R-05 Profile switch (AC-16–19) | §6.4 state machine |
| R-06 Changes (AC-20–23) | §6.2 evaluator |
| R-07 Exception lifecycle (AC-24–29) | §6.3 |
| R-08 Hard floor (AC-30–31) | Compiled + packaged floor manifest; evaluator refusal; custom profile validation |
| R-09 BU scope (AC-32–35) | §6.6; reuses `iam.bu_closure` |
| R-10 App drift (AC-36–37) | §6.7 |
| R-11 Deployment drift (AC-38–42) | §6.8, `posture-scanner` |
| R-12 Posture page (AC-43–44) | §7 API + frontend view; links to audit and approvals |
| R-13 OSCAL export (AC-45–48) | §6.9 |

## 11. Deployment modes
The configured mode is `saas`, `self-hosted` or `air-gapped` (ADR-005, amended 2026-10-28 with T-37).

| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Profile packages | Release pipeline | In the bundle | Offline import; signature verified with the bundled public key |
| Scanner | Always deployed | Deployed only on consent | Same as self-hosted |
| `fips-probe` | Deployed when the profile requires FIPS | Optional; otherwise installer-attested node labels | Same |
| TLS probing | Internal + public endpoints | Internal + customer ingress | Internal only |
| Notifications | Email/webhook + vendor SecOps | Customer channels | Internal relay |

## 12. Changes to other features
- **F-001:** add `ErrStepUpRequired` and the reauth-freshness check to `authz.Check()` (§6.6). Add `auth_time` to the session. Replace the T-00b settings stub with this feature. → Tracked as F-015 T-24 (the `authz` check, done) and T-24b (session `auth_time` and IdP re-authentication, after F-001 T-13/T-15/T-16).
- **F-014:** installer profile selection, the permission manifest UI for scanner consent, and `fips-probe` attestation.
- **F-010:** enforce `export.reason_required`.

## 13. Alternatives considered
- **Kyverno / OPA Gatekeeper as the deployment drift engine:** rejected as a *mandatory* dependency, because it adds an admission controller the customer may not want. If one is present, the scanner can optionally ingest its PolicyReports.
- **Settings in Kubernetes ConfigMaps:** rejected. ConfigMaps don't support approvals, exceptions, BU scoping, or tamper detection, and they don't work for SaaS ops separation.
- **Runtime OSCAL resolution in `posture`:** deferred to the F-013 migration. Build-time generation keeps the runtime small and air-gap-friendly (AC-08).

## 14. Resolved
- In-repo profile sources (T-04, approved by Robert Former, 2026-10-26):
  - **CMMC L2 (`cmmc-l2-r2`)** maps SP 800-171 Rev 2 to 800-53r5 through official NIST data. NIST publishes Rev 2 in no OSCAL form, has withdrawn it (May 2024), and publishes no Rev 2 to 800-53r5 mapping; Rev 2's Appendix D maps informally to 800-53 **Rev 4**. The chain is NIST's Rev 2 to Rev 3 change analysis, then each Rev 3 requirement's 800-53r5 source controls from NIST's Rev 3 OSCAL catalog.
  - **Enterprise Baseline** keeps NIST 800-53r5 Moderate's control selection unchanged. Its relaxations live only in the setting bindings, each with a `platform_choice` rationale.
- **D-OQ1 CMMC L2 source:** follow the current CMMC rule. Today that is NIST SP 800-171 **Rev 2**, shipped as `cmmc-l2-r2`. A Rev 3 package will be added when the rule changes (§4.2).
- **D-OQ2 FIPS node check:** **offer both** options:
  - `fips-probe` DaemonSet, which is the default when the profile requires FIPS. It uses a single-file read-only hostPath mount.
  - installer-attested node labels, which customers can choose if they decline the probe. Exports record this as "attested, not verified".
- **D-OQ3 `profilegen` tooling:** **written in Go**. It implements the OSCAL profile-resolution subset we need: imports (paths, URLs and back-matter references), include/exclude-controls, `as-is` and `flat` merge, `set-parameters`, and `alters` (adds and removes by id; added 2026-10-26 because FedRAMP's baselines depend on it). Conformance is tested against NIST's published resolved-profile examples and the FedRAMP resolved baselines.
- D-OQ4 FedRAMP Moderate OSCAL source (needed by T-02): **OSCAL-Foundation/fedramp-resources** (`baselines/rev5/json`), named by Robert Former (2026-10-26). The repository has no releases or tags, so T-02 pins a commit SHA (inspected: `383977291aad960b0811faf6ebf5a893b0811f7f`) plus SHA-256 per file. Facts from the inspection:
  - Files: the Moderate baseline profile, its resolved catalog (generated by libOSCAL-Java), and the FedRAMP catalog tailoring profile it imports.
  - Their metadata declares OSCAL 1.1.3 and version `fedramp-3.0.0rc1-oscal-1.1.2` (last modified 2025-03-03). All three validate and decode under the pinned OSCAL 1.2.3 schema and types.
  - The tailoring profile imports the NIST SP 800-53 rev5 catalog from **usnistgov/oscal-content v1.3.0**. The FedRAMP build must resolve against that catalog, so T-02 pins it alongside the v1.6.0 catalog used for the NIST-based profiles.
  - The repository declares no license; T-02 records the provenance in the manifest.
- OSCAL pins (T-01, approved by Robert Former, 2026-10-26): OSCAL **v1.2.3** schemas, and NIST content from usnistgov/oscal-content **v1.6.0** (SP 800-53 v5.2.0). Pinned files are committed under `third_party/oscal` with a SHA-256 manifest. Go types come from `defenseunicorns/go-oscal` v0.7.2, wrapped in `internal/oscal`.

## 15. Open items
- Live OpenShift and RKE2 runs of the scanner and `fips-probe` (from T-28/T-29; T-37 ran them live on kind and on a four-node Docker Desktop cluster only). They need OpenShift and RKE2 clusters or CI runners; the OpenShift run includes the SELinux behaviour of the probe's hostPath under its SCC.
- D-OQ5 (needed by T-10 and the release pipeline, not by T-06): where the release signing key is held (KMS or Vault, per §8) and where the bundled public key ships in the install bundle. T-06 reads the private key from a file and takes the public key as a file.

## Change Log
- 2026-10-24: Initial draft.
- 2026-10-24: D-OQ1–3 resolved (CMMC follows the current rule, currently 800-171 Rev 2; both FIPS check options offered; `profilegen` written in Go). Design **approved**.
- 2026-10-26: T-01 implementation notes (`internal/oscal`, `third_party/oscal`).
  - `oscal.Parse` validates against the pinned OSCAL 1.2.3 complete schema (`santhosh-tekuri/jsonschema`, format assertions on), accepts only the five F-015 models, and decodes strictly: an unknown field is an error, so data can never be dropped silently. `oscal.Marshal` re-validates its output (AC-47).
  - `go-oscal`'s embedded schema is semantically identical to NIST's published one; it only inlines datatype references. `TestPinnedSchemaMatchesTypesSource` re-checks this on every upgrade.
  - `go-oscal` v0.7.2 generates one `LocalDefinitions` type for three schema shapes, so an assessment result's `tasks` and `assessment-assets` would be lost. `internal/oscal` declares the assessment-results subtree itself (`types.go`), and `TestTypesMatchSchema` walks every supported model's Go types against the schema so that any such gap fails CI.
  - Round trip: all eight pinned NIST documents (the full 800-53 catalog, the Moderate profile and its resolved catalog, and examples of every model) parse, re-encode and compare equal. Date-times compare as instants, because Go writes `11:30:00.00000-00:00` as `11:30:00Z`.
- 2026-10-26: D-OQ4 opened and resolved the same day. The FedRAMP OSCAL baselines come from OSCAL-Foundation/fedramp-resources, pinned by commit; the FedRAMP build resolves against oscal-content v1.3.0 (§14).
- 2026-10-26: §4.1 changed (approved by Robert Former). `from_param` is replaced by transcribed values with drift-checked `source` constraints, because published OSCAL baselines carry prose constraints rather than parameter values; parameters left unconstrained need `platform_choice`. The example now names `ac-11_odp.02` (the lock time) instead of `ac-11_odp.01`. The T-02 resolution subset gains `alters` (D-OQ3).
- 2026-10-26: Restored the D-OQ1 to D-OQ3 entries in §14. A T-01 edit had deleted them by mistake.
- 2026-10-26: T-02 implementation notes (`internal/profilegen`).
  - Resolution works on generic JSON so that `alters` are lossless. Imports resolve only to files pinned in `third_party/oscal/MANIFEST.json`, matched by source URL: relative `href`s are resolved against the importing file's source URL, `#uuid` back-matter references are followed, and NIST's XML import paths map to the pinned JSON renditions. Nothing is fetched.
  - The subset supports include-all, `with-ids`, `matching` (glob) and `with-child-controls`; `as-is` and `flat` merge; and `combine: merge`. It refuses `merge.custom`, other combine methods, a selected control whose parent control is not selected, controls imported twice, import cycles, and `set-parameters` or `alters` aimed at missing targets.
  - `set-parameters`: `label`, `values` and `select` replace; `props`, `links`, `constraints` and `guidelines` add to the catalog's. Supplying `values`, `select` or `constraints` removes the catalog's open `select`/`values`. This matches FedRAMP's published resolution, which drops the select in all 23 such cases.
  - Output is deterministic: the UUID is a v5 UUID derived from the profile UUID and source, timestamps are copied from the profile, and metadata records `resolution-tool` and the `source-profile` link. Output validates against the pinned schema.
  - Conformance (the verification): structure (group and control order and nesting) plus every group's and control's full content must equal the published resolved catalog, after normalizing artifacts of the reference resolvers. Those artifacts are collapsed whitespace (NIST adds a space before parameter insertions), `file:/home/...#id` links reduced to `#id` (FedRAMP's tool rewrote links to controls outside the baseline as paths on its author's machine), and unescaped brackets. Metadata, UUIDs and back-matter are resolver-specific and not compared.
  - Result: all five targets conform (the three NIST examples, NIST 800-53r5 Moderate, and FedRAMP rev5 Moderate through its tailoring profile and oscal-content v1.3.0). Mutation checks confirmed the suite catches a broken `alters` position, a missing exclude and the select rule; a dedicated test covers append-versus-replace.
  - The v1.3.0 catalog is pinned under the exact `refs/tags/v1.3.0` URL that FedRAMP's tailoring profile imports.
- 2026-10-26: T-03 implementation notes (`internal/profilegen/binding.go`).
  - Binding files are YAML, decoded strictly with `go.yaml.in/yaml/v3` (the YAML organization's maintained continuation of the archived `gopkg.in/yaml.v3`).
  - The validator reuses `pkg/settings`' types, strictness comparator and hard floors. A binding for a registered key must agree with its definition: type, direction, enum order and floor.
  - Every profile listed must be covered, and no others. Each entry's default must lie within its bound, and the bound must not be weaker than the hard floor where the floor applies to that profile's family.
  - Each entry states its origin: `source`, drift-checked against the resolved profile, or `platform_choice`. The §4.1 example was updated to follow this rule (clarification accepted by Robert Former with the T-03 commit).
  - The `set` type (§3) is refused until a setting needs it; no F-001 setting does.
  - Note for T-05: `pkg/settings` still maps `session.idle_timeout` to `ac-11_odp.01` (the selection) rather than `ac-11_odp.02` (the time period).
- 2026-10-26: T-04 implementation notes (`internal/profilegen/cmmc.go`, `cmd/profilegen`, `profiles/`).
  - Pinned inputs: NIST's `sp800-171r2-to-r3-analysis.xlsx` (csrc.nist.gov), the SP 800-171 Rev 3 OSCAL catalog (oscal-content v1.6.0), and the SP 800-171 Rev 2 PDF (provenance of the Appendix D fallback).
  - Mapping result: 110 requirements; 104 via the Rev 3 chain, 6 via Rev 2 Appendix D. The six are 3.5.6, 3.5.8, 3.5.9, 3.7.1, 3.13.2 and 3.13.14, which Rev 3 withdrew without a successor. They are recorded in `profiles/cmmc-l2-r2/supplement.yaml`, whose notes the build checks against NIST's text. 3.13.14 maps to no control, because SC-19 is withdrawn in 800-53r5 with no successor. The profile selects 123 800-53r5 controls, including the base controls of selected enhancements.
  - NIST data issue: the change analysis contains a row "3.11.4", which is a mislabeled duplicate of 3.12.4. It is recorded as an erratum and skipped.
  - `go run ./cmd/profilegen profiles` regenerates `profiles/**/profile.json` and `mapping.md`. Tests fail if the committed files are stale, require both profiles to resolve and validate, and require Enterprise Baseline to conform exactly to NIST's resolved Moderate catalog.
  - Verification pending: a person must review `mapping.md`. Rows marked "confirm against the PDF" (3.5.8 and 3.5.9, where Table D-5 uses merged cells) need particular attention.
- 2026-10-26: T-05 implementation notes (`bindings/`, one YAML file per F-001 setting).
  - All 19 F-001 settings are bound in all three profiles. FedRAMP's text supports a drift-checked `source` for three of them: `session.idle_timeout` (ac-11_odp.02, "fifteen (15) minutes"), `auth.inactive_disable_after` (ac-02.03_odp.02, "ninety (90) days ...") and `fips.enabled` (sc-13_odp.02).
  - The rest carry `platform_choice`, citing the control, the 800-171 Rev 2 requirement or the F-001/F-015 acceptance criterion. Their FedRAMP parameters are unconstrained (AC-7, AC-12, IA-5), have no parameters (IA-2(1), IA-2(2)), or have text that is not a value for the setting (AC-8, SC-8).
  - Values are unchanged from the `pkg/settings` stand-in, which implements the approved F-001 and F-015 secure defaults. A test keeps the bindings and `settings.BuiltinProfiles()` equal until packages (T-06) and the posture service (T-16) replace the stand-in.
  - The Enterprise Baseline relaxation rationales were written by Claude and are for review.
  - Parameter fixes in `pkg/settings`: `session.idle_timeout` now names ac-11_odp.02 instead of .01 (the selection), and `auth.inactive_disable_after` names ac-02.03_odp.02 instead of .01 (the time to disable). `auth.totp_enabled`, `banner.enabled`, `token.max_lifetime` and `fips.enabled` now list their parameters.
  - Tests check that every bound parameter is present in all three resolved profiles, and that a change to FedRAMP's AC-11 text fails the build.
- 2026-10-26: T-06 implementation notes (`internal/profilepkg`, `internal/profilegen/package.go`, `profiles/packages*`). §4.3 gains the build and release detail, pending approval. D-OQ5 is opened for T-10.
  - `internal/profilepkg` holds the format: canonical encoding, strict decoding and validation (reusing `pkg/settings.ValidateProfile`), ECDSA P-256 signing over SHA-256 (the Go FIPS 140 module), and the signed package manifest. It is shared by `profilegen` and the `posture` importer (T-10).
  - The build validates and drift-checks every binding against the resolved profiles, requires every registered key to be bound, and round-trips each package through the importer's decoder before writing it. Any failure means no packages.
  - The pinned loader now re-checks each file's SHA-256 against `MANIFEST.json` when it reads the file.
  - `.gitattributes` pins LF for `bindings/**` and `profiles/**`, because packages record their inputs' digests. The race-enabled Linux run reproduces the packages built on Windows byte for byte.
  - Verification:
    - Two builds are byte-identical.
    - The committed packages are current.
    - The packages equal the `settings.BuiltinProfiles()` stand-in.
    - These are refused: a byte flipped anywhere in a package; a tampered, missing or swapped signature; a package re-signed after a change (it no longer matches its pin); and a release signed by another key.
    - A drifted, missing or below-floor binding fails the build.
- 2026-10-26: T-07 implementation notes (`internal/profilegen/release.go`, `profilegen release-check`, `.github/workflows/release.yml`).
  - The release gate is the `release-checklist` job in a new `release` workflow, which runs on every `v*` tag. F-012's later release jobs must depend on it. It uploads its report as release evidence.
  - Offline checks (blocking):
    - Every OSCAL source matches its SHA-256 in `MANIFEST.json`. The report lists all pinned sources with URL and digest.
    - The in-repo profiles and the profile packages rebuild byte for byte from the pins and bindings.
    - A `cmmc-l2-r<rev>` package exists for the confirmed revision.
    - The confirmation in `profiles/release-checklist.yaml` is complete and not dated in the future.
  - Online CMMC re-check (`-online`, blocking), read from the eCFR versioner API over TLS 1.2+:
    - 32 CFR part 170's latest amendment date must equal the recorded `part_amended` (2024-12-16). Any amendment blocks the release until a person re-reads the rule and updates the file.
    - §170.14(c)(3) must still read "The security requirements in CMMC Level 2 are identical to the requirements in NIST SP 800-171 R2."
    - An unreachable eCFR fails closed.
  - Limitation: the eCFR shows rules in force. A published final rule with a future effective date is not visible until it takes effect, so watching the Federal Register stays a manual task.
  - Verification:
    - The committed tree passes, and the live eCFR passed on 2026-10-26.
    - A confirmed Rev 3 without a `cmmc-l2-r3` package fails.
    - These fail closed: a later amendment, changed rule text, an eCFR server error, missing or malformed versions, an incomplete or future-dated confirmation, and a changed pinned file.
- 2026-10-26: §5 access model added (approved by Robert Former). The nullable `bu_id` conflicted with F-001 AC-24 and its CI gate, which require user-scoped BU RLS on any table with a `bu_id` that application roles can reach; the posture tables' system-context readers also cannot pass user-scoped RLS. Resolution: no application-role access, definer functions only (`posture_definer`), and a dedicated `app_posture` login role. T-08's verification now reads accordingly.
- 2026-10-26: T-08 implementation notes (`db/migrations/0011_posture.sql`, `db/bootstrap`, `cmd/posture`).
  - Roles: `db/bootstrap/0001_roles.sql` adds `posture_definer` (NOLOGIN) and `app_posture` (LOGIN, NOBYPASSRLS, `row_security = on`, password from `FAIR_POSTURE_PASSWORD_FILE`). `fair_owner` may `SET ROLE posture_definer`, so migrations can hand functions to it. Existing installs must re-run the bootstrap before migrating; migration 0011 refuses to run without the roles, with a message saying so.
  - Grants: schema `USAGE` goes to `app_posture` and `posture_definer` only. `app_rw` gets none until T-11's read function. No role has any table privilege. `posture_definer` gets its table grants with the functions that need them (T-09, T-10).
  - Every table: RLS enabled and forced, with one policy `definer_only` for `posture_definer`.
  - Columns beyond §5, needed to hold what a package carries:
    - `setting_def.enum_order` and `hard_floor_families`.
    - `profile.family` (hard floors apply per family), `base_version`, `created_at` and `created_by`.
    - `change.created_at`.
  - Naming and keys:
    - `profile_value.default` is named `default_value` (`default` is reserved).
    - `profile` is keyed by `(id, version)`. `active_profile` is a singleton row.
    - The `set` type's direction is named `subset_is_stricter`.
  - Constraints:
    - Type and direction must agree.
    - A built-in profile has a package digest; a custom profile has a base.
    - A loosened profile value needs a justification.
    - At most one value per key and BU, where NULL is instance-wide (`UNIQUE NULLS NOT DISTINCT`).
    - `source` agrees with `change_id` and `exception_id`.
    - `row_mac` is 32 bytes.
  - Foreign keys:
    - `change` and `exception` reference `setting_def`, so only registered keys can be changed.
    - `profile_value` and `setting_value` do not, because a package can bind keys of features that have not registered yet (T-10, T-12).
    - `approval_request_id` and `switch_id` have no foreign key until the approvals module and `profile_switch` exist.
  - `cmd/posture`: hardened server (health, readiness, FIPS, TLS, audit lifecycle events; audit failure at start is fatal) and a database pool as `app_posture`. Readiness fails unless the connection is `app_posture`, the schema is usable, and the role cannot read posture tables directly.
  - Container image and Kubernetes manifest for `posture` are not added here. F-012 builds images; F-014 owns the charts.
  - Verification:
    - DB tests: the tables are owned by `fair_owner`, RLS is enabled and forced, and `definer_only` is the only policy. `app_rw`, `app_engine`, `app_posture` and `app_migrator` have no table privileges, and their reads are denied.
    - A mistaken grant still returns 0 rows and updates nothing.
    - Each constraint refuses its case for the intended reason.
    - The F-001 BU-RLS gate still passes.
    - Smoke run: the service is ready on a migrated database, and turns not-ready after a stray `GRANT`.
- 2026-10-26: T-09 implementation notes (`db/migrations/0012_posture_write.sql`). Decision (Robert Former): out-of-bounds changes fail closed until approvals can be verified, and F-001 T-26 (dual-approval engine) moves ahead of F-015 T-14. The tasks.md verification reference "drift (T-21)" is corrected to T-25, the drift engine.
  - The database is the enforcement point (AC-02). `posture.request_change(key, bu_id, value, explanation, requested_by, approval_request_id)` validates the value, refuses anything below the hard floor, and classifies the change against the current value (tighten, neutral or loosen). Out-of-bounds changes need an explanation and an approval request and are recorded as `pending_approval`; everything else is recorded as `requested`. The caller's own labels are never trusted.
  - `posture.apply_change(change_id)` re-checks the floor and bound at apply time, writes the value, and marks the change `applied`. On a `pending_approval` change it raises PF005 until F-001 T-26 exists; a later migration will make it verify `iam.approval_request` (approved, decided by someone other than the requester, not expired) and create the exception.
  - `posture.apply_revert(exception_id)` runs only on an expired, active (or `revert_failed`) exception. An instance value returns to the active profile default (source `revert`). A BU override is removed so the BU inherits. If a later change already replaced the value, only the exception closes.
  - Values are JSON as in packages; durations are Go duration strings, parsed by `posture.duration_ns`. The strictness comparators cover duration, int, bool and enum; `set` is refused until a setting needs it.
  - "Current value" is the BU row, else the instance row, else the active profile default. Inheritance along `iam.bu_closure` and strictest-of arrive with T-22.
  - Row MAC: HMAC-SHA-256 (pgcrypto) over the canonical jsonb text of (key, bu_id, value, source, change_id, exception_id), keyed by `posture.mac_key`.
    - The key store mirrors `authz.ctx_key`: `add_mac_key`/`retire_mac_key` may be called by `fair_owner` only. New rows use the newest unretired key, and each row records `mac_key_id`, so retired keys still verify.
    - The installer adds the first key (README). With no key, writes fail closed (PF006).
    - `posture.mac_mismatches()` lists rows that do not verify, for the drift engine (T-25).
  - Grants: only `app_posture` may execute `request_change`, `apply_change`, `apply_revert` and `mac_mismatches`. The helpers (`write_value`, `row_mac`, the comparators) are callable by nobody but their owner. `posture_definer` gets exactly the table privileges these functions need, plus `authz.hmac`.
  - Errors use SQLSTATE class PF: PF001 hard floor, PF002 approval required, PF003 not applicable, PF004 invalid value, PF005 approvals unavailable, PF006 configuration.
  - `requested_by` is the user the posture service authenticated; the database cannot verify it. Binding it to a signed database context is left to T-14.
  - Verification (DB tests):
    - No application role can insert, update or delete posture rows, `mac_key` included.
    - `app_rw` and `app_engine` cannot call the functions, and `app_posture` cannot call the helpers.
    - Change flow: tighten, loosen within bounds, out-of-bounds pending and refused, hard floors (global and per family), invalid values, BU-scopable keys only, re-evaluation at apply time, and no writes without a MAC key.
    - Direct superuser edits are all detected: changed value, changed source, swapped MAC, inserted row, re-keyed row.
    - Key rotation leaves old rows verifiable.
    - Reverts: instance, BU, not yet expired, already reverted, superseded.
    - The duration parser accepts and rejects the expected inputs.
    - A mutation that disables the floor check makes the tests fail.
- 2026-10-26: T-10 implementation notes (`db/migrations/0013_posture_packages.sql`, `internal/posture`, `cmd/posture seed|import`, `profiles/embed.go`). §4.3 gains "Loading and seeding" (decisions above).
  - `migrate.Run` now takes a `migrate.Release` (catalog payload plus profile packages) and loads both in one privileged transaction. The `db.migrated` audit event lists `profiles_imported`.
  - `profilepkg.LoadRelease` checks each embedded package against the manifest pin and decodes it. It checks no signature, because the integrity of embedded packages comes from the signed binary. The Dockerfile copies `profiles/packages`.
  - `posture.import_package` returns `imported` or `unchanged`. Only newly imported packages are audited (`posture.package_imported`, high severity).
  - `posture.seed` runs once (an existing active profile gives PF003) and needs a MAC key (PF006). Concurrent seeds serialize on the singleton `active_profile` key. It returns the version, digest and settings count for the audit event.
  - D-OQ5 stays open for key custody. The public key is a file the operator passes (`-pub`), and where it ships in the bundle is part of D-OQ5.
  - For T-12: a package may bind keys that are not registered yet. Their values are checked when they are loaded only if a definition exists, so registration must re-check the active profile's values and bounds against the new definition.
  - Verification:
    - DB tests: the release loads at migrate with the database-computed digests, and a re-run changes nothing.
    - Changed bytes under the same version, a below-floor bound for a registered setting, and a non-package are all refused. Application roles cannot call the release path.
    - Seed with no MAC key, with a failing audit sink, and with an unknown profile each leave nothing behind. A successful seed writes 19 values equal to the defaults, emits one audit event with the digest, marks the profile active, and leaves no MAC mismatches. A second seed is refused.
    - Signed import loads only the new version and audits it. Tampered, unsigned and wrong-key releases load nothing and emit no audit events. A forged below-floor package sent straight to `import_package` gives PF001.
    - CLI smoke run: migrate, add a MAC key, seed, seed again (refused), sign and import (all unchanged), tamper and import (refused). The `iam` image builds.
- 2026-10-26: T-11 implementation notes (`db/migrations/0014_posture_read.sql`, `pkg/settings/client.go`, `source.go`, `internal/posture.PublishChanged`).
  - Read side:
    - `posture.state.version` is bumped by statement-level triggers on `setting_value`, `active_profile` and `profile_value`. The trigger runs as `posture_definer`, so out-of-band edits bump it too.
    - `posture.effective_settings()` returns one consistent snapshot: `{version, profile, profile_version, instance, bu}`. Instance values are the active profile's defaults overlaid by instance-wide values.
    - `posture.settings_version()` is the cheap poll.
    - Both are granted to `app_rw` and `app_posture`, with schema `USAGE` for `app_rw`, as planned in T-08. Services still have no table privileges.
  - `settings.Client` sits alongside the T-00b `Registry` (unchanged until T-16):
    - `Register` validates definitions locally. Registration with the posture service and the startup check are T-12.
    - `Get(key, buID)` and typed accessors (`Duration`, `Int`, `Bool`, `Enum`) decode package-format JSON per definition. A BU override applies only to BU-scopable settings.
    - `Run` refreshes at once on a `posture.setting.changed` event for a newer version, and polls the version every TTL (30 s), reloading only when it moved.
    - `Get` fails closed (`ErrStale`) after `MaxStale` (2 minutes) without a confirmed refresh. A registered key with no value in force gives `ErrUnbound`.
  - Heartbeats go on `posture.settings.heartbeat` (core NATS) every 60 s: service, instance, version, the instance values of registered keys, a BU override count, and a SHA-256 digest of the whole snapshot. The drift engine (T-25) consumes them.
  - Publishing: `internal/posture.PublishChanged` publishes `{key, bu_id, version}` through `natspub` (JetStream, acknowledged) after commit. The installer provisions a stream for `posture.setting.changed`. Clients listen with core subscriptions; a lost event is covered by the poll.
  - Verification:
    - Unit tests: typed values, BU scoping, unregistered and unbound keys, bad values, conflicting registration, reload only on a version change, wake-ups only for newer events, event-driven versus poll-driven propagation, fail-closed staleness and recovery, and heartbeat contents and digest.
    - DB tests: the snapshot before and after the seed, the version moving on changes and on a direct edit, BU overrides in the snapshot, and no table access for `app_rw`.
    - Propagation across three services (separate pools and NATS connections, default TTL): an announced change reached all three in about 20 ms; with the event withheld, the poll delivered it in 29.8 s (requirement: 60 s). All three heartbeats agree.
- 2026-10-26: T-12 implementation notes (`db/migrations/0015_posture_register.sql`, `pkg/settings/register.go`).
  - `posture.register_settings(owner_feature, version, defs)` is executable by `app_rw` and `app_posture`. Any service may register, so registration can never weaken anything:
    - A new key is inserted, and the table's checks validate it.
    - An existing key must keep its type, direction, enum order, BU scoping and owning feature (PF004).
    - Its hard floor may only stay or tighten: no lower value, no removal, and no narrower family list. An empty list means every family (PF001).
    - Every key must be bound by the active profile (PF006, listing the unbound keys). The profile's default and bound, and every value in force, must be valid for the definition and not below its floor (the T-10 follow-up).
    - The whole call is one transaction: a refused registration records nothing.
  - `settings.Client.Start(ctx, registrar, ownerFeature, version)` is the startup sequence. It registers the locally declared definitions (`DBRegistrar`), loads the snapshot, and checks that every key has a value in force. Any failure returns `ErrStartup`, and the service must not start. Wiring `Start` into `iam` comes with T-16, when the stand-in `Registry` is replaced; until then no service reads posture settings.
  - Limitation: all definitions a client registers are recorded under one owning feature. A service that reads another feature's setting declares it with `Register` but cannot `Start`-register it. T-16 will add the distinction if a service needs it.
  - Verification:
    - Unit tests: the definition encoding (kinds, directions, floors as package values, sorted), and `Start` refusing on a registrar error, on unbound keys and with nothing registered.
    - DB tests: `Start` before the seed fails. With an extra key the active profile does not bind, `Start` fails, names the key, and records nothing; this is the service refusing to start. With the F-001 keys it succeeds and records 19 definitions with their floors and parameters, and a restart is idempotent.
    - Refused: a flipped direction, made BU-scopable, a changed enum order, another owning feature, a lowered or removed floor, narrowed floor families, a floor the active profile does not meet, an invalid value in force, and `app_engine` calling the function. A tightened floor the profile meets is accepted.
    - A mutation that disables the no-weakening rule fails four of those cases.
- 2026-10-26: T-13 implementation notes (`pkg/settings/strictness_test.go`, `db/migrations/0016_posture_strictness.sql`, `db/tests/posture_strictness_test.go`). Decision (Robert Former): the `set` type stays deferred until a setting needs it. Subset order is only a partial order, so it cannot meet the "total order" property; its rules (incomparable counts as weaker, strictest-of is the intersection) arrive with the first set setting. The task row is amended accordingly.
  - The comparators already existed (`Def.Compare` and `Def.Strictest` in Go; `posture.compare` in SQL since T-09). T-13 proves them and makes the two sides agree.
  - SQL `posture.strictest(def, values)` is added, owned by `posture_definer` and callable by nobody else, for T-22's BU resolution.
  - Go property tests (fixed seed; `FAIR_PROPERTY_SEED` explores others), for every kind and direction:
    - The comparator is reflexive, total, antisymmetric and transitive; equal strictness means equal values; and it matches each direction's meaning.
    - Strictest-of returns one of its inputs, at least as strict as all of them, independent of order and monotonic as values are added.
    - Invalid values and kind/direction mismatches are refused.
    - "Floor never violated": over 50 random profiles and 40 random changes and approvals each on the stand-in registry, no value in force is ever below an applicable floor. The test computes the floor condition itself, after a mutation showed that reusing the code under test hid a disabled floor check.
  - Go/database parity test: validity on 47 edge-case candidates, comparison on 300 random pairs per kind and direction, and strictest-of on 100 random lists per kind and direction. The test found four divergences, all fixed:
    - The settings client decoded JSON `null` as a zero value, so `audit.enabled: null` would have read as `false` (fail-open). `settings.DecodeValue` (now exported, and the test uses it) refuses null.
    - The client refused integral exponent forms such as `1e3`, which the database accepts as 1000. They are now accepted.
    - The client accepted a quoted `"3"` as an int, and `"+5m"` as a duration. Both are now refused, as in the database.
    - The database accepted negative ints and values beyond int64 (ints and durations). `check_value` now refuses them, as Go does.
- 2026-10-27: T-04 signed off, and the Enterprise Baseline rationales reviewed, by Robert Former.
  - The CMMC L2 mapping table (`profiles/cmmc-l2-r2/mapping.md`) is reviewed and signed off, including 3.5.8 and 3.5.9 (Table D-5). The sign-off is recorded in `supplement.yaml` (`signoff`), and the generator writes it into `mapping.md`. The two rows' notes now read "confirmed against the PDF". T-04 is Done.
  - The Enterprise Baseline relaxation rationales (`platform_choice` in `bindings/`, T-05) are reviewed and signed off as written.
  - Neither changes a profile or a package: `profile.json` and the signed packages are unchanged.
- 2026-10-27: T-14 implementation notes (`db/migrations/0018_posture_evaluator.sql`, `internal/posture/evaluator.go`).
  - Requester binding (deferred from T-09): `posture.request_change(key, bu_id, value, explanation)` takes the requester from the signed database context (ADR-007; PF007 without one). The requester must hold `settings.change` at the BU, or the root for instance-wide changes (PF008). `iam.holds_permission`, a narrow definer function, answers that for `posture_definer`, which reads no iam table.
  - Out of bounds: an explanation is required, and `request_change` opens the `settings.out_of_bounds` approval (F-001 T-26) for the same user in the same transaction. `posture.preview_change` gives the service what the warning needs (current value, bound, floor, parameters) without writing anything.
  - `posture.apply_change(change_id)` returns the exception it created, if any.
    - For an approved change it consumes the approval (once, for exactly this change) and creates the exception: the approver from the approval, the requester as owner, and the explanation as justification.
    - The exception expires after the `exception.max_duration` value in force: 90 days in all three profiles (AC-24).
    - The hard floor is re-checked, so no exception can sit below it (AC-30).
  - `iam.consume_approval` now returns `{payload, requested_by, decided_by}`; no feature consumed approvals before this task.
  - `posture.Evaluator`:
    - `Change`:
      - Below the floor: `ErrHardFloor`, with `setting.hard_floor_refused` (high) audited after the refusal; if that audit fails, the error says so.
      - Out of bounds without an explanation: `ErrExplanationRequired` with the warning, which names the affected controls derived from the parameter ids (e.g. `ac-02.03_odp.02` → AC-2(3)). Nothing is written.
      - Out of bounds with an explanation: pending approval, with `setting.change_requested` (high).
      - Otherwise: applied, with `setting.changed` (info; low for a loosening within bounds).
      - Audit events for writes are emitted inside the transaction, so no audit means no change. Applied changes are announced on `posture.setting.changed`.
    - `ApplyApproved(change_id)` applies the approved change and emits `setting.exception_created` (high, with the approver as actor).
  - The SaaS SecOps notification (AC-23) is T-15. Flagging exceptions on the Posture page needs the API and UI.
  - Verification (DB tests, against the seeded Enterprise Baseline with the F-001 settings registered):
    - Tighten and in-bounds loosening apply, with their audit events and announcements. FIPS can be switched off in Enterprise, whose floor does not cover it.
    - Four hard-floor settings are refused, each with a high-severity event, and nothing is recorded. A failing audit sink is reported.
    - Out of bounds: the warning without an explanation; a pending approval with one; refused before approval; self-approval refused; the second Platform Admin approves; an exception with owner, approver and a 90-day expiry; a high-severity event and an announcement; a second apply refused; no MAC mismatches.
    - An Auditor and a missing context are refused, as are invalid values. A failing audit sink rolls the change back.
    - The T-09 to T-12 tests now run with a signed context for a Platform Admin.
    - A mutation that drops the `settings.change` requirement fails two tests.
- 2026-10-27: T-15 implementation notes (`db/migrations/0019_posture_secops.sql`, `internal/posture/secops.go`, `internal/config`).
  - Decisions (Robert Former):
    - The channel is a transactional outbox delivered to a signed HTTPS webhook. F-009 may take over the transport later without changing the outbox.
    - The deployment mode is required configuration and fails closed.
  - Deployment mode (ADR-005): `FAIR_DEPLOYMENT_MODE=saas|self-hosted` is part of the shared service config. It is required when `FAIR_ENV=production` and defaults to self-hosted in development. The installer also records it once in the database as `fair_owner` (`posture.set_deployment_mode`). The posture service refuses to start if the two differ, or if production has no recorded mode. The reference manifest `deploy/k8s/iam.yaml` sets `self-hosted`.
  - `posture.apply_change` itself queues the notification in `posture.secops_outbox`, in the change's own transaction, when the recorded mode is `saas`. So neither the service nor a direct call can apply a weakening without it: a failed insert rolls the change back.
    - A weakening is a value weaker than the one in force until then (event `setting.weakened`), or any exception (`setting.exception_created`).
    - The event carries the key, BU, previous value, new value, bound, profile family, change and exception ids, requester, approver and explanation.
    - Tightening and pending requests queue nothing.
  - Delivery is a loop in the posture service every 10 s:
    - `posture.secops_claim` leases due rows with `SKIP LOCKED`, so replicas never send the same row at the same time.
    - Each row is POSTed with `X-FAIR-Delivery` (the id, for de-duplication), `X-FAIR-Timestamp` and `X-FAIR-Signature` (HMAC-SHA-256 of `timestamp.body`, with a secret of at least 32 bytes read from `FAIR_SECOPS_SECRET_FILE`). TLS 1.2 is the floor, and production requires `https://`.
    - Any 2xx acknowledges the notification. Failures back off from 10 s, doubling, capped at 15 minutes.
    - `posture.secops_backlog()` reports the queue for the drift engine (T-25).
  - Verification:
    - Unit tests: the mode check, the webhook constructor (URL, scheme and secret rules), and signatures.
    - DB tests (mode-gated):
      - Self-hosted queues nothing.
      - In SaaS mode, tightening and pending requests queue nothing, while an in-bounds weakening and an approved exception each queue one event with the right before and after values.
      - Delivery to a TLS receiver that checks every signature: while the intake is down, both fail and back off; after recovery both are delivered once, with distinct delivery ids; a wrong secret is rejected and stays queued.
      - A failing queue insert rolls the weakening back. Only `fair_owner` can set the mode. Application roles cannot claim from or touch the queue.
    - A mutation that queues regardless of mode fails the self-hosted test.
- 2026-10-27: T-16 implementation notes (`db/migrations/0020_settings_registry.sql`, `pkg/settings/setter.go`, `internal/posture/setter.go`).
  - Decision (Robert Former): `settings.Set` is served by the change evaluator embedded in each service, connecting as `app_rw`. The evaluator's entry points (`preview_change`, `request_change`, `apply_change` and the summaries) are therefore granted to `app_rw` as well as `app_posture`. This is safe because the database enforces every rule on the caller's signed context: requester and `settings.change`, floors, bounds, approvals and the SecOps queue. The posture service keeps import, seed, SecOps delivery and (later) drift. A posture HTTP API (§7) can wrap the same evaluator.
  - `settings.Setter` (`Set(ctx, principal, Request)`) is the F-001 §8 contract. `posture.Setter` implements it and adds `ApplyApproved`. `settings.Request` gains `BUID`, and `settings.Result` gains `ChangeID`; both are additive, so the public API stays stable. Reads use `settings.Client` (T-11) and startup uses `Client.Start` (T-12).
  - Fix found while porting the F-001 tests (AC-22): T-14 sent a tightening that is still outside the bound back to approval, even when an active exception covered the value in force. Now:
    - Such a tightening applies at once, under the covering exception, whose value follows it.
    - A change back within the bound supersedes the exception (new state `superseded`).
    - A further loosening inside the exception still needs approval.
    - `preview_change` reports `covered`.
  - F-001 keys: they are bound in every package (T-05/T-06), seeded (T-10) and registered by `Client.Start` with the F-001 definitions (T-12). Nothing else needs to move.
  - The T-00b `Registry` remains for the exception lifecycle (renewal, auto-revert, notices) until T-17 and T-18. Its `BuiltinProfiles` equality test with the bindings stays until then.
  - No service calls `settings.Set` yet. `iam` gets a database pool and `Client.Start` when its first settings-dependent feature arrives (F-001 Phase 2, sessions), so the iam image keeps starting without a database for the CI image checks.
  - Verification: the T-00b tests, ported as `TestRegistry*` against the real registry through `settings.Setter` and `settings.Client` as `app_rw`:
    - tightening immediate, with no SecOps notification;
    - loosening within bounds, audited low and notified;
    - out of bounds needing an explanation, a control warning, dual approval and a 90-day exception;
    - hard-floor refusals audited in all three profiles;
    - the FIPS floor conditional on family;
    - break-glass enablement needing approval in all three profiles;
    - tightening inside an exception keeping coverage, then superseding it;
    - failing closed without audit.
    - The stand-in tests for seed audit, missing bindings, floor validation and the comparators map to the T-10, T-12, T-06/T-10 and T-13 tests.
    - A mutation that disables the coverage rule fails the exception test.
    - The T-09 test now checks that `app_rw` can call the change functions but is refused without a signed context (PF007) or without `settings.change` (PF008), while `app_engine` gets no access.
- 2026-10-27: T-17 implementation notes (`db/migrations/0021_posture_exception_lifecycle.sql`, `internal/posture/lifecycle.go`).
  - Expiry (AC-24): a change request may ask for a shorter exception (`ChangeRequest.ExceptionDuration`, `settings.Request.ExceptionDuration`), which the approver sees in the approval payload.
    - The duration must be positive and no longer than the `exception.max_duration` value in force (PF009, `ErrExpiryOutOfRange`, `settings.ErrExpiryTooLong`).
    - It is clamped again when the exception is created, so tightening the maximum while a request waits shortens it.
    - Without an exception duration in force, an out-of-bounds request is refused: no exception may be open-ended.
  - Renewal (AC-26): `posture.request_renewal(exception, justification, duration)` (`Evaluator.RequestRenewal`).
    - It is allowed only while the exception is active and unexpired, by a holder of `settings.change` where it applies, with a new justification. It opens a `settings.exception_renewal` approval (a new F-001 approval kind; approver permission `settings.approve`).
    - `posture.apply_renewal` (`Evaluator.ApplyRenewal`) consumes the approval once. It refuses if the exception has expired or closed in the meantime. It re-checks the floor and creates a new exception (`renewed_from` set; owner the renewal's requester), then marks the old one `renewed` and points the value at the new one.
    - Audit: `setting.exception_renewal_requested` and `setting.exception_renewed` (high). In SaaS mode a renewal also notifies SecOps (`setting.exception_renewed`).
  - Notices (AC-25): `posture.exception_notices()` records the 14-, 7- and 1-day notices once each (`posture.exception_notice`). It queues them for the owner and the holders of `settings.approve` in `posture.notice_outbox`, and returns them.
    - When thresholds are crossed together (a 5-day exception), only the nearest is sent; the others are recorded as unsent.
    - The posture service runs it every minute (`posture.RunNotices`) and audits each notice inside the recording transaction: `setting.exception_expiring`, info at 14 days, low at 7, high at 1. A failed audit records nothing, so the next run retries.
    - This is a minute loop rather than per-exception River jobs (§6.3): it is idempotent and needs no job store.
  - Delivery to people: the outbox is drained by F-009 (notifications), which does not exist yet. Until then the audit events are the only signal.
  - Verification (time travel moves an exception's timestamps; rules use the database clock):
    - Duration: the default is 90 days, 30 days on request; 200 days and negative durations are refused, with nothing written; a 60-day request is clamped to 30 days after the maximum is tightened.
    - Renewal: refused without a justification or by an Auditor, and before approval; self-approval refused; the second admin approves; the new exception lasts 14 days, the old one is `renewed`, and the value is re-pointed; both are audited; a second apply and renewing the old exception are refused; after expiry neither apply nor request works.
    - Notices: none at 90 days left; 14, 7 and 1 at the thresholds, once each, with outbox recipients; a 5-day exception sends 7 only; a failing audit records nothing, then the retry succeeds.
    - A mutation that drops the before-expiry check on apply fails the renewal test.
    - The T-09 test profile now binds `exception.max_duration`.
- 2026-10-27: T-18 implementation notes (`db/migrations/0022_posture_auto_revert.sql`, `internal/posture/revert.go`).
  - `posture.drift_finding` is created with the design §5 columns, plus `resolved_at` and `last_escalated_at`, and at most one unresolved finding per check and subject. The people-facing lifecycle is T-26; the drift engine is T-25.
  - `posture.due_reverts()` claims, under a one-minute lease, the active exceptions past expiry and the failed ones whose retry is due. The posture service reverts them every 10 s as `system:posture` (`posture.RunReverts`). Each revert runs in its own transaction with `setting.exception_reverted` (high) audited inside it, and is announced to the caches when a publisher is configured.
  - `posture.apply_revert` (T-09) now also resolves the exception's open `revert_failed` finding and queues the `setting.exception_reverted` notice for the owner and admins (AC-27).
  - Failure (AC-29): the revert rolls back and `posture.record_revert_failure` marks the exception `revert_failed`. Retries back off from 5 s, doubling, up to the design's 5-minute cap. A critical `revert_failed` finding is opened, or refreshed with the attempt count and last error, and resolves only when a revert succeeds. Every failure is audited as `setting.revert_failed` (critical). The first failure and then one per hour escalate (`setting.revert_failed_escalation`, plus a notice). The value stays at the exception's value, never silently changed.
  - Timing (AC-28): the 10 s revert loop plus the settings client's 30 s poll keeps a revert within 60 s even without change events. Measured end to end: 29 s. The posture service does not publish change events yet (no NATS configured for it).
  - Session termination at the next request (AC-28) belongs to the gateway and sessions (F-001 Phase 2): they read the timeout through `settings.Client`, which is verified here to see the reverted value.
  - The T-00b stand-in is retired: `Registry` and its tests are removed. `pkg/settings` keeps the definitions, profiles, comparators, `Client`, `Setter` and the shared request and result types (`Request.Actor` is gone: the requester is always the signed-context principal). Its last two behavior tests are ported (auto-revert and renewal before expiry). The T-13 property "floor never violated" now runs against the real registry: `TestFloorNeverViolatedRealRegistry`, 60 random changes and approvals per built-in profile.
  - Verification:
    - Revert on expiry: the value returns to the profile default (source `revert`), with audit and notice; no double revert; renewal refused afterwards.
    - A renewed exception does not revert at the original expiry.
    - Fault injection with a failing audit sink: `revert_failed`, an open critical finding and an escalation; backoff respected; retry within the hour without a second escalation; a repeated escalation after an hour.
    - Fault injection with no usable MAC key: the failure is audited (critical); after restoring a key the next attempt reverts and the finding resolves.
    - Application roles cannot claim reverts or read findings.
    - Timing test: 29 s.
    - Mutation checks: dropping the finding resolution fails the fault-injection test; disabling both floor checks fails the real-registry property test in all three profiles.
- 2026-10-27: T-19 implementation notes (`db/migrations/0023_custom_profiles.sql`, `internal/posture/profiles.go`).
  - All functions act for the signed-context user (PF007 without one). Changes need `profile.manage` at the root, since profiles are instance-wide (PF008). `posture.Profiles` wraps them, and every write is audited inside its transaction.
  - Create (AC-11): `create_custom_profile(base, version, id, name)` clones any built-in profile, not only the active one, into a `draft`: version `1`, the base's family, all of the base's values. T-20 adds versioning. Ids are unique across profiles.
  - Edit (AC-11, AC-12): `edit_custom_value` (drafts only) sets a registered key's default and bound.
    - Both are validated against the registered definition, the default may not be weaker than the bound, and the bound may not be below a hard floor that applies to the profile's family (PF001).
    - A key is `loosened` when its default or bound is weaker than the base's. A loosened key needs a written justification (PF002).
    - `label_deviates` follows the loosened rows: "Deviates from <base>" (`posture.DeviationLabel`). Returning a key to the base clears its deviation.
  - View (AC-13): `custom_profile_view`, for holders of `profile.manage` or `profile.approve`, gives per key the base and new default and bound, the direction against the base (tighten, loosen, unchanged), the loosened flag, the justification and the parameters. `posture.ProfileKey` adds the affected controls.
  - Submit and approve (AC-12): `submit_custom_profile` validates the whole profile against every registered setting: bound, valid values, floor, default within bound, and justified loosening. It then opens a `profile.approval` request (new F-001 approval kind; approver permission `profile.approve`) whose payload lists the loosened keys.
    - Self-approval is impossible through the approvals engine (API, database function and table check).
    - `approve_custom_profile` consumes the approval once, re-validates, and sets `approved`, recording the approver in the audit event. Activation is the profile switch (T-21).
    - `reopen_custom_profile` returns a submitted profile to `draft`, for example after a rejection; its old approval can no longer be used.
  - Audit: `profile.created` (info), `profile.value_changed` (low when loosened), `profile.submitted` and `profile.approved` (high), `profile.reopened`.
  - Verification (DB tests):
    - An Auditor cannot create or view; duplicate ids and custom bases are refused.
    - Tightening needs no justification; loosening needs one and sets the deviation label.
    - TLS, audit and the FedRAMP-family FIPS floor are refused; invalid values and defaults weaker than bounds are refused.
    - The view shows directions, controls and justifications.
    - No edits after submit; self-approval refused through the API and the database; no approval before the decision; an Auditor cannot decide; the second admin approves; a second approval is refused; audit severities checked.
    - Reopen: an Enterprise FIPS-off default needs a justification; rejection, reopen (Auditor refused), back to base clears the label, then resubmit and approve.
    - A mutation that skips consuming the approval fails the lifecycle test.
- 2026-10-27: T-20 implementation notes (`db/migrations/0024_custom_profile_versions.sql`, `internal/posture/profile_io.go`).
  - Versions (AC-14): custom profile versions are numbered. `new_custom_version` copies any version into the next draft; a profile has at most one draft, and submitted versions never change. `profile_diff` compares any two profile versions key by key: `tighten`, `loosen`, `mixed`, `unchanged`, `added`, `removed`.
  - Base updates (AC-15): `base_update_effects(base, new version)` shows, for every approved or active profile derived from the base, what moving to the new base version does per key. With C the custom value and N the new base value:
    - N weaker than C: **pinned** (C kept).
    - N stricter than C: **proposed** (C kept, N offered).
    - Equal: unchanged. Keys only in the new base: added.
    - `rebase_custom_profile` creates the next draft on the new base accordingly, so nothing in a custom profile silently weakens.
    - A proposed key that is now looser than the base keeps its justification if it had one. If not, it is marked `needs_review`, and submission is refused ("the base update proposes ...; adopt it or justify the current value") until the key is edited: either the proposal is adopted or the current value is justified.
    - The T-08 check that a loosened row needs a justification becomes "a loosened row needs a justification unless it is under review"; approved profiles never carry `needs_review`.
  - Export (AC-14):
    - Native JSON (`fair-custom-profile/v1`): id, version, name, family, base, deviation flag, and per key default, bound and justification.
    - OSCAL 1.2.3 profile, validated before release:
      - It imports the base as `urn:fair-app:profile:<id>:<version>`.
      - It has one `set-parameters` entry per OSCAL parameter a setting implements: the default as the value, with `fair-setting`, `fair-bound` and `fair-justification` props in namespace `urn:fair-app:posture`.
      - The title carries "Deviates from <base>".
      - The native JSON is embedded in back-matter, because settings without an OSCAL parameter cannot be expressed in `set-parameters`.
    - UUIDs are deterministic version 5, because OSCAL accepts only versions 4 and 5. SHA-1 is used only as the RFC 9562 name hash, which `fips140=on` permits.
  - Import (AC-14) always creates a draft with a new id, in one transaction, through the edit rules: registered definitions, hard floors, and a justification for every loosened key. Any problem refuses the whole import (`ErrImport`), leaving nothing behind.
    - Our own OSCAL exports import losslessly from back-matter.
    - Other OSCAL profiles must import a base as above; their `set-parameters` map to the settings that implement the parameters, and a parameter no setting implements refuses the import.
    - Imports are audited as `profile.imported` (high). Built-in profiles are not exported this way; they ship as signed packages.
  - Verification (DB tests):
    - Upgrade simulation: FedRAMP Moderate 1.1.0 loaded through the release path relaxes idle timeout (pinned at ACME's 10m), and tightens lockout and token lifetime (both proposed). The effects list 19 keys for ACME 1. Rebase gives version 2: the pinned value is kept; the proposed lockout keeps its justification; the proposed token lifetime blocks submission until adopted. Version 2 is approved, the diff shows no loosening, and the rebased version leaves the effects list.
    - Versions: a copy, only one draft, approved versions immutable, an Auditor cannot diff.
    - Export/import: the JSON round trip, the OSCAL export validating with the parameter and the label, the OSCAL round trip through back-matter, and import from bare `set-parameters` (justification kept). Refused, with nothing created: a wrong format, below the floor, loosened without a justification, an unknown setting, an unmapped parameter, no permission. A built-in profile cannot be exported.
    - A mutation that lets rebase take the new base's weaker value fails the upgrade simulation.
- 2026-10-27: T-21 implementation notes (`db/migrations/0025_profile_switch.sql`, `internal/posture/switch.go`).
  - States: the design's `requested → conflicts_computed → resolving → (awaiting_approval) → activating → active | cancelled` maps to `resolving → activated | cancelled`. Requesting computes the conflicts in the same call, "awaiting approval" is whether the approvals have been granted, and activating is the activation transaction itself. At most one switch is open at a time.
  - Request (`posture.request_switch`, `profile.manage`): the target must be an `approved` profile version: a built-in, a custom profile, or a newer version of the active built-in (AC-07, whose differences `profile_diff` shows first).
    - Conflicts (AC-16) are the explicit values (changes, exceptions, reverts, BU overrides) that are weaker than the target's bound. Instance values that came from the current profile are not conflicts; they follow the target's defaults at activation (§6.4). This keeps a switch from Enterprise to FedRAMP from presenting every relaxed Enterprise default as a conflict.
    - A target with any bound weaker than the current profile's is a loosening (AC-19): a justification is required, a `profile.switch` approval is opened (new F-001 approval kind; approver `profile.approve`), and the request is audited high.
  - Resolve (`posture.resolve_conflict`):
    - `conform` sets the target default at activation.
    - `exception` needs a reason and an optional duration, and opens a `settings.out_of_bounds` approval. It is refused when the value is below a hard floor of the target's family, for example FIPS off when switching to FedRAMP.
  - Activate (`posture.activate_switch`) is one transaction (AC-17, rollback-safe):
    - It refuses while any conflict is unresolved, or if a value became a new conflict after the request.
    - It consumes the loosening approval and every exception approval; any missing approval aborts everything.
    - It makes the target active and the previous profile `approved`.
    - It re-seeds values from the old profile with the target's defaults, first, so that new exceptions use the target's `exception.max_duration`.
    - It keeps explicit values within the new bounds, applies conforms, creates the exceptions (superseding old ones on conflicting values), records the switch on `active_profile`, and notifies SecOps of a loosening switch in SaaS mode.
    - The service audits `profile.activated` (high) inside the transaction and announces `posture.profile.activated` and a settings change when a publisher is configured.
  - While pending (AC-18), the current profile stays in force. `posture.pending_switch` and `Switches.Pending` give the Posture page the switch and its conflicts, with unresolved counts.
  - Verification (DB tests):
    - Enterprise to FedRAMP: the explicit 30m idle timeout and FIPS-off are the only two conflicts.
    - Still pending: the current profile in force, no second switch, no activation while unresolved.
    - Conflict rules: FIPS cannot be an exception (below the floor); an exception needs a reason.
    - Activation before the exception's approval fails with nothing changed. After approval, activation conforms FIPS, re-seeds lockout and network binding to FedRAMP, keeps idle timeout under a new 30-day exception approved by the second admin, and updates the profile statuses, with an audit and no MAC mismatches.
    - FedRAMP to Enterprise in SaaS mode: a justification is required, audited high; activation is refused before approval; self-approval is refused; after activation the SecOps queue holds `profile.switched` and the settings client sees the Enterprise values.
    - Newer built-in (AC-07): the 1.0.0 → 1.1.0 diff shows three changes, and the switch is a loosening; cancelling allows a new request.
    - Stale conflict: a value made weaker after the request blocks activation.
    - A mutation that drops the unresolved-conflict check fails the activation test.
- 2026-10-27: T-22 implementation notes (`db/migrations/0026_bu_overrides.sql`).
  - `posture.current_value(k, bu)` implements §6.6 without the overlay (T-23): the strictest of the instance value and every BU override at `bu` or at an ancestor whose path to `bu` is unblocked in `iam.bu_closure`. An override on a restricted BU applies to it and below; one above stops at it, as F-001 role assignments do. posture_definer reads the tree only through two narrow `iam` definer functions, `iam.unblocked_ancestors(bu)` and `iam.unblocked_descendants(bu)`.
  - The change evaluator, switch and exception paths already call `current_value`, so they now see effective values. A BU write is classified against the BU's effective value. A weaker override under a stricter ancestor is therefore treated as a loosening (audited, approved when out of bounds) even though the ancestor's value stays in force. This is deliberately conservative.
  - `posture.effective_settings()` "bu" now lists, for each BU an override reaches, only the BU-scopable values that differ from the instance value. The settings client falls back to the instance value otherwise, so its `Get` is unchanged.
  - Moving or restricting a BU changes which overrides reach it, so a statement trigger on `iam.bu_closure` bumps the posture version, and every cache refreshes.
  - Verification (DB tests):
    - `TestBUOverridesProperty`: 5 seeds, each a random 20-BU tree with 12 random `session.network_binding` overrides and a random instance value, written through the evaluator. Then 8 random restrict/unrestrict and subtree-move steps. After each step, `current_value`, the snapshot and the settings client must equal a Go model of the rule, and each tree change must bump the version.
    - `TestBUOverrideBlockedAtRestricted`: a worked example.
    - Mutations (ignoring the blocked flag, using the BU's own row only, dropping the tree trigger) each fail the tests.
    - `TestPostureEffectiveSettings` now expects no BU entry for an override equal to the instance value.
- 2026-10-27: Restricted BU overlay storage and bound, approved by Robert Former with T-23 (`db/migrations/0027_restricted_bu_overlay.sql`, `internal/posture/overlay.go`).
  - **Computed, not rows.** The design applied the overlay as `source = overlay` rows in `setting_value`. That table allows one row per (key, BU), so a restricted BU's own override and its overlay row would collide, and §6.6's formula treats the two separately. Now `posture.current_value` adds the overlay for every BU in a restricted subtree (`iam.in_restricted_subtree`), and `effective_settings` lists those BUs (`iam.restricted_subtree`). Restrict/unrestrict already bumps the posture version (T-22), so nothing is copied, removed or left behind; F-001 audits restrict/unrestrict.
  - **Defaults in code.** The AC-33 defaults are `posture.overlay_defaults()`: `bu.reauth_max_age = 15m0s`, `session.network_binding = reauthenticate`, `export.reason_required = true`. A key takes effect, and becomes editable, once its setting is registered as BU-scopable. Today that is `session.network_binding`; `bu.reauth_max_age` arrives with T-24 and `export.reason_required` with F-010. An overlay value that does not fit its registered setting fails the read (closed).
  - **Edits.** `posture.overlay_value` holds edited values, row-MAC'd like `setting_value` (domain-separated as `overlay:<key>`) and included in `mac_mismatches()`; `posture.overlay_change` records requests. Edits need `settings.change` at the root.
  - **Bound = the AC-33 default (AC-34).** Tightening, and moving back towards the default, apply at once (audited `overlay.changed`; low severity for a loosening). Weaker than the default needs an explanation and a `settings.out_of_bounds` approval, and applies as an exception with `exception.overlay = true` (`bound_at_creation` = the default). That exception has R-07's expiry, notices, renewal (`apply_renewal`) and auto-revert (`apply_revert` restores the default). A tightening under an active overlay exception updates it; returning to the default supersedes it. SaaS mode queues `overlay.weakened` / `overlay.exception_created` for SecOps. The hard floor applies as everywhere.
  - Verification (DB tests):
    - `TestOverlayOnEveryRestrictedBU`: 4 seeds of random trees with weaker overrides, then 10 random restrict/unrestrict and move steps. The settings client must show the overlay on every BU in a restricted subtree and the T-22 value everywhere else.
    - `TestOverlayDefaults`: the three defaults (only network binding applies yet), present on the restricted BU and its child and nowhere else, gone after unrestrict; editing an unregistered key is refused.
    - `TestOverlayWeakeningNeedsApproval` (SaaS):
      - Without `settings.change`: refused.
      - Without an explanation: refused, with a warning naming the default.
      - With an explanation: pending, value unchanged until approval; applying early and self-approval are refused.
      - After approval: a 7-day overlay exception and a SecOps event, with the instance value untouched.
      - Renewal takes over the overlay row; at expiry the revert restores the default with no MAC mismatches.
    - `TestOverlayTighteningAndMAC`: tightening under the exception and returning to the default apply at once (the exception is superseded); an out-of-band edit of `overlay_value` shows in `mac_mismatches()`; application roles cannot reach the table or the write functions.
    - The T-22 tests now weaken the overlay to `off` through an approved overlay exception, so that it does not mask the inheritance rule.
    - Mutations (applied everywhere, never applied, missing from the snapshot, no approval for weakening, revert keeping the value) each fail the tests.
- 2026-10-27: T-24 split, approved by Robert Former. The F-001 pieces T-24 needs for its end-to-end verification do not exist yet: gateway sessions (F-001 T-13), the SAML SP (T-15) and the OIDC RP (T-16). T-24 now covers everything that does not need them; new task T-24b, sequenced after F-001 T-16, captures the session's `auth_time`, runs the IdP re-authentication on `step_up`, and carries the E2E test.
  - **`bu.reauth_max_age`** (F-001 setting, `bindings/bu.reauth_max_age.yaml`, IA-11): BU-scopable duration, lower is stricter. Its default and bound equal each profile's session absolute timeout (12h; Enterprise Baseline may relax to 24h), so step-up never triggers outside restricted BUs before the session would end anyway. The Restricted BU overlay lowers it to 15m (T-23), and per-BU overrides can tighten it (T-22).
  - All three built-in packages move to version 1.1.0 for the new binding (packages are immutable); the release ships 1.1.0 only. Installs already on 1.0.0 keep those rows and can switch to 1.1.0 (AC-07). DB tests that synthesize a newer release now use 1.2.0.
  - **`authz`:** `Principal.AuthTime` (zero = unknown, which always needs step-up). `CacheOptions.ReauthMaxAge` (wired to `settings.Client.ReauthMaxAge`) enables the check. `Cache.Check` returns `*StepUpError{MaxAge}` (`errors.Is(err, ErrStepUpRequired)`) when the sign-in is older than the BU's effective value. The check runs only after the permission is granted, so a stale sign-in never reveals an out-of-scope BU (F-001 AC-25). A settings error denies. Service accounts are unaffected; they are refused before this until F-001 T-33.
  - **HTTP:** `server.WriteAuthzError` answers step-up with 401 and `WWW-Authenticate: step_up max_age=<seconds>`, and every other refusal with 404, without echoing the error.
  - Verification:
    - `pkg/authz` `TestCheckStepUp`: fresh, at the limit, stale, unrestricted, unknown auth time, denial precedence, policy error, max age carried.
    - `internal/server` `TestWriteAuthzError`.
    - DB `TestStepUpOnRestrictedBU`: real grants, overlay and settings client. A 20-minute-old sign-in needs step-up within 15m on a restricted BU and below it, but not on an unrestricted BU (12h). A stricter 1h BU override applies. Unrestricting removes the requirement.
    - A mutation that skips the step-up check fails both the unit and the DB test.
- 2026-10-27: T-25 implementation notes (`db/migrations/0028_app_drift.sql`, `internal/posture/drift.go`, `cmd/posture`).
  - **When it runs.** `posture.RunDrift` scans whenever the posture version moves (polled every 10 s), on every `posture.setting.changed` (NATS wake-up; imports and switches publish it too), and at least every 15 minutes (AC-36). The version triggers fire on direct database edits as well, so those are scanned within one poll; an edit with triggers disabled is still caught by the 15-minute scan.
  - **Checks 1-3 in the database.** `posture.drift_scan()` is read-only:
    - `row_mac_mismatch` (critical; CM-5, CM-6, SI-7) for `setting_value` and `overlay_value` rows.
    - `unapproved_deviation` (high; CM-3, CM-6): weaker than the active profile's bound (the overlay: its AC-33 default) without a covering active or `revert_failed` exception with the same value.
    - `hard_floor_violation` (critical; CM-6, CM-7), exception or not.
    - `missed_revert` (high; CA-5, CM-6): an active exception more than a minute past expiry. A failing revert is T-18's `revert_failed` finding, which this engine leaves alone.
  - **Check 4 in Go.** Services' heartbeats are stored per instance by `posture.record_heartbeat`. The input is untrusted: it is validated, size-limited, and kept for a day. Heartbeats from the last 3 minutes are compared with the snapshot in force, using the digest the settings library computes (`settings.Snapshot.Digest`, shared by both sides):
    - `settings_mismatch` (critical): the current version with a different digest, or an unknown version. The finding lists the differing instance keys.
    - `stale_settings_cache` (high): the instance still reports an older version more than 90 s (the 30 s poll plus a 60 s heartbeat) after the change.
  - **Findings.** One scan reports every finding it sees. `posture.sync_drift_findings` opens new ones, refreshes those still present (`last_seen`), and resolves those of the scanned checks that are gone, all in one transaction. The engine audits each opened finding as `posture.drift_detected` (high, or critical) and each resolved one as `posture.drift_resolved` inside that transaction: an audit failure records nothing (AC-37; the audit pipeline feeds the SIEM). `posture.open_drift_findings()` is the Posture page's list. People's acknowledgement and the SIEM event schema are T-26.
  - **NATS.** The posture service now connects to NATS (`FAIR_NATS_URL`, required in production, otherwise check 4 would silently never run) and subscribes to `posture.settings.heartbeat` and `posture.setting.changed` (`natspub.Publisher.Subscribe`).
  - Verification (DB tests):
    - `TestDriftDetectsDirectDBEdit`:
      - A clean install has no findings.
      - A direct `UPDATE` of the idle timeout moves the version and opens `row_mac_mismatch` (critical) and `unapproved_deviation` (high), both audited.
      - A second scan neither reopens nor re-audits.
      - A direct TLS 1.0 opens `hard_floor_violation`.
      - Setting both values properly resolves all four, audited.
    - `TestDriftExceptionsAndMissedRevert`: an approved exception is not drift, and neither is one expired for 1 s. Two minutes past expiry it is `missed_revert`, which the revert resolves.
    - `TestDriftOverlay`: a tampered overlay row opens MAC and deviation findings.
    - `TestDriftHeartbeats`:
      - A matching heartbeat gives no finding.
      - A rogue instance gives `settings_mismatch` naming the differing key.
      - After a change, instances still on the old version are stale.
      - Refreshed and silent instances clear.
      - Malformed heartbeats are refused.
    - `TestRunDriftDetectsDirectEdit`: the loop detected a direct edit in 0.66 s, with no event.
    - `TestDriftAccess`: only `app_posture` runs scans, and nobody writes findings or heartbeats directly.
    - `TestDriftScanAtScale` (`FAIR_TEST_SCALE=1`): 2,011 BUs and 4,040 setting values (two BU overrides on every BU), with 100 reporting instances, scanned in 4.4 s (requirement: 30 s).
    - Mutations (no MAC check, no deviation check, findings never resolved, heartbeat digest ignored) each fail the tests.
- 2026-10-27: T-26 implementation notes (`db/migrations/0029_drift_lifecycle.sql`, `internal/posture/drift.go`, `internal/posture/drift_events.schema.json`).
  - **Lifecycle.** A finding goes `open → acknowledged → resolved`, or `open → resolved`.
    - `posture.acknowledge_drift` (`Drift.Acknowledge`): the signed-context user needs `drift.acknowledge` at the root and a stated reason, and only an open finding can be acknowledged. `acknowledged_at` and `acknowledge_reason` are new columns, kept after resolution.
    - Acknowledging never closes a finding, so drift cannot be silenced. Only the check that raised it resolves it, once the condition is gone: the drift scan, or the revert for `revert_failed`. Later scans keep an acknowledged finding acknowledged, and the same drift after resolution is a new, open finding.
    - `posture.drift_findings(resolved_since)` (`posture.Findings`) replaces `open_drift_findings()` for the Posture page: unresolved findings, then those resolved since a time.
  - **Events (the SIEM contract).** `drift_events.schema.json` (JSON Schema 2020-12, embedded as `posture.DriftEventSchema`, checked by `posture.ValidateDriftEvent`) specifies the three events as every audit sink writes them: the JSON-lines stream for OTLP/SIEM collectors (with `"kind": "audit"`) and the RFC 5424 syslog body.
    - Every event carries `finding_id`, `check_id`, `kind`, the finding's `severity`, `controls` (comma-separated 800-53 ids) and `subject` (also the event target), so each finding includes its severity, controls and remediation (AC-42).
    - `posture.drift_detected`: actor `system:posture-drift`; high, or critical for a critical finding; with `detail` and `remediation`.
    - `posture.drift_acknowledged`: actor the user; low; with the reason, `remediation` and `acknowledged_by`.
    - `posture.drift_resolved`: actor `system:posture-drift`; info; with `acknowledged_by` when it had been acknowledged.
  - Verification:
    - Unit test `TestDriftEventSchema`: the three events in both sink forms are accepted, and 21 violations are refused (missing or malformed attributes, wrong severities or actors, reasons where none belong, unknown fields).
    - DB test `TestDriftLifecycleAndEventSchema`, with a real JSON-lines sink:
      - Acknowledging without `drift.acknowledge`, without a reason, or twice is refused.
      - An acknowledged finding survives later scans and is resolved only by the fix, keeping its acknowledgement; the same drift then opens a new finding.
      - Every emitted event, as a JSON line and as a syslog body, validates against the schema.
    - Mutations (acknowledgement closing the finding, no permission check, scans clearing the acknowledgement, events without remediation) each fail the test.
- 2026-10-27: T-27 implementation notes. Robert Former approved two choices: a minimal in-repo Kubernetes client rather than client-go, and a separate binary and image for the scanner.
  - **Contract** (constitution A2, ADR-002): `api/proto/fair/posture/v1/scanner.proto`, service `ScannerReports.Report(ScanReport) → ReportAck`. Generated code is committed in `internal/api/posturev1` (`scripts/gen-proto.sh`, pinned protoc-gen-go v1.36.6 and protoc-gen-go-grpc v1.5.1). New dependencies: `google.golang.org/grpc` v1.74.2 and `google.golang.org/protobuf` v1.36.6; Go stays at 1.24.
  - **Kubernetes client** (`internal/scanner/kube`): standard library only.
    - It issues GET requests only (paginated list and streaming watch), and refuses Secrets before any request is made.
    - It uses the projected service-account token, re-read for every request so rotation works, and verifies the cluster CA over TLS 1.2 or later.
    - 403 and 404 are distinct errors, so an absent CRD is not a refused read.
  - **Scanner** (`internal/scanner`, `cmd/posture-scanner`):
    - Scans at start, every 15 minutes, and 10 s after a watched change (namespaces; pods, deployments and network policies in the platform namespaces).
    - Every scan includes an access probe that reads each resource of the §6.8 permission table once and reports refused reads as `scanner_access` check errors.
    - A failing check is reported as an error, not as "passed", so its open findings stay open.
    - The check catalog is T-28.
    - The client certificate is re-read on each TLS handshake, so cert-manager rotation needs no restart.
  - **Posture side** (`posture.ScannerService`, migration 0030; `FAIR_SCANNER_GRPC_ADDR`, `_CERT_FILE`, `_KEY_FILE`, `FAIR_SCANNER_CLIENT_CA_FILE`, optional `FAIR_SCANNER_IDENTITY`):
    - The channel requires a client certificate from the scanner CA carrying the URI SAN `spiffe://fair-platform/posture-scanner`; any other platform identity gets PermissionDenied.
    - Reports are untrusted input and are validated whole: check ids, findings only for checks run, severities, 800-53 control ids, JSON-object details, subjects without control characters, size limits, no application check ids.
    - Findings are recorded with `kind = deployment` through the T-26 lifecycle and events (`sync_drift_findings` gained a `finding_kind` parameter), with subjects prefixed `deployment:`. The latest report per instance is kept (`posture.scanner_reports()`) for T-30.
    - Database errors are logged, never returned to the client in detail.
    - In SaaS mode posture refuses to start without the scanner channel (AC-38).
  - **Images:** the Dockerfile has one build stage and one final stage per binary (`iam`, the default; `posture`; `posture-scanner`), each distroless, non-root, holding only its binary. A new CI job, `scanner-image`, builds, checks, SBOMs, scans, pushes and signs the scanner image like iam.
  - **Manifest** (`deploy/k8s/posture-scanner.yaml`):
    - Its own ServiceAccount, with no automount and a projected 1-hour token.
    - A ClusterRole and a platform-namespace Role granting exactly the §6.8 table, get/list/watch only, never Secrets.
    - A hardened pod. It uses `fsGroup` with 0440 Secrets: the kind test found that 0400 Secrets are root-owned and unreadable by the non-root user.
    - A NetworkPolicy with no ingress and egress only to the API server endpoints, posture:9443 and DNS, plus posture's ingress from the scanner only.
  - Verification:
    - **Static RBAC audit** (`internal/scanner/manifest_test.go`): only get/list/watch, no wildcards, subresources, non-resource URLs or Secrets; grants exactly equal to `scanner.Access`; bindings to the scanner's ServiceAccount only; pod hardening and egress rules.
    - **Unit tests:** the kube client (GET only, pagination, token rotation, Secrets refused before any request, error mapping, watch) and the scan loop.
    - **DB tests** (`scanner_grpc_test.go`):
      - Reports over real mTLS record deployment findings, resolve fixed ones, and keep those of a failing check; every event matches the drift event schema.
      - Wrong identity, no identity, a foreign CA, no client certificate and TLS 1.1 are all refused.
      - 11 kinds of malformed report are refused whole.
    - **Live test on kind** (`scripts/k8s-e2e-scanner.sh`; kind 0.33, Kubernetes 1.36, kindnet enforcing NetworkPolicy), 37 checks, PASS:
      - The scanner's first report reached a posture stand-in over mTLS with no refused reads.
      - `kubectl auth can-i` as the ServiceAccount: 9 expected reads allowed; 18 writes, Secrets, exec, logs, tokens, impersonation, escalation, other namespaces and wildcards refused; `--list` shows only get/list/watch.
      - From the scanner pod's own network namespace, the API server and posture:9443 (with DNS) are reachable. Another platform pod, posture on another port, the node's kubelet and the internet are not.
      - A control allow rule makes the decoy reachable, proving the CNI enforces the policy.
    - **Mutations:** a write verb and Secrets in the Role fail the static audit; an egress rule opened to the namespace fails the live test; accepting any CA-signed identity fails the channel test.
- 2026-10-28: T-28 implementation notes. Robert Former approved four choices:
  - the scanner probes TLS itself, with its egress widened to the platform's TLS ports;
  - a signed platform release manifest is defined now;
  - PersistentVolumeClaims are added to the permission table above;
  - verification uses kind live runs plus distribution fixtures, with live OpenShift and RKE2 runs following in T-37.
  - **Release manifest** (`internal/releasemanifest`, `cmd/releasegen`): `fair-platform-release-manifest/v1`.
    - It lists the image of each platform component by digest, and a SHA-256 of each platform RBAC object's normalized content. Rules, verbs and subjects are sorted and defaulted subject `apiGroup`s dropped, so the YAML reference manifest and the API server's object hash the same.
    - `releasegen manifest` hashes the RBAC of `deploy/k8s` and takes the digests from the image builds; `releasegen sign` adds a detached ECDSA P-256 signature with the release key (as profile packages; D-OQ5 custody still open).
    - The scanner verifies it from the `fair-release-manifest` ConfigMap on every scan. A missing, unsigned or tampered manifest makes the image and RBAC checks report errors, never "passed".
  - **Catalog** (`internal/scanner/checks`, wired into `cmd/posture-scanner`). Every finding carries a severity, controls and remediation (AC-42). Findings name the owning workload rather than the pod, so they do not change across restarts.
    1. `pod_security_admission` (CM-6, CM-7): `enforce=restricted` on each platform namespace. Where the API server enforces restricted cluster-wide (RKE2 CIS), the installer attests it (`FAIR_PSA_DEFAULT`); an explicit weaker label still fails.
    2. `network_policy` (SC-7, AC-4): a default deny per namespace (high), and a non-default policy selecting every workload (medium).
    3. `tls_endpoints` (SC-8, SC-13, SC-23): every TCP port of every platform Service, plus the ingress endpoints (`FAIR_INGRESS_ENDPOINTS`).
       - A real handshake records the negotiated version and suite and the certificate's expiry: under 30 days is medium, expired is high, plaintext is high. The state is captured in `VerifyConnection`, so mTLS servers such as posture still reveal their certificate.
       - Hand-built ClientHellos, which read only the ServerHello and need no cryptography (the FIPS-mode client cannot offer them), detect TLS 1.0/1.1 (high) and non-approved TLS 1.2 suites (medium: CBC, RSA key exchange, 3DES, ChaCha20).
       - The probes were validated against a real, deliberately weak Go TLS server in a non-FIPS helper process.
    4. `node_fips` (SC-13): each node labelled `fair-platform.io/fips` = `verified` (fips-probe, T-29) or `attested` (installer). Posture keeps these findings only where `fips.enabled` is in force (AC-41 "where the profile requires it"); an unreadable value counts as required.
    5. `image_digests` (CM-14, SI-7, SR-4): every container's image is a release image by digest (unknown image high, tag reference medium, other digest critical), and the running image digest matches (critical).
    6. `signature_admission` (CM-14, SI-7): a ValidatingAdmissionPolicy or webhook annotated `fair-platform.io/verifies-image-signatures=true`, or a known verifier (Sigstore policy-controller, Connaisseur, Ratify). Absent is high; a fail-open webhook is medium.
    7. `pod_hardening` (CM-6, CM-7): non-root (an explicit UID 0 is root whatever `runAsNonRoot` says; OpenShift's SCC-assigned UIDs count as non-root), read-only root filesystem, no privilege escalation, `drop: [ALL]` (only `NET_BIND_SERVICE` may be added), no privileged mode, host namespaces or hostPath.
    8. `storage_encryption` (SC-28): the class of every platform PVC, or the default class. Recognized are EBS `encrypted`, provider-managed GCE/Azure, Ceph RBD and Longhorn `encrypted`, and Portworx `secure`; anything else (local-path, no-provisioner, NFS, vSphere) fails unless the installer annotates the class `fair-platform.io/encrypted-at-rest=true`.
    9. `plaintext_secrets` (IA-5, SC-28): secret-looking env names with literal values (not `*_FILE` or paths), credentials in URLs, and secrets in command-line arguments (high; values are never copied into findings). Where the External Secrets Operator is installed, referenced Secrets that no ExternalSecret produces are low.
    10. `platform_rbac` (AC-6, CM-5): every manifest object present (missing is medium) and unchanged (high); unexpected objects are high. This covers Roles and bindings in platform namespaces, platform-labelled cluster roles, and any ClusterRoleBinding granting to a platform ServiceAccount.
  - **Permissions and egress** (`deploy/k8s/posture-scanner.yaml`):
    - The Role adds `persistentvolumeclaims` (get/list/watch).
    - Egress adds platform pods (`app.kubernetes.io/part-of: fair-platform`) on their TLS pod ports 8443, 9443 and 4222 (policies apply after Service translation), and the ingress controller address (`REPLACE_WITH_INGRESS_CIDR`) on 443. Pods outside the platform, other ports, the kubelet and the internet stay unreachable.
    - The release manifest ConfigMap is mounted at `/release`.
  - Verification:
    - **Fixtures** (`internal/scanner/checks/testdata/{kind,openshift,rke2}/{pass,fail}.yaml`, `TestCatalogFixtures`): each distribution's compliant cluster gives no findings, and its non-compliant cluster gives exactly the expected findings for all 10 checks. The fixtures are written as each distribution's API objects:
      - OpenShift: SCC-assigned UIDs, `openshift.io/scc` restricted-v2 or anyuid, gp3/gp2-csi, RHCOS nodes, the Sigstore policy-controller, ESO.
      - RKE2: the attested restricted default, Longhorn vs local-path, FIPS-verified nodes, Connaisseur.
      - kind/k3d: local-path, attested or not.
      - Service addresses dial local endpoints: real TLS with good, expiring or expired certificates, plaintext, and raw TLS 1.0 or weak-suite servers.
    - **Other unit tests:** `TestReleaseManifestRequired` (none, wrong key, tampered → errors); `TestRawProbesAgainstRealTLS`; the release manifest hash, signature and format tests.
    - **DB test** `TestScannerNodeFIPSFollowsProfile`.
    - **Live kind run** (`scripts/k8s-e2e-scanner.sh`, 49 checks, PASS):
      - All 10 checks ran without errors against a signed release manifest.
      - `pod_security_admission`, `network_policy` and `platform_rbac` passed, and posture's mTLS endpoint passed the TLS check.
      - The expected findings appeared: a plaintext platform endpoint, the unlabelled node, no signature verifier, kind's unencrypted local-path class, an unhardened workload, an inline password, and tag-referenced images.
      - The T-27 RBAC and egress checks still pass, plus "platform TLS port reachable".
    - **Mutations:** PSA accepting baseline, root UID 0 under `runAsNonRoot`, URL credentials ignored, the legacy-TLS probe disabled, the running digest ignored, extra RBAC ignored, and a fail-open webhook accepted each fail the tests. The root-UID mutation needed a stricter OpenShift fixture, which was added.
- 2026-10-28: T-29 implementation notes. Robert Former approved three choices: a hostPath read as designed, reporting through pod readiness, and per-node evidence for the export.
  - **fips-probe** (`cmd/fips-probe`, image target `fips-probe`, `deploy/k8s/fips-probe.yaml`):
    - A DaemonSet on every node, tolerating all taints. It mounts exactly one host file, `/proc/sys/crypto/fips_enabled` (hostPath type File), read-only.
    - Its readiness probe runs `fips-probe check`, which succeeds only when the flag reads exactly `1`; a missing file (a kernel without FIPS support) or any other content means not Ready.
    - It has no ServiceAccount token, no RBAC, no listener, and no network (deny-all policy); it does no cryptography.
    - hostPath is forbidden under restricted and baseline pod security, so it has its own namespace, `fair-fips-probe` (enforce privileged; warn and audit restricted), which holds nothing else.
  - **OpenShift** (`deploy/k8s/openshift/fips-probe-scc.yaml`): the SCC `fair-fips-probe` adds only hostPath volumes to restricted-v2 (non-root, no escalation, drop ALL, read-only root, no host namespaces), and a Role grants `use` of it to the fips-probe ServiceAccount only. Two items await a live OpenShift run (T-37), since none was available: whether SELinux lets the default container type read the host's `/proc/sys/crypto` file (if not, adjust the SCC's `seLinuxContext`, never to a privileged type), and the SCC itself.
  - **Reporting:** posture-scanner reads the probe pods in `fair-fips-probe` (its new Role there: pods, plus roles and rolebindings for the RBAC drift check). For each node:
    - a Ready probe pod means **verified**;
    - otherwise the label `fair-platform.io/fips=attested` (set at install when the probe is declined) means **attested**;
    - otherwise it is a finding, whose detail says whether the probe is absent or not Ready.
    A `verified` label is no longer accepted (it was in T-28): only the probe verifies.
  - **Evidence:**
    - Scan reports carry observations (`Observation{check_id, subject, method: verified|attested, detail}`), and checks return `scanner.Result{Findings, Observations}`.
    - Posture validates them like findings and replaces each check's observations whenever the check runs (`posture.deployment_observation`, migration 0031; `posture.Observations`), so T-33's export can mark attested nodes "attested, not verified".
  - **Release manifests:** `releasegen manifest -deploy` takes several directories; OpenShift releases add `deploy/k8s/openshift`, so the SCC's Role and binding are expected there and only there.
  - Verification:
    - **Unit tests:** the flag parsing; the static audits of the probe manifest (one read-only file, no token, no listener, exec readiness, every node, a namespace with nothing else, deny-all) and of the SCC (only hostPath added; `use` only by the probe's ServiceAccount); the RKE2 fixtures (one node verified by a Ready probe, one attested, a "verified" label without a Ready probe failing); and observation assertions per distribution.
    - **DB test** `TestScannerObservations`: stored, replaced per scan, kept when the check fails, and invalid ones refused.
    - **Live kind run** (62 checks, PASS):
      - On this kernel, which lacks the flag, the probe is not Ready and the node is a finding.
      - Labelled attested, it gets an "attested" observation and no finding.
      - With the hostPath pointed at a node file reading `1` (a simulated FIPS kernel), the probe becomes Ready and the node is "verified" without the label.
      - With the flag back at `0`, the probe leaves Ready and the finding returns.
    - **Mutations:** any probe pod counting as verified, labels recorded as verified, `0` accepted, and observations never replaced each fail the tests.
- 2026-10-28: T-30 implementation notes (`internal/scanner/permissions.go`, `deploy/k8s/permission-manifest.json`, `db/migrations/0032_k8s_access.sql`, `internal/posture/k8saccess.go`, `posture k8s-access`).
  - **Permission manifest** (AC-39):
    - Generated from `scanner.Access` by `releasegen permissions` into `deploy/k8s/permission-manifest.json`; a test keeps the committed file current.
    - It lists every read with its purpose, by scope (cluster, platform namespaces, the fips-probe namespace). It also discloses the scanner's network reach and fips-probe's single host file, and states what is never granted (Secrets, any write, exec, logs, tokens, impersonation, escalation, bind).
    - The scanner's RBAC already grants exactly these reads (static audit, T-27). The installer (F-014) shows the manifest; its SHA-256 is what consent records, so a release that changes the permissions asks again.
  - **State** (`posture.k8s_access`, the design's `k8s_access` with the consented digest):
    - The installer records decisions with `posture k8s-access grant|decline|request|revoke|status [-reason]` (actor `system:installer`): grant or decline at install, revoke later, and request after a later Helm flip.
    - A request becomes granted only when an administrator acknowledges it in the UI (`K8sAccess.Acknowledge`, `settings.change` at the root, for the digest shown).
    - Declines and revocations need a reason and are audited high (`posture.k8s_access_<state>`).
    - In SaaS mode declining or revoking is refused, and an undecided install counts as granted (AC-38).
  - **Declined means disabled** (AC-40): `ScannerService.Report` refuses reports with FailedPrecondition unless access is granted, so a scanner deployed anyway records nothing; the installer deploys none.
  - **Banner:** `K8sAccess.Status` gives the persistent warning for the Posture page (T-32) when access is undecided, declined, revoked, or awaiting acknowledgement, or when this release's permissions differ from those consented to.
  - **Not assessed:** `K8sAccess.Assessment` maps each of the 10 deployment checks (with its controls) for the OSCAL export (T-33). It is Not assessed while access is not granted, when the scanner has not reported for 45 minutes (three scan intervals), when the check failed in the latest report, or when it did not run; otherwise it is assessed.
  - Verification:
    - `TestK8sAccessConsent`:
      - Granted at install: reports are accepted; ran checks are assessed, while a failed check, checks not run, and a silent scanner are Not assessed.
      - Revoking needs a reason and is audited high; reports are then refused, a banner appears, and everything is Not assessed.
      - The installer cannot grant directly after a revoke; a request plus acknowledgement is needed. Acknowledging without `settings.change` or for other permissions is refused; after acknowledgement reports are accepted again.
      - Changed permissions raise a banner until re-consent.
    - `TestK8sAccessDeclinedAndSaaS`: undecided gives a banner; a decline needs a reason and leaves everything Not assessed with a banner; SaaS counts as granted and cannot decline.
    - `TestPermissionManifest`.
    - Mutations (no report gate, SaaS decline allowed, acknowledged digest not checked, assessment ignoring the state) each fail the tests.
- 2026-10-28: T-31 implementation notes. Robert Former approved two choices: pulling F-001 T-14 (internal JWT) forward, and a shared idempotency middleware with a store.
  - **API** (`internal/postureapi`, mounted by `cmd/posture` under `/api/v1/posture/` when `FAIR_JWT_KEYS_DIR` holds the gateway's public keys; required in production). It serves the 24 routes of §7 apart from `/exports`, which come with T-33 to T-35. The contract is `api/openapi/posture.yaml`; a test keeps it equal to the routes served and requires an `Idempotency-Key` and an `x-permission` on every mutation.
  - **Authentication and idempotency:** the shared F-001 middleware (internal JWT plus DB context token, see the F-001 change log) and `server.Idempotent`, with posture's store (`posture.idempotency`, 24 hours; an in-progress key is taken over after 5 minutes).
  - **Authorization:**
    - Every route requires `posture.view`, checked on the caller's grant snapshot (`authz.Cache`; the posture service may now read `authz.grant_snapshot`, which returns only the signed-context user's own grants). It is checked at the root, or at the BU of `?bu=`. Without it the answer is 404 (F-001 AC-25).
    - Mutations then go through the posture services, whose functions check their own permission (`settings.change`, `profile.manage`, `drift.acknowledge`); 403 without it.
    - BU overrides and BU exceptions are listed only for BUs where the caller holds `posture.view`, so a restricted BU's overrides are hidden from users not assigned inside it, administrators at the root included (AC-32).
  - **Responses:**
    - Domain errors map to 400 (invalid values), 403, 404, 409 (not applicable or not approved), 422 (hard floor, explanation required, with the AC-21 warning) and 503; other errors are 500 without detail.
    - Applied changes are 200; changes waiting for approval are 202 with the approval ID.
    - Design §7's "loosening calls require explanation" is enforced for setting changes in bounds too: the API previews the change and refuses an unexplained loosening.
  - **New reads** (migration 0033): `registry_view` (AC-03: value, source, default, bound, deviation in_bounds, exception, out_of_bounds, below_floor or unbound, and the exception's expiry), `bu_overrides`, `changes_view`, `exceptions_view` and `profiles_view`.
  - **Change to T-19/T-20:** reading profiles, their differences, exports and the pending switch (`profile_reader`, `custom_profile_view`) now also accepts `posture.view`, because AC-43's Posture page shows them to `posture.view` holders. Every profile write still needs `profile.manage`.
  - Verification (DB tests over HTTP, with gateway-style tokens):
    - `TestPostureAPIAccessAndChanges`:
      - Unauthenticated requests are 401, and callers without `posture.view` get 404 on reads and mutations.
      - The registry gives 20 settings with value, source, bound, deviation and controls.
      - The auditor gets 403 on changes. A tightening is 200, an unexplained loosening 422, an explained in-bounds loosening 200, out of bounds 202 with the approval and warning, a hard-floor violation 422, and an unknown field 400.
      - Idempotency: a missing key is 400; a replayed key returns the same body without a second change; a key reused for another request is 422.
      - The other read endpoints answer, and an unknown switch is 404.
    - `TestPostureAPIRestrictedBUHidden`: the auditor and the administrator at the root see the override at A but not at the restricted R, and get 404 for `?bu=R`. A user assigned at R sees R's values but not the instance-wide views.
    - `TestOpenAPIMatchesRoutes`.
    - The T-19/T-20 tests now expect the auditor to read profiles and diffs, still not to edit.
    - Mutations (unfiltered overrides, no `posture.view` check, loosening without explanation, the JWT not bound to the DB context, replay disabled) each fail the tests.
- 2026-10-28: T-32 implementation notes. Robert Former approved two choices: React Aria Components for UI primitives (recorded in ADR-003), and E2E tests against the real backend through a test-only dev gateway.
  - **Frontend** (`web/`): React 19 and TypeScript 7 (strict) with Vite 8 (ADR-003); exact versions pinned with a lockfile; served from the platform with no CDN.
    - Design tokens and base CSS (`web/src/styles.css`) give AA contrast in the light and dark themes, a visible focus ring, reduced motion honoured, and status always as text (colour only reinforces it).
    - Data tables are semantic HTML (caption, `th scope`). Buttons, dialogs (focus trapping, Escape, focus return) and form fields with errors are React Aria Components.
    - Every mutation sends a fresh `Idempotency-Key` (T-31).
  - **The Posture page** (AC-43): a section, with a heading and a region, for each item AC-43 lists:
    - the active profile and conformance (settings within bounds, under exception, out of bounds, below the floor);
    - deviations and the active exceptions with owners, approvers, expiry and justification;
    - expiries within 30 days and reverts in the last 30 days;
    - the pending switch and its conflicts;
    - drift findings, most severe first;
    - Kubernetes access, with the AC-40 banner at the top of the page and each deployment check assessed or Not assessed;
    - per-control status, from the settings' OSCAL parameters, the deployment checks and the open findings (worst first: deviation, open finding, exception, not assessed, OK).
  - **Links and actions** (AC-44):
    - Every item links to its audit history at `/audit?target=<audit target>` (the route of F-002's audit page) and, where one exists, to its approval at `/approvals/<id>` (F-001's).
    - The actions are renewing an exception and acknowledging a drift finding (each a dialog with a required reason) and acknowledging a requested Kubernetes grant (a confirmation naming the permission digest).
    - The server decides permissions; a refusal is shown in the dialog.
  - **API addition:** `GET /switches` returns the pending switch (or null), because §7's `GET /switches/{id}` gives the page no way to find it. It is in the OpenAPI contract.
  - **Fixes found by the E2E tests:**
    - The page recomputed the drift cut-off on every render, so it refetched forever; it is now fixed per page load.
    - The registry sent `controls: null` for settings without OSCAL parameters, which crashed the page; it now sends `[]`, and the client tolerates either.
  - **UI security headers** (`server.UISecurityHeaders`, for the gateway, F-001 T-13): the API's CSP blocks everything, so the UI has its own `server.UICSP`.
    - It allows only the page's own scripts, styles, images, fonts and API, with no framing, no `<base>`, and forms to self only.
    - The one inline stylesheet allowed is the fixed rule React Aria injects, by its SHA-256. The E2E tests fail on any CSP violation or script error, so a library update that changes it is caught.
  - **E2E harness:** `scripts/ui-e2e.sh`, and the CI job `ui-e2e`.
    - `db/tests` `TestPostureUIHarness` (`FAIR_UI_HARNESS=1`) seeds a scenario through the real services: an in-bounds loosening, an approved exception expiring in 10 days, a reverted exception, overrides in a restricted BU, a pending switch to FedRAMP Moderate with conflicts, drift findings from a direct database edit, and undecided Kubernetes access.
    - It then serves `web/dist` and the real Posture API as a dev gateway, minting the internal JWT and DB context token for the user chosen with `/dev/as/{user}`. (Since F-001 T-19 the harness runs the real gateway instead: `/dev/as/{user}` creates a real session, and the specs acknowledge the system-use banner.)
    - Playwright runs `web/e2e/posture.spec.ts`.
  - Verification (4 E2E tests, PASS; axe with the wcag2a, wcag2aa, wcag21a and wcag21aa tags):
    - An auditor sees every AC-43 part with the seeded data, the AC-40 banner, and audit links with the right targets; no axe violations.
    - An administrator acknowledges a finding by keyboard only: Enter opens the dialog, axe passes on it, Escape returns focus to the button, an empty reason is refused, and the typed reason is submitted and shown.
    - An auditor's acknowledge is refused with the permission message in the dialog; axe passes on the error state.
    - A user without `posture.view` gets the no-access message; axe passes.
    - Every test fails on a CSP violation or script error.
    - Mutations (muted text below AA contrast, the reason field without its label, no refresh after acknowledging) each fail the tests.
- 2026-10-28: T-33 implementation notes (`internal/posture/assessment_results.go`). Robert Former approved the commit; the choices below fill gaps in §6.9 and were made by default, without a separate question:
  - **Snapshot:** `posture.LoadARSnapshot` reads the posture in one read-only repeatable-read transaction as `app_posture`. `as_of` is that transaction's time.
    - The snapshot (`ARSnapshot`: active profile, deployment mode, Kubernetes access, the latest scanner report, every setting's instance-wide effective value, unresolved drift findings, deployment checks assessed or not, deployment observations) has a JSON form.
    - `BuildAssessmentResults` is a pure function of it. T-35 stores the snapshot with the `export_record`, which is how an earlier `as_of` is reproduced; T-33 does not reconstruct past states.
    - Who may export, the API and signing are T-35's.
  - **Document** (validated against the pinned OSCAL 1.2.3 schema by `oscal.Marshal`; nothing is returned otherwise):
    - an observation per setting and OSCAL parameter (a setting without one is still observed once): method `TEST`, type `finding` when the setting deviates (below the floor, out of bounds, or under an exception) and `control-objective` otherwise; the effective value, profile default, bound, source, deviation and exception are `urn:fair-app:posture` props;
    - an observation per assessed deployment check (collected at the latest scanner report) and per deployment observation; attested node FIPS evidence says "attested, not verified" (T-29);
    - a finding per unresolved drift finding and control (`objective-id` target, `not-satisfied`, reason `fail`), related to the observations of its setting or check; a check that names no control is reported against CM-6;
    - **Not assessed:** OSCAL's objective status has only `satisfied` and `not-satisfied`, so a control of a deployment check that is not assessed is a finding with `not-satisfied`, reason `other`, the reason in its remarks, and the prop `fair-assessment-status=not-assessed`;
    - reviewed controls: every control the settings and checks touch, in catalog order (800-53 ids such as `ac-2.3`).
  - **Component definition (AC-48):** F-014 has not started, so the export declares the platform component under the fixed `posture.PlatformComponentUUID` (in the result's local definitions, so subjects resolve) and links it to a back-matter resource for the component definition. F-014 must publish the platform component definition with that component UUID.
  - **Assessment plan:** `import-ap` references a generated plan, a back-matter resource describing the continuous tests for the active profile, rather than a separate assessment-plan document (not a model the pinned set supports).
  - **Determinism:** UUIDv5 names (document and observations include `as_of`; a finding's UUID depends only on its subject, as OSCAL recommends) and every list sorted, so the output does not depend on row order.
  - `posture.Reader` (a pool or a transaction) lets `Findings`, `Observations` and the Kubernetes-access status and assessment run inside the snapshot transaction; the assessment takes `as_of` instead of the wall clock.
  - Verification:
    - Unit: the document validates; observations per parameter with values; drift and Not assessed findings; reviewed controls; the component and plan references resolve; identical bytes after reversing every row order and after a JSON round trip of the snapshot; a different `as_of` gives a different document while finding UUIDs stay; with access declined every check is Not assessed; an empty posture is still valid.
    - DB (`TestAssessmentResultsExport`): a real posture with a direct edit and a scanner run gives a valid document observing every setting, with the drift findings, the 8 checks that did not run as Not assessed and the node evidence; two snapshots at the same `as_of` give identical bytes, as does the stored snapshot; revoking access changes the document and makes all 10 checks Not assessed.
    - Mutations (unsorted settings, wall-clock collection time, no Not assessed findings, no component link) each fail the tests.
- 2026-10-28: T-34 implementation notes (`internal/posture/poam.go`). The choices below fill gaps in §6.9 and were made by default, without a separate question:
  - **One snapshot for both exports:** T-33's `ARSnapshot` is renamed `ExportSnapshot` (`posture.LoadExportSnapshot`) and now also holds the open exceptions (state `active` or `revert_failed`; instance-wide, BU and Restricted BU overlay). T-35 stores one snapshot per export.
  - **Items** (`BuildPOAM` / `ExportPOAM`, validated against the pinned schema):
    - one per open exception: title, a description with the value, the bound when it was created, scope, approver, owner and expiry, and the justification; props for each of these plus creation, state and renewal; remarks on the automatic revert, or, for `revert_failed`, that the revert failed and the value is still in force;
    - one per instance-wide deviation with no exception (below the hard floor, or out of bounds), with the remediation;
    - each names its controls (from the setting's OSCAL parameters).
  - **Cross-references:** an item relates the observations of its setting (instance-wide items only; a BU or overlay value is not the instance-wide observation) and the drift findings about it. Drift findings are matched by their subject (`setting:<key>`, `setting:<key>@<bu>`, `overlay:<key>`, and `exception:<id>` for `revert_failed`). The POA&M includes exactly those observations and findings, built by the same code with the same UUIDs as the Assessment Results at the same `as_of`.
  - **Identity:** item UUIDs depend only on the exception or setting, so an item is the same item across monthly exports; the document UUID includes `as_of`.
  - **Approver and owner** are platform user ids (`iam.app_user`), not names: posture has no access to user names, and names in exports are personal data that leave the platform. Resolving them for a reader is F-002/F-001 territory.
  - **Nothing open:** OSCAL requires at least one POA&M item. Rather than a placeholder item (which tools reading POA&Ms would count as an open item), `ExportPOAM` returns `ErrNoPOAMItems`; T-35's API reports that nothing is open.
  - **Fixes to T-33 found by the database test:**
    - The Assessment Results related a drift finding to its setting's observations by comparing the subject with the bare key, so on real data nothing was related; it now uses the `setting:<key>` subject (the unit fixture used bare keys and is corrected).
    - The Kubernetes-access status failed when no deployment mode was recorded (NULL); it now reads as empty.
  - Verification:
    - Unit: the document validates; the items in order (expiry, then deviations) with their titles; the exception's justification, approver, owner, expiry, value and control; a BU exception relates no instance-wide observation and records its renewal; `revert_failed` remarks and its finding related; the deviation related to its two drift findings and observations; every reference resolves inside the document and is the Assessment Results' own; only related observations and findings included; identical bytes after reversing row order and after a JSON round trip; item UUIDs kept across `as_of`; nothing open gives `ErrNoPOAMItems`.
    - DB (`TestPOAMExport`): nothing open is refused; with an approved exception and a direct edit below the TLS floor, the two items match the database row (id, key, justification, owner, approver, expiry, state) and the drift finding; the POA&M's observations and findings appear in the Assessment Results; the same `as_of` gives identical bytes.
    - Mutations (no justification, relating by the bare key, unsorted exceptions, every observation included, no deviations) each fail the tests.
- 2026-10-28: T-35 implementation notes (`internal/posture/exports.go`, migration 0034, `internal/postureapi/exports.go`). Robert Former approved four choices: the signing key from a file for now, the snapshot stored in `export_record`, a signed statement as the timestamp, and `POST /exports` exporting now or reproducing by `as_of`.
  - **Signing key:** `FAIR_EXPORT_SIGNING_KEY_FILE` (PEM ECDSA P-256; required in production, otherwise exports answer 503). `posture export-key -out FILE -pub FILE` generates the installation's pair at install time and never overwrites a file. The key id is the SHA-256 of the PKIX public key. KMS or Vault signing (§8) follows with the key-custody decision (D-OQ5), behind the same signing call.
  - **Signed statement (the timestamp):** the signature (base64 ASN.1 DER ECDSA over SHA-256) covers a JSON statement `{type: fair-posture-export, export_id, kind, as_of, created_at, created_by, oscal_version, snapshot_sha256, document_sha256, key_id}`, not the document directly; the statement binds the document by its digest. It works air-gapped; an RFC 3161 timestamp can be added later. `posture verify-export -pub -document -statement -signature` (and `posture.VerifyExport`) checks an export as a recipient would.
  - **`export_record`** (migration 0034) gains `created_at`, `snapshot` (the exact snapshot bytes), `snapshot_digest`, `document_digest` (renamed from `digest`), `statement` and `key_id`; `UNIQUE (kind, as_of)`.
    - Append-only: `posture_definer` has INSERT and SELECT only; application roles nothing (definer functions only).
    - `posture.record_export` takes the creator from the signed DB context and needs `posture.export`. PostgreSQL cannot verify ECDSA, so it checks what it can: the snapshot's SHA-256, that the statement names exactly the recorded id, kind, `as_of`, creation time, creator, digests and key, that `created_at` is within a minute of the database clock, and that `as_of` is not after it.
    - `export_get` and `export_at` need `posture.export`; `export_records` (history, no snapshots) is read by `posture.view` holders through the API.
  - **Create:** a consistent snapshot (T-33), the document built and validated, the statement signed, and the record and its audit event (`posture.exported`, high: the posture leaving the platform reveals its weaknesses) written in one transaction, so an audit failure records nothing.
  - **Reproducibility (AC-47):** documents are not stored. `Get` (and `Reproduce` by kind and `as_of`) rebuilds the document from the stored snapshot and serves it only if the snapshot digest, the document digest and the signature all still match. Otherwise it answers 500 `export_not_reproducible` and emits `posture.export_mismatch` (critical). Each fetch is audited (`posture.export_fetched`, low).
  - **API** (`api/openapi/posture.yaml`): `GET /exports` (history, `posture.view`); `POST /exports {kind, as_of?}` (`posture.export`, idempotent): without `as_of` 201 with the export and `Location`; with `as_of` 200 with the reproduced export, 404 if none was made then; 409 `nothing_open` for a POA&M with nothing open. `GET /exports/{id}` (`posture.export`): the export, 404 for an unknown or malformed id. Responses carry `document`, `statement` and `signature` as strings with the exact signed bytes.
  - Verification:
    - DB (`TestExportsSignedRecordedReproducible`): permissions (no `posture.view` 404, no `posture.export` 403), unknown kind 400, an empty POA&M 409; an export is valid OSCAL, its signature verifies, the statement carries the timestamps and digest, it is recorded and audited (high); a verifier refuses another key, a changed document and a changed statement; fetching and reproducing by `as_of` return the identical document, statement, signature and digest, each audited; reproducing an export never made is 404; `GET` by auditor 403, nobody 404, malformed or unknown id 404; the POA&M after a deviation; the history lists both without documents; the table is not updatable or deletable by the definer and not readable by `app_posture`; a snapshot tampered with consistently (digest recomputed) and a tampered digest are both refused (500) with critical mismatch events naming the cause.
    - DB (`TestExportRecordChecks`): `record_export` refuses a caller without `posture.export`, a wrong snapshot digest, a statement naming another kind or document digest or creator, a creation time an hour off, a statement that is not JSON, and a second export of the same kind and `as_of`; the audit sink down records nothing; no key is `ErrConfiguration`.
    - Unit (`cmd/posture`): `export-key` writes a matching pair, the private key 0600, and refuses to overwrite.
    - Mutations (signing the document instead of the statement, no rebuilt-digest check, no snapshot-digest check, ignoring an audit failure, a verifier that skips the document digest) each fail the tests.
- 2026-10-28: T-36 implementation notes (the STRIDE suite: `db/tests/stride_test.go`, `make test-stride`, the CI step "STRIDE suite"; migration 0035; `posture.RevertLockTimeout`). Writing the suite as attacks found two §8 mitigations missing, both implemented here as the design states them; no design change.
  - **The suite:** each §8 row ("Threat | Example") maps to named tests. Most rows are attacked by earlier tests: package forgery (T-10 import, T-06 release tamper), direct `setting_value` edits (T-09 no-DML and MAC detection, T-25 drift), restricted-BU disclosure (T-31), Secrets and scanner privilege (T-27/T-30 static RBAC, pod and egress audits, mTLS channel), and the collusion ceiling (T-15 SecOps, T-17 duration, T-18 revert). New attacks:
    - `TestSTRIDEExceptionExtension`: a superuser extends an exception by ten years, or rewrites its approver; each is a critical `row_mac_mismatch` on `exception:<id>`, audited; posture's later updates never clear the evidence.
    - `TestSTRIDERevertStarvation`: another session holds the setting's row; the revert gives up within the lock timeout, is recorded (`revert_failed`, critical finding), the other due revert in the batch still runs, and the retry succeeds once the lock is gone.
    - `TestSTRIDERepudiationAndCollusion`: self-approval refused; requester and approver recorded on the approval request, the exception and both audit events; what two admins obtain expires within `exception.max_duration` and the POA&M names both.
    - `TestSTRIDECompromisedScanner`: with a valid scanner identity, claiming to run (or reporting findings of) application checks is refused, so app findings cannot be resolved or forged; a valid report never touches app findings; its findings are always `kind = deployment`.
  - **`TestSTRIDECatalog`** (no database) parses the §8 table and fails if a row has no tests, a mapped test does not exist, a mapping names a row the table no longer has, or `make test-stride` does not run a mapped test. Changing §8 therefore means updating the suite.
  - **Fix 1, exception row MACs (migration 0035).** §8 lists "MAC on exception rows", but only `setting_value` and `overlay_value` had one, so an extended expiry went unnoticed.
    - Every exception row carries HMAC-SHA-256 (current posture MAC key) over its identity, key, BU, overlay flag, value, bound at creation, justification, owner, approver, creation and expiry (as epoch seconds, independent of the session time zone), lineage and state.
    - A trigger signs the row only when the writer is `posture_definer` (inside posture functions). Any other writer, superuser or not, leaves the old MAC, and drift check 1 reports `row_mac_mismatch` on `exception:<id>` (critical, CM-5/CM-6/SI-7) with exception-specific remediation.
    - **No laundering:** a posture update of a row whose MAC is already wrong keeps the wrong MAC, so supersede or revert never erase the evidence; people review it (acknowledge). A row left unsigned because no MAC key was active (the T-18 key-outage fault, where the revert loop must still record its failure) is signed again on its next update; new exceptions are refused without a key.
    - Residual, as for the other MACs: a superuser who reads the in-database key, or assumes `posture_definer`, can forge a MAC (key custody, D-OQ5).
    - Tests that move an exception's times now do it as `posture_definer` (`env.timeTravel`), as the posture functions would.
  - **Fix 2, revert lock timeout.** A revert waiting on a row lock held by another session (a DBA's open transaction) blocked indefinitely, and every revert behind it. Each revert transaction now sets `lock_timeout` (`posture.RevertLockTimeout`, 5 s); a timeout is an ordinary failure: recorded, backed off, escalated, retried.
  - **Deferred to F-002:** "expiry is checked against the audit trail" and "every step goes to the hash-chained audit" need F-002's audit store; today the evidence is the audit events (sinks) and the exception MAC. The revert runs on posture's own loop (T-18), not a River queue; starvation is covered by the lock timeout and the `missed_revert` drift check.
  - Verification: `make test-stride` (22 tests in four packages) green; the full database suite green. Mutations each fail the suite: signing for any writer, re-signing tampered rows, leaving exceptions out of the drift check, no lock timeout (the pass took 60 s), and letting the scanner run application checks.
- 2026-10-28: T-37 implementation notes. Robert Former approved air-gapped as a third deployment mode (ADR-005 amended), startup checks and matrix tests for the per-mode keys, and live runs on the local Docker Desktop cluster.
  - **`air-gapped` mode** (migration 0036; `config.ModeAirGapped`): `posture.state` and `posture.set_deployment_mode` accept it; `FAIR_DEPLOYMENT_MODE` validation accepts it. Every database rule that differs by mode tests for `saas`, so air-gapped behaves as self-hosted there (Kubernetes access opt-in with the warning, no SecOps queue). What is specific to it:
    - the posture service refuses `FAIR_SECOPS_WEBHOOK_URL` and `FAIR_SECOPS_SECRET_FILE` (no outbound connections), in every environment;
    - the scanner (`FAIR_DEPLOYMENT_MODE`, now in `deploy/k8s/posture-scanner.yaml`) refuses at startup any ingress endpoint that is not, or does not resolve only to, a private, loopback or link-local address (`scanner.InternalOnly`; an unresolvable one is refused too): TLS probing is internal only;
    - profile packages: the release's packages load at migrate as in every mode; later ones come through `posture import` with the bundled public key.
  - **Keys per mode** (`posture.CheckInstall`, run by the posture service at startup; the table is in `internal/posture/install.go`): in production every mode needs an active posture MAC key (`posture.mac_key_active()`, migration 0036), `FAIR_EXPORT_SIGNING_KEY_FILE` and `FAIR_JWT_KEYS_DIR`; SaaS also needs the SecOps webhook URL and secret and the scanner channel; air-gapped refuses the SecOps webhook. The release public key is bundled and passed to `posture import -pub` in every mode. Key custody in KMS or Vault stays D-OQ5.
  - **The matrix** (`db/tests` `TestDeploymentModeMatrix`, one subtest per mode; CI job `deployment-modes`, `strategy.matrix.mode`) checks every row of the table for each mode: the recorded mode; the startup key check passes for a complete install and the SecOps webhook is refused only when air-gapped; the three built-in profiles from the release; a signed offline import accepted and an unsigned one refused; Kubernetes access granted by default only in SaaS, undecided with the warning otherwise, and declining refused only in SaaS; an in-bounds loosening queues a SecOps notification only in SaaS; an Assessment Results export, signed with the installation's key, naming the mode; an unknown mode refused.
  - **Live Kubernetes:** `scripts/k8s-e2e-scanner.sh` gains `CONTEXT=<kube context>` to run on an existing cluster instead of a new kind one.
    - Images are imported into each node's containerd, and node files written, through test-only privileged pods (`scripts/e2e/node-access.yaml`, own namespace).
    - The script refuses to start if the platform namespaces already exist, and its cleanup deletes everything it created (manifests, namespaces, node labels, node files).
    - Multi-node fixes: the probe pod is chosen on the node under test, and the simulated FIPS flag is written on every node, because the DaemonSet's rolling update waits for each node's probe.
    - The CI job `k8s-e2e` runs the script on kind (single node).
  - Verification:
    - Live on the local Docker Desktop Kubernetes (v1.36.1, four nodes, kind-based, local-path storage): all 62 checks pass: reports over mTLS, the check catalog, the RBAC audit, egress (the CNI enforces policy), and node FIPS evidence probed, attested and verified on the control-plane node; afterwards the cluster was left clean (no namespaces, labels or node files).
    - Live on kind: all 62 checks pass (single node, unchanged path).
    - Unit: `TestCheckInstall` (each mode complete; no MAC key; no export key; SaaS without SecOps or scanner; air-gapped with a webhook, also outside production); `TestInternalOnly` (private, IPv6 ULA and loopback pass; public, mixed, unresolvable and malformed refused); the config accepts `air-gapped`.
    - Mutations (the database refusing `air-gapped`, an air-gapped webhook allowed, SaaS without the scanner channel) each fail the tests.
    - **Not covered:** OpenShift and RKE2 live (an open item, §15). The new CI jobs have not yet run in GitHub Actions.
- 2026-10-28: T-38 implementation notes (statements signed off by Robert Former, 2026-10-28; `status: approved`). Robert Former approved the format (YAML source with an automated OSCAL check) and that T-38 is done only after his review.
  - **Statements:** `compliance/statements/F-015.yaml` states, for each control of F-015's control mapping (requirements; a superset of the task row: CM-2, CM-2(2), CM-3, CM-3(1), CM-5, CM-6, CM-6(1), CM-6(2), CM-7, CA-2, CA-5, CA-7, CA-7(4), SI-4, AU-6, PL-2), how F-015 implements it, the responsibility in each deployment mode (provider, shared or customer; ADR-005: the self-hosted customer owns the boundary), the customer's part wherever it is not the provider's alone, and the evidence (code paths and tests). `status` is `draft` until sign-off.
  - **Claims kept to what is built:** expiry notices are queued for F-009 to deliver, and the Posture page's audit links point to F-002's audit page; the statements say so.
  - **`internal/compliance`:** `Load` (strict), `Check` (OSCAL control ids, each once; a responsibility for every mode; the customer's part exactly where needed; every evidence path and test exists) and `ComponentDefinition` (the OSCAL component definition of the platform component, `posture.PlatformComponentUUID`, with one control implementation per feature against the pinned NIST SP 800-53 Rev 5 catalog; UUIDv5 identifiers; validated against the pinned schema). F-014 publishes it; F-001 T-43 adds `compliance/statements/F-001.yaml` in the same form.
  - `oscal.UUIDv5` replaces the identical private helpers in `internal/posture` and `internal/profilegen` (outputs unchanged: the regenerated profile packages are byte-identical; `TestPlatformComponentUUID` pins the component UUID).
  - Verification: `TestF015Statements` (the controls are exactly the requirements' mapping; `Check` passes; the component definition validates, names the platform component, and is deterministic); `TestCheckRefuses` (each malformed case refused, unknown fields refused). Mutations (a control dropped, a missing evidence test cited, a customer part on a provider-only control) each fail.
