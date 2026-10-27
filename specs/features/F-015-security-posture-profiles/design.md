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
| `fips-probe` (optional) | DaemonSet | Reads the node's FIPS kernel flag and reports it to the scanner (see D-OQ2) |
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
- `overlay_def` (id = 'restricted-bu', settings jsonb, version, updated_by)
- `drift_finding` (id, kind[app|deployment], check_id, severity, controls text[], subject, detail jsonb, remediation, first_seen, last_seen, status[open|acknowledged|resolved], acknowledged_by)
- `k8s_access` (state[requested|granted|declined|revoked], decided_by, decided_at, reason)
- `export_record` (id, kind[assessment_results|poam], as_of, digest, signature, created_by)

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
- **Overlay activation:** on F-001 `bu.restricted` = true, the overlay is applied as `source = overlay` rows. On unrestrict (which F-001 already requires dual approval for), the overlay rows are removed and audited.
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
| Platform namespaces | pods, deployments, statefulsets, daemonsets, services, networkpolicies, serviceaccounts, roles, rolebindings, externalsecrets (CRD, if present) | Workload hardening, NetworkPolicy presence, secret references, platform RBAC |
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

| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Profile packages | Release pipeline | In the bundle | Offline import; signature verified with the bundled public key |
| Scanner | Always deployed | Deployed only on consent | Same as self-hosted |
| `fips-probe` | Deployed when the profile requires FIPS | Optional; otherwise installer-attested node labels | Same |
| TLS probing | Internal + public endpoints | Internal + customer ingress | Internal only |
| Notifications | Email/webhook + vendor SecOps | Customer channels | Internal relay |

## 12. Changes to other features
- **F-001:** add `ErrStepUpRequired` and the reauth-freshness check to `authz.Check()` (§6.6). Add `auth_time` to the session. Replace the T-00b settings stub with this feature. → Adds F-001 task T-44 (step-up). The F-001 design gets a change-log entry once this design is approved.
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
