# F-001 Identity, BU Hierarchy & RBAC — Design
Status: **Approved** (Robert Former, 2026-10-24) | Requirements: Approved 2026-10-24 | Last updated: 2026-10-24
ADRs: 001, 002, 003, 005, 006, **007 (signed database context, accepted)**, **008 (in-house authorization, accepted)**

## 1. Overview
Identity and access are delivered by one Go service, **`iam`**, plus a shared Go library, **`authz`**, that every Go service embeds.

Access is enforced in **two independent layers**:
1. **Action layer (application):** `authz.Check(principal, permission, buID)` decides whether the caller may perform this action in this BU.
2. **Data layer (PostgreSQL row-level security):** decides which rows the caller can see or change. It is enforced through a **signed database context**, so neither an application bug nor SQL injection can widen scope (ADR-007).

A failure in either layer alone does not expose data.

## 2. Components

| Component | Language | Responsibility |
|---|---|---|
| `gateway` (BFF) | Go | TLS termination behind ingress; session cookie handling; CSRF; idle/absolute timeout; session network binding (§5.8); mints short-lived **internal tokens**; routes to services |
| `iam` service | Go | Modules: `authn` (SAML/OIDC, MFA evidence, break-glass WebAuthn), `scim` (SCIM 2.0 server), `directory` (users, groups, service accounts, tokens), `org` (BU tree, restriction), `access` (permission catalog, roles, assignments, group mappings, SoD, scope materialization), `approvals` (generic dual approval), `reviews` (access review campaigns, entitlement reports) |
| `authz` library | Go | In-process permission checks against a cached effective-grant snapshot; verifies internal tokens; sets the database context per transaction |
| Scope worker | Go (River jobs) | Recomputes materialized user scope after any access-relevant change; runs expiry sweeps (assignments, inactivity, SoD exceptions) |
| PostgreSQL | — | Schemas `iam` (identity data) and `authz` (security-definer functions, scope tables, HMAC key) |
| NATS JetStream | — | Events: `iam.scope.changed`, `iam.session.revoked`, `iam.user.deactivated`, `audit.*` |
| Keycloak (optional, bundled) | — | IdP for self-hosted installs whose customer has no IdP of its own: WebAuthn, PIV/CAC via X.509 |

**Why a modular monolith for `iam`:** the modules share a transactional boundary. For example, a SCIM deactivation must disable the user, revoke sessions and recompute scope atomically. The modules can be split later along module lines if scale demands it.

**Python engine:** never makes access decisions. Go services authorize simulation jobs before enqueueing them. Each job carries the caller's database context token, so engine writes are still constrained by RLS.

## 3. Data model (schema `iam`)

### Organization
- `bu` (id uuid PK, parent_id FK null-only-for-root, name, code, restricted bool, rollup_mode enum[excluded|aggregate|full], depth smallint, archived_at, created_at/by, updated_at/by)
- `bu_closure` (ancestor_id, descendant_id, depth, **blocked** bool). `blocked` is true when a restricted node exists on the path *(ancestor, descendant]*. `rollup_visible` is derived from the rollup_mode of the blocking node. The affected subtree is rebuilt on move, restrict and unrestrict.
- Constraint triggers: single root; depth ≤ configured maximum; no cycles; archive blocked while owned records are active (other features register their BU-owned tables in `iam.bu_owned_tables`).

### Identity
- `idp` (id, kind[saml|oidc|keycloak], name, email_domains text[], metadata jsonb, metadata_source[url|file], mfa_evidence_rule jsonb, enabled)
- `app_user` (id, idp_id, external_id, scim_id, email, display_name, status[active|disabled|locked], source[scim|jit|breakglass], last_login_at, disabled_reason, created_at)
- `grp` (id, scim_id, external_id, display_name) / `grp_member` (grp_id, user_id)
- `service_account` (id, name, bu_id, scopes text[], auth_method[client_credentials|mtls], status, created_by)
- `api_token` (id, owner_kind[service_account|scim], owner_id, token_hmac bytea, prefix, scopes, expires_at, last_used_at, revoked_at)
- `webauthn_credential` (id, user_id, credential_id, public_key, sign_count, aaguid, created_at)
- `session` (id_hmac bytea PK, user_id, auth_method, mfa_evidence jsonb, created_at, last_seen_at, absolute_expiry_at, ip, ip_prefix, asn, user_agent, banner_ack_at, revoked_at, revoked_reason)

### Access
- `permission` (key PK, resource_type, action[read|write|approve|admin|export], privileged bool, risk_data bool, introduced_in_version), seeded from the versioned catalog file shipped with each release (v1: `permission-catalog.md`)
- `role` (id, name, builtin bool, status[active|retired], current_version) / `role_version` (role_id, version, permissions text[], changed_by, change_reason, created_at)
- `assignment` (id, principal_kind[user|group], principal_id, role_id, bu_id, source[manual|mapped], mapping_id, granted_by, granted_at, expires_at, revoked_at, revoked_by)
- `group_role_mapping` (id, grp_id, role_id, bu_id, created_by)
- `sod_rule` (id, permission_a, permission_b, enabled, builtin) / `sod_exception` (id, role_id, rule_id, reason, approved_by, expires_at)
- `approval_request` (id, kind, target_ref, payload jsonb, reason, requested_by, status[pending|approved|rejected|expired], decided_by, decided_at, expires_at), with CHECK `decided_by <> requested_by`
- `access_review_campaign` / `access_review_item` (assignment_id, reviewer_id, decision[certify|revoke], decided_at, comment)

### Materialized scope (schema `authz`)
- `user_scope` (user_id, scope_version bigint, read_bus jsonb, write_bus jsonb, rollup_aggregate_bus jsonb, computed_at)
  - `read_bus` and `write_bus` map `resource_type` → `uuid[]`, e.g. `{"analysis": [...], "register": [...]}`.
- The scope worker recomputes it within the 60-second SLA. The version increments on every change and is embedded in internal tokens, so stale tokens are detectable.

### Effective-access rule
For user U, resource type T and action A, BU **b is in scope** iff there is an assignment at node **a** (to U directly, or to a group U belongs to) such that:
- the role's current version contains permission (T, A);
- `bu_closure(a, b).blocked = false`;
- the assignment is unexpired and unrevoked.

Two roll-up modes adjust this:
- **Full** treats the blocked path as unblocked, for **read only**.
- **Aggregate** adds b to `rollup_aggregate_bus`, which only roll-up functions may use, never row queries.

## 4. Data-layer enforcement (ADR-007, accepted)
1. For each request, `gateway` mints an **internal JWT** (ES256, signed with a KMS/Vault-held key, 5-minute TTL) for service-to-service calls, and a **DB context token** (`user_id | scope_version | expiry | nonce`, HMAC-SHA-256).
2. Services start each transaction with `SET LOCAL authz.ctx = '<db context token>'`.
3. RLS policies call `authz.visible_bus('<resource_type>')`, a `SECURITY DEFINER STABLE` function owned by a non-login role. The function:
   - verifies the HMAC with a key in `authz.ctx_key`, which application roles **cannot read**;
   - rejects expired tokens and stale scope_versions;
   - returns the BU array from `authz.user_scope`.
4. Policies are written as `bu_id = ANY ((SELECT authz.visible_bus('analysis')))`, so the function is evaluated **once per statement** (as an InitPlan), not once per row.
5. Every BU-owned table is created through `authz.apply_bu_rls(table, resource_type)`. The helper enables **and forces** RLS and installs SELECT, INSERT, UPDATE and DELETE policies; writes use `write_bus` in `WITH CHECK`.
6. Application DB roles are `app_rw` (NOBYPASSRLS, owns no tables) and `app_engine` (narrower grants). Migrations run as `app_migrator`, and the owner role cannot log in.
7. **Missing or invalid context yields an empty scope** (fail closed).
8. **Key rotation:** two keys are valid during a rotation window. Tokens carry a key ID.

**Residual risk:** a compromised service can replay a token it legitimately received for up to 5 minutes, limited to that user's scope.

## 5. Key flows

### 5.1 Federated login
1. The user enters an email at `/login`. Home-realm discovery picks the IdP by email domain. Unknown domains get a generic response, so users can't be enumerated.
2. The service sends a signed SAML AuthnRequest, or starts OIDC authorization code + PKCE with nonce and state.
3. On callback, `authn` validates the signature, issuer, audience, timestamps (±2 min skew) and InResponseTo/nonce. A replay cache keeps assertion IDs until they expire.
4. **MFA evidence** is checked against the IdP's rule: an AuthnContextClassRef allow-list for SAML, `amr`/`acr` for OIDC. On failure the login is denied and `authn.mfa_missing` is audited.
5. The user is looked up by (idp, external_id). If not found and JIT is off, the login is denied with a generic message and audited.
6. The banner acknowledgment page is shown, then the session is created. The cookie is `__Host-sid` (Secure, HttpOnly, SameSite=Strict, Path=/) and holds 256 random bits; only its HMAC is stored. The client IP prefix and ASN are recorded for §5.8.
7. `authn.login.success` is audited.

### 5.2 Authenticated request
1. `browser → gateway`. The gateway looks up the session, checks idle and absolute expiry, applies the network binding check (§5.8), throttles `last_seen` updates to one per 60 s, and validates the CSRF header on non-GET requests.
2. The gateway mints the internal JWT and DB context token and forwards the request to the service.
3. The service calls `authz.Check` against its cached grant snapshot, keyed by user and scope_version and invalidated by `iam.scope.changed`.
4. The service opens a DB transaction with `SET LOCAL authz.ctx`, and RLS applies.

### 5.3 SCIM deactivation (≤ 60 s)
In one transaction: the user is disabled, all sessions are revoked, mapped assignments become inert, and the `user_scope` row is deleted. After commit, `iam.user.deactivated` and `iam.session.revoked` are published. Gateways drop cached sessions immediately, with a 30 s cache TTL as a backstop.

### 5.4 Access change → scope recompute
Any access-relevant change writes an outbox row. The scope worker then:
1. computes the affected users, bounded to the subtree for BU changes;
2. upserts `user_scope` with a new version;
3. publishes `iam.scope.changed`.

The SLA is p99 ≤ 60 s. A nightly full reconciliation alerts on drift.

### 5.5 Dual approval (generic)
Applies to:
- un-restricting a BU or loosening its roll-up mode;
- SoD exceptions;
- admin + risk-data combinations;
- post-install break-glass enablement;
- out-of-bounds settings (F-015).

Each creates an `approval_request`, and the change applies only after a *different* Platform Admin approves it. Requests expire after 72 h (configurable), and every step is audited.

### 5.6 Custom role change
Before saving, the editor shows a diff and the number of affected users. The SoD check either blocks the save or creates an exception request. Adding a privileged permission triggers a high-severity audit event. Saving writes a new `role_version` and triggers a scope recompute. When an upgrade introduces new catalog permissions, they go only to the built-in roles that define them, and admins are notified.

### 5.7 Break-glass
- **Disabled by default:** `/breakglass` returns 404.
- **When enabled:** login is WebAuthn-only with lockout (3 failures per 15 min). The role carries admin permissions only, and the access engine refuses to give break-glass principals any risk-data permission. Every login triggers a high-severity audit event and notifications on all channels.
- **When disabled again:** active break-glass sessions are revoked immediately.

### 5.8 Session network binding (profile setting)
- The setting `session.network_binding` takes one of three values:
  - `off`: no check.
  - `flag`: the change is recorded and the session continues. A `session.network_changed` audit event is emitted and the session is marked on the admin sessions view.
  - `reauthenticate`: the session is revoked (`revoked_reason = network_change`), the event is audited, and the user is redirected to their IdP to sign in again. The redirect preserves the requested URL.
- **Network change** means the client IP leaves the session's recorded prefix (IPv4 /24, IPv6 /64) **or** the ASN changes. Prefix sizes are configurable.
- The client IP comes only from the trusted proxy header configured for the ingress. A spoofed header from untrusted hops is ignored.
- **Profile defaults:**

| Profile | Default |
|---|---|
| Enterprise Baseline | `off` |
| FedRAMP Moderate | `reauthenticate` |
| CMMC L2 | `reauthenticate` |

- Changing the setting goes through `settings.Set` (§8). Moving to a less strict value than the profile default is a loosening, so it is warned, audited and flagged on the posture page.
- Air-gapped installs without an ASN database fall back to prefix-only checks.

## 6. API (REST `/api/v1`, OpenAPI published with the release)
- **Auth:** `POST /auth/discover`, `GET /auth/saml/{idp}/login`, `POST /auth/saml/{idp}/acs`, `GET /auth/oidc/{idp}/callback`, `POST /auth/banner/ack`, `POST /auth/logout`, `/breakglass/*` (WebAuthn)
- **Self:** `GET /me`, `GET /me/permissions?bu=`, `GET|DELETE /me/sessions`
- **SCIM:** `/scim/v2/Users`, `/Groups`, `/Bulk`, `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes` (SCIM token auth only)
- **Organization:** `/bus` (tree, CRUD, move, archive), `/bus/{id}/restriction`, `/bus/{id}/rollup-mode`, `/bus/import`, `/bus/export`
- **Access:** `/permissions`, `/roles` (+ `/versions`, `/diff`, `/clone`, `/export`, `/import`), `/assignments`, `/group-mappings`, `/sod-rules`, `/sod-exceptions`
- **Identity admin:** `/idps`, `/users`, `/groups`, `/service-accounts` (+ `/tokens`), `/sessions`
- **Governance:** `/approvals`, `/access-reviews`, `/entitlements/report?format=csv|pdf`
- **Conventions:**
  - Out-of-scope IDs return 404.
  - Every mutating call requires an `Idempotency-Key`.
  - Admin mutations accept a `reason`, which is required where the active profile demands one.

## 7. Security design (threat model, STRIDE)

| Threat | Example | Mitigations |
|---|---|---|
| Spoofing | Forged or replayed SAML assertion; XML signature wrapping | Strict schema validation; signature verified against the pinned IdP certificate; reject multiple assertions; replay cache; audience and recipient checks; maintained SAML library plus a negative test corpus |
| Spoofing | Session theft | `__Host-` cookie, HttpOnly, SameSite=Strict; idle/absolute timeouts; server-side revocation; network binding per profile (§5.8) |
| Tampering | App bug widens data scope | Signed DB context (ADR-007); forced RLS; `NOBYPASSRLS`; fail closed |
| Tampering | Admin edits a role to gain access | Self-assignment blocked in both API and DB; dual approval for high-risk combinations; versioned roles; privileged-permission alerts |
| Repudiation | Admin denies a change | All mutations audited with actor, reason and before/after; approvals record both parties (F-002 hash chain) |
| Information disclosure | ID enumeration across BUs | 404 for out-of-scope; generic login errors; no user enumeration in discovery or SCIM |
| Information disclosure | Restricted BU leaks via roll-ups | Roll-ups only through `authz` definer functions that honor rollup_mode; aggregate mode returns totals only; exclusions are marked |
| Denial of service | Login floods; SCIM bulk abuse | Rate limits per IP, IdP and token; SCIM bulk size caps; lockout only for local accounts |
| Elevation of privilege | BU Admin grants admin rights or crosses a restricted boundary | Grantor must hold `access.assign` at the target BU; role must contain no admin permissions; restricted BUs require an explicit right |
| Elevation of privilege | Break-glass misuse | Off by default; WebAuthn only; no risk-data permissions; loud alerting |

**Crypto (all FIPS 140-validated):**
- Go builds use the native FIPS 140-3 module.
- ES256 for internal JWTs.
- HMAC-SHA-256 for session IDs, the DB context and token hashing (with a pepper).
- RSA-SHA256 or ECDSA for SAML.
- AES-256-GCM envelope encryption via KMS/Vault for secrets at rest.
- pgcrypto runs on a FIPS-enabled OpenSSL provider.

**Audit events:** `authn.*`, `session.*` (including `session.network_changed`), `scim.*`, `bu.*`, `role.*`, `assignment.*`, `sod.*`, `approval.*`, `breakglass.*`, `token.*`, `setting.*`. Each carries the actor, target, reason, before/after, request ID and source IP.

## 8. Secure defaults implementation
Defaults are seeded from the active F-015 profile at install. Every setting write goes through `settings.Set(key, value, reason)`, which checks the change against the profile bounds and takes one of three paths:
- applies it;
- applies it with a warning, an audit event and a posture flag;
- routes it to dual approval (ADR-006).

Until F-015 exists, F-001 ships a minimal settings module that holds the three profile definitions for its own keys behind the same interface.

## 9. Requirements traceability

| Requirement | Satisfied by |
|---|---|
| R-01 SSO (AC-01–04) | `authn` SAML/OIDC handlers; replay cache; metadata upload (§5.1) |
| R-02 MFA (AC-05–06) | MFA evidence rules per IdP; Keycloak realm policy |
| R-03 SCIM (AC-07–11) | `scim` module; SCIM token type; §5.3; inactivity sweep |
| R-04 Group mapping (AC-12–14) | `group_role_mapping`; mapped vs. manual source; recompute |
| R-05 BU hierarchy (AC-15–19) | `bu` + `bu_closure`; triggers; `bu_owned_tables`; import/export |
| R-06 Assignments (AC-20–23) | `assignment`; grantor checks; expiry sweep |
| R-07 Data-layer enforcement (AC-24–27) | §4 (ADR-007); `apply_bu_rls`; DB roles |
| R-08 SoD (AC-28–30) | DB constraint + API check; `sod_rule`; dual approval |
| R-09 Sessions (AC-31–35) | `gateway` sessions; profile-bounded settings; banner; network binding (§5.8) |
| R-10 Service accounts (AC-36–38) | `service_account`, `api_token`; client-credentials and mTLS |
| R-11 Break-glass (AC-39–46) | §5.7; installer flag (F-014); ops runbook |
| R-12 Lockout (AC-47) | Local/WebAuthn failure counter |
| R-13 Access reviews (AC-48–49) | `reviews` module; report generator |
| R-14 Events (AC-50) | Event emitter → NATS → F-002 + OTLP/syslog |
| R-15 Custom roles (AC-51–58) | §5.6; `role_version`; catalog upgrade handling; JSON export/import |
| R-16 Restricted BUs (AC-59–64) | `bu.restricted` + `bu_closure.blocked`; rollup_mode; §5.5 |

## 10. Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Signing keys (JWT, DB context, pepper) | Cloud KMS per instance | Vault/OpenBao or customer KMS | Same; generated at install |
| IdP metadata | URL refresh with pinning | URL or file | File only |
| Keycloak | Not deployed | Optional | Optional |
| Network binding ASN data | Bundled database, updated with releases | Same | Prefix-only fallback if absent |
| Break-glass notifications | Email/webhook | Customer SMTP/webhook | Internal relay |

## 11. Alternatives considered
- **External authorization engine (OPA, OpenFGA, SpiceDB):** rejected by ADR-008 (accepted).
- **Keycloak as a mandatory broker in front of every IdP:** rejected. It would add an always-on dependency and widen the SaaS attack surface.
- **Application-only filtering:** rejected because it conflicts with constitution A6.
- **Plain RLS with an unsigned session variable:** rejected by ADR-007 (accepted).

## 12. Risks & open items (resolved during implementation)
- **D-OQ1. SAML library selection** (`crewjam/saml` vs `russellhaering/gosaml2`), judged on maintenance record, CVE history and FIPS-only algorithms. An XML signature wrapping (XSW) test corpus is required regardless. → Task T-15.
- **D-OQ3. `authz.visible_bus` performance at target scale.** → Task T-11, which gates the features that build on it.
- **R1. Closure rebuild on large subtree moves:** resolved, see Resolved.
- **D-OQ4. Contents of the v1 permission catalog:** resolved, see Resolved.
- **D-OQ5. Removed or reclassified permissions on upgrade.** T-03 reports them in the catalog diff but does not reject them. T-29 must decide whether a release may remove a key that custom roles reference, and whether reclassifying a permission as non-privileged is allowed.

## Resolved
- Assignment authority (T-07, approved by Robert Former, 2026-10-26):
  - A **root-level grantor** holds `access.assign` through an assignment at the Enterprise root. Root-level grantors may assign into restricted BUs; this is for assigning only and never widens data access. Everyone else needs an assignment at or below the restricted BU (AC-22). Without this, nobody could make the first assignment in a new BU, because new BUs are restricted by default (AC-61).
  - Only root-level grantors may grant roles that contain an `admin` permission, at any BU (AC-22).
  - Granting to a group the grantor belongs to is self-assignment (AC-28). Revoking one's own assignment is also refused.
  - Until T-26, an assignment that would give any affected user both admin and risk-data permissions is refused (AC-30, fail closed).
- D-OQ4 v1 permission catalog: `permission-catalog.md` approved, with a `risk_data` flag per permission (2026-10-25)
- R1 closure rebuild: synchronous, inside the move/restrict transaction, so RLS never sees a half-rebuilt closure. Measured with `db/bench/bu_rebuild.sql` on PostgreSQL 16: 2,011 BUs: move of the largest subtree 9 ms, restrict 71 ms, unrestrict 127 ms; 20,011 BUs: 75 ms, 62 ms, 56 ms. T-11 guards against regression (2026-10-25)
- ADR-007 signed database context: accepted (2026-10-24)
- ADR-008 in-house authorization: accepted (2026-10-24)
- D-OQ2 session binding: profile setting; `off` in Enterprise Baseline, `reauthenticate` in FedRAMP Moderate and CMMC L2 (2026-10-24)

## Change Log
- 2026-10-24: Initial draft.
- 2026-10-24: ADR-007 and ADR-008 accepted; session network binding added (§5.8); design **approved**.
- 2026-10-25: T-03 implementation notes. The catalog file is JSON with an integer catalog `version`; `introduced_in_version` holds that catalog version. The loader rejects unprivileged approve/admin/export permissions (AC-54). Added open items D-OQ4 and D-OQ5.
- 2026-10-25: T-04 implementation notes (`db/migrations/0002_bu.sql`). The root is depth 0 and the maximum applies to `bu.depth`, so the default 6 allows seven levels including the root. The maximum is stored in the singleton `iam.bu_config` and cannot drop below the current tree depth. The root is seeded by the migration and cannot be moved or archived. The synchronous closure relink on move is in T-04 because the no-cycles trigger needs moves; T-05 adds restrict/unrestrict (refused until then) and the asynchronous path for large subtrees. `bu.restricted` defaults to true until T-30 wires the instance setting (AC-61). No application-role grants until T-09 adds RLS.
- 2026-10-25: R1 resolved: the closure rebuild stays synchronous; the asynchronous path is dropped (approved by Robert Former). AC-17 split: T-05 delivers the closure recalculation (`db/migrations/0003_bu_restrict.sql`); the old/new-parent audit moves to the T-08 outbox, written in the move's transaction so a move cannot commit unaudited. T-11 adds the closure rebuild to the benchmark gate.
- 2026-10-25: D-OQ4 resolved: permission catalog v1 approved. §3 `permission` gains `risk_data` (PC-1), which the T-03 loader now requires along with `privileged`.
- 2026-10-25: T-06 implementation notes (`db/migrations/0004_roles.sql`, `internal/access/catalog/release/`). The build embeds the approved catalog and built-in roles; a unit test fails if they drift from `permission-catalog.md`. `iam.sync_release(payload)` (SECURITY DEFINER, executable only as `fair_owner`) is the only writer of `iam.permission`, `iam.permission_catalog` and built-in roles. It is idempotent, gives new permissions only to the built-in roles that define them (AC-57), and refuses downgrades, removals and reclassification until T-29 (D-OQ5). Role versions are append-only, numbered consecutively, and advance `role.current_version`; roles are never deleted. Calling `sync_release` from the migration step is pending the embedded Go migration runner.
- 2026-10-26: T-02b added (approved by Robert Former): `iam migrate` embeds `db/migrations` and replaces `scripts/db-migrate.sh` with the same semantics, plus an advisory lock, `PGSSLMODE=verify-full` and TLS 1.2 minimum in production, and a final `iam.sync_release` with the build's catalog. This closes the T-06 gap: every install and upgrade applies the catalog it ships with. The run emits a `db.migrated` audit event (high severity when an upgrade adds permissions, AC-57); a failed emit fails the run.
- 2026-10-26: T-07 implementation notes (`db/migrations/0005_assignments.sql`). Grantor checks (AC-22), self-assignment (AC-28) and the AC-30 combination check are enforced by triggers on `iam.assignment`, so they hold for every writer. Assignments are immutable apart from a one-time revocation, and are never deleted. `iam.user_has_permission` implements the §3 effective-access rule, which T-08 materializes. `iam.bootstrap_platform_admin(user)` (installer only, `fair_owner`, only while no root-level grantor exists) creates the first Platform Admin. Minimal `app_user`, `grp` and `grp_member` tables per §3 are created here; directory tasks extend them. Still open: `granted_by`/`revoked_by` are trusted from the caller until T-09 binds them to the signed context; mapped assignments are refused until T-24; system revocation waits for T-32; AC-30 must also be re-checked when group membership changes (T-24) and when roles are edited (T-28).
