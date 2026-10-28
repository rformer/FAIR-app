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
- **D-OQ1. SAML library selection:** resolved, see Resolved.
- **D-OQ3. `authz.visible_bus` performance at target scale:** resolved, see Resolved.
- **R1. Closure rebuild on large subtree moves:** resolved, see Resolved.
- **D-OQ4. Contents of the v1 permission catalog:** resolved, see Resolved.
- **SAML interop with Entra ID, Okta and Ping (T-15):** covered by the dialect fixtures (their namespace and signing conventions) and the live Keycloak run; live runs against those three need test tenants. Open until tenants are available.
- **D-OQ5. Removed or reclassified permissions on upgrade.** T-03 reports them in the catalog diff but does not reject them. T-29 must decide whether a release may remove a key that custom roles reference, and whether reclassifying a permission as non-privileged is allowed.

## Resolved
- **D-OQ1 SAML library:** `russellhaering/gosaml2` with `goxmldsig`, wrapped in `internal/authn/saml`, with F-001's own algorithm, structure, time and replay checks around it and the XSW corpus (ADR-009, accepted by Robert Former, 2026-10-28). The module moves to Go 1.26 (gosaml2 needs 1.25; 1.24 is out of support).
- D-OQ3 `visible_bus` performance: meets the NFR at target scale (T-11, `db/bench/REPORT.md`, 2026-10-26). The context check plus query has p95 0.4 ms for small and medium scopes and 1.2–1.7 ms for the largest (1,952 BUs).
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
- 2026-10-26: T-08 implementation notes (`db/migrations/0006_scope.sql`, `0007`/`0008` River schema, `internal/scope`, `iam worker`).
  - Triggers write `iam.outbox` in the same transaction as every access-relevant change. A BU move's row carries the old and new parent and the actor (AC-17); the worker emits it as a `bu.moved` audit event.
  - `authz.drain_outbox` recomputes affected users from source tables and queues `iam.scope.changed` and audit events in `iam.event_outbox`. The worker delivers them at least once, marking each delivered only after the sink accepts it (audit fails closed). JetStream message IDs combine event id and creation time, so a restored database cannot collide with earlier ids.
  - `authz.reconcile_scopes` (nightly, 02:00 UTC) repairs drift and raises a high-severity `authz.scope.drift` audit event.
  - No `user_scope` row means no access; empty scopes are not stored. Disabled users' rows are deleted.
  - River v0.30.0 is pinned (approved by Robert Former): newer River requires Go 1.26 and this repo is on Go 1.24. River's schema is applied by `iam migrate` from `db/rivergen`, split where an enum value must commit first. The installer provisions the JetStream stream for `iam.scope.changed`.
  - Measured at target scale (10,001 users, 2,011 BUs, 51,976 assignments; PostgreSQL 16 in Docker on a developer workstation): single grant p50 34 ms, p99 102 ms; restrict a level-1 BU 41.2 s (508 users changed); unrestrict 37.7 s; move a level-2 subtree 33.3 s; re-version a role held by about 1/6 of assignments 29.3 s (5,541 users); full reconcile 1 min 55 s. With the 2 s poll the worst case is about 43 s against the 60 s NFR. The margin for wide-fan-out BU changes is thin; T-11 tracks it.
- 2026-10-26: T-09 implementation notes (`db/migrations/0009_db_context.sql`, `pkg/authz.MintDBContext`).
  - Token: `v1.<key_id>.<user_id>.<scope_version>.<expiry_unix>.<nonce>.<hmac>`, where the HMAC is hex HMAC-SHA-256 over everything before the last dot. The database also refuses tokens claiming more than 10 minutes of life; the minting library caps them at 5.
  - `authz.ctx_scope()` and `authz.visible_bus(resource_type, mode)` are owned by `authz_definer`. A missing, malformed, forged, expired, overlong or stale token, a retired key or a user without a scope row all yield an empty BU set.
  - Key rotation: `authz.add_ctx_key` / `authz.retire_ctx_key(key, valid_until)`. The old key stays valid until `valid_until`.
  - `authz.apply_bu_rls` adds the `bu_id` foreign key and index, enables and forces RLS, and installs one policy per operation: SELECT on read scope; INSERT, UPDATE and DELETE on write scope, with UPDATE checked both before and after. It refuses tables that carry other policies, and registers the table in `iam.bu_owned_tables`.
  - Correction to the ADR-007 example: PostgreSQL parses `bu_id = ANY ((SELECT ...))` as a subquery comparison. Policies use `bu_id = ANY ((SELECT authz.visible_bus(...))::uuid[])`, which is still a once-per-statement InitPlan.
  - Roles without `EXECUTE` on `visible_bus`, `fair_owner` included, get a permission error on BU tables rather than rows (fail closed).
  - Deployment requirements:
    - HMAC in the database uses `pgcrypto`, so FIPS on the database side depends on the PostgreSQL server's OpenSSL running in FIPS mode. F-014 preflight and F-015 deployment checks must verify this.
    - The bootstrap now grants `authz_definer` to `fair_owner` (SET only), so existing databases must re-run `scripts/db-bootstrap.sh` before `iam migrate`.
- 2026-10-26: T-10 implementation notes (`internal/rlstest`, `db/tests/rls_harness_test.go`).
  - `rlstest.Check` runs against any BU-owned table and builds its own state: BUs the user can read and write, read only, or not access at all; a user; a scope row; and a context key.
  - It reports findings in five groups:
    - structure: RLS forced, exactly the four policies bound to the registered resource type, owner `fair_owner`, nothing granted to `PUBLIC`;
    - context: 13 invalid-token cases see and change nothing;
    - writes: write scope, not read scope, governs every write;
    - AC-25: an out-of-scope row behaves exactly like a missing one;
    - SQL-injection simulation: arbitrary SQL run as `app_rw`.
  - CI gate: every table in `iam.bu_owned_tables` must have a fixture in `rlsFixtures` and pass, and any table with `bu_id` that an application role can access must be registered.
  - A meta-test proves the harness detects eight kinds of broken table, and that the gate catches unregistered ones.
  - PostgreSQL applies SELECT policies to `COPY ... TO` (zero rows without a context) and to the new row of an UPDATE whose WHERE reads columns. That is why the harness needs a read-only BU to detect a missing `WITH CHECK`.
- 2026-10-26: T-11 implementation notes (`db/tests/bench_test.go`, `db/bench/baseline.json`, CI job `bench`).
  - The gate fails if a request-path p95 exceeds 10 ms, or if any budgeted result exceeds max(3× baseline, baseline + 5 ms).
  - Known hotspot: an unfiltered "newest 50 rows" query for a user with a single BU had p95 8.6 ms and p99 10.0 ms. The RLS BU array is unknown at plan time, so PostgreSQL walks the primary key past rows outside the caller's scope. Feature tables with list views must filter by BU or carry a `(bu_id, <sort key>)` index; their T-10 fixtures should be benchmarked the same way.
  - Closure rebuild at 2,011 BUs (R1): restrict plus unrestrict of a level-1 BU 0.49 s, subtree move 5 ms; budget 2 s.
- 2026-10-26: T-12 implementation notes (`pkg/authz`, `db/migrations/0010_grant_snapshot.sql`).
  - `authz.grant_snapshot()` returns each permission and its BUs for the user named by the signed context only (no parameters), under the §3 rule on unblocked paths. Roll-up modes widen data reads in RLS but never action permissions. An invalid or stale context returns nothing.
  - `authz.Cache` implements `Checker` over snapshots keyed by (user, scope_version), with concurrent misses loaded once and a bounded size. `iam.scope.changed` (`SubscribeNATS`) evicts the user and records their latest version, so older principals get `ErrStaleScope`. `MaxAge` (60 s) bounds staleness if events are lost. Any error is a denial.
  - Measured invalidation: revocation to cache invalidated in 1.7–2.5 s, against the 60 s requirement.
  - `authz.WithDBContext(ctx, pool, token, fn)` sets `authz.ctx` with `set_config(..., true)`: parameterized, and local to the transaction.
  - Contract change: `Principal` gains `DBToken`, the gateway-minted context, which the loader and services use.
  - Service accounts are denied until T-33.
- 2026-10-26: T-26 implementation notes (`db/migrations/0017_approvals.sql`, `internal/approvals`). T-26 was pulled forward before F-015 T-14 (approved by Robert Former).
  - Decision (Robert Former): approver authority is per kind. Each kind names the permission its approver must hold at the request's BU, or the root when none: `access.approve` (AC-30), `breakglass.manage` (AC-41), `sod.manage` (AC-53), `bu.restrict` (AC-63, un-restrict and roll-up loosening) and `settings.approve` (F-015 AC-21). Today only Platform Admin holds these, so this is "a second Platform Admin" (§5.5) and also F-015's "holder of `settings.approve`". A custom role given one of these privileged permissions would let its holders approve that kind.
  - §3 `approval_request` gains `bu_id`, `decision_reason`, `created_at` and `consumed_at`. A new table `approval_kind` holds each kind's approve permission and its TTL (72 h by default, configurable per kind by the operator). The design's `CHECK decided_by <> requested_by` is in place.
  - Requester and approver come from the signed database context (`authz.ctx_scope`, ADR-007), never from parameters, so self-approval is impossible in the database. The API (`approvals.Service.Decide`) refuses it first as well. A disabled user's still-valid token is refused.
  - Functions:
    - `request_approval`, `decide_approval` (a rejection needs a reason), `expire_approvals` (scheduled job) and `approval` (a read for the requester or an eligible approver; anyone else gets "not found") are executable by `app_rw`.
    - `consume_approval(id, kind, target)` is for the approved action's own definer function. It allows one use of an unexpired approval of exactly that kind and target, and returns the payload. Each consuming feature's definer role is granted it with that feature (F-015 T-14: `posture_definer`).
    - Application roles have no table privileges.
  - Every step writes an audit event to `iam.event_outbox` in the same transaction: requested, approved (high severity), rejected, expired and consumed. Errors use SQLSTATE class AP.
  - Gap, still open: AC-30's consumer. T-07 still refuses an assignment that would combine admin and risk-data permissions; routing it through an `access.admin_risk_combination` approval is not done yet. The other consumers arrive with their own tasks (break-glass, SoD T-27, restricted BU T-30, F-015 T-14).
  - Verification (DB tests):
    - The full lifecycle with audit trail and one-time consumption.
    - Self-approval refused by the API and, when the API is bypassed, by the database function and the table check.
    - A BU Admin can neither see nor decide a request.
    - A Platform Admin's own request needs the second Platform Admin, and a rejection needs a reason.
    - Expiry: an expired request cannot be decided, an approval cannot be used after its window, the expiry job marks overdue requests and audits them, and the TTL is configurable.
    - Missing, forged and disabled-user contexts are refused; unknown kinds and blank reasons are refused.
    - A mutation that lets anyone approve fails the tests.
- 2026-10-28: T-14 pulled forward with F-015 T-31 (approved by Robert Former), so the Posture API can authenticate requests (`pkg/authz/jwt.go`).
  - **Token:** the gateway mints, per request and per target service, an ES256 JWT valid at most 5 minutes. Claims: `iss` `fair-gateway`, `aud` the service, `sub` user, `sv` scope version, `auth_time`, `iat`, `exp`, `jti`, and `dbc`, the SHA-256 of the DB context token sent alongside, so the two cannot be recombined across requests.
  - **Verification** (`VerifyJWT`) accepts only `alg` ES256 with a known `kid`, the issuer, the audience, a lifetime of at most 5 minutes, and an unexpired token (30 s leeway).
  - **Keys** sit behind `KeyProvider`. `LoadLocalKeys` reads a directory of PEM files named by key ID: the newest private key signs, every key verifies, and a service may hold public keys only. KMS and Vault providers implement the same interface with T-41.
  - **Shared middleware** (`internal/server/api.go`), which T-42 will reuse and lint-enforce:
    - `Authenticate` turns the JWT and the `X-Fair-DB-Context` header into the `authz.Principal` (401 otherwise).
    - `Idempotent` requires `Idempotency-Key` on POST, PUT, PATCH and DELETE (400 otherwise). It stores each outcome per user and key and replays it for the same request; the same key with a different request is 422, one in progress is 409, and a server error frees the key.
  - `authz.Cache.BUsWith` lists where a permission applies, for filtering lists to what the caller may see.
  - Verification:
    - `TestInternalJWT`: tampered claims, `alg` none and HS256, an unknown or missing key ID, the wrong audience or issuer, a lifetime over 5 minutes, expiry, a missing DB context, a foreign signer, and malformed tokens are refused; verification with public keys only works; rotation keeps old tokens valid.
    - `TestAuthenticate` and `TestIdempotent` (internal/server).
    - A mutation that drops the DB-context binding fails `TestAuthenticate`.
- 2026-10-28: T-13 implementation notes (`cmd/gateway`, `internal/gateway`, migration 0037, `api/openapi/gateway.yaml`). Robert Former approved three choices: a new gateway binary with its own database role, a session-bound CSRF token plus an origin check, and the session APIs served by the gateway in this task.
  - **Gateway** (`cmd/gateway`, image target `gateway`): serves the session APIs, and proxies `/api/v1/<service>/` to the services named in `FAIR_UPSTREAMS` (TLS 1.2+, trusting `FAIR_UPSTREAM_CA_FILE`), and optionally the web UI (`FAIR_UI_DIR`, with the UI's CSP). For each proxied request it mints a 2-minute internal JWT (audience = the service; `auth_time` = the session's start until T-24b records the IdP's) and DB context token (`FAIR_DB_CONTEXT_KEY_ID`/`_FILE`, the key installed in `authz.ctx_key`); a failure to mint answers 503 without reaching the service. The browser's cookie, CSRF token, and any `Authorization` or `X-Fair-DB-Context` it sends never reach a service.
  - **Database role `app_gateway`** (bootstrap; `FAIR_GATEWAY_PASSWORD_FILE`; existing installs re-run `scripts/db-bootstrap.sh`): NOBYPASSRLS, no table privileges; EXECUTE only on the session functions and on `posture.effective_settings` / `settings_version` (to read the timeouts as every service does).
  - **Sessions** (`iam.session`, migration 0037; owned by `fair_owner`, unreadable by every application role):
    - The cookie `__Host-sid` holds 256 random bits (base64url); Secure, HttpOnly, SameSite=Strict, Path=/, no Domain, no expiry (the browser drops it on close; the server enforces the timeouts).
    - Only HMAC-SHA-256(pepper, token) is stored; the pepper (`FAIR_SESSION_PEPPER_FILE`, at least 32 bytes) is the gateway's alone, so a database read or backup yields no usable session. Each session also has a public `handle` (UUID) for listing and revocation.
    - `iam.session_lookup` applies the idle and absolute timeouts in force on every request (`session.idle_timeout`, `session.absolute_timeout` through `settings.Client`; a stale snapshot fails requests closed), so a tightened timeout applies to existing sessions; it closes an ended session with its reason (`idle_timeout`, `absolute_timeout`, `user_disabled`), and writes `last_seen_at` at most once a minute (§5.2).
    - Creation, expiry and revocation are audited through `iam.event_outbox` in the same transaction (`session.created`, `session.expired`, `session.revoked`; revoking another user's session is high), and revocations publish `iam.session.revoked`.
    - The client IP and its /24 or /64 prefix are recorded (from the caller until T-20 adds the trusted proxy header and the binding check).
  - **CSRF (AC-35):** every state-changing request needs the session's CSRF token, HMAC(pepper, token) from `GET /api/v1/me`, in `X-CSRF-Token`, and must be same-origin: `Origin` equal to `FAIR_PUBLIC_ORIGIN`, or without `Origin`, `Sec-Fetch-Site: same-origin`; a request with neither is refused. SameSite=Strict is a third layer.
  - **Session APIs (AC-33)** (`api/openapi/gateway.yaml`): `GET /me` (with the CSRF token), `POST /auth/logout`, `GET|DELETE /me/sessions` (list; sign out everywhere else), `DELETE /me/sessions/{handle}`, `GET /sessions?user=`, `DELETE /sessions?user=`, `DELETE /sessions/{handle}`. Other users' sessions need `session.view` / `session.revoke` and a reason, checked by the database from the signed context. The gateway's own mutations are idempotent by nature (repeating one leaves the same state), so they take no `Idempotency-Key` (a clarification of §6's convention); proxied requests keep theirs.
  - **Login handoff:** `gateway.Sessions.Create` is the entry point the SAML and OIDC flows (T-15/T-16) will call; until then tests create sessions with it directly. No test-only login route exists.
  - Verification (`db/tests` `TestGateway*`):
    - Cookie and storage: the token is 256 bits; the raw token appears nowhere in the database; only a 32-byte HMAC, the auth method, IP and prefix are stored; no application role can read the table or call the functions it is not granted; the cookie's attributes; forged and malformed cookies are 401; a disabled user cannot sign in.
    - Timeouts (AC-31): idle after 15 minutes, absolute after 12 hours, each closing the session with its reason, clearing the cookie and auditing; a tightened absolute timeout ends an existing session; `last_seen_at` not written within the minute and refreshed after it; a disabled user's session ends at the next request.
    - Revocation (AC-33): users list their sessions (current marked, no HMAC exposed) and revoke one, which then fails at once; a user cannot list or revoke another's; an admin lists another user's sessions and revokes one only with a reason (high audit event naming the reason); `iam.session.revoked` events; sign out everywhere else; logout clears the cookie and ends the session.
    - CSRF (AC-35): no token, a wrong token, another session's token, a cross-site `Origin`, cross-site Fetch Metadata, and neither header are each refused on logout, a revocation and a proxied mutation, and nothing reaches the service; same-origin Fetch Metadata and GETs pass.
    - Proxy: unauthenticated requests never reach the service; unknown services 404; the service receives the path, query and `Idempotency-Key` but no cookie or CSRF token, a fresh DB context for the user (forged ones replaced) that the database accepts, and a JWT for its audience bound to that context, valid for at most 2 minutes.
    - Unit: the OpenAPI document matches the routes and every state change documents the CSRF header; upstream parsing (names, https only outside development). The image is non-root and refuses to start unconfigured.
    - Mutations (no origin check, no CSRF token check, the cookie forwarded, no idle timeout, a tightened absolute ignored, anyone listing sessions, no reason for an admin revocation) each fail the tests.
- 2026-10-28: T-15 implementation notes (`internal/authn`, `internal/authn/saml`, migration 0038, `internal/gateway/login.go`, ADR-009). Robert Former approved: gosaml2 (ADR-009) and Go 1.26; the SP in the iam service handing logins to the gateway with a signed login ticket; Keycloak as the live interop target, with Entra, Okta and Ping an open item until test tenants exist.
  - **Flow** (§5.1): `GET /api/v1/auth/saml/{idp}/login?return=/path` records the AuthnRequest's ID (with the return path, 10 minutes, single use) and redirects to the IdP (HTTP-Redirect); the IdP posts to `POST /api/v1/auth/saml/{idp}/acs` (HTTP-POST); `GET .../metadata` gives the IdP this SP's metadata. The SP's entity ID is `<origin>/api/v1/auth/saml`; each IdP has its own ACS URL. IdP-initiated login works only where the IdP's configuration allows it (`allow_idp_initiated`).
  - **Validation** (`internal/authn/saml`, around gosaml2): before the library, a 256 KiB limit, no DTD, exactly one `Assertion` anywhere in the document and no `EncryptedAssertion`, and FIPS-only algorithms on every signature and digest (RSA or ECDSA with SHA-256/384/512); after it, one signed assertion, Destination and an AudienceRestriction naming this SP present and matching (the library only warns, or checks them only when present), Issuer, NotBefore and NotOnOrAfter within ±2 minutes, a non-empty NameID; InResponseTo the same on the response and the assertion and naming a pending request of this IdP (consumed), or absent where IdP-initiated login is allowed; and a replay cache of assertion IDs until they expire (`iam.saml_assertion`). Encrypted assertions are not supported in v1.
  - **User:** looked up by (IdP, NameID) in `iam.app_user` (`idp_id`, `external_id`; migration 0038 adds the IdP table and the foreign key); unknown or inactive users are refused (JIT provisioning is T-23). The AuthnContextClassRef is kept as the session's MFA evidence; T-18 applies the IdP's rule.
  - **Handoff to the gateway (login ticket):** iam answers a valid login with `X-Fair-Login-Ticket`: a compact JWS (ES256, iam's key `FAIR_LOGIN_TICKET_KEYS_DIR`) naming the user, method, IdP, MFA evidence, the IdP's authentication time and the return path, valid 60 seconds. The gateway forwards `/api/v1/auth/saml/` to iam without a session and without the browser's cookie or credentials, strips any ticket header the browser sends, and on iam's response verifies the ticket with iam's public key, redeems its ID once (`iam.login_ticket_use`, app_gateway only), creates the session (T-13) and answers with the cookie and a page that moves the browser to the return path (a same-site navigation, so the SameSite=Strict cookie is sent; a redirect straight after the IdP's cross-site POST would not carry it). Only iam can issue a ticket (app_rw is shared by services, so the signature, not the database, is the proof), and none reaches the browser.
  - **Data** (migration 0038): `iam.idp` (design §3; SAML metadata as JSON: `entity_id`, `sso_url`, `certificates`, `allow_idp_initiated`; managed by T-17); `iam.saml_request`, `iam.saml_assertion`, `iam.login_ticket_used`; all through definer functions (`idp_for_login`, `saml_request_save`/`consume`, `saml_assertion_record`, `login_user`, `authn_event` for app_rw; `login_ticket_use` for app_gateway). Logins are audited through the outbox: `authn.login.success`, and `authn.login.denied` with the reason (users see a generic message).
  - **Services:** `iam` serves the SAML routes when `FAIR_PUBLIC_ORIGIN` is set (required in production), with `FAIR_DB_PASSWORD_FILE` (app_rw) and `FAIR_LOGIN_TICKET_KEYS_DIR`; the gateway forwards them when it has an `iam` upstream, with `FAIR_LOGIN_TICKET_KEYS_DIR` holding iam's public key.
  - Verification:
    - XSW and negative corpus (`internal/authn/saml`, a test IdP signing real responses with goxmldsig): unsigned; another key; SHA-1; the NameID changed after signing; seven wrapping variants (evil assertion before or after the signed one, the signed one hidden in Extensions or wrapped inside the evil one, the evil one in the signature's Object or reusing the signed ID, an unsigned assertion swapped into a signed response); an encrypted assertion; a DTD; expired; not yet valid beyond the skew; wrong or missing audience; wrong or missing Destination; wrong Recipient; wrong issuer; a failure status; an empty NameID; unknown or mismatched InResponseTo; IdP-initiated where not allowed; oversized. Each is refused, and where F-001's own pre-check is the defence (wrapping, SHA-1, DTD, encryption) the test requires its reason, since gosaml2 and FIPS mode also refuse some of them (defence in depth). A comment inside the NameID cannot truncate it. Accepted: assertion, response or both signed, RSA-SHA512, a clock 90 s off, within the skew; Entra, Okta and Ping dialects (default namespace, saml2 prefixes, response signing), each also refusing a wrapped response. Replays: an SP-initiated response or its request answered twice, and an IdP-initiated response replayed (the replay cache alone).
    - Tickets: round trip; expired, another key, changed claims, `alg: none`, truncated, not yet valid.
    - DB, end to end through the gateway and iam (`TestSAMLLoginEndToEnd`): SP-initiated login lands at the requested path with the cookie, `/me` shows the SAML session and its MFA evidence, the ticket never reaches the browser, success audited; refused, with no session and audited reasons: the replay, an unknown user, a disabled user, a wrapped response, IdP-initiated where not allowed; app_rw cannot redeem tickets, app_gateway cannot look users up or read IdPs. `TestLoginTicketRedemption` (a stand-in iam): a good ticket once (an off-site return path becomes /), then refused on reuse; a foreign signer, an expired ticket and garbage refused; a ticket sent by the browser never reaches iam.
    - **Live interop with Keycloak 26.0.7** (`scripts/saml-e2e-keycloak.sh`, `TestSAMLKeycloakInterop`): a realm, SAML client (RSA-SHA256, signed assertions and documents, email NameID) and user configured through Keycloak's admin API; the platform's IdP configured from the realm's metadata; SP-initiated login through Keycloak's login form and IdP-initiated login (the client's SSO URL) each end with a session; both audited.
    - Mutations (the one-assertion pre-check, the algorithm allow-list, a required AudienceRestriction, a required Destination, the skew window, the IdP-initiated switch, the replay cache, single ticket redemption, stripping a browser's ticket, and the ticket signature check) each fail the tests.
