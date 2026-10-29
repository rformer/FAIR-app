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
6. The session is created unacknowledged, and the system-use banner is shown: until the user acknowledges it (AC-34) the gateway serves the session nothing but `/me`, the acknowledgment and logout (amended 2026-10-29, T-19). The cookie is `__Host-sid` (Secure, HttpOnly, SameSite=Strict, Path=/) and holds 256 random bits; only its HMAC is stored. The client IP prefix and ASN are recorded for §5.8.
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
- **BU overrides** (the setting is BU-scopable; added 2026-10-29, T-20): the gateway does not know a request's BU, so it applies the instance value. In `off` and `flag` mode it marks a session whose network changed (`network_changed_at`), and the mark travels in the internal JWT (`nch`); a service's permission check (`authz.Cache`, `CacheOptions.NetworkBinding`) refuses such a session in a BU whose own value is `reauthenticate`, with 401 `step_up_required` (`max_age=0`: sign in again).
- **ASN data:** iptoasn.com's `ip2asn-v4.tsv` and `ip2asn-v6.tsv` (public domain), read from `FAIR_ASN_DB_DIR`. Prefix sizes come from the gateway's configuration (`FAIR_SESSION_PREFIX_V4`, `_V6`).

## 6. API (REST `/api/v1`, OpenAPI published with the release)
- **Auth:** `POST /auth/discover`, `GET /auth/saml/{idp}/login`, `POST /auth/saml/{idp}/acs`, `GET /auth/oidc/{idp}/callback`, `POST /auth/banner/ack`, `POST /auth/logout`, `/breakglass/*` (WebAuthn)
- **Self:** `GET /me`, `GET /me/permissions?bu=`, `GET|DELETE /me/sessions`
- **SCIM:** `/scim/v2/Users`, `/Groups`, `/Bulk`, `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes` (SCIM token auth only)
- **Organization:** `/bus` (tree, CRUD, move, archive), `/bus/{id}/restriction`, `/bus/{id}/rollup-mode`, `/bus/import`, `/bus/export`
- **Access:** `/permissions`, `/roles` (+ `/versions`, `/diff`, `/clone`, `/export`, `/import`), `/assignments`, `/group-mappings`, `/sod-rules`, `/sod-exceptions`
- **Identity admin:** `/idps`, `/users`, `/groups`, `/service-accounts` (+ `/tokens`), `/sessions`, `/banner` (T-19)
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
- **SAML and OIDC interop with Entra ID, Okta and Ping (T-15, T-16):** covered by the dialect fixtures (their namespace and signing conventions) and the live Keycloak run; live runs against those three need test tenants. Open until tenants are available.
- **ASN database in the release images (T-20):** the gateway reads the iptoasn files from `FAIR_ASN_DB_DIR` and checks prefixes only without them; shipping the files with each release (§10) belongs with the release tooling (F-012). Open until then.
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
    - **Live interop with Keycloak 26.0.7** (`scripts/sso-e2e-keycloak.sh`, `TestSAMLKeycloakInterop`): a realm, SAML client (RSA-SHA256, signed assertions and documents, email NameID) and user configured through Keycloak's admin API; the platform's IdP configured from the realm's metadata; SP-initiated login through Keycloak's login form and IdP-initiated login (the client's SSO URL) each end with a session; both audited.
    - Mutations (the one-assertion pre-check, the algorithm allow-list, a required AudienceRestriction, a required Destination, the skew window, the IdP-initiated switch, the replay cache, single ticket redemption, stripping a browser's ticket, and the ticket signature check) each fail the tests.
- 2026-10-28: T-16 implementation notes (`internal/authn/oidc`, `internal/authn/oidchttp.go`, `internal/authn/logins.go`, migration 0039). Robert Former approved coreos/go-oidc v3 with golang.org/x/oauth2, and a client secret read from a file.
  - **Flow** (§5.1): `GET /api/v1/auth/oidc/{idp}/login?return=/path` stores a started login (a 256-bit state, a 256-bit nonce, the PKCE S256 code verifier and the return path; 10 minutes, consumed once; `iam.oidc_state`) and redirects to the IdP's authorization endpoint (scope `openid` plus the configured scopes); the IdP redirects to `GET .../callback`, where the state is consumed, the code exchanged with the verifier (client_secret_basic), and the ID token verified. The redirect URI is `<origin>/api/v1/auth/oidc/<idp>/callback`.
  - **ID token:** go-oidc verifies signature, issuer, audience and expiry, with only RS/PS/ES 256-512 accepted (no HMAC, no `none`; FIPS 140); keys from the IdP's `jwks_uri` (cached per URI, refetched on an unknown key ID) or inline `jwks` (air-gapped). Around it: the nonce must match; with several audiences `azp` must be this client, and any `azp` must be; `iat` and `auth_time` not in the future beyond ±2 minutes (expiry also gets the skew); the configured subject claim (`sub` by default; e.g. `oid` for Entra, whose SCIM provisions it, or `email`) must be present and is the user's external id. `amr` and `acr` are kept as MFA evidence (T-18 applies the rule); `auth_time` becomes the ticket's authentication time.
  - **Configuration** (`iam.idp`, kind `oidc` or `keycloak`): `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` or `jwks`, `client_id`, `client_secret_file` (a mounted file; the secret is never stored in the database), `scopes`, `subject_claim`. Endpoints come from the configuration, never from discovery at login time (T-17 adds discovery and upload).
  - **Shared with SAML:** `authn.Logins` (user lookup by IdP and external id, the login ticket, the audit events, the generic failure) now serves both flows; the gateway forwards `/api/v1/auth/oidc/` like `/api/v1/auth/saml/` and turns the ticket into a session (the callback is a top-level cross-site navigation, so the same landing page applies).
  - Verification:
    - Unit (`internal/authn/oidc`, against `oidctest`, a provider whose token endpoint checks the client's credentials, the code's redirect URI and PKCE): RS256, PS256 and ES256 accepted; inline JWKS; another subject claim. Refused, with the reason pinned for the security-critical ones: a wrong or missing nonce, a wrong audience, several audiences without `azp`, another client's `azp`, a wrong issuer, expired beyond the skew, issued or authenticated in the future, HS256 signed with the client secret, `alg: none`, a key the IdP does not publish (same key ID), a missing subject claim, a wrong client secret, an inline JWKS without the key. State: an IdP error spends it; unknown, missing and reused states are refused; a code from another login (another PKCE challenge) cannot complete this one.
    - DB, end to end through the gateway and iam (`TestOIDCLoginEndToEnd`): login lands at the requested path with the cookie and an OIDC session carrying the `amr` evidence, the ticket never reaches the browser; refused with no session and audited reasons: the callback replayed, an unknown user, a disabled user, a changed nonce, the IdP's `access_denied`; the client secret is not in the database; app_gateway cannot touch login state.
    - **Live interop with Keycloak 26.0.7** (`scripts/sso-e2e-keycloak.sh`, renamed from `saml-e2e-keycloak.sh`; `TestOIDCKeycloakInterop`): a confidential client requiring PKCE S256, the platform's IdP configured from the realm's discovery document with users matched by `email`; a user signs in through Keycloak's form and gets a session.
    - Mutations (no nonce check, several audiences without azp, another client's azp, HS256 allowed, no iat check, no auth_time check, no PKCE, the subject claim ignored) each fail the tests.
  - **Found on the way:** `govulncheck` reports 11 reachable vulnerabilities in dependencies that predate T-16 (golang.org/x/net, golang.org/x/text, google.golang.org/grpc, github.com/jackc/pgx/v5); they are fixed separately, as a dependency security update.
- 2026-10-29: T-17 implementation notes (`internal/authn/discover.go`, `internal/authn/metadata.go`, `internal/iamapi`, `api/openapi/iam.yaml`, migration 0040). Robert Former approved routing by path segment in the gateway (keeping the §6 root paths), a discovery answer of the same shape for unknown domains, and administrator fetches with confirmation of new fingerprints.
  - **Home-realm discovery** (§5.1 step 1, AC-02): `POST /api/v1/auth/discover {"email", "return"}`, no session, served by iam and forwarded by the gateway like the login routes. The domain of the address is looked up among enabled IdPs (`iam.idp_discover`); the answer always has the same shape, `{"login_url", "message"}`, with `login_url` null and a generic message for unknown domains, disabled IdPs and non-addresses. Discovery works on domains (configuration), so it says nothing about users. A return path that is not local becomes `/`. Rate limit: a token bucket of 20 requests per minute per client address (429 with `Retry-After`).
  - **Several IdPs:** `iam.idp.email_domains` are stored lower-case and validated by a trigger, which also refuses (PF003, 409) a domain served by another enabled IdP, so routing is unambiguous; a GIN index serves the lookup.
  - **The iam API** (`internal/iamapi`, contract `api/openapi/iam.yaml`): the first authenticated iam API, built like the Posture API (`server.Authenticate` with audience `iam`, `server.Idempotent` over `iam.idempotency`, `idp.view` at the root BU through `authz.Cache` or 404, `idp.manage` checked by the definer functions or 403). Routes: list, create (disabled until it has metadata), read, `PATCH` (name, domains, enabled, settings: `allow_idp_initiated` for SAML; `client_id`, `client_secret_file`, `scopes`, `subject_claim` for OIDC), `PUT .../metadata` (upload) and `POST .../metadata/fetch`. An IdP is enabled only with complete configuration. Every change goes to the outbox as a high-severity audit event with its reason (`idp.created`, `idp.updated`, `idp.enabled`, `idp.disabled`, `idp.metadata_changed` with the fingerprints). The gateway routes the §6 resource segments (`idps`, `users`, `groups`, ... `entitlements`) to iam with an `iam` token (`gateway.Segments`); a service keeps `/api/v1/<name>/` too. cmd/iam serves the API when `FAIR_JWT_KEYS_DIR` holds the gateway's public keys (required in production).
  - **Metadata** (AC-03): SAML metadata (an EntityDescriptor with an IDPSSODescriptor: entity ID, HTTP-Redirect SSO URL, signing certificates; no DTD), an OIDC discovery document (issuer, endpoints, JWKS URI; the code flow) or a JWKS file (public RSA >= 2048 or EC signing keys only; it replaces `jwks_uri`). Endpoints are https (http only in development). Uploaded documents merge into the stored configuration. A fetch is https, TLS 1.2+, 10 s, 1 MiB and follows no redirects; for OIDC the URL is the issuer and the document's issuer must match it. Air-gapped installs refuse fetches (409 `air_gapped`) and take files.
  - **Pinning:** the trust anchors are SAML certificates (`cert:sha256:`), the OIDC issuer and JWKS URI, and inline JWKS keys (`jwk:sha256:`, RFC 7638). Once an IdP has anchors, a document that changes them is applied only when the request confirms exactly the new set; otherwise 409 `confirm_fingerprints` with the current and proposed sets. There is no background refresh: a rotation is an administrator's confirmed, audited change.
  - Verification:
    - Unit: the three parsers (accepted documents and their fingerprints; refused: http SSO, no certificate, RSA-1024, a DTD, SP metadata, not XML; issuer mismatch, an http endpoint, no code flow; a private key, RSA-1024, no signing key), stored fingerprints equal parsed ones, the fetch (untrusted certificate, http outside development, oversized, a redirect), the rate limiter (per client, refill, 429). The OpenAPI document and the served routes are the same set.
    - DB, through the gateway (`TestIDPRoutingByDomain`): a SAML and an OIDC IdP configured over the API (upload; discovery fetch from a test provider; settings), routed by domain (case-insensitive, a display-name address); unknown domains, subdomains, non-addresses and disabled IdPs get the same answer; an off-site return becomes `/`; overlapping and invalid domains refused; the audit trail. `TestIDPMetadataPinningAndAirGapped`: unchanged anchors need no confirmation; a rotation is refused until exactly the new set is confirmed (not a subset); air-gapped refuses the fetch, accepts the discovery document and the JWKS file (pinned) and records the source `file`; symmetric keys refused. `TestIDPAdminAccess`: no session 401; without `idp.view` 404; a viewer reads but cannot create (403, nothing created); an idempotent replay creates one IdP; key reuse with another body refused.
    - Mutations (no pinning check, no air-gapped refusal, no `idp.view` check) each fail the tests.
- 2026-10-29: T-18 implementation notes (`internal/authn/mfa.go`, `internal/authn/logins.go`, migration 0041). Robert Former approved standards defaults for IdPs without a rule, and the requirement following the settings.
  - **When MFA is required:** `auth.mfa_required_all` (true in every profile) requires it of everyone; when it is off, `auth.mfa_required_privileged` (a hard floor) still requires it of users holding a privileged permission (AC-54) through an active assignment, directly or through a group (`iam.login_user_privileged`). The iam service reads both through `settings.Client`; without settings, or when they cannot be read, MFA is required (fail closed).
  - **Evidence and rules** (`iam.idp.mfa_evidence_rule`): a rule lists conditions, any one of which is MFA: SAML `authn_contexts` (AuthnContextClassRef values) and `attribute` ({name, values}, matched against the assertion's attributes, which the SP now keeps); OIDC `amr`, `amr_two_categories` (amr values from two RFC 8176 factor categories: knowledge pwd/pin/kba, possession otp/hwk/swk/sms/tel/sc, inherence fpt/face/iris/retina/vbm) and `acr`. A rule replaces the defaults; an empty rule is the defaults: for SAML the REFEDS MFA profile, the two-factor SAML 2.0 classes (MobileTwoFactorContract, MobileTwoFactorUnregistered, SmartcardPKI, TimeSyncToken), the widely used MultiFactor class and Microsoft's multipleauthn (AD FS as a class; Entra ID in the `authnmethodsreferences` attribute); for OIDC `amr` `mfa` or two categories. Values match exactly. A stored rule that does not validate fails the login closed (503). Rules are set with `PATCH /api/v1/idps/{id}` (`mfa_evidence_rule`; null restores the defaults), validated per kind and audited (`idp.mfa_rule_changed`, high).
  - **Outcome:** a login that must show MFA and does not is refused like any other (generic message, no session) and audited as `authn.mfa_missing` (high) with the evidence and the user. Every login's ticket, and so the session's `mfa_evidence`, records `satisfied`, for later step-up decisions.
  - Verification:
    - Unit: the defaults class by class (exact matches only; PasswordProtectedTransport, Password, unspecified and Smartcard are not MFA), Entra's attribute, amr combinations (one category or non-factor values are not MFA), evidence of the other protocol never counts; explicit rules replace the defaults; rule validation per kind; fail closed without or with unreadable settings.
    - DB, through the gateway (`TestMFAEvidenceSAML`, `TestMFAEvidenceOIDC`, `TestIDPMFARuleAPI`): password-only SAML and amr `pwd` logins denied, without a session, audited (high, with the evidence and user); MultiFactor, REFEDS, Entra's attribute, `pwd`+`otp` and `mfa` accepted with `satisfied` recorded; an explicit attribute or acr rule; with `auth.mfa_required_all` off a non-privileged user signs in without MFA (recorded unsatisfied) while a user privileged through a group is denied until the group's assignment is revoked; an invalid stored rule fails closed; the API validates, stores, restores defaults and audits rules.
    - **Live with Keycloak 26.0.7** (`scripts/sso-e2e-keycloak.sh`): a password-only Keycloak login is denied and audited as `authn.mfa_missing` for both SAML and OIDC; with MFA required of privileged users only, the same non-privileged user signs in. (Keycloak's own MFA policy for the bundled realm is AC-06.)
    - Mutations (the denial skipped, the privileged check ignored, nil or unreadable settings not requiring MFA, one amr category counted as MFA, an explicit rule falling back to the defaults) each fail the tests.
- 2026-10-29: T-19 implementation notes (migration 0042, `internal/gateway`, `internal/iamapi/banner.go`, `web/src/banner.tsx`). Robert Former approved gating the session until acknowledgment (amending §5.1 step 6, which had the banner before the session was created) and the banner text in iam with an API.
  - **Gate** (AC-34): a session starts with `banner_ack_at` null. While `banner.enabled` is on (the default in every profile; the gateway reads it through `settings.Client`, and a missing or unreadable setting counts as on), the gateway answers every route but `GET /me`, `POST /auth/banner/ack` and `POST /auth/logout` with 403 `banner_required`, before anything is forwarded. `/me` carries the banner (`required`, `version`, `text`, or `acknowledged_at`). The acknowledgment is same-site with the CSRF token and names the version shown; a version that is no longer current is refused (409) so the user reads the current text. It is recorded on the session (`banner_ack_at`, `banner_version`, through `iam.session_banner_ack`, app_gateway only) and audited (`session.banner_acknowledged`). Every new session acknowledges again; `session_lookup` (recreated) returns the acknowledgment.
  - **Text** (`iam.banner`, versioned): a neutral AC-8 notice ships as version 1. `GET /api/v1/banner` (any session) and `PUT /api/v1/banner` (`banner.manage`, checked by `iam.banner_admin_set` from the signed context; 1 to 10,000 characters) on the iam API, audited (`banner.changed`, high, with the text). Sessions already acknowledged keep their acknowledgment; new ones see the new version.
  - **UI:** the app reads `/me` first and shows only the notification (focus on its heading; Acknowledge and continue, or Sign out) until it is acknowledged. The API client now sends the session's CSRF token on every mutation.
  - **E2E harness:** `TestPostureUIHarness` now runs the real gateway (sessions, CSRF, the banner gate) in front of the Posture API instead of the T-32 dev gateway; `/dev/as/{user}` creates the session as a redeemed login ticket does.
  - Verification:
    - DB, through the gateway (`TestBannerGatesTheSession`, `TestBannerTextAPI`): before acknowledgment `/me` carries the banner and posture, session and mutation routes answer `banner_required` without reaching the service; acknowledgment without the CSRF token, with a malformed body or a stale version refused; afterwards the service is reached and `/me` shows the time; audited; a new session acknowledges again; logout works before acknowledgment; with `banner.enabled` off there is no gate, and an unreadable setting keeps it; app_rw cannot acknowledge and app_gateway cannot write the text. The text API: read by anyone signed in, changed by `banner.manage` only (403 otherwise), blank text refused, audited; a new session sees the new version and cannot acknowledge the old one.
    - **E2E** (Playwright, `web/e2e/banner.spec.ts`, axe WCAG 2.1 AA): after sign-in only the notification shows, accessibly; the API refuses the session (403 `banner_required`) until the user acknowledges; then the Posture page loads, a reload goes straight to it, and a new session sees the notification again; signing out from it ends the session. The Posture specs now acknowledge first and run their actions through the real gateway's CSRF check.
    - Mutations (every route exempt, logout gated, an unreadable setting or no setting treated as off, a stale version accepted) each fail the tests.
- 2026-10-29: T-20 implementation notes (migration 0043, `internal/gateway/network.go`, `pkg/authz`). Robert Former approved BU overrides applied through the services' permission checks, and iptoasn.com's TSV files as the ASN data.
  - **Client address:** the gateway believes `FAIR_CLIENT_IP_HEADER` (`X-Forwarded-For` or `X-Real-IP`) only from `FAIR_TRUSTED_PROXIES` (the ingress; required with the header); in `X-Forwarded-For` the client is the right-most address that is not a trusted proxy, so addresses a client prepends are ignored, and an unparseable entry stops at the last hop a trusted proxy vouched for. The same address is recorded at login, used for the check, and sent to the services as `X-Forwarded-For` (they no longer see the ingress's address).
  - **Check** (every authenticated request): the client is on the session's network while its address stays in the login's prefix (`/24` and `/64` by default, `FAIR_SESSION_PREFIX_V4`/`_V6`) and, with the ASN database, maps to the same AS (no AS on both sides counts as the same). Otherwise `iam.session_network_changed` (app_gateway): `reauthenticate` revokes the session (`network_change`), audits `session.network_changed` and `session.revoked` (high), and the gateway answers 401 with a `login_url` for the session's IdP (sessions now record it); the UI goes there with the current page as the return path. `flag` marks the session once, audits it (high) and shows it on the sessions views (`network_changed_at`); `off` marks it silently. A marked session is revoked if the mode later becomes `reauthenticate`. The instance value comes from `settings.Client`; unreadable, it is `reauthenticate` (fail closed).
  - **BU overrides** (see §5.8): the internal JWT's `nch` claim carries the mark to the services, whose `authz.Cache` refuses it in a BU set to `reauthenticate` (iam and posture read the setting per BU; posture now has a settings client, which before seeding denies).
  - **Data** (migration 0043): `iam.session` gains `idp_id` and `network_changed_at`; `session_create` takes the IdP, the ASN and the prefix sizes; `session_lookup` returns the network fields and, for ended sessions, why (so a revoked session keeps answering with the way back); `session_list` returns the mark.
  - Verification:
    - Unit: client address (no header, an untrusted hop's header ignored, the ingress's header, a spoofed left-most entry, chains of trusted hops, garbage, IPv6, IPv4-mapped, X-Real-IP); same network (prefixes, families, configured sizes, ASN changes inside a prefix, no ASN on either side); the ASN loader (TSV and gzip, AS 0 skipped, overlapping, short, malformed, reversed and mixed-family ranges, no files); the configuration (a header without trusted proxies refused); `authz.Cache` (a strict BU refuses a moved session with step-up, other BUs and unmoved sessions pass, a policy error denies, a denial stays a denial).
    - DB, through the gateway (`TestNetworkBindingModes`, `TestNetworkBindingClientAddressAndASN`, `TestNetworkBindingStrictBU`): `off` marks without auditing and the token says so; `flag` audits once and the sessions view shows it; `reauthenticate` keeps a same-network session, revokes a moved one with the IdP's sign-in link, audits both events, and revokes a previously flagged session; an unreadable setting acts as `reauthenticate`; a spoofed left-most address is ignored; a header from a hop outside the trusted ingress is ignored; an ASN change inside the /24 is a change and is audited with both ASNs; the service gets the client's address; a BU set to `reauthenticate` refuses a moved session (401 `step_up_required`, `max_age=0`) while the instance only flags it. The profile defaults (`off`, `reauthenticate`, `reauthenticate`) are the F-015 bindings' and covered by its registry tests.
    - Mutations (a header believed from any hop, the left-most address chosen, the ASN ignored, an unreadable setting treated as `flag`, no `nch` claim, a marked session exempt from `reauthenticate`) each fail the tests.
- 2026-10-29: T-21 implementation notes (`internal/scim`, `internal/iamapi/scimtokens.go`, migration 0044). Robert Former approved our own implementation (no SCIM library), tokens per IdP issued through the iam API, and our own RFC test suite as the compliance test (the vendors' validators are T-25).
  - **Endpoint:** `/scim/v2` on iam, forwarded by the gateway without a session (cookies and internal headers stripped; the bearer token passes). `Users`, `Groups` (GET, POST, PUT, PATCH, DELETE, `.search`), `Bulk`, `ServiceProviderConfig`, `ResourceTypes`, `Schemas` (all need the token); `/Me` answers 501. `application/scim+json`, RFC 7644 §3.12 errors, weak ETags with `If-Match` (412) and `If-None-Match` (304), resource locations at the platform's origin.
  - **Tokens** (AC-08; `iam.api_token`, design §3): `fscim_` + 256 random bits, per IdP, issued by `POST /api/v1/idps/{id}/scim-tokens` (`scim.manage`, audited `token.created`, high), shown once; only the SHA-256 is stored, and the idempotency store keeps a redacted answer instead (`server.SecretResponse`: a replay answers 409 `secret_not_replayed`). Expiry 90 days by default, at most a year; rotation is issuing another and revoking the old (`DELETE .../scim-tokens/{token}`, audited); list without secrets. A token only works at `/scim/v2` and only for its IdP: every `iam.scim_*` function takes the token's hash and acts for that token's IdP alone, so holding app_rw is not enough to provision. Rate limit 1,200 requests per minute per token (429).
  - **Users:** the resource is stored as sent (minus `id`, `meta`, read-only `groups`; `password` is never stored), with `userName` unique per IdP, an email (the primary, else the first, else a `userName` that is an address), the display name, `active`, and SCIM's `externalId` (`scim_external_id`). The login subject (`app_user.external_id`) is `userName` or, by the IdP setting `scim_subject_attribute`, `externalId`. `active: false` disables the user (`disabled_reason` scim; audited `scim.user.deactivated`, high), `true` re-enables a SCIM-disabled user but never a locked one. DELETE removes the user from SCIM, disables it, releases its identifiers and memberships and keeps the record (`scim.user.deleted`, high); the same `userName` can be provisioned again. The enterprise extension is supported; other extensions are kept as sent. Booleans sent as strings ("False", Entra ID) are accepted.
  - **Groups:** `displayName`, `externalId`, members (users of the same IdP; nested groups and other IdPs' users are refused). Membership is written as a difference, so the scope outbox (T-08) sees exactly what changed; group-to-role mappings follow in T-24.
  - **Filters** (RFC 7644 §3.4.2.2): all operators, `and`/`or`/`not`, grouping, value paths and extension URNs; case rules from the schema (`id`, `externalId` and member values are case-exact); `gt`/`ge`/`lt`/`le` compare dateTimes as times. Filters are evaluated over the IdP's resources in the iam service, which is sized for the target scale (tens of thousands of users per IdP); pages of up to 1,000 (`startIndex`, `count`). Sorting is not offered (`sort.supported: false`).
  - **PATCH** (§3.5.2): add, replace, remove with and without paths, value paths with sub-attributes, extension paths, case-insensitive ops; the forms Entra ID and Okta send (a missing filtered element created by `add`, `remove` of members by value list, extension objects without a path). Applied to the current resource and stored under the version read; a concurrent change is retried unless the client sent `If-Match`.
  - **Bulk** (§3.7): at most 100 operations and 1 MiB (413 beyond), `bulkId` references in paths and data (an unresolved one is a 409 for that operation), `failOnErrors`; operations apply in order, not atomically.
  - Verification:
    - Unit: filters (every operator, precedence, value paths, URNs, case rules, dateTimes, numbers, absent values; 16 malformed filters and excessive nesting refused); PATCH (16 user cases and 7 member cases, including the Entra ID and Okta forms; 11 refusals with their `scimType`); input preparation and the derived fields; the per-token rate limit; refusal without a bearer token.
    - DB, through the gateway (`TestSCIMTokens`, `TestSCIMUsers`, `TestSCIMListing`, `TestSCIMGroups`, `TestSCIMBulk`, `TestSCIMDiscovery`), each check citing its RFC section: token issue, one-time display (not in the idempotency store, not in clear), listing, use recorded, refusals (no token, unknown, a session cookie, another scheme, revoked, expired, a SCIM token on the platform API), isolation between IdPs, rotation, expiry bounds, `scim.manage`; the User lifecycle (create with Location and ETag, uniqueness, syntax and schema errors, 415, conditional GET, projections, PATCH with If-Match and 412, mutability, noTarget, invalidVers, deactivation and reactivation with audit, a locked user stays locked, PUT clears, the subject setting, DELETE and re-provisioning); filtering as Entra ID and Okta query, pagination, `.search`; groups and memberships through PATCH in both vendors' forms, user `groups`, deletion; Bulk with references, failOnErrors and both caps; discovery documents.
    - Mutations (token expiry ignored, the issued token stored for replay, case rules ignored, no Bulk operation cap, members from any IdP, If-Match ignored on PATCH, user listing across IdPs) each fail the tests.
- 2026-10-29: T-22 implementation notes (migration 0045, `internal/scope.Subjects`).
  - **In the deactivating transaction** (§5.3): a trigger on `iam.app_user.status` (active to anything else: SCIM deactivation, SCIM DELETE, Bulk, and any later path such as an administrator, the inactivity sweep or a lockout) revokes every live session (`user_disabled`; audited `session.revoked`, high; announced on `iam.session.revoked`), deletes the user's `authz.user_scope` row (DB context tokens already minted see no BU) and announces `iam.scope.changed` with `revoked` as the scope worker does, so services evict cached grants, and `iam.user.deactivated` (with the number of sessions revoked). Reactivation restores nothing.
  - **No window:** the gateway reads the session on every request (it keeps no session cache, so §5.3's 30 s cache backstop does not arise), and internal JWTs are minted per request, so the next request after the SCIM call is refused. The AC-10 tokens are sessions today; personal API tokens do not exist, and service-account tokens (T-33) belong to service accounts, not users.
  - **Found on the way, fixed:** the worker publishes every non-audit outbox topic to JetStream but checked at startup only that a stream captures `iam.scope.changed`. `iam.session.revoked` (since T-13) and `iam.user.deactivated` would have failed to publish, and delivery stops at the first failure, holding back every later event, audit events included. `scope.Subjects` now lists all three; the worker refuses to start unless streams capture them all, and the installer's streams must (README, `deploy/k8s/iam.yaml`).
  - Verification:
    - DB, timed through the gateway (`TestDeactivationPropagation`): a provisioned user with access and two acknowledged sessions; SCIM deactivation as Entra ID sends it; both sessions are refused on the next request (6 ms after the SCIM call, against AC-10's 60 s) and no request reaches the service; the sessions were revoked by the deactivation itself, not at the next lookup; the scope row is gone; the audit, `iam.session.revoked` (two), revoked `iam.scope.changed` and `iam.user.deactivated` events are queued; reactivation does not revive sessions; SCIM DELETE, a Bulk deactivation and a lockout do the same; a further status change of an inactive user does nothing. `TestDeactivationEventsPublished` (JetStream): the worker delivers the announcements (7 ms) and nothing is left queued; a publisher refuses to start without a stream for one of its subjects. The session-timeout test now expects the immediate revocation.
    - Mutations (no revocation in the transaction, the scope kept, no revoked scope event, the trigger firing on any status change, a subject missing from `scope.Subjects`) each fail the tests.
