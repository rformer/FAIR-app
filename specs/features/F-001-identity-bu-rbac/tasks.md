# F-001 Identity, BU Hierarchy & RBAC — Tasks
Status: **Approved** (Robert Former, 2026-10-24) | Design: Approved 2026-10-24

**Sizing:** S ≤ 1 day · M = 2–3 days · L = up to 1 week (split further when picked up).

**Cross-feature stubs:** F-002 (audit), F-012 (CI/images) and F-015 (profiles) don't exist yet. F-001 codes against their interfaces using minimal stubs, tracked as T-00a/b/c. Each stub is replaced when its feature lands (T-00b is replaced by F-015 T-16).

**Cross-feature change:** step-up re-authentication for restricted BUs (`ErrStepUpRequired`, session `auth_time`) is implemented in F-001 code but tracked as **F-015 T-24**.

## Phase 0 — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-00a | Audit event emitter interface + NATS/OTLP/syslog stub sink | AC-50 | Contract tests; events visible in collector | S | Done (Phase 0 zip, 2026-10-24) |
| T-00b | Minimal settings module with the three profiles for F-001 keys, behind the `settings.Set` interface | AC-31, AC-32, §5.8, §8 | Unit tests for apply / warn / dual-approval paths | M | Done (Phase 0 zip, 2026-10-24) |
| T-00c | Minimal CI for `iam` + `authz`: FIPS-mode build, lint, unit tests, SBOM, image signing | Constitution S2, S5 | CI green; image runs non-root with a read-only root filesystem | M | Done (Phase 0 zip, 2026-10-24) |
| T-01 | Scaffold the `iam` service and `authz` library (module layout, config, health checks, OTel) | Design §2 | Service boots in kind/k3d | S | Done (Phase 0 zip, 2026-10-24) |
| T-02 | DB roles and migration framework (`app_migrator`, `app_rw` NOBYPASSRLS, `app_engine`, non-login owner) | AC-27 | Test proves `app_rw` cannot bypass RLS, read `authz.ctx_key`, or alter tables | S | Done (Phase 0 zip, 2026-10-24) |

## Phase 1 — Authorization core (gates other features)
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-02b | Embedded Go migration runner (`iam migrate`) replacing `scripts/db-migrate.sh` with the same semantics (app_migrator under `SET ROLE fair_owner`, SHA-256 checksums, refuse modified migrations); advisory lock against concurrent runs; verified TLS in production; applies the release catalog via `iam.sync_release` | AC-27, AC-57 | Idempotency, tamper, rollback, bad-name and concurrent-runner tests; fresh install has the catalog and built-in roles | S | Done (2026-10-26) |
| T-03 | Permission catalog file format, loader and versioning | AC-51, AC-57 | Catalog diff test across two versions | S | Done (2026-10-25; `risk_data` added 2026-10-25 with catalog v1 approval) |
| T-04 | BU schema + closure table + triggers (single root, depth, no cycles) | AC-15, AC-16 | Trigger tests; property tests on random trees | M | Done (2026-10-25) |
| T-05 | BU move / restrict / unrestrict with closure rebuild and `blocked` flag, synchronous in the same transaction (design §12 R1) | AC-17 (closure recalculation), AC-59, AC-60 | Property tests: no inheritance across restricted nodes | M | Done (2026-10-25) |
| T-06 | Roles + `role_version` + built-in role seeds | AC-52, AC-55 | Built-in roles are immutable; versions increment | S | Done (2026-10-25) |
| T-07 | Assignments with grantor checks and DB-level block on self-assignment | AC-20, AC-21, AC-22, AC-28 | Escalation test suite (BU Admin → admin role, cross-restricted, self-grant) | M | Done (2026-10-26) |
| T-08 | Scope materialization worker, outbox and nightly reconciliation; BU move writes an outbox row with old and new parent in the move's transaction | AC-17 (move audit), AC-21, AC-60, NFR 60 s | Change → scope visible ≤ 60 s p99 at target scale; drift alert test; a move cannot commit without its outbox row | M | Todo |
| T-09 | Signed DB context: key table, rotation, `authz.visible_bus`, `authz.apply_bu_rls` | AC-24, AC-25, AC-27, ADR-007 | Integration tests on a sample BU-owned table | M | Todo |
| T-10 | RLS negative test harness: forged / expired / stale / missing context → empty; SQL-injection simulation | AC-24, AC-25 | Harness becomes a reusable CI suite for every feature | M | Todo |
| T-11 | **Benchmark gate:** `visible_bus` + RLS at 10k users / 2k BUs / 50k assignments; BU closure rebuild (`db/bench/bu_rebuild.sql`) | NFR p95 ≤ 10 ms, D-OQ3, R1 | Benchmark report committed; fails CI on regression | S | Todo |
| T-12 | `authz` library: `Check()`, grant snapshot cache, invalidation on `iam.scope.changed`, DB-context transaction helper | AC-24, NFR | Unit + integration tests; cache invalidation ≤ 60 s | M | Todo |

## Phase 2 — Authentication & sessions
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-13 | Gateway sessions: `__Host-` cookie, HMAC storage, idle/absolute timeouts, revocation, CSRF | AC-31, AC-33, AC-35 | Timeout and revocation tests; CSRF negative tests | M | Todo |
| T-14 | Internal JWT minting/verification (ES256) behind a KMS / Vault / local key-provider interface | Design §4 | Tests with each provider; tampered and expired tokens rejected | S | Todo |
| T-15 | SAML SP: library selection memo (D-OQ1), SP- and IdP-initiated flows, replay cache, XSW negative corpus | AC-01, AC-04 | Selection ADR; corpus passes; interop with Entra/Okta/Ping | L | Todo |
| T-16 | OIDC RP: code + PKCE, nonce/state, JWKS validation | AC-01, AC-04 | Conformance tests against test IdPs | M | Todo |
| T-17 | Home-realm discovery, multiple IdPs, metadata/JWKS file upload | AC-02, AC-03 | Routing tests; air-gapped metadata test | S | Todo |
| T-18 | MFA evidence rules (SAML AuthnContext, OIDC amr/acr) | AC-05 | Non-MFA assertion denied and audited | S | Todo |
| T-19 | System-use banner with acknowledgment, on by default | AC-34 | E2E test: no access before acknowledgment | S | Todo |
| T-20 | Session network binding (`off`/`flag`/`reauthenticate`), trusted proxy header, prefix + ASN, air-gap fallback | §5.8 | Tests per mode and per profile default; spoofed-header test | M | Todo |

## Phase 3 — Provisioning
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-21 | SCIM 2.0 Users/Groups: filter, PATCH, Bulk (size caps), discovery endpoints; SCIM-only tokens | AC-07, AC-08 | Unit + RFC 7644 compliance tests | L | Todo |
| T-22 | Deactivation propagation (sessions revoked ≤ 60 s) | AC-10 | Timed E2E test | S | Todo |
| T-23 | JIT provisioning (off by default, no roles) + inactivity sweep | AC-09, AC-11 | Default-off test; sweep test | S | Todo |
| T-24 | Group-to-role mappings with recompute on membership change | AC-12, AC-13, AC-14 | Add/remove membership → assignment change ≤ 60 s | M | Todo |
| T-25 | SCIM interop runs against Entra ID, Okta and Ping | AC-07 | Recorded conformance results per IdP | M | Todo |

## Phase 4 — Governance & administration
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-26 | Generic dual-approval engine (requester ≠ approver, expiry, audit) | AC-30, AC-41, AC-53, AC-63 | Self-approval impossible (DB check + API); expiry test | M | Todo |
| T-27 | SoD rules and time-boxed exceptions | AC-29, AC-53 | Conflicting role blocked; exception expires | S | Todo |
| T-28 | Custom roles: create, clone, edit, diff, affected-user count, privileged flags, retire guard | AC-51 – AC-56 | Functional tests + audit assertions | M | Todo |
| T-29 | Catalog upgrade handling (deny by default, admin notice) + role JSON export/import | AC-57, AC-58 | Upgrade simulation; round-trip import test | S | Todo |
| T-30 | Restricted BU admin: toggle, new-BU default ON, roll-up modes, roll-up definer functions, loosening via dual approval | AC-26, AC-59 – AC-64 | Leakage tests for every roll-up mode; restricting takes effect immediately | M | Todo |
| T-31 | BU import/export; archive guard via `bu_owned_tables` registry | AC-18, AC-19 | Round-trip test; archive blocked with active records | S | Todo |
| T-32 | Assignment expiry sweep | AC-23 | Expired assignment removed; scope updated | S | Todo |
| T-33 | Service accounts + tokens (shown once, HMAC-stored, max lifetime) + client credentials + mTLS | AC-36, AC-37, AC-38 | Token never retrievable after creation; expiry enforced | M | Todo |
| T-34 | Break-glass: disabled default, install-time opt-in hook, post-install dual-approved enablement, WebAuthn-only, lockout, alerts, immediate disable | AC-39 – AC-45, AC-47 | Route 404 when disabled; risk-data permission add refused; alerts fire | M | Todo |
| T-35 | IdP-outage recovery runbook (SaaS + self-hosted) | AC-46 | Runbook dry-run recorded | S | Todo |
| T-36 | Bundled Keycloak realm config (phishing-resistant MFA for privileged roles, TOTP off) | AC-06 | Realm export test; policy verified | S | Todo |

## Phase 5 — Evidence & reporting
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-37 | Full security event catalog wired to the emitter (incl. privileged-permission and break-glass events) | AC-43, AC-50, AC-54 | Every mutation emits its event; schema test | M | Todo |
| T-38 | Entitlement report (CSV/PDF), restricted-BU access listing | AC-48, AC-64 | Report matches DB state; scope-respecting for Auditors | M | Todo |
| T-39 | Access review campaigns (certify/revoke, audited) | AC-49 | Revoke decision removes access ≤ 60 s | M | Todo |

## Phase 6 — Hardening & release readiness
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-40 | Security test suite from the STRIDE model (XSW, CSRF, enumeration, escalation, roll-up leakage, header spoofing) | Design §7 | Suite in CI; external pen test findings tracked | L | Todo |
| T-41 | Deployment-mode matrix: SaaS KMS, Vault/OpenBao, air-gapped metadata + keys | Deployment modes | CI matrix green | M | Todo |
| T-42 | OpenAPI spec published; API conventions (404 scoping, Idempotency-Key, reason) lint-enforced | Design §6 | Spectral lint in CI | S | Todo |
| T-43 | 800-53r5 control implementation statements for F-001 (feeds OSCAL component definition) | Control mapping | Statements reviewed | S | Todo |

## Definition of Done (F-001)
- All 64 acceptance criteria have passing automated tests
- T-11 benchmark meets NFRs
- Security event catalog complete and verified
- OpenAPI published
- Threat-model suite green; pen-test highs closed
- Control implementation statements written
