# F-011 Integrations and automation inputs — Tasks
Status: **Approved** (Robert Former, 2026-11-17) | Design: Approved 2026-11-17

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites, all done:
- F-001: `integration.manage`, service accounts and their tokens (mTLS), BU scoping, restricted subtrees, keys, the gateway.
- F-002: the audit trail. F-015: settings, the `set` type with dual approval, deployment modes.
- F-003: library entries, controls, versions, pins, newer-version flags, `DiffDocuments`, archive. F-004: reference classes. F-007: the register. F-009: notices, the destination guard.

Rules for every task:
- A task that adds a migration follows the immutability rule.
- A new event type gets its catalog entry with the task that first emits it.
- Every new route is linted by `scripts/openapi-lint.sh`.
- Every UI task runs `scripts/ui-e2e.sh`, with axe on every page it touches.
- No test reaches the internet: connector tests use local test servers and recorded fixtures, with destinations in TEST-NET (the guard refuses loopback).

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | Permission catalog version 6 (`integration.view` for Platform Admin and Auditor; `integration.push`, not privileged, no built-in role); re-sign | OQ5, D-OQ1; §10 | `TestCatalogVersion6Upgrade` | S | Done (2026-11-17) |
| T-02 | `settings.F011Defs()` (`integration.allowed_hosts` set with dual approval on additions, `integration.records_retention_days`), bindings, packages 1.10.0; the risk and integrate services register them | AC-04; §4 | `TestIntegrationSettings` | S | Done (2026-11-17) |
| T-03 | Bootstrap roles `integration_definer`, `app_integrate`; schema `integration` (§5) with PF031, PF032; `integration.loss_event` under RLS (type `library`, `shared_down`, definer insert and update) with its fixture; `integration.notice_outbox` | AC-02, AC-19; §5 | DB tests: access by role, state rules; `TestRLSHarnessEveryBUOwnedTable` | M | Not started |
| T-04 | `internal/egress`: F-009's guard moved out of `internal/notify` (notify unchanged in behaviour) | AC-04; §3.1 | `internal/egress` and `internal/notify` tests pass unchanged | S | Not started |
| T-05 | The control document's `implementation` (§3.7) in `model.Validate` and `risk.check_document`, the parity corpus and the JSON schema | AC-23; §3.7 | `TestRiskValidationParity`; model unit tests | S | Not started |

## Phase B — Receiving records
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-06 | `internal/integration`: `fair.integration.v1` (`docs/formats/fair-integration-v1.md` and schema), the five record kinds' typed validation, CSV with column mappings and value maps, refusals by position and pointer | AC-06, AC-15 to AC-17, AC-23; §3.2 | Unit tests and golden files | M | Not started |
| T-07 | Integrations in the database: `integration.create` / `change` / `pause` / `resume` / `delete` / `list` / `get` (BU subtree, restricted rule, limits), sealed secrets (`integration.secret`), events | AC-01 to AC-03, AC-05; §3.1, §5 | DB tests through functions: scope, restricted subtrees, secrets never readable but by `app_integrate` | M | Not started |
| T-08 | Batches in the risk service (`internal/importapi`, `api/openapi/import.yaml`, gateway segment `imports`): `POST /imports/{integration}/batches` (JSON or CSV, dry run, limits), staging, matching by external ID, runs and their counts; `GET /imports/runs/{id}` | AC-06 to AC-09; §3.2, §6.2 | DB tests: refusals keep valid records, dry runs write nothing, a failed run stages nothing, limits | L | Not started |
| T-09 | Proposals: computation per kind (merge with the current version, completion of new records, digests against current and rejected), supersession, complete batches proposing archives with the records' users | AC-10, AC-12, AC-14; §3.4 | DB tests per kind | M | Not started |

## Phase C — Review and inputs
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-10 | Review (`/proposals`: list by view scope, get with diff, accept with expected_version through the existing save code, batch accept, reject with reason), provenance (`integration.applied`, `provenance` on version reads), `auto_accept` for descriptive-only proposals; `integration.proposals_waiting` notices (F-009 source `integration`) | AC-10 to AC-13, AC-25, AC-26; §3.4, §3.8 | DB tests: RLS and permissions on accept, pins unchanged with newer flags, stale accepts refused, events | L | Not started |
| T-11 | Assets and asset groups end to end (members by external ID, pinned on accept) | AC-15, AC-16; §3.5 | DB tests through the API | S | Not started |
| T-12 | Loss events (direct upsert, archive on complete batches, `/loss-events` under RLS) and derivations (`/library/{id}/derivation`, computed counts and losses, proposals on change, one restricted root) | AC-17 to AC-19; §3.5 | DB tests: visibility per viewer, restricted roots, proposals only on change | M | Not started |
| T-13 | Control status end to end: proposals of `implementation`; `control.lapsed` notices to scenario owners; `control_lapsed` on scenario and risk reads | AC-23, AC-24; §3.7 | DB tests: only lapses notify, only `in_place` uses in current sets, nothing changed automatically | M | Not started |
| T-14 | The register import (`/register/imports`: CSV mapping or `fair.register-import.v1`, owners by email, categories by name, ratings refused or kept as text, dry run with a fingerprint, all or nothing, repeat imports as proposals; the per-BU file integration) | AC-20 to AC-22; §3.6 | DB tests through the register API | M | Not started |

## Phase D — The integrate service and connectors
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-15 | `cmd/integrate` (image target `integrate`, `deploy/k8s/integrate.yaml` with its NetworkPolicy), DB role `app_integrate`, keys `integrate/jwt` and `integrate/secrets` (`iam keys upgrade`, `rotate -kind integrate-secrets`), `CheckInstall` per mode, leader election, gateway segment `integrations` | §1, §2, §11 | `TestDeploymentModeMatrix` rows; install checks; manifest tests | M | Not started |
| T-16 | The integrations API (`internal/integrateapi`, `api/openapi/integrate.yaml`): CRUD, credentials write-only, pause, resume, delete, run now, test, runs | AC-01 to AC-05, AC-08; §6.1 | DB tests through the API; the allow-list checked on save | M | Not started |
| T-17 | The connector runner: claims, back-off, the service account's token, fetch through `egress.Guard` (paging re-checked, bounded pages and time), submission as a complete batch; `integration.run_failed` after three failures; connectors `http_json` and `servicenow_cmdb` (recorded fixture) | AC-04, AC-08, AC-14; §3.3, OQ2 | Tests against local HTTPS test servers in TEST-NET; refused destinations recorded; the ServiceNow fixture | L | Not started |

## Phase E — Pages and gates
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-18 | Pages `web/src/integrations`: integrations and their runs, the review queue with diffs and batch accept, loss events and derivations, the register import with its dry run, provenance on version history, `control_lapsed` warnings on scenarios and risks; the UI harness seeds an integration with runs and proposals | AC-01 to AC-25 | `web/e2e/integrations.spec.ts`; axe on every page | L | Not started |
| T-19 | Benchmark gate `TestBenchmarkGateImports` (a batch of 10,000 records validated and matched ≤ 60 s; a run's proposals open ≤ 1 s p95; 1,000 accepted ≤ 30 s) | NFR | Bench gate passes | M | Not started |
| T-20 | STRIDE suite for design §7 (`db/tests/stride_f011_test.go` and unit tests, rows in `TestSTRIDECatalog`) | §7 | `make test-stride` covers every §7 row | M | Not started |
| T-21 | Control implementation statements `compliance/statements/F-011.yaml`; the control mapping added to the requirements; Robert Former signs off | — | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Change Log
- 2026-11-17: Initial draft, In Review.
- 2026-11-17: Approved by Robert Former.
- 2026-11-17: T-01: catalog version 6: `integration.view` (read, not risk data; Platform Admin, Auditor) and `integration.push` (write, risk data, not privileged; no built-in role, so a service account may hold it as a scope while `integration.manage` stays refused); `TestCatalogVersion6Upgrade`; the catalog awaits re-signing.
- 2026-11-17: T-01: catalog version 6 re-signed by Robert Former.
- 2026-11-17: T-02: `settings.F011Defs()` (`integration.allowed_hosts`: set, subset is stricter, every added host needs dual approval; `integration.records_retention_days`: 30, bound 365), bindings, packages 1.10.0 with 59 settings (tests use a synthetic 1.11.0 for a later release); the risk service registers them (the integrate service will too, T-15). `TestIntegrationSettings`.
