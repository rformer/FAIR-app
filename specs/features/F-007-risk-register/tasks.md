# F-007 Risk Register — Tasks
Status: **Approved** (Robert Former, 2026-11-13) | Design: Approved 2026-11-13

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites:
- F-001: `register.*`, `treatment.*`, the Risk Owner role, restricted BUs and roll-up modes.
- F-002: the audit trail.
- F-003: scenarios.
- F-005: runs and aggregates.
- F-006: result views.
- F-015: settings.

All are done.

Rules for every task:
- A task that adds a migration follows the immutability rule.
- A new event type gets its catalog entry with the task that first emits it.
- Every new route is linted by `scripts/openapi-lint.sh`.
- Every new BU-owned table gets an `rlstest` fixture.
- Every UI task runs `scripts/ui-e2e.sh`, with axe on every page it touches.

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | Settings (design §4): `settings.F007Defs()` (`register.iterations`, `register.analysis_max_age_days`), bindings, packages 1.6.0; the risk service registers them | AC-06, AC-08; §4 | Settings tests (bounds, stricter direction, iterations within the simulation bounds); release-check passes; the risk service refuses to start on an unbound key | S | Done (2026-11-13) |
| T-02 | F-005 changes (design §5.2): aggregate `purpose`; members that are aggregates (`member_aggregate_id`), recursive `analysis.members_visible`; the worker reads aggregate members' series; the Aggregates list and page show purpose `analysis` only | AC-07, AC-11; §5.2, §10 | DB tests: a nested aggregate worked from two aggregates; hidden unless every leaf is visible; purpose filters the list; F-005's aggregate tests still pass; the RLS harness passes | M | Not started |
| T-03 | Schema `register` (migration; bootstrap role `register_definer`): risks, versions (PF025), links with the one-open-risk index, treatment and its versions, roll-ups, categories with the default list; `register.check_document` (owner, scenarios in the subtree and visible, pins succeeded, of the scenario, at the register's iterations, with the set); RLS fixtures | AC-01 to AC-06, AC-15, AC-17, AC-21; §3, §5.1 | DB tests: app_rw writes only through the functions; versions append-only for every role; one open risk per scenario; every document rule refused with its pointer; RLS harness passes | L | Not started |

## Phase B — The service
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-04 | The register API for risks (`internal/register`, `internal/registerapi`, contract `api/openapi/register.yaml`, gateway segment `register`): list with filters and sort, create, read, PUT with `expected_version`, close, reopen, move, versions, diff, categories; events | AC-01 to AC-05, AC-19, AC-21, AC-22; §6, §8 | DB tests of every route (permissions, 404 and 403, refusals, versions and diffs, moves refused when a scenario would be left behind); audit events in the transaction | L | Not started |
| T-05 | Pins and exposure: pins on PUT, adopt, `register.exposure_status` (every reason), `register.newer_runs`, exposure aggregates requested when pins change (purpose `exposure`), `/coverage`; the F-003 scenario move check | AC-06 to AC-10; §3.3, §10 | DB tests with the fake engine: one- and multi-scenario exposure, every stale reason, newer runs and adoption, coverage counts, iteration count refused, the scenario move refused while linked | M | Not started |
| T-06 | Treatment: `GET/PUT /risks/{id}/treatment` (decision, rationale, targets, actions), overdue on read, expected exposure after treatment from the pinned runs' target sets (AC-16), `accept` marked for F-008; events | AC-15 to AC-18, AC-21; §3.2 | DB tests: versions, target sets checked, overdue actions, expected exposure equal to the runs' target-set results, treatment hidden without treatment.view | M | Not started |
| T-07 | Roll-ups: planning (`authz.rollup_coverage`, visible current risks, the aggregate-only totals by `register.rollup_means`, excluded counts), nesting and splitting at 200, node reuse by digest, the River job `register.rollup`, limits, staleness; `/rollups` routes; events | AC-11 to AC-14; §3.4 | DB tests with the fake engine: a three-level tree, a level split at 200, reuse, each restricted mode, staleness on a pin change and a closed risk, limits (running, rate, size) | L | Not started |

## Phase C — The pages
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-08 | Register pages (`web/src/register`): the list with filters and sorting, coverage, the new-risk form, a risk's page (scenarios, pins and adoption, exposure with the F-006 views, history and diff), close, reopen, move | AC-01 to AC-10, AC-19, AC-20; §6 | `web/e2e/register.spec.ts` with the UI harness seeding risks; axe on every page | L | Not started |
| T-09 | Treatment and roll-up pages: the treatment plan and actions, expected exposure beside the current, the roll-up page (request, progress, the curve and contributions, what was left out and why) | AC-11 to AC-18, AC-20 | `web/e2e/register.spec.ts` (treatment by keyboard, a roll-up with an aggregate-only unit); axe | M | Not started |

## Phase D — Assurance
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-10 | Benchmark gate `TestBenchmarkGateRegister`: the list of 10,000 open risks over 2,000 BUs ≤ 1 s p95; a risk's page ≤ 1 s; a roll-up of 500 risks ≤ 30 s (bench engine) | Requirements NFR; §9 | Bench gate passes in CI | M | Not started |
| T-11 | STRIDE suite for design §7 (`db/tests/stride_f007_test.go`, rows in `TestSTRIDECatalog`) | Q5; §7 | `make test-stride` covers every §7 row | M | Not started |
| T-12 | Control implementation statements `compliance/statements/F-007.yaml`, built into the component definition; the control mapping added to the requirements; Robert Former signs off | S1, Q1 | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Definition of Done
- All linked acceptance criteria have passing automated tests.
- Audit events are emitted per design §8, each in the catalog.
- The API contract is updated and linted.
- axe passes on every F-007 page.
- Security review notes are recorded (STRIDE rows and tests).

## Change Log
- 2026-11-13: Initial draft.
- 2026-11-13: **Approved** by Robert Former.
- 2026-11-13: T-01: `settings.F007Defs()` (`register.iterations`, higher is stricter, default 100,000, weakest 10,000; `register.analysis_max_age_days`, lower is stricter, default 365, weakest 730), bindings, packages 1.6.0 with 40 settings; the risk service registers F-007's definitions and refuses to start on an unbound key; `internal/register` (`Limits.Check`: the iteration count within the simulation bounds in force, the maximum age at least 30 days). Tests: `TestRegisterSettings`, `internal/register:TestLimitsCheck`; tests that pin the shipped packages follow 1.6.0, and the synthetic later release is now 1.7.0 (`posture.spec.ts` included).
