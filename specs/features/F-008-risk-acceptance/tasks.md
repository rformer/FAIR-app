# F-008 Risk Acceptance Lifecycle — Tasks
Status: **Approved** (Robert Former, 2026-11-15) | Design: Approved 2026-11-15

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites, all done:
- F-001: `acceptance.*`, the Risk Owner and Approver roles, SoD, restricted BUs.
- F-002: the audit trail.
- F-007: risks, treatment, exposure status.
- F-015: settings.

Rules for every task:
- A task that adds a migration follows the immutability rule.
- A new event type gets its catalog entry with the task that first emits it.
- Every new route is linted by `scripts/openapi-lint.sh`.
- Every new BU-owned table gets an `rlstest` fixture.
- Every UI task runs `scripts/ui-e2e.sh`, with axe on every page it touches.

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | Settings (design §4): `settings.F008Defs()` (the tiers and `acceptance.max_duration_days`), bindings, packages 1.7.0; the risk service registers them; `acceptance.Limits.Check` (tier 2 above tier 1) | AC-04, AC-12; §4 | Settings tests (bounds, stricter direction, no tier without an approval); release-check passes; the risk service refuses to start on an unbound key or tiers out of order | S | Done (2026-11-15) |
| T-02 | Schema `acceptance` (migration; bootstrap role `acceptance_definer`): heads and steps (append-only, PF027), the open-acceptance indexes, the notice outbox; RLS (`acceptance`), definer access (ADR-007 amendments 3 and 5); RLS fixtures | AC-16, AC-17; §3.1, §5 | DB tests: app_rw cannot write either table; steps append-only for every role; one open acceptance per risk (a renewal beside it); RLS harness passes | M | Done (2026-11-15) |
| T-03 | Exposure reads for the job (design §3.5): `analysis.register_summary`, `analysis.pinned_summary`, `register.exposure_for` (status and mean), each granted to one definer | AC-13, AC-14; §3.5, §10 | DB tests: equal to what the risk's owner reads; closed to the application role and every other definer | S | Done (2026-11-15) |

## Phase B — The service
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-04 | Requests and decisions (definer functions): `acceptance.request` (checks, the tier placed and resolved, the evidence copied), `decide` (authority at the tier's BU, SoD, one decision each, the shortest expiry, activation), `withdraw`, `revoke`; renewal replacing without a gap; closing a risk ends its acceptance; events | AC-01 to AC-07, AC-11, AC-15, AC-18; §3.2, §3.4 | DB tests: every refusal with its reason; tiers 1 to 3 with their levels and approvals; two approvals by two people; SoD; renewal without a gap; a closed risk; the events | L | Done (2026-11-15) |
| T-05 | The acceptance API (`internal/acceptanceapi`, contract `api/openapi/acceptance.yaml`, gateway segment `acceptances`): list with filters, request, read (history, evidence, needs-review reasons, who may decide), decisions, withdraw, revoke, inbox, tiers; the register API's `acceptance` summary and filter | AC-01 to AC-08, AC-14, AC-16, AC-19; §3.3, §6 | DB tests through the API: who may (404 / 403), every error, the inbox only what the caller may decide, needs review (stale, treatment, moved), the register's filter | M | Done (2026-11-15) |
| T-06 | The job (`acceptance.sweep`, run by the risk service's leader every minute): expiry, higher-tier suspension and its review, notices (30, 14, 7 days, on expiry), once each; reads of a past expiry as expired | AC-09, AC-10, AC-13; §3.2, §3.6 | DB tests with time travel: expiry, notices once each, a higher tier suspends and reopens review, approval reactivates, a lower tier and a stale exposure do not suspend; the job catches up after an outage | M | Done (2026-11-15) |

## Phase C — The pages
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-07 | Pages (`web/src/acceptance`): the list with filters, the approver's inbox, an acceptance's page (state, needs review, evidence, history, the decision form), the request and renewal forms; the risk page's Acceptance section and the register's acceptance filter | AC-01 to AC-19, AC-20 | `web/e2e/acceptance.spec.ts` with the UI harness seeding acceptances (a request, a two-approval tier, a renewal); axe on every page | L | Done (2026-11-15) |

## Phase D — Assurance
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-08 | Benchmark gate `TestBenchmarkGateAcceptances`: the list and the inbox with 10,000 acceptances over 2,000 BUs ≤ 1 s p95; an acceptance's page ≤ 1 s; the sweep over them | Requirements NFR; §9 | Bench gate passes | M | Done (2026-11-15) |
| T-09 | STRIDE suite for design §7 (`db/tests/stride_f008_test.go`, rows in `TestSTRIDECatalog`) | §7 | `make test-stride` covers every §7 row | M | Done (2026-11-15) |
| T-10 | Control implementation statements `compliance/statements/F-008.yaml`, built into the component definition; the control mapping added to the requirements; Robert Former signs off | — | `internal/compliance` checks pass; sign-off recorded | S | Done (2026-11-16) |

## Definition of Done
- All linked acceptance criteria have passing automated tests.
- Audit events are emitted per design §8, each in the catalog.
- The API contract is updated and linted.
- axe passes on every F-008 page.
- Security review notes are recorded (STRIDE rows and tests).

## Change Log
- 2026-11-15: Initial draft.
- 2026-11-15: **Approved** by Robert Former.
- 2026-11-15: T-01: `settings.F008Defs()` (`acceptance.tier1_max` 100,000 and `tier2_max` 1,000,000, lower is stricter, weakest 10,000,000 and 100,000,000; `tier1_levels_up` 0 and `tier2_levels_up` 1, higher is stricter; `tier1_approvals` 1, `tier2_approvals` 1, `tier3_approvals` 2, higher is stricter, weakest 1, so no profile makes a tier need no approval; `max_duration_days` 365, weakest 730), bindings, packages 1.7.0 with 48 settings (tests use a synthetic 1.8.0 for later releases); the risk service registers F-008's definitions and refuses to start on an unbound key or tiers it cannot work with; `internal/acceptance` (`Limits.Check`: tier 2 above tier 1, levels 0 to 10, 1 or 2 approvals, at least 30 days; `Place`; `LimitsFrom`). Tests: `TestAcceptanceSettings`, `internal/acceptance` `TestLimitsCheck`, `TestPlace`, `TestLimitsFrom` (the shipped profiles pass the check).
- 2026-11-15: T-02: migration 0115 (schema `acceptance`; bootstrap role `acceptance_definer`, re-run `scripts/db-bootstrap.sh`): `acceptance.acceptance` (heads: state and end reason, tier, the tier's BU, approvals needed, mean, expiry; indexes `acceptance_open`, one active, suspended or non-renewal pending acceptance per risk, and `acceptance_renewal`, one pending renewal per risk), `acceptance.step` (append-only for every role, PF027; only the definer moves a step's `bu_id`), `acceptance.notice_outbox`; RLS type `acceptance` with `acceptance_definer` reading, updating and inserting every row (ADR-007 amendments 3 and 5); app_rw reads only. Tests: `TestAcceptanceSchema`, RLS fixtures in `db/tests/rls_fixtures_acceptance_test.go` (`rlsfx.acceptance`), `TestRoleAttributes` and `TestOwnerRolesCannotLogIn` (acceptance_definer).
- 2026-11-15: T-03: migration 0116: `analysis.register_summary` and `analysis.pinned_summary` (analysis_definer, granted to register_definer only) and `register.exposure_for` (register_definer, granted to acceptance_definer only: status, mean, 90th percentile, BU, state, owner of a risk, with no caller's scope). Tests: `TestAcceptanceExposureReads` (equal to what the risk's owner reads for one- and two-scenario risks, computing and unquantified; closed to app_rw and the other definers).
- 2026-11-15: T-04: migration 0117: `acceptance.request`, `decide`, `withdraw`, `revoke` (acceptance_definer; the caller from the signed context; refusals PF027 with the reason as hint, 42501 `forbidden`, `not_your_tier`, `separation_of_duties`, P0002 for unseen ids), `acceptance.place` and `tier_bu` (the tier and its BU from the settings in force), `add_step`, `emit`; the requested step copies the evidence (justification, conditions, expiry, risk version, exposure, pins, tier and its settings); a trigger on `register.risk` ends a closed risk's open acceptances and moves a moved risk's (pending and suspended ones' tier BU resolved from the new BU); catalog entries `acceptance.requested`, `approved`, `rejected`, `activated`, `reactivated`, `replaced`, `withdrawn`, `revoked`, `ended` (`acceptance.emit` scanned by `TestCatalogMatchesCode`). Tests: `TestAcceptanceLifecycle`. Design change log: three clarifications.
- 2026-11-15: T-05: `internal/acceptanceapi` (contract `api/openapi/acceptance.yaml`, gateway segment `acceptances`, mounted by `cmd/risk` with the settings in force): the list (state as read, needs review, BU with its subtree, risk, expiring within), request and renewal, one acceptance (history, evidence, may decide, withdraw, revoke, renew), decisions, withdraw, revoke, the inbox (`BUsWith(acceptance.approve)`, neither requester nor owner, undecided this round), the tiers; migration 0118 (`acceptance.subtree`; a moved risk's active acceptance too has its tier's BU resolved from the new BU); the register API's `acceptance` summary per risk and `?acceptance=` filter; `internal/register/sql.go` (`LinkStats`, `StatusSQL`) shared by both APIs. Tests: `TestAcceptanceAPI`, `internal/acceptanceapi` `TestOpenAPIMatchesRoutes`. Design change log: three clarifications.
- 2026-11-15: T-06: migration 0119 (`acceptance.sweep()` for app_rw, `acceptance.notify`; `notice_outbox.tier` in the once-only key), `internal/acceptance.Job` (`Sweep`, `Run`) run by the risk service's leader beside the estimate jobs; events `acceptance.expired`, `suspended`, `review_requested` (actor `system:risk`). Test: `TestAcceptanceSweep`. Design change log: two clarifications.
- 2026-11-15: T-07: pages `web/src/acceptance` (`/acceptances` with filters, `/acceptances/inbox`, `/acceptances/{id}` with terms, needs review, evidence, history and the decision form, withdraw, revoke and renew; `/acceptances/new?risk=[&renews=]`), the risk page's Acceptance section (`RiskAcceptance.tsx`) and the register's Acceptance column and filter; migration 0120 (`acceptance.people`: names of requesters and actors on acceptances the caller sees), `names` and `requested_by_name` in the API, `GET /api/v1/acceptances/permissions?bu=`. The UI harness mounts the acceptance API and seeds acceptances inside the restricted R at its new child R1 (`seedAcceptances`: investigator requests; approver, approver2 at R; tier 2 needs two approvals there), so the register pages' counts stay as they were; `web/e2e/acceptance.spec.ts` (5 tests, axe on every page). Design change log: one clarification.
- 2026-11-15: T-08: `TestBenchmarkGateAcceptances` (`db/tests/acceptance_bench_test.go`, over the register gate's data, `seedRegisterBench`; `FAIR_BENCH_ACCEPTANCES` for a smaller hand run; CI bench timeout 150m). Migration 0122 makes the sweep set-based (`register.exposures`, the set form of `register.exposure_for`, parity in `TestAcceptanceExposureReads`; `acceptance.notify_users`) and bounded (`acceptance.sweep_batch()`, 500 per sweep, `more` and `Job.Run` sweeping again at once). Design change log: two clarifications.
- 2026-11-15: T-09: F-008's STRIDE rows in `TestSTRIDECatalog` (`strideF008`; `db/tests/stride_f008_test.go`: Authority, SeparationOfDuties, HistoryTamper, Visibility, Attribution, Limits); `make test-stride` runs `TestAcceptance*`. Design §7 gains the restricted-tier row and names the tests that exist (it named three that did not).
- 2026-11-16: T-10: `compliance/statements/F-008.yaml` (9 controls; `TestF008Statements`, and F-008 in `TestComponentDefinitionAllFeatures`), signed off by Robert Former 2026-11-16. F-008 is complete.
