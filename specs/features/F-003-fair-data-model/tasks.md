# F-003 FAIR Data Model — Tasks
Status: **Draft** | Design: Approved 2026-11-06

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites: F-001 (BU hierarchy, RBAC, RLS, the risk-data permission keys) and F-002 (audit trail, secrets refusal). Both are done.
Every task that adds a migration follows the immutability rule. Every new event type gets a catalog entry. Every new route is linted by `scripts/openapi-lint.sh`. Every new BU-owned table gets an `rlstest` fixture.

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | ADR-007 amendment 2 (migration): `authz.inherited_bus(type)`, the `shared_down` option of `authz.apply_bu_rls` (adds the inherited term to the `SELECT` policy only), `iam.restricted_root(bu)`. RLS harness: shared-down fixtures and cases | AC-08, AC-18; design §4.4, §11 | DB tests: a child BU reads its ancestors' rows and cannot write them; siblings, a restricted BU's rows from outside, and a restricted BU's view of its ancestors are refused; no context admits nothing; both scope forms covered | M | Not started |
| T-02 | `internal/risk/canon`: the RFC 8785 subset we emit (sorted keys, no whitespace, decimal-string numbers), SHA-256 digests. `internal/risk/model`: JSON Schemas per kind (§3.3) and the Go validator for §3: taxonomy levels and the exact required-estimate set, estimate rules and units, forms of loss, Vulnerability direct or derived, control sets, text limits, `audit.LooksSecret` | AC-02 to AC-06, AC-12, AC-13, AC-23, AC-29; §3 | Unit tests per rule with every failure reported by JSON pointer; RFC 8785 vectors for the subset; property tests: canonicalisation is idempotent and the digest changes with any value | M | Not started |
| T-03 | Schema `risk` (migration): tables of §4.1 with `apply_bu_rls` (library and control `shared_down`), triggers of §4.2 (append-only, numbering, `risk.check_document`, pins filled and visibility-checked), `risk.instance`, bootstrap role `risk_definer` and `risk.pinned_versions` (definer). `TestRiskValidationParity` against T-02 | AC-05, AC-06, AC-15, AC-18, AC-23; §4 | DB tests: update and delete of versions refused (owner included), stale version numbers refused, every T-02 invalid case refused by the trigger too (parity corpus), pins to unseen entries refused, RLS harness fixtures pass | L | Not started |
| T-04 | `risk` service scaffold: `cmd/risk`, `internal/risk` config, health, OTel, image target, `deploy/k8s/risk.yaml`, key `risk/jwt` (`keys.Mounts`, `iam keys init|rotate|check|upgrade`), `CheckInstall`, gateway segments `scenarios`, `library`, `controls`, `risk`. `risk currency set|show` (audited `risk.currency_set`; refused once a magnitude is stored); catalog entries for design §9 | AC-07, AC-21; §2, §3.4, §7, §9 | Service boots; gateway routes to it; currency set, shown, and refused after data exists; `TestDeploymentModeMatrix` covers the service; catalog tests pass | M | Not started |

## Phase B — Scenarios, library and controls
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-05 | Scenarios API (contract `api/openapi/risk.yaml`): list (`NewestQuery`, filters), create, get (with the taxonomy view), save a version with `expected_version` and change note, versions; every change audited in its transaction | AC-01 to AC-06, AC-15, AC-21, AC-26, AC-28, AC-29; §5, §6.1 | API tests per AC: 422 lists every failure; a stale save is refused; author from the DB context; one audit event per change, absent when the change rolls back | M | Not started |
| T-06 | Library and controls API: the four library kinds (asset groups with members and valuation), controls with effects and external references; list marks inherited entries | AC-08, AC-12, AC-14, AC-26; §3.3, §3.5, §5 | API tests: create, edit, version; a child BU lists its ancestors' entries as inherited and cannot edit them; asset group members must be visible assets | M | Not started |
| T-07 | Pins, newer-version flags, `adopt`, structural diff of two versions (scenarios, library entries, controls) | AC-09, AC-10, AC-17; §6.2, §6.3 | Tests: a new library version leaves the scenario unchanged and flags it; adopt saves a new scenario version with the new pins; diff vectors (added, removed, changed, pin changes) | M | Not started |
| T-08 | Input bundles: `/versions/{v}/bundle` with the pinned versions through `risk.pinned_versions`, currency, canonical form and digest | AC-16, AC-20; §1, §4.4 | Tests: the same inputs give the same digest; any change to the scenario or a pinned version changes it; a scenario reader without `library.view` gets the pinned versions and nothing else | S | Not started |
| T-09 | Move, archive and restore: move between BUs (both permissions, reason, refused out of a restricted subtree), visibility flags after a move, archive and restore with reasons; archived heads refuse new versions; archive guard registration | AC-19, AC-20, AC-22; §6.4, §6.7 | DB and API tests: versions and pins follow the head; digests unchanged; restricted move refused; flags appear when a pin is no longer visible from the BU; F-001's archive guard counts active scenarios only | M | Not started |
| T-10 | Starter library: content in `internal/risk/starter/` (generic threat communities, guidance per form of loss, illustrative values marked), sync at `iam migrate`, list and copy. Robert reviews the text | AC-11; §6.6 | Sync is idempotent; starter entries cannot be edited; a copy is an ordinary editable entry with its origin; no unmarked number in the content (test) | M | Not started |
| T-11 | Export and import `fair.risk.v1`: format documentation and JSON Schema, export of a selection or subtree with pinned versions, import with dry run, re-mapped ids, pins by id and digest, currency check, all or nothing | AC-24, AC-25; §6.5 | Round-trip test; export contains only what the requester sees; a dry run lists every failure and changes nothing; one bad item rolls back the whole import; a currency mismatch is refused | M | Not started |

## Phase C — User interface
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-12 | Scenario pages in `web/src/risk`: list, editor (levels per branch, estimates with rationale and sources, control sets), taxonomy view, versions and diff, newer-version prompts and adopt | AC-27, AC-28, AC-17, AC-10; §5 | Playwright and axe (WCAG 2.1 AA) in `scripts/ui-e2e.sh` against the real API | L | Not started |
| T-13 | Library and control pages, starter library and copy, move, archive and restore, export and import with dry run | AC-27, AC-11, AC-19, AC-22, AC-24, AC-25 | Playwright and axe in `scripts/ui-e2e.sh` | M | Not started |

## Phase D — Assurance
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-14 | Benchmark gate `TestBenchmarkGateRiskScenarios`: 10,000 scenarios in a subtree, list ≤ 500 ms p95, load with pins ≤ 300 ms p95; inherited read cost included | Requirements NFR; §10 | Bench gate passes in CI | S | Not started |
| T-15 | STRIDE suite for design §8 (`db/tests/stride_f003_test.go`, rows in `TestSTRIDECatalog`) | Q5; §8 | `make test-stride` covers every §8 row | M | Not started |
| T-16 | Control implementation statements `compliance/statements/F-003.yaml` (AC-3, AC-6, AU-2, AU-12, CM-3, RA-3, RA-7, SI-10), built into the OSCAL component definition; Robert Former signs off | S1, Q1 | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Definition of Done
- All linked acceptance criteria have passing automated tests.
- Audit events emitted per design §9, each in the catalog.
- API contract updated and linted.
- Security review notes recorded (STRIDE rows and tests).

## Change Log
- 2026-11-06: Initial draft.
