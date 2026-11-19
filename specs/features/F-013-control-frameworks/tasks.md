# F-013 Control framework library — Tasks
Status: **Approved** (Robert Former, 2026-11-18) | Design: Approved 2026-11-18

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites, all done:
- F-001: `framework.manage`, BU scoping, restricted subtrees and roll-up modes, row-level security.
- F-002: the audit trail. F-015: signed release content, settings. F-010: the CSV writer and export reasons.
- F-003: controls, versions, effects, references, scenarios and control sets. F-005: runs. F-007: the register. F-011: implementation status.
- `internal/oscal` (OSCAL 1.2.3 schema validation and types).

Rules for every task:
- A task that adds a migration follows the immutability rule.
- A new event type gets its catalog entry with the task that first emits it.
- Every new route is linted by `scripts/openapi-lint.sh`.
- Every UI task runs `scripts/ui-e2e.sh`, with axe on every page it touches.
- No test reaches the internet: shipped content is vendored at a pinned commit; tests use it and small fixtures.

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | Permission catalog version 7 (`framework.view`: not privileged; Platform Admin, Auditor, Risk Analyst); re-sign | OQ3; §10 | `TestCatalogVersion7Upgrade` | S | Done (2026-11-18) |
| T-02 | Bootstrap role `framework_definer`; schema `framework` (§5) with PF033 state rules and PF034 limits; the mapping projection under RLS (type `control`, written only by the definer) and its RLS fixture | §2, §5 | `TestFrameworkSchema`; RLS harness | M | Done |
| T-03 | `internal/framework`: OSCAL catalogs (requirements, statements flattened, withdrawn and incorporated-into), profiles resolved (§3.2), `fair.framework.v1` and `fair.crosswalk.v1` (JSON and CSV), limits, version diffs; `docs/formats/fair-framework-v1.md`, `fair-crosswalk-v1.md` and schemas | AC-01 to AC-03, AC-05, AC-10; §3.1 to §3.3 | Unit tests over small fixtures and the shipped catalog; refusals by pointer | L | Done |
| T-04 | Shipped content (`internal/framework/content`, vendored at a pinned commit, D-OQ2): 800-53r5 and its baselines, 800-171r3, FedRAMP Rev 5 baselines, the 800-171r3 to 800-53r5 crosswalk; `migrate.Release.Frameworks` and `framework.sync_shipped` at `iam migrate`; digests in the release manifest | AC-04; §2, §11 | DB test: a fresh install has them, a re-run changes nothing; release-check sees the digests | M | Not started |

## Phase B — Frameworks, mappings and crosswalks
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-05 | Imports (`POST /frameworks/imports`, dry run, River queue `framework`, whole or nothing, problems listed) and reads (frameworks, versions, requirements, diff, baselines, retire) in `internal/frameworkapi` (contract `api/openapi/framework.yaml`, gateway segment `frameworks`) | AC-01 to AC-06, AC-19; §3.1, §3.2, §6 | `TestFrameworkImports` through the API | L | Not started |
| T-06 | Control `mappings` in the document (Go and SQL, parity), `risk.check_document` against framework tables, the projection trigger, `control.mappings_changed`; suggested mappings from references and version moves | AC-07 to AC-09; §3.4 | `TestControlMappings`, `TestRiskValidationParity` | M | Not started |
| T-07 | Crosswalks: import, read, retire; derived coverage relationships | AC-10, AC-11; §3.3 | `TestCrosswalks` | M | Not started |

## Phase C — Coverage and analysis
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-08 | Coverage (`framework.coverage`: direct, derived, states, counts; restricted units by roll-up mode; `as_of`) and its CSV and JSON exports with reasons | AC-12 to AC-15, AC-20; §3.5, §3.7 | `TestFrameworkCoverage` | L | Not started |
| T-09 | Requirements to analysis: `/requirements/{id}/scenarios`, the risk API's `/scenarios/{id}/proposed?add_control=`, the register's `requirements` on a risk | AC-16 to AC-18; §3.6 | `TestRequirementScenarios` | M | Not started |

## Phase D — UI, gates and statements
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-10 | Pages `web/src/frameworks`: frameworks and versions with diffs, requirements, baselines, crosswalks, imports with dry runs, coverage with exports, a requirement's scenarios and the proposal into the scenario editor; the mapping editor (with suggestions and version moves) in the control editor; requirements on the risk page; the UI harness seeds the shipped content and mapped controls | AC-01 to AC-18 | `web/e2e/frameworks.spec.ts`; axe on every page | L | Not started |
| T-11 | Benchmark gate `TestBenchmarkGateFrameworks` (800-53r5 import ≤ 60 s; coverage of a baseline at the root over 10,000 controls and 50,000 mappings ≤ 2 s p95; a requirement's scenarios ≤ 1 s p95) | NFR | Bench gate passes | M | Not started |
| T-12 | STRIDE suite for design §7 (`db/tests/stride_f013_test.go`, rows in `TestSTRIDECatalog`) | §7 | `make test-stride` covers every §7 row | M | Not started |
| T-13 | Control implementation statements `compliance/statements/F-013.yaml`; the control mapping added to the requirements; Robert Former signs off | — | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Change Log
- 2026-11-18: Initial draft, In Review.
- 2026-11-18: Approved by Robert Former.
- 2026-11-18: T-01 done: permission catalog version 7 (`framework.view`: read, not privileged, not risk data; Platform Admin, Auditor and Risk Analyst gain it; custom roles untouched); `TestCatalogVersion7Upgrade` (`catalogVersion6` builds the previous release for the earlier upgrade tests). Needs re-signing.
- 2026-11-19: Catalog version 7 re-signed by Robert Former.
- 2026-11-19: T-02 done (migration 0161; bootstrap role `framework_definer`: re-run `scripts/db-bootstrap.sh`): schema `framework` (families, versions, requirements, baselines, crosswalks and relationships, imports: definer-only; versions, baselines and crosswalks change only their state, retired once; requirements and relationships immutable; PF033), limits checked per statement (PF034: 100 versions, 20,000 requirements a version, 200,000 relationships, 500 mappings a control version), and `framework.control_mapping` (the mapping projection: BU-owned, type control, shared down, inserted and updated only by `framework_definer`, never deleted; RLS fixture `rlsfx.control_mapping`). `TestFrameworkSchema`; RLS harness.
- 2026-11-19: T-03 done (no migration): `internal/framework`: `ParseCatalog` (OSCAL 1.2.3 through `internal/oscal`: controls and enhancements as requirements with labels, statements flattened with `[Assignment: …]` and `[Selection: …]` placeholders, parents, withdrawn and incorporated-into), `ParseProfile` (include-all, with-ids, matching, with-child-controls, exclude-controls, set-parameters recorded, alters reported as not applied, nested profiles to depth 3, nothing fetched: imports resolved by a `Lookup`), `ParseSimple` / `ParseSimpleCSV` (`fair.framework.v1`), `ParseCrosswalk` / `ParseCrosswalkCSV` (`fair.crosswalk.v1`), `Compare` (added, changed, withdrawn, renumbered); every file refused whole with problems by pointer or row. `docs/formats/fair-framework-v1.md`, `fair-crosswalk-v1.md` and their schemas (`TestSchemas`). Over the pinned NIST content (`third_party/oscal`): the 800-53 5.2.0 catalog reads whole (1,196 requirements, 182 withdrawn) in about 0.2 s, and profile resolution equals NIST's resolved catalogs, the moderate baseline included (`TestNISTCatalog`, `TestNISTProfiles`). D-OQ1: OSCAL 1.2.3 (go-oscal) defines mapping collections; they are read with crosswalks (T-07).
