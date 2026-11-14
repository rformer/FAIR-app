# F-007 Risk Register — Design
Status: Approved | Owner: Robert Former | Last updated: 2026-11-13
Requirements: `requirements.md` (Approved 2026-11-13) · ADR-003, ADR-007

## 1. Overview
- **The register lives in the risk service.** New schema `register`, packages `internal/register` and `internal/registerapi` (contract `api/openapi/register.yaml`, gateway segment `register`). It sits beside scenarios and analyses: same database, same signed context, same audit path.
- **Risks are versioned documents.** A risk is a head and append-only versions. Its treatment is a separate versioned record under the resource type `treatment`, so row-level security, not the service, keeps it from people without `treatment.view`. Every change is a version (AC-03); a projection table of current scenario links enforces "one open risk per scenario" with a unique index (AC-02).
- **Exposure is read, not copied.** A one-scenario risk's exposure is its pinned run's stored result. A multi-scenario risk's exposure is an F-005 aggregate of its pinned results, requested when its pins change. Staleness is computed when read, from the pins, the scenarios and the setting (AC-08), so it is never out of date itself.
- **One iteration count for the register (decided 2026-11-13).** Pins must have `register.iterations` iterations (default 100,000), so every exposure and roll-up aggregates (F-005 aggregates need equal counts). Pinning a run with another count is refused with a hint to run one at the register's count.
- **Roll-ups nest by business unit (decided 2026-11-13).** A business unit's roll-up aggregates its own risks' exposures and its children's roll-ups. Each level stays within F-005's 200 members and the engine's memory; levels are reused while their members are unchanged. Restricted subtrees contribute by F-001's roll-up mode (§3.4).

## 2. Components
| Component | Change |
|---|---|
| `db/migrations` | Schema `register` (bootstrap role `register_definer`; re-run `scripts/db-bootstrap.sh`); F-005 aggregates gain `purpose` and aggregate members (§5.2); F-003's scenario move checks links (§10) |
| `internal/register` | Risks, versions, links, pins, exposure status, treatment, roll-up planning and the roll-up job |
| `internal/registerapi` | The register API (§6), mounted by `cmd/risk` |
| `internal/analysis` | Members that are aggregates; `purpose`; the aggregate worker reads aggregate members' series |
| `pkg/settings` | `settings.F007Defs()`: `register.iterations`, `register.analysis_max_age_days`; packages 1.6.0 |
| `web/src/register` | The register list, a risk's page, the new-risk form, roll-ups, coverage; reuses `web/src/charts` and the F-006 views |
| `pkg/audit/catalog.yaml` | F-007's events (§8) |

## 3. Model

### 3.1 A risk
- **Head `register.risk`** (BU-owned, type `register`): `id`, `bu_id`, `state` (`open`, `closed`), `current_version`, `seq`, and summary columns kept by the version trigger for listing (`title`, `owner`, `category_id`, `exposure_aggregate_id`).
- **Versions `register.risk_version`** (append-only): `risk_id`, `version`, `document` (jsonb), `change_note`, `author`, `created_at`. The document holds:
  - `title`, `description`, `owner`, `category`;
  - `scenarios`: each `{scenario_id, pin: {run_id, control_set, reason?, pinned_by, pinned_at} | null}`;
  - `state` and `close_reason`.
- **Checks.** The document is validated in Go (`register.Validate`) and checked again in the database (`register.check_document`), as F-003 does:
  - the owner is a user with `register.view` at the risk's business unit;
  - each scenario is visible to the author and in the risk's subtree;
  - each pinned run is succeeded, of that scenario, has the register's iteration count, and holds the control set.
- **Links projection `register.risk_scenario`** (`risk_id`, `scenario_id`, `open`), kept by the version trigger, with `UNIQUE (scenario_id) WHERE open` (AC-02). Closing a risk sets `open = false`, freeing its scenarios (AC-04).
- **Moves.** `register.move_risk` moves the head, versions, links and treatment, refusing a move that would leave a linked scenario outside the new subtree (AC-05).

### 3.2 Treatment
- **Head `register.treatment`** (BU-owned, type `treatment`, same `bu_id` as its risk) and **versions `register.treatment_version`**. The document holds:
  - `decision` (`mitigate`, `transfer`, `avoid`, `accept`, or null) and `rationale`;
  - `targets`: per scenario, the control set the treatment is expected to reach;
  - `actions`: each `{id, title, owner, due, state, cancel_reason?}`.
- A risk's history merges both version streams by time (AC-03).
- An action is overdue when its due date has passed and it is neither done nor cancelled (AC-17); computed on read.
- `accept` marks that an acceptance is needed; F-008 will add the acceptance's state beside it (AC-18).

### 3.3 Exposure and staleness (AC-06 to AC-10)
- **Pins.** A pin is a run of the scenario, one of the run's control sets (the current one unless a reason is given, OQ2) and the pinner. Pinning or adopting writes a new risk version.
- **Exposure.** With one scenario it is the pinned `analysis.result`. With more, it is an F-005 aggregate with purpose `exposure` of the pinned results at the risk's business unit, requested in the transaction that changes the pins. It is worked by the analysis aggregate worker and recorded on the head. Until it succeeds the exposure is "computing".
- **Status.** `register.exposure_status(risk)` returns `current`, `stale` with reasons, `unquantified` or `computing`. The stale reasons are:
  - `no_pin`: a linked scenario without a pin;
  - `newer_version`: a pinned run of an older version than the scenario's latest;
  - `too_old`: a result finished more than `register.analysis_max_age_days` ago;
  - `archived`: a linked scenario archived.

  `unquantified` means the risk has no scenarios.
- **Newer runs.** `register.newer_runs(risk)` lists, per pin, succeeded runs of the scenario that are newer and have the register's iteration count (AC-10). Adoption is a new version.
- **Coverage.** `register.coverage(bu)` gives the open risks in the subtree by status (AC-09).

### 3.4 Roll-ups (AC-11 to AC-14)
- **Building a roll-up of business unit B for a requester:**
  - The service reads `authz.rollup_coverage('register', B)`.
  - **Full units** contribute the requester's visible open risks whose exposure is `current` and whose pinned results the requester sees (AC-13). Stale and unquantified risks are left out and counted.
  - **Aggregate-only units** contribute their open current risks' mean exposure through `register.rollup_means(B)`, owned by `rollup_definer` (F-001 T-30), as one labelled total: added to the mean, listed apart, not in the distribution.
  - **Excluded units** are counted as such.
- **Nesting (decided 2026-11-13).** The roll-up of B is an aggregate with purpose `rollup` whose members are B's own risks' exposures and the roll-ups of B's children that have any included risk.
  - A level with more than 200 members is split into partial aggregates of at most 200, by risk order.
  - Each node is keyed by the digest of its members (risk ids with pin run ids and sets, or child node digests) and reused while unchanged.
  - Independence holds across all leaves, since each aggregate permutes its members by its own seed and position (F-005 §3.5).
- **The job.** A River job `register.rollup` (queue `analysis`) builds the tree bottom up: it requests the missing nodes as aggregates and works them with the analysis aggregate worker. The roll-up record keeps the requester, the tree's root aggregate, the risks included, the counts left out, the aggregate-only totals and the time.
- **Staleness.** A roll-up is stale when the digest of what it would include now differs from the one it used (AC-12), or a risk in it is stale.
- **Listing.** Risks are ordered by mean or 90th percentile, with each risk's share of the roll-up taken from the aggregate's contributions (AC-14).
- **Limits.** One running roll-up per business unit and requester, at most one requested per business unit per minute (OQ5), and 2,000 risks per roll-up.

### 3.5 Categories (OQ3)
- `register.category` (not BU-owned): `id`, `name`, `archived_at`. It is managed by holders of `register.edit` at the root and readable with `register.view` anywhere.
- It ships with: Cyber, Operational, Third party, Data privacy, Business continuity, Regulatory, Fraud.

## 4. Settings (F-015)
| Key | Kind | Default | Bounds | Notes |
|---|---|---|---|---|
| `register.iterations` | int | 100,000 | `simulation.iterations_min` to `simulation.iterations_max`; profiles bound it at ≥ 10,000 | The iteration count of pinned runs |
| `register.analysis_max_age_days` | int | 365 | 30 to 730 | A pinned result older than this is stale (OQ4) |

Packages 1.6.0 with 40 settings.

## 5. Data model

### 5.1 Schema `register`
| Table | BU-owned (type) | Writes |
|---|---|---|
| `register.risk` | yes (`register`) | `register_definer` functions; app_rw inserts id and bu_id |
| `register.risk_version` | yes (`register`) | append-only for every role (PF025); version = current + 1 |
| `register.risk_scenario` | yes (`register`) | the version trigger only |
| `register.treatment` | yes (`treatment`) | as risk |
| `register.treatment_version` | yes (`treatment`) | append-only (PF025) |
| `register.rollup` | yes (`register`) | `register_definer` functions |
| `register.category` | no | `register_definer` functions (root `register.edit`) |

- Every BU-owned table has `apply_bu_rls` and an `rlstest` fixture.
- Functions take the caller from the signed context and emit their events in the transaction (§8).
- Limits and refusals use PF026.

### 5.2 Changes to schema `analysis` (F-005)
- **`analysis.aggregate.purpose`:** `analysis` (default), `exposure` or `rollup`. The Aggregates page and list show `analysis` only. Register aggregates are reached through the register.
- **Members.** `analysis.aggregate_member` members may be runs (as now) or aggregates (`member_aggregate_id`, no control set). `analysis.members_visible` follows aggregate members recursively, so a nested aggregate is visible only with every leaf.
- **The worker** reads an aggregate member's series from `analysis.aggregate.ale`.
- **Requests.** `analysis.request_aggregate` takes the purpose. Requests with purpose `exposure` or `rollup` are made only through `register_definer` functions, which check `register.edit` (exposure) or `register.view` (roll-up) at the business unit instead of `analysis.run`.

## 6. API (`api/openapi/register.yaml`, `/api/v1/register`)
| Method and path | Who | Purpose |
|---|---|---|
| `GET /risks?bu=&subtree=&owner=&category=&state=&decision=&status=&overdue=&sort=` | register.view (RLS) | The list, paged (AC-19, AC-14) |
| `POST /risks` | register.edit at the BU | Create (AC-01) |
| `GET /risks/{id}` | register.view | Head, current version, scenarios with pins and newer runs, exposure with status, treatment if treatment.view |
| `PUT /risks/{id}` | register.edit | Change fields, links and pins (`expected_version`, `change_note`) (AC-02, AC-06) |
| `POST /risks/{id}/adopt` | register.edit | Adopt newer runs (AC-10) |
| `POST /risks/{id}/close`, `/reopen`, `/move` | register.edit | With a reason (AC-04, AC-05) |
| `GET /risks/{id}/versions`, `/diff?from=&to=` | register.view | History and differences (AC-03) |
| `GET /risks/{id}/treatment`, `PUT …/treatment` | treatment.view / treatment.edit | The plan, decision and actions (AC-15 to AC-18) |
| `GET /coverage?bu=` | register.view | Current, stale, unquantified (AC-09) |
| `POST /rollups`, `GET /rollups?bu=`, `GET /rollups/{id}` | register.view at the BU | Request and read roll-ups (AC-11 to AC-14) |
| `GET /categories`, `POST /categories`, `PATCH /categories/{id}` | register.view; register.edit at the root | Categories (OQ3) |

Conventions are F-001 §6 (lint-enforced). Errors: 409 `stale_version`, `scenario_linked` (naming nothing the caller cannot see), `closed`, `rollup_running`; 422 `invalid_document` with problems by pointer; 429 `rollup_rate`.

## 7. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| I: a risk, its treatment or a roll-up crosses business units | RLS on every table (`register`, `treatment`); roll-ups include only visible risks with visible pins; nested aggregates visible only with every leaf | `TestSTRIDEF007Visibility` |
| I: a roll-up reveals a restricted subtree's detail | Aggregate-only units contribute one mean total through `rollup_definer`; their risks, scenarios and series never enter the aggregate | `TestSTRIDEF007RestrictedRollup` |
| I: treatment details reach people without treatment.view | Treatment is its own RLS resource type; the risk's API omits it without the permission | `TestSTRIDEF007TreatmentScope` |
| T: a risk's history is altered | Versions append-only for every role; heads and links changed only by definer functions and triggers | `TestSTRIDEF007HistoryTamper` |
| T: loss counted twice, or a pin that does not stand for the scenario | One open risk per scenario (unique index); pins checked in the database (scenario, state, iterations, control set) | `TestSTRIDEF007Pins` |
| R: a change cannot be attributed | Every change audited in its transaction with actor, BU and reason | `TestRegisterAuditEvents` |
| D: roll-up floods | One running roll-up per BU and requester, one request per BU per minute, 2,000 risks, 200 members per node, node reuse | `TestRegisterRollupLimits` |
| E: a viewer edits risks, or a risk owner gains engine use beyond the register | register.edit / treatment.edit required; exposure and roll-up aggregates only through register functions, of results the caller sees | `TestSTRIDEF007Escalation` |

## 8. New catalog event types
- **Risks:** `register.risk_created`, `register.risk_changed`, `register.risk_moved`, `register.risk_closed`, `register.risk_reopened`.
- **Links and pins:** `register.scenario_linked`, `register.scenario_unlinked`, `register.pin_set` (attribute `adopted`).
- **Treatment:** `register.treatment_changed` (attributes `decision`, `actions_changed`).
- **Roll-ups and categories:** `register.rollup_requested`, `register.rollup_computed`, `register.rollup_failed`, `register.category_changed`.

All are category `risk_data` with BU required, except `register.category_changed` (BU optional).

## 9. Requirements traceability
| AC | Design | Verification |
|---|---|---|
| AC-01 to AC-05 | §3.1, §5.1, §6 | DB tests of the register API; RLS harness |
| AC-06 to AC-10 | §3.3, §4, §5.2 | DB tests (pins, status reasons, exposure aggregates, newer runs, coverage) |
| AC-11 to AC-14 | §3.4, §5.2 | DB tests with the fake engine (nesting, reuse, restricted modes, staleness, ordering) |
| AC-15 to AC-18 | §3.2 | DB tests (treatment versions, overdue, expected exposure) |
| AC-19, AC-20 | §6, UI | Playwright and axe |
| AC-21, AC-22 | §5, §7, §8 | STRIDE suite; audit event tests |
| NFR performance | §3.3, §3.4 | `TestBenchmarkGateRegister` (10,000 risks over 2,000 BUs; a roll-up of 500 risks with the fake engine's bench mode, and its timing on the real engine in CI) |

## 10. Changes to other features
- **F-005:** aggregate `purpose` and aggregate members (§5.2): requirements AC-18 and AC-19 still hold, with members that may themselves be aggregates (independence stated). The Aggregates page lists purpose `analysis` only.
- **F-003:** moving a scenario linked to an open risk outside the risk's subtree is refused (409 `linked_to_risk`, naming the risk if visible) (OQ7); archiving a linked scenario is allowed and makes the risk stale.
- **F-001:** bootstrap role `register_definer`; resource types `register` and `treatment` (in the catalog) gain tables and fixtures.
- **F-015:** two settings, packages 1.6.0.
- **F-006:** a risk's page reuses the run and aggregate views; comparisons of a risk's current and target control sets (AC-16) use F-006's comparison.
- **F-008:** reads the treatment decision `accept` and adds the acceptance's state.

## 11. Deployment modes
Identical in SaaS, self-hosted and air-gapped. No new keys or services.

## 12. Alternatives considered
- **One aggregate per roll-up with a higher member cap:** rejected (decided 2026-11-13). The engine holds every member's series (about 800 MB for 500 members at 100,000 iterations).
- **Any iteration count, excluding mismatches:** rejected (decided 2026-11-13). Roll-ups would silently leave risks out.
- **Treatment inside the risk's document:** rejected. `treatment.view` would be enforced only by the service, not by row-level security.
- **Stored staleness flags:** rejected. They go out of date. Computing status on read from indexed columns meets the list budget.

## 13. Open items
- Whether a roll-up should also be scheduled (for example nightly) is left to F-010's reports.

## Change Log
- 2026-11-13: Initial draft. Decisions taken with Robert Former: nested roll-ups by business unit within F-005's 200 members; one register iteration count (`register.iterations`). Requirements OQ1 is settled by the register iteration count, and OQ2 to OQ7 as proposed.
- 2026-11-13: **Approved** by Robert Former, with the changes to F-005 (aggregate purpose, aggregate members) and F-003 (scenario moves) in section 10.
- 2026-11-14: T-02 (clarifications, approved with the task): (1) an aggregate member reaches the engine with its id in the member's run field and its name as the label; the engine contract is unchanged; (2) in the results digest an aggregate member is `{position, aggregate_id, result_digest}`, run members keep their fields, so every earlier aggregate's digest is unchanged; (3) app_rw has no INSERT privilege on `purpose`, so analysts' aggregates are always `analysis`; the register's definer functions (T-05, T-07) are granted it.
- 2026-11-14: T-03 (clarifications, approved with the task): (1) the owner rule reads the owner's materialized scope (`authz.user_scope`, `register` read BUs): what RLS enforces, groups, mappings and restricted BUs included, rather than role assignments; (2) links are written by the version trigger under the caller's own write scope (no `allow_definer` on `risk_scenario`, which would admit only SELECT and UPDATE); the one-open-risk index sees every row; (3) the roll-up table comes with T-07, where its only writers (the roll-up functions) are built; category changes with T-04; the Go document validation and its parity test with T-04's API; (4) a treatment head takes its risk's BU, one per risk; a closed risk's treatment does not change; (5) an impossible date (2026-02-30) is a problem by pointer, not an error.
