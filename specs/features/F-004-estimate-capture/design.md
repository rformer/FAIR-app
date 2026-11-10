# F-004 Calibrated Estimate Capture — Design
Status: **Approved** (Robert Former, 2026-11-09) | Requirements: approved 2026-11-09 | Last updated: 2026-11-09
Constitution refs: P2, P3, P4, A2, A5, A6, S0, S3, S4, Q1, Q3, Q5 | ADRs: 003, 006, 007

## 1. Overview
F-004 extends the risk service (F-003) with estimate requests, answers, acceptance into scenarios, and calibration exercises and scores. Everything lives in a new schema `estimate`, next to `risk`, written by the same service as `app_rw`.

- **Requests are scenario data.** A request belongs to its scenario's business unit and is read by analysts under F-001's row policies with the `scenario` resource type. It holds a snapshot of the scenario context the analyst chose to share, so estimators never read the scenario itself (AC-02, AC-07).
- **Estimators work through functions.** Estimators (who hold `estimate.submit`, not `scenario.view`) reach requests and their own answers only through SECURITY DEFINER functions that take the caller from the signed DB context and check, on every call, that the caller is an addressed estimator holding `estimate.submit` at the request's BU. `app_rw` has no privileges on the answer tables.
- **Acceptance is a scenario version.** Accepting answers saves a new scenario version through F-003's save path, in one transaction. Each accepted estimate carries its provenance (request, method, weights, the answers used with their estimators and scores at the time) inside the scenario document, so it is covered by the version's digest, the simulation bundle and the export (AC-17, AC-18, AC-31), and it moves with the scenario.
- **Combination without a shape.** Pools average the answers' minimum, most likely and maximum (quantile averaging), with equal weights or weights from calibration scores, over answers given at the request's confidence. No distribution shape is assumed; F-005 chooses the shape (OQ2).
- **Reference classes are library entries.** A new F-003 library kind, `reference_class`, so reference data is versioned, inherited down the tree and exported like the rest of the library (AC-13, AC-14).
- **Calibration is personal data.** Exercises, answers and scores are per person, not BU-owned, and reached only through definer functions with the visibility rules of AC-27 to AC-29; question answers never leave the database for a person taking an exercise. Retention purges them (AC-30).
- **Every change audited** in its transaction (F-002).

## 2. Components
| Component | Kind | Responsibility |
|---|---|---|
| `internal/estimate` | Go (risk service) | Requests, factor lists, context snapshots, combination (`Pool`), warnings, calibration scoring, retention and due-date jobs |
| `internal/estimate/bank` | Go, data | The shipped question bank (`questions.json`, 120 questions) and its sync payload |
| `internal/estimateapi` | API (Go), mounted by `cmd/risk` | `/api/v1/estimates/...` and `/api/v1/calibration/...` (contract `api/openapi/estimate.yaml`) |
| `estimate` schema | PostgreSQL | Requests, factors, estimators, answers, the notice outbox, question sets, exercises, scores. Definer functions owned by the new bootstrap role `estimate_definer` |
| `internal/risk/model` | Existing (F-003) | Library kind `reference_class`; estimate `elicitation` provenance and source type `elicitation` (§12) |
| `cmd/risk` | Existing | Mounts the estimate API; runs the leader-only jobs (§6.7) under an advisory lock (`internal/audit.Leader` reused) |
| Gateway | Existing | Segments `estimates` and `calibration` route to the risk service |
| `web/src/estimate` | UI | Estimator inbox and answer form, request creation and review from the scenario page, calibration exercises and record, question set administration; the estimating aids also in the F-003 scenario editor |

## 3. The model

### 3.1 Factors (AC-01, AC-06)
A requested factor is addressed by the JSON pointer of its estimate in the scenario document, for example `/lef/tef/contact_frequency`, `/primary_loss/response`, `/secondary_risk/0/slef`, `/secondary_risk/0/loss/fines_judgments`, `/lef/vulnerability/threat_capability/estimate`. The request may name only pointers that the scenario version's taxonomy levels require (`model.Taxonomy`, F-003 §3.1). For each factor the request stores the factor name, its unit and the definition shown to estimators (from `internal/estimate`'s factor glossary, written from Open FAIR).

### 3.2 Context snapshot (AC-02, AC-07)
At creation the analyst ticks the context to share: name, description, scope, analysis period, asset (name, type, description), threat community (name, description), threat effects, loss event. The service copies those fields from the scenario version and its pinned documents into `request.context`. Values of the scenario's own estimates are never copied. Estimators read the snapshot, never the scenario.

### 3.3 Answers (AC-08 to AC-10)
An answer is per (request, estimator, factor), append-only by revision: each save is a new revision with state `draft` or `submitted`, the F-003 estimate (validated by `model.ValidateEstimate` for the factor's unit), or a decline with a reason. The current answer is the latest submitted revision; a later draft is visible only to its author. Revisions are refused once the request is no longer open.

### 3.4 Combination (AC-15 to AC-17; OQ2)
`Pool(method, answers, weights)` over the current submitted answers of one factor at the request's confidence:

- `single`: one answer, as given.
- `equal`: min = Σ min_i / n, likewise most likely and max.
- `calibration`: the same with weights w_i / Σ w_j, where w_i comes from the estimator's range calibration at answer time (§3.6): 1.0 when calibrated, 0.5 when not yet measured, and max(0.1, 1 − 2.5·|rate − 0.9|) when over- or underconfident.
- `own`: the analyst's estimate, with a rationale that must reference the request.

Averaging ordered triples keeps them ordered, and keeps values within their unit's bounds. Arithmetic is exact (`math/big.Rat` over the decimal strings), and results are rounded half-even to 12 significant digits and written with `canon.Decimal`, so the same inputs always give the same digits. Answers at another confidence may be used alone (`single`), not pooled. The result's confidence is the request's. Its rationale is generated ("equal-weight average of 3 answers to estimate request …") and the sources are the answers' sources plus a source of type `elicitation` referencing the request.

### 3.5 Provenance in the scenario (AC-18, AC-31)
An accepted estimate gains an optional `elicitation` member in the F-003 document:

```json
"elicitation": {
  "request": "<request id>", "method": "calibration", "confidence": "0.9",
  "answers": [
    {"estimator": "<user id>", "name": "Dana Ruiz", "revision": 2, "weight": "0.5",
     "min": "2", "ml": "5", "max": "12", "confidence": "0.9",
     "calibration": {"class": "not_measured", "range_rate": null, "as_of": "2026-11-09"}}
  ]
}
```

The database re-checks it (§4.2): the request and answer revisions exist, belong to the scenario, are submitted, and the pooled values follow from them by the stated method. Export and import carry it with the document (F-003 T-11), so an imported scenario keeps its provenance without the request (AC-31). `request_factor.accepted_version` records which version accepted each factor (AC-19).

### 3.6 Calibration scoring (AC-20 to AC-23; OQ1)
Over a person's submitted exercise answers within `calibration.window`:

- **Ranges**: n answers, k containing the truth (inclusive bounds). Under perfect calibration k ~ Binomial(n, 0.9). With the central 90% interval [k_lo, k_hi] of that binomial: k < k_lo → overconfident, k > k_hi → underconfident, otherwise calibrated. Rate = k / n.
- **Binary**: n answers with confidences c_i and c correct. Expected μ = Σ c_i, σ² = Σ c_i (1 − c_i); z = (c − μ) / σ. z < −1.645 → overconfident, z > 1.645 → underconfident, otherwise calibrated. The Brier score Σ (c_i − y_i)² / n is shown as a second figure.
- A part with fewer than `calibration.min_answers` (default 20) answers is not measured. The overall class is the range class when ranges are measured, otherwise the binary class, otherwise `not_measured`.

A score is recomputed on every exercise submission and by the daily job (the window moves), and kept as history. The rules are published in the user documentation (`docs/guides/calibration.md`).

### 3.7 Warnings (AC-11, AC-12; OQ3)
`estimate.Warnings(unit, estimate, requestedConfidence)` returns, without refusing:

| Check | Units | Threshold |
|---|---|---|
| Most likely equals a bound | all | min = ml or ml = max |
| Narrow range | events per year, currency | max / min < 1.1 (when min > 0) |
| Wide range | events per year, currency | max / min > 1,000 (when min > 0) |
| Narrow range | probability, fraction | max − min < 0.02 |
| Narrow or wide range | percentile | max − min < 2, or > 90 |
| Reaches certainty | probability | min = 0 or max = 1 |
| Other confidence | all | confidence ≠ the requested one |

The UI's preview draws an illustrative Beta-PERT through the triple, labelled as illustrative: the simulation's distribution is F-005's choice. The equivalent-bet prompt is text, at the stated confidence.

### 3.8 Reference classes (AC-13, AC-14)
Library kind `reference_class`: `name`, `description`, `data` (either `{"kind": "counts", "series": [{"period_start", "period_end", "count"}]}` or `{"kind": "losses", "amounts": ["…"]}`, currency amounts in the installation currency), `period`, `sources`. Limits: 200 series entries or 1,000 amounts. Summaries (events per year, observed minimum, median and maximum) are computed in Go for display. A request pins reference class versions (`estimate.request_reference`, with the pinned document copied as F-003 pins are), and estimators read the copies.

## 4. Data model (schema `estimate`)

### 4.1 Tables
| Table | Owner of rows | Columns (main) | Access |
|---|---|---|---|
| `request` | scenario's BU | id, bu_id, scenario_id, scenario_version, title, instructions, confidence, due_at, status (`open`, `complete`, `closed`, `cancelled`), affected (reason or NULL), context (jsonb), created_by, created_at, ended_at, seq | RLS `scenario`; app_rw inserts, updates through functions |
| `request_factor` | request's BU | request_id, pointer, factor, unit, definition, accepted_version, accepted_at | RLS `scenario` |
| `request_estimator` | request's BU | request_id, user_id, added_by, added_at, removed_at, finished_at | RLS `scenario` |
| `request_reference` | request's BU | request_id, entry_id, version, digest, document | RLS `scenario` |
| `answer` | request's BU | id, request_id, estimator, pointer, revision, state, estimate (jsonb) or declined (text), calibration (jsonb snapshot), created_at | no app_rw privileges; definer functions only |
| `notice_outbox` | — | id, kind, user_id, request_id, created_at, delivered_at | app_rw none; F-009 reads |
| `question_set` | installation | id, origin (`shipped`, `custom`), name, status (`draft`, `active`, `retired`), release, created_by | definer functions only |
| `question` | installation | id, set_id, version, kind (`range`, `binary`), text, unit, answer, source, retired_at | definer functions only; answers never returned to takers |
| `exercise` | person | id, user_id, started_at, submitted_at, questions (ids and versions) | definer functions only |
| `exercise_answer` | person | exercise_id, question_id, version, low, high, choice, confidence, correct | definer functions only |
| `score` | person | user_id, computed_at, score (jsonb: ranges, binary, class) | definer functions only |

Requests, factors, estimators and references are registered BU-owned tables (`authz.apply_bu_rls(..., 'scenario')`, harness fixtures). `answer` is BU-owned too (its `bu_id` follows the request) but only reachable through functions. Calibration tables are not BU-owned (they belong to people) and are outside the RLS registry; `TestRLSHarnessEveryBUOwnedTable` lists them as person-owned exceptions with their own access tests.

### 4.2 Functions and triggers
- `estimate.my_requests()`, `estimate.request_for_estimator(id)`: requests addressed to the caller, open or not, with the snapshot, factors, references and the caller's own answers; only while the caller holds `estimate.submit` at the request's BU (`iam.user_has_permission`).
- `estimate.save_answer(request, pointer, estimate, declined, submit)`: appends a revision; re-validates the estimate (`risk.check_estimate`, shared with `risk.check_document`); refuses a closed request or a removed estimator; snapshots the caller's current score.
- `estimate.request_answers(id)`: submitted answers (latest revision per estimator and factor, with history) for holders of `scenario.view` at the request's BU.
- `estimate.change_request`, `estimate.cancel_request`: status and estimator changes for holders of `scenario.edit` (the API checks `estimate.request`).
- `risk.check_document` gains the `elicitation` check: every referenced answer revision exists, is submitted, belongs to the referenced request of this scenario, and the values follow from the method (re-computed in SQL with `numeric`; the parity test holds Go and SQL equal).
- Calibration: `estimate.start_exercise()`, `estimate.exercise(id)` (no answers before submission), `estimate.submit_exercise(id, answers)`, `estimate.my_calibration()`, `estimate.calibration_of(user)` (rules of AC-28, AC-29; records `calibration.record_viewed` in the transaction), `estimate.question_sets…` for `calibration.manage`.
- Installation-wide permissions (`calibration.manage`, `calibration.audit`) are checked at the root BU.

### 4.3 Retention (AC-30)
The daily job deletes exercises and their answers submitted before now − `calibration.retention`, and score history older than it except each person's latest score, through `estimate.purge_calibration()` (definer), recording `calibration.records_purged` with counts. Answer snapshots and scenario provenance are kept: they are part of the risk record.

### 4.4 Limits (denial of service)
Per request: 60 factors, 50 estimators, 20 references; per answer: 100 revisions; per scenario: 20 open requests; instructions 10,000 characters; exercise size 10 to 50 (setting); custom question sets: 1,000 questions each. Text bounded and secret-checked as in F-003.

## 5. API (`api/openapi/estimate.yaml`)
| Method and path | Who | Purpose |
|---|---|---|
| `GET/POST /api/v1/estimates/requests` (`?scenario=`) | scenario.view / estimate.request + scenario.edit | List a scenario's requests; create one (AC-01, AC-02) |
| `GET/PATCH /api/v1/estimates/requests/{id}` | scenario.view / analyst | Read; change due date, estimators (AC-03) |
| `POST …/{id}/cancel` | analyst | Cancel with a reason |
| `GET …/{id}/answers` | scenario.view | Answers side by side, with pooled previews (AC-15) |
| `POST …/{id}/accept` | analyst | `expected_version`, per factor `single`/`equal`/`calibration`/`own`, change note; saves the scenario version (AC-16 to AC-19) |
| `GET /api/v1/estimates/inbox` | estimate.submit | Requests awaiting the caller (AC-05, AC-07) |
| `GET /api/v1/estimates/inbox/{id}` | addressed estimator | The request as the estimator sees it |
| `PUT /api/v1/estimates/inbox/{id}/answers` | addressed estimator | Save drafts or submit, per factor (AC-08 to AC-10) |
| `POST /api/v1/estimates/warnings` | any risk user | Warnings and preview for an estimate (AC-11, AC-12) |
| `POST /api/v1/calibration/exercises`, `GET …/{id}`, `POST …/{id}/submit` | calibration.take | Exercises (AC-20 to AC-22) |
| `GET /api/v1/calibration/me` | calibration.take | Own record (AC-27) |
| `GET /api/v1/calibration/people/{user}` | estimate.request at a shared BU, or calibration.audit | Another person's score (AC-28, AC-29) |
| `/api/v1/calibration/question-sets…` | calibration.manage | Sets and questions (AC-25, AC-26) |

Conventions as F-001 §6 (lint-enforced): Idempotency-Key, reasons, 404 for unseen ids, `x-permission`, `x-audit-events`.

## 6. Key flows

### 6.1 Create a request
Check `estimate.request` and `scenario.edit` at the scenario's BU; load the current version; check the factors against its taxonomy; check each estimator holds `estimate.submit` at the BU; copy the context and pinned references; insert the request, factors, estimators, references and notice rows; record `estimate.request_created`. One transaction.

### 6.2 Answer
The estimator's client reads the request through the inbox, calls `/warnings` while typing, and saves drafts or submits. The function appends the revision with the caller's score snapshot; the last factor submitted marks the estimator finished and queues the analyst's notice; when all estimators have finished, the request becomes `complete`.

### 6.3 Accept
With `expected_version` of the scenario, the service builds each accepted estimate (`Pool`, §3.4) with its `elicitation` provenance, sets it at its pointer (`model.Set`), validates the whole document, and saves the version through F-003's save path; the database re-checks the provenance; `request_factor.accepted_version` is set; `estimate.accepted` and `scenario.version_saved` are recorded. One transaction; a stale scenario version answers 409.

### 6.4 Scenario changes (AC-06)
`risk.move_scenario`, `risk.set_archived` and the version trigger mark open requests of the scenario as affected (with the reason: moved, archived, or factor no longer required by the new version's levels). The analyst sees the mark and may cancel or continue; nothing is re-pointed.

### 6.5 Exercise
`start_exercise` draws `calibration.exercise_size` questions from active sets, about half range and half binary, excluding questions the person answered within `calibration.reuse_period`, and returns text and units only. `submit_exercise` scores it, returns each truth with its source, recomputes the score and records `calibration.exercise_submitted`.

### 6.6 Shipped question bank (AC-24; OQ4)
`internal/estimate/bank/questions.json` (120 questions: 60 range, 60 binary; stable general-knowledge facts, each with a citable source) is synced by `iam migrate` into a `shipped` set per release (`estimate.sync_bank`, like the starter library), read-only. Robert Former reviews its text, answers and sources for each release that changes it.

### 6.7 Jobs (leader only)
Every minute: close requests past their due date (`estimate.request_closed`), queue reminders `estimate.reminder_lead` before due. Daily: recompute scores, purge calibration records (§4.3).

## 7. Settings (F-015)
| Key | Kind | Default | Bounds | Stricter |
|---|---|---|---|---|
| `estimate.reminder_lead` | duration | 2 days | 1 hour to 14 days | — (not security) |
| `calibration.exercise_size` | int | 20 | 10 to 50 | — |
| `calibration.reuse_period` | duration | 180 days | 0 to 3 years | — |
| `calibration.window` | duration | 365 days | 30 days to 5 years | — |
| `calibration.min_answers` | int | 20 | 10 to 200 | higher |
| `calibration.retention` | duration | 3 years | 90 days to 7 years | lower (privacy) |

Packages 1.4.0.

## 8. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| S: an estimator answers as another person | Answers only through definer functions taking the caller from the signed context; addressee and permission checked per call | `TestSTRIDEF004AnswerAuthor` |
| T: an answer is changed after it was used | Revisions append-only for every role; provenance copied into the scenario version under its digest and re-checked by the database | `TestSTRIDEF004AnswerTamper` |
| T: a client supplies a pooled result | The service computes combinations; the database re-computes them from the referenced revisions and refuses a mismatch | `TestSTRIDEF004CombinationChecked` |
| R: an acceptance cannot be attributed | Audited in its transaction; provenance names the request, method and answers | `TestEstimateAuditEvents` |
| I: an estimator is anchored by other answers or the scenario | Estimators read only their own answers and the snapshot; no scenario permissions in the Estimator role; drafts hidden | `TestSTRIDEF004Independence` |
| I: a removed estimator, or one without the permission at the BU, keeps reading | Addressee and `estimate.submit` at the BU checked on every call | `TestSTRIDEF004EstimatorScope` |
| I: question answers reach a person taking an exercise | No table privileges; functions return truths only after submission | `TestSTRIDEF004QuestionSecrecy` |
| I: calibration records are exposed | Visibility rules in the functions; views of others' records audited; retention | `TestSTRIDEF004CalibrationPrivacy` |
| D: request, answer or exercise floods | Limits (§4.4), body limits, settings bounds | `TestEstimateLimits` |
| E: an estimator edits the scenario or accepts answers | Acceptance needs `estimate.request` and `scenario.edit`; the Estimator role holds neither | `TestSTRIDEF004Escalation` |

## 9. New catalog event types
`estimate.request_created`, `estimate.request_changed`, `estimate.request_cancelled`, `estimate.request_closed`, `estimate.request_affected`, `estimate.answer_saved` (submitted revisions only; drafts are not events), `estimate.accepted`, `calibration.exercise_submitted`, `calibration.record_viewed`, `calibration.question_set_changed`, `calibration.records_purged`. Request and answer events with `bu: required`; calibration events without a BU.

## 10. Requirements traceability
| AC | Satisfied by |
|---|---|
| AC-01, AC-02 | §3.1, §3.2; §6.1; `POST /estimates/requests` |
| AC-03, AC-04 | `PATCH`, `/cancel`; §6.2 completion; §6.7 due dates |
| AC-05 | `notice_outbox`; §6.7 reminders; `/inbox` |
| AC-06 | §6.4 |
| AC-07 | §1, §3.2, §4.2 estimator functions |
| AC-08 to AC-10 | §3.3; `save_answer` |
| AC-11, AC-12 | §3.7; `/warnings`; the scenario editor and the answer form |
| AC-13, AC-14 | §3.8; library kind `reference_class`; `request_reference` |
| AC-15 to AC-17 | §3.4; `/answers`, `/accept` |
| AC-18, AC-19 | §3.5; `accepted_version` |
| AC-20 to AC-22 | §6.5 |
| AC-23 | §3.6 |
| AC-24 | §6.6 |
| AC-25, AC-26 | §4.2 question set functions; §8 |
| AC-27 to AC-29 | §4.2 calibration functions |
| AC-30 | §4.3 |
| AC-31 | §3.5 (provenance in the document; F-003 export) |

## 11. Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Question bank | Synced at migrate from the release | Same | Same, from the bundle |
| Notices | Outbox, delivered by F-009 | Same | Same; delivery inside the enclave |
| Jobs | Risk service leader | Same | Same |

## 12. Changes to other features
- **F-001**: permission catalog version 3: `estimate.request`, `estimate.submit`, `calibration.take`, `calibration.manage`, `calibration.audit`; built-in role Estimator (`estimate.submit`, `calibration.take`); Risk Analyst gains `estimate.request`; every built-in role gains `calibration.take`; Platform Admin gains `calibration.manage`; Auditor gains `calibration.audit`. Through `iam.sync_release` with catalog notices (F-001 T-29).
- **F-003**: library kind `reference_class` (§3.8); estimates gain the optional `elicitation` member (§3.5) and source type `elicitation`; `risk.check_document` and the JSON Schemas updated by a new migration, the parity corpus extended; `risk.move_scenario`, `risk.set_archived` and the version trigger mark affected requests (§6.4); the scenario editor shows the aids (AC-11, AC-12). Recorded in F-003's change log.
- **F-015**: F-004's settings (§7); packages 1.4.0.
- **F-009**: reads `estimate.notice_outbox`.

## 13. Alternatives considered
- A separate estimate service: rejected; accepting answers would span two services and lose the single transaction with the scenario version.
- Provenance in side tables only: rejected; it would not be covered by the scenario's digest or bundle, and would need its own move, export and import.
- Linear opinion pools under a fixed Beta-PERT: rejected for v1; it fixes a distribution shape before F-005 chooses one. Quantile averaging needs no shape.
- Brier score as the only measure: rejected as the headline; hit rates are what users understand. Brier is shown as a second figure.
- Estimators reading requests through RLS: rejected; they would need a per-user policy on BU-owned tables and could see sibling requests' metadata. Definer functions keep the estimator's view to exactly their requests.

## 14. Open items
- The shipped question bank's content (120 questions with sources) is written and reviewed in its task, like the starter library (F-003 T-10).

## Change Log
- 2026-11-09: Initial draft; design decisions (risk service with schema `estimate`, quantile-averaging pools, hit rate with binomial tolerance, a 120-question shipped bank) taken with Robert Former.
- 2026-11-09: Approved by Robert Former.
- 2026-11-09: T-01: permission catalog version 3 (`internal/access/catalog/release`, F-001 `permission-catalog.md`): calibration keys are classified as not risk data, so Platform Admin keeps no risk-data access; `calibration.manage` and `calibration.audit` are privileged; `calibration.take` is a read action (decided with Robert Former): it writes only the person's own record, and as a write it gave view-only roles a business-unit write scope that access reviews would misread. `TestCatalogVersion3Upgrade` installs version 2 (`setupWith`) and upgrades it.
- 2026-11-09: T-02: §7's settings as `settings.F004Defs()` (in `ReleaseDefs`, packages 1.4.0, 33 settings). The settings model bounds only the loosening side, so each setting has a direction (higher is stricter for all but `calibration.retention`, where lower is: personal data) and one bound: reminder lead at least 1 hour, exercise size at least 10, reuse period and window at least 30 days, minimum answers at least 10, retention at most 7 years. The upper limits of §7 (an exercise of at most 50 questions) are the service's (§4.4). The risk service registers them and refuses to start while one is unbound.
