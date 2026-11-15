# F-008 Risk Acceptance Lifecycle — Design
Status: Approved | Owner: Robert Former | Last updated: 2026-11-15
Requirements: `requirements.md` (Approved 2026-11-15) · ADR-003, ADR-007 (amendments 3 to 5)

## 1. Overview
- **Acceptances live in the risk service**, beside the register: new schema `acceptance` (bootstrap role `acceptance_definer`), packages `internal/acceptance` and `internal/acceptanceapi` (contract `api/openapi/acceptance.yaml`, gateway segment `acceptances`), pages in `web/src/acceptance`.
- **An acceptance is a head and an append-only history.** The head holds the state the lifecycle moves through; every request, decision and change of state is a step with its actor, time, reason and data. The request's evidence (the exposure, the analyses pinned, the tier) is copied into the first step, so it survives whatever happens to the risk later (AC-16).
- **F-008's own records, not F-001's approval engine (OQ7).** The decisions are evidence of the acceptance itself, and the tiers, suspension and renewal are F-008's rules. The engine's pattern is kept: decisions are made by definer functions that take the actor from the signed context and check their authority there.
- **Authority by tier (AC-04, AC-05).** The risk's mean annualized loss places a request in one of three tiers. A tier names how many levels above the risk's business unit its approvers must hold `acceptance.approve` (tier 3: the root) and how many approvals it needs. Requester, owner and approvers are all different people.
- **Time-driven changes by a job.** Expiry, suspension for a higher tier, and notices are made by a leader job of the risk service every minute, which catches up after an outage. Being past the expiry date reads as expired even before the job runs (Availability NFR).
- **"Needs review" is read, not stored (AC-14, OQ4, OQ5).** It is computed on read from the risk: stale exposure, treatment no longer accept, or moved since approval.

## 2. Components
| Component | Change |
|---|---|
| `db/migrations` | Schema `acceptance` (bootstrap role `acceptance_definer`; re-run `scripts/db-bootstrap.sh`); helpers in `register` and `analysis` that read a risk's exposure for the job (§3.5) |
| `pkg/settings` | `settings.F008Defs()`: the tiers and the maximum duration (§4); packages 1.7.0 |
| `internal/acceptance` | Tiers (placing an exposure, resolving the approvers' business unit), the request's checks, the jobs (expire, suspend, notices) |
| `internal/acceptanceapi` | The acceptance API (§6), mounted by `cmd/risk` |
| `internal/registerapi` | A risk's acceptance summary and the list's `acceptance` filter (F-007-AC-18) |
| `web/src/acceptance` | The list, the approver's inbox, an acceptance's page with its history and the decision form, the request and renewal forms; the risk page's Acceptance section |
| `pkg/audit/catalog.yaml` | F-008's events (§8) |

## 3. Model

### 3.1 An acceptance
- **Head `acceptance.acceptance`** (BU-owned, type `acceptance`, the risk's BU):
  - `id`, `bu_id`, `risk_id`, `renews` (the acceptance it renews, if any);
  - `state`: `pending`, `active`, `suspended`, `expired` or `ended`, with `end_reason` (`rejected`, `withdrawn`, `revoked`, `replaced`, `risk_closed`);
  - `tier` (1 to 3), `tier_bu_id` (where approvers must hold `acceptance.approve`), `approvals_needed`;
  - `mean` (the mean annualized loss the tier was placed on), `expires_on` (a date);
  - `approved_bu_id` (the risk's BU when approved), `requested_by`, `requested_at`, `seq`.
- **Steps `acceptance.step`** (BU-owned, type `acceptance`, append-only for every role):
  - `acceptance_id`, `n`, `kind`, `actor`, `at`, `reason`, `data` (jsonb);
  - kinds: `requested`, `approved`, `rejected`, `withdrawn`, `activated`, `suspended`, `review_requested`, `reactivated`, `revoked`, `expired`, `replaced`, `ended`.
  - The `requested` step's data is the evidence: justification, conditions, proposed expiry, the risk's version, its exposure (mean, 90th percentile, the exposure aggregate's id and results digest, or the one pinned run), each linked scenario's pin (run, control set, scenario version), and the tier with its settings.
- **One open acceptance per risk.** A unique index on `risk_id WHERE state IN ('pending', 'active', 'suspended')` holds it. A renewal is the one exception: it is pending beside the active acceptance it renews, so the index excludes renewals' pending rows and a second index allows one pending renewal per risk.

### 3.2 Lifecycle
```
request ──► pending ──approvals complete──► active ──expiry──► expired
              │  └─rejected / withdrawn──► ended        │  │
              │                                         │  └─revoked / risk closed──► ended
              │                                         └─higher tier──► suspended ──approved──► active
              │                                                              └─rejected / revoked──► ended
renewal (pending, renews A) ──approved──► active, A ──► ended (replaced)
```
- **Request (AC-01, AC-02):** the risk is open, its treatment decision is accept, its exposure is current (F-007 status), no request is pending for it (besides a renewal), and the expiry is after today and within `acceptance.max_duration_days`. The tier is placed on the exposure's mean. The requester holds `acceptance.request` at the risk's BU; the risk's owner may request.
- **Decisions (AC-05, AC-06):** an approver holds `acceptance.approve` at the tier's BU (inherited from above, as F-001's assignments are; never into a restricted subtree from outside) and is neither the requester nor the risk's owner. Each approver decides once. An approval may shorten the expiry, never lengthen it; the shortest one given stands. One rejection ends the request.
- **Activation (AC-07):** when the approvals reach `approvals_needed`, the acceptance becomes active. For a renewal, the acceptance it renews ends as `replaced` in the same transaction, so there is no gap (AC-11).
- **Expiry (AC-09):** the job ends active and suspended acceptances whose `expires_on` has passed. Reads treat a past `expires_on` as expired before then.
- **Higher tier (AC-13):** the job places every active acceptance's current exposure. One that falls in a higher tier than its own is suspended, and a `review_requested` step names the new tier, its business unit and its approvals. Approvals at that tier reactivate it with the new tier recorded; a rejection ends it.
  - While suspended the risk shows as not accepted.
  - A stale exposure does not suspend (§3.3).
  - An exposure that falls to a lower tier changes nothing.
- **Revocation (AC-15):** by an approver who could approve it at its tier, with a reason.
- **Withdrawal (AC-03):** by the requester, with a reason.
- **Risk closed (OQ5):** closing a risk ends its open acceptance (`risk_closed`), through a trigger on the register's head in the closing transaction.

### 3.3 Needs review (AC-14; OQ4, OQ5)
An active acceptance needs review, and stays in force, while any of these holds:
- **`stale`:** the risk's exposure status is not current;
- **`treatment`:** the treatment decision is no longer accept;
- **`moved`:** the risk's BU differs from `approved_bu_id`.

These are computed when read, with the reasons, as F-007 computes staleness.

### 3.4 Tiers (AC-04; OQ1, OQ6)
- **Placing a request:** tier 1 if the mean is at most `acceptance.tier1_max`, tier 2 if it is at most `acceptance.tier2_max`, otherwise tier 3.
- **The tier's BU:** the ancestor of the risk's BU `acceptance.tierN_levels_up` levels above it (the root when that is beyond it). Tier 3 is always the root.
- **Approvals needed:** `acceptance.tierN_approvals`.
- **Approvers:** both approvals of a two-approval tier come from holders at the tier's BU (OQ6).
- **Snapshot:** the tier's settings are copied into the `requested` (or `review_requested`) step; later changes to the settings do not move existing acceptances, except through the higher-tier check, which uses the settings in force.

### 3.5 Reading the exposure without a user (the job)
- The job runs without a signed context, so it reads a risk's exposure through `register.exposure_for(risk)`, owned by `register_definer` and granted to `acceptance_definer` alone. It returns the status (`register.status_of`) and the mean.
- The mean comes from two new `analysis_definer` functions granted to `register_definer` alone, so no caller's scope applies: the exposure aggregate's summary (`analysis.register_summary(aggregate)`, purpose not `analysis`) or the pinned result's (`analysis.pinned_summary(run, control_set)`).
- Requests and the API read the exposure under the caller's context as F-007 does.

### 3.6 Notices (AC-10; OQ3)
- `acceptance.notice_outbox` (as F-004's): `expiring` at 30, 14 and 7 days before `expires_on` and `expired` on it, to the risk's owner and the requester.
- Also `decision_needed` to nobody in particular: approvers find requests in their inbox (AC-08). F-009 may fan it out.
- Each notice is queued once per acceptance, kind and lead time.

## 4. Settings (F-015)
| Key | Kind | Default | Bounds (weakest) | Stricter |
|---|---|---|---|---|
| `acceptance.tier1_max` | int (currency units) | 100,000 | 0 to 10,000,000 | lower |
| `acceptance.tier2_max` | int | 1,000,000 | 0 to 100,000,000 | lower |
| `acceptance.tier1_levels_up` | int | 0 | 0 to 10 | higher |
| `acceptance.tier2_levels_up` | int | 1 | 0 to 10 | higher |
| `acceptance.tier1_approvals` | int | 1 | 1 to 2 | higher |
| `acceptance.tier2_approvals` | int | 1 | 1 to 2 | higher |
| `acceptance.tier3_approvals` | int | 2 | 1 to 2 | higher |
| `acceptance.max_duration_days` | int | 365 | 30 to 730 | lower |

- Packages 1.7.0 with 48 settings.
- The service refuses `tier2_max` below `tier1_max` (`acceptance.Limits.Check`, as F-007's).
- No profile can make a tier need no approval.

## 5. Data model
| Table | BU-owned (type) | Writes |
|---|---|---|
| `acceptance.acceptance` | yes (`acceptance`) | `acceptance_definer` functions only (definer insert and update: ADR-007 amendments 3 and 5) |
| `acceptance.step` | yes (`acceptance`) | `acceptance_definer` functions only; append-only for every role |
| `acceptance.notice_outbox` | no | the functions and the job; read by F-009 |

- **Writes:** every write goes through definer functions that take the actor from the signed context and check the permission there:
  - `acceptance.request(risk, justification, conditions, expires_on, renews)`;
  - `acceptance.decide(id, decision, rationale, expires_on)`;
  - `acceptance.withdraw(id, reason)`;
  - `acceptance.revoke(id, reason)`;
  - the job's `acceptance.sweep()`.

  Approvers hold `acceptance.approve`, not write scope, so decisions cannot rest on the BU write policy; the definer checks `iam.holds_permission` at the tier's BU.
- **Reads:** under RLS with `acceptance.view`.
- **Refusals:** PF027, with the reason as hint and problems by pointer.

## 6. API (`api/openapi/acceptance.yaml`, `/api/v1/acceptances`)
| Method and path | Who | Purpose |
|---|---|---|
| `GET /acceptances?state=&bu=&subtree=&expiring_within=&risk=` | acceptance.view (RLS) | The list (AC-19) |
| `POST /acceptances` | acceptance.request at the risk's BU | Request, or renew (`renews`) (AC-01, AC-11) |
| `GET /acceptances/{id}` | acceptance.view | Head, needs-review reasons, history, the evidence, who may decide (AC-16) |
| `POST /acceptances/{id}/decisions` | acceptance.approve at the tier's BU | Approve or reject with a rationale (AC-05, AC-06) |
| `POST /acceptances/{id}/withdraw`, `/revoke` | the requester; an approver | With a reason (AC-03, AC-15) |
| `GET /acceptances/inbox` | acceptance.approve anywhere | Pending and suspended acceptances the caller may decide (AC-08) |
| `GET /acceptances/tiers` | acceptance.view anywhere | The tiers in force, for the forms |

- Conventions are F-001 §6.
- Errors:
  - 409 `exposure_not_current`, `not_accept`, `pending_exists`, `already_decided`, `not_pending`;
  - 403 `not_your_tier`, `separation_of_duties`;
  - 422 `invalid_request` with problems.
- The register API (F-007) gains each risk's `acceptance` (`state`, `expires_on`, `needs_review`) and the list's `?acceptance=` filter (`active`, `pending`, `suspended`, `none`, `needs_review`, `expiring`).

## 7. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| E: someone accepts a risk beyond their authority | The tier's BU and approvals are fixed at request (or review) from the settings in force; the definer checks `acceptance.approve` at the tier's BU for each decision | `TestSTRIDEF008Authority` |
| E: one person requests and approves, or approves twice | Requester, owner and approvers differ; one decision per approver; F-001's built-in SoD rule keeps `analysis.edit` and `acceptance.approve` apart | `TestSTRIDEF008SeparationOfDuties` |
| T: an acceptance's history or evidence is altered | Heads written only by definer functions; steps append-only for every role; the evidence copied at request | `TestSTRIDEF008HistoryTamper` |
| T: an acceptance outlives its terms | Expiry bounded by the setting; the job expires, and reads treat a past expiry as expired; a higher tier suspends | `TestAcceptanceExpiry` |
| I: acceptances cross business units | RLS on both tables (`acceptance`); the inbox lists only acceptances the caller can see and decide | `TestSTRIDEF008Visibility` |
| R: a decision cannot be attributed | Every step audited in its transaction with actor, BU and reason | `TestAcceptanceAuditEvents` |
| D: request floods | One open request per risk; bodies bounded; the job's sweep set-based | `TestAcceptanceLimits` |

## 8. New catalog event types
- **Lifecycle:** `acceptance.requested`, `acceptance.withdrawn`, `acceptance.approved`, `acceptance.rejected`, `acceptance.activated`.
- **Review:** `acceptance.suspended`, `acceptance.review_requested`, `acceptance.reactivated`.
- **Ending:** `acceptance.revoked`, `acceptance.expired`, `acceptance.replaced`, `acceptance.ended`.

All are category `risk_data`, severity low, BU required. Decisions (`approved`, `rejected`, `revoked`) are severity medium.

## 9. Requirements traceability
| AC | Design | Verification |
|---|---|---|
| AC-01 to AC-03 | §3.2, §6 | DB tests of the API |
| AC-04 to AC-08 | §3.2, §3.4, §6 | DB tests (tiers, levels, two approvals, SoD, the inbox) |
| AC-09 to AC-12 | §3.2, §3.6, §4 | DB tests with time travel (expiry, notices, renewal without gap) |
| AC-13 to AC-15 | §3.2, §3.3, §3.5 | DB tests (higher tier suspends, stale flags, revoke) |
| AC-16 to AC-19 | §3.1, §5, §6, §8 | DB tests; RLS harness; audit event tests |
| AC-20 | §2, UI | Playwright and axe |
| NFR performance | §3.5, §6 | `TestBenchmarkGateAcceptances` (10,000 acceptances over 2,000 BUs) |

## 10. Changes to other features
- **F-007:**
  - A risk's acceptance summary and the `acceptance` list filter.
  - Closing a risk ends its open acceptance.
  - `register.exposure_for` for the job.
  - The risk page's Acceptance section (F-007-AC-18).
- **F-005:** two read functions for the register (§3.5).
- **F-001:** bootstrap role `acceptance_definer`; resource type `acceptance` gains tables and fixtures.
- **F-015:** eight settings, packages 1.7.0.
- **F-009:** reads `acceptance.notice_outbox`.

## 11. Deployment modes
Identical in SaaS, self-hosted and air-gapped. No new keys or services.

## 12. Alternatives considered
- **F-001's approval engine for decisions:** rejected (OQ7). Its requests are single-step with one approver and no tiers, suspension or renewal, and the decisions belong in the acceptance's own evidence.
- **Storing "needs review":** rejected, as F-007's staleness. It would go out of date.
- **Suspending on a stale exposure:** rejected (decided 2026-11-15). It is flagged only.
- **Tiers as one structured setting:** rejected (OQ1). F-015's settings are scalars with comparators; eight scalars keep strictness checkable.

## 13. Open items
- The reference node for the performance budget, as F-005 §14.

## Change Log
- 2026-11-15: Initial draft. Requirements OQ1 to OQ7 settled as proposed: eight scalar settings for the tiers and the duration; notices at 30, 14 and 7 days and on expiry; a treatment change or a move flags review; closing the risk ends the acceptance; both approvals at the tier's BU; F-008's own records.
- 2026-11-15: **Approved** by Robert Former.
