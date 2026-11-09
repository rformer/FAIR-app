# F-004 Calibrated Estimate Capture — Requirements
Status: **Approved** | Owner: Robert Former | Last updated: 2026-11-09

## Summary
F-004 is how the numbers in a FAIR analysis are obtained and how far they can be trusted (constitution P2). An analyst sends estimate requests for chosen factors of a scenario to subject-matter experts, who answer independently with a range, a confidence level, a rationale and sources, helped by the factor's definition, reference data the analyst attaches, a preview of what their range implies and the equivalent-bet test. The analyst reviews the answers side by side and accepts them into the scenario (F-003) — one answer, or several combined by a named method — so that every accepted number traces back to who gave it, how calibrated they were at the time, and how it was combined. People train and measure their calibration with exercises in the platform; their calibration score accompanies their estimates and is personal data, shown only to those who need it.

## Concepts
- **Estimate request**: a request from an analyst to one or more estimators for estimates of named factors of one scenario version, with a due date. Each estimator answers independently.
- **Answer**: one estimator's estimate of one factor in a request: minimum, most likely, maximum, confidence level, rationale and sources (the F-003 estimate), or a declined factor with a reason.
- **Combination**: how the accepted estimate of a factor is made from the answers: one answer chosen, a named pooling method over several answers, or the analyst's own estimate informed by them.
- **Calibration**: a person is calibrated when their stated confidence matches how often they are right — their 90% ranges contain the true value about 90% of the time, and their "70% sure" answers are right about 70% of the time.
- **Calibration exercise**: a set of questions with known answers: range questions ("give a range you are 90% sure contains the answer") and binary questions ("true or false, and how sure are you, from 50% to 100%").
- **Calibration score**: a measure of a person's calibration over their recent exercises, with a classification (calibrated, overconfident, underconfident, not yet measured).
- **Reference class**: data a customer records to inform estimates — counts of events over a period, or observed losses — with its source, for example a business unit's past incidents. It is the customer's own data, never presented as industry data.
- **Equivalent-bet test**: the prompt that checks a range: "would you rather win a prize if the true value is in your range, or by spinning a wheel with a 90% chance of winning?" A calibrated estimator is indifferent.

## Users & roles affected
- **Risk analyst**: sends, manages and accepts estimate requests (`estimate.request`, with `scenario.edit`); maintains reference classes (`library.edit`); sees the calibration scores of the estimators they work with.
- **Estimator** (new built-in role): answers requests addressed to them (`estimate.submit`) at a business unit. Any user may hold it alongside other roles.
- **Everyone with an account**: may take calibration exercises and see their own record (`calibration.take`, in every built-in role).
- **Calibration administrator**: maintains customer question sets (`calibration.manage`; in the Platform Admin role by default).
- **Auditor**: reads requests, answers, acceptances and calibration scores and history (`calibration.audit` in the Auditor role).

## Requirements

### F-004-R-01 Estimate requests
**As a** risk analyst, **I want** to ask the people who know for estimates of specific factors, **so that** a scenario's numbers come from the best-informed sources.

- F-004-AC-01: THE SYSTEM SHALL let a holder of `estimate.request` and `scenario.edit` at a scenario's business unit create an estimate request for one or more factors of the scenario's current version — any factor the scenario's chosen taxonomy levels need (F-003-AC-03), including forms of loss and secondary risk — naming one or more estimators who hold `estimate.submit` at that business unit, a due date, and optional instructions.
- F-004-AC-02: THE SYSTEM SHALL let the analyst choose what scenario context each request shows its estimators (at least the scenario's name, scope, analysis period, asset, threat community, threat effects and loss event), and SHALL show estimators the definition and unit of every requested factor.
- F-004-AC-03: WHILE a request is open THE SYSTEM SHALL let its analyst extend the due date, add or remove estimators, and cancel it with a reason; removing an estimator keeps the answers they already gave.
- F-004-AC-04: WHEN the due date passes THE SYSTEM SHALL close the request to new answers and keep the answers given; WHEN every estimator has answered or declined every factor THE SYSTEM SHALL mark the request complete.
- F-004-AC-05: THE SYSTEM SHALL queue a notification (F-009) to each estimator when they are added to a request, a reminder before the due date (a setting), and a notification to the analyst when an estimator finishes, and SHALL show every user the requests awaiting their answer.
- F-004-AC-06: IF the scenario moves to another business unit, is archived, or gains a newer version that changes a requested factor's definition (its taxonomy level), THEN THE SYSTEM SHALL mark the request as affected and show it to the analyst; answers are never silently re-pointed.

### F-004-R-02 Answering independently
**As an** estimator, **I want** to give my estimate without being anchored by others, **so that** my answer reflects what I know.

- F-004-AC-07: THE SYSTEM SHALL show an estimator only the requests addressed to them and only the context those requests include; it SHALL NOT show an estimator other estimators' answers, the scenario's current value for the factor, or the rest of the scenario.
- F-004-AC-08: WHEN an estimator answers a factor THE SYSTEM SHALL record a minimum, most likely and maximum with a confidence level, a rationale and one or more sources, validated as F-003 validates an estimate (F-003-AC-05, AC-06), or a decline with a reason.
- F-004-AC-09: WHILE a request is open THE SYSTEM SHALL let an estimator revise their answers, keeping every revision with its time; the latest revision is their answer.
- F-004-AC-10: THE SYSTEM SHALL let an estimator save a draft answer that the analyst cannot see until the estimator submits it.

### F-004-R-03 Estimating aids
**As an** estimator or analyst, **I want** help checking my ranges, **so that** my stated confidence is honest.

- F-004-AC-11: WHILE an estimate is being entered (an answer, or an estimate in the F-003 scenario editor) THE SYSTEM SHALL show the factor's definition and unit, a preview of the distribution the range implies, and the equivalent-bet prompt for the stated confidence.
- F-004-AC-12: THE SYSTEM SHALL warn, without refusing, when a most likely value equals a bound, when a range is implausibly narrow or wide for its unit (thresholds in the design), when a probability range reaches 0 or 1, or when the stated confidence is not the one the request asked for.
- F-004-AC-13: THE SYSTEM SHALL let a holder of `library.edit` at a business unit maintain reference classes owned by that business unit — a name, a description, the data (event counts over stated periods, or observed loss amounts in the installation currency, F-003-AC-07), the period covered and the source — versioned and available to descendants as the library is (F-003-AC-08, AC-09).
- F-004-AC-14: THE SYSTEM SHALL let the analyst attach reference classes (a pinned version of each) to a request, show them to its estimators with their sources and with simple summaries (counts per year, observed range), and label them as the customer's own data.

### F-004-R-04 Reviewing and accepting answers
**As a** risk analyst, **I want** to compare the answers and decide what goes into the scenario, **so that** the scenario's estimates are deliberate and traceable.

- F-004-AC-15: THE SYSTEM SHALL show the analyst every submitted answer per factor side by side, with each estimator's calibration score as it was when they answered, the declines with their reasons, and a preview of each combination method's result.
- F-004-AC-16: WHEN the analyst accepts a factor THE SYSTEM SHALL let them use one answer, combine several by a named method (at least an equal-weight pool and a calibration-weighted pool, defined in the design), or enter their own estimate with a rationale that refers to the answers, and SHALL save the accepted estimates as one new scenario version (F-003-AC-15) with a change note.
- F-004-AC-17: THE SYSTEM SHALL compute a combination deterministically, express its result as an estimate (minimum, most likely, maximum at a stated confidence) and record the method, its parameters, and the answers and revisions it used.
- F-004-AC-18: THE SYSTEM SHALL keep, for every accepted estimate, the link from the scenario version and the estimate's place in it to the request, the answers used, their estimators, the estimators' calibration scores at the time, and the method; and SHALL show that provenance on the scenario.
- F-004-AC-19: THE SYSTEM SHALL let an analyst accept a request's factors in more than one step and record which factors of a request have been accepted, into which scenario version.

### F-004-R-05 Calibration exercises
**As a** user, **I want** to practise and measure my calibration, **so that** my estimates improve and others can weigh them.

- F-004-AC-20: THE SYSTEM SHALL let a holder of `calibration.take` start an exercise of a configurable number of questions (a setting) drawn from the active question sets, mixing range questions answered at 90% confidence and binary questions answered with a confidence from 50% to 100%.
- F-004-AC-21: THE SYSTEM SHALL NOT reveal a question's answer before the person submits the exercise, SHALL NOT give a person a question they answered within a period (a setting), and SHALL NOT impose a time limit on any question.
- F-004-AC-22: WHEN a person submits an exercise THE SYSTEM SHALL show each answer against the truth with its source, how many of their ranges contained the truth against the 90% expected, their binary answers' accuracy against their stated confidence, and the equivalent-bet prompt as feedback.
- F-004-AC-23: THE SYSTEM SHALL compute each person's calibration score over their exercises within a window (a setting), classify it as calibrated, overconfident, underconfident or not yet measured (fewer answers than a minimum), and keep the score's history; the scoring rules are defined in the design and documented for users.

### F-004-R-06 Question sets
**As a** calibration administrator, **I want** good questions with sourced answers, **so that** exercises measure calibration and not trivia.

- F-004-AC-24: THE SYSTEM SHALL ship a reviewed set of general-knowledge calibration questions, each with its answer and a citable source, updated with releases and read-only to customers.
- F-004-AC-25: THE SYSTEM SHALL let a holder of `calibration.manage` create, edit, activate and retire installation-wide question sets of range and binary questions, each question with its answer, unit and source; questions in use keep their version, and a retired question no longer appears in new exercises.
- F-004-AC-26: THE SYSTEM SHALL show a question's answer only to holders of `calibration.manage` (and to a person after they submit an exercise containing it), and SHALL keep answers out of every view and export available to those taking exercises.

### F-004-R-07 Calibration records are personal data
**As a** user, **I want** my calibration record seen only by those who need it, **so that** practising does not expose me.

- F-004-AC-27: THE SYSTEM SHALL show a person their own exercises, answers and score history.
- F-004-AC-28: THE SYSTEM SHALL show a holder of `estimate.request` at a business unit the current calibration score and classification — not the exercises or answers — of the estimators who hold `estimate.submit` there, and the score recorded with each answer they review.
- F-004-AC-29: THE SYSTEM SHALL show holders of `calibration.audit` scores, classifications and their history, and SHALL record every view of another person's calibration record in the audit trail.
- F-004-AC-30: THE SYSTEM SHALL delete exercises and their answers older than a retention period (a setting) and the score history beyond it, and SHALL keep the score recorded with an answer as part of that answer's record.

### F-004-R-08 Transfer and history
**As a** risk analyst, **I want** requests and answers to travel with the scenario's history, **so that** an export still explains where the numbers came from.

- F-004-AC-31: THE SYSTEM SHALL include, in the F-003 risk export (F-003-AC-24) of a scenario, the provenance of its accepted estimates (method, answers used, estimators by name and their scores at the time), and SHALL import it as provenance without recreating requests or calibration records.

## Secure defaults
- Estimate requests and answers are owned by the scenario's business unit and enforced in the data layer (A6); estimators read through their own assignment only.
- Answers are invisible to other estimators and to the analyst until submitted; the scenario's own value is never shown to estimators.
- Calibration question answers are never sent to clients taking an exercise.
- Calibration records are personal data: minimal visibility by default, every view of another person's record audited, retention bounded by a setting.
- Free text is length-bounded and refused when it looks like a secret (F-002).
- No external estimators: every estimator signs in through the customer's IdP (S3).

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Shipped question bank | With the release | In the bundle | In the bundle |
| Notifications | Queued for F-009 | Queued for F-009 | Queued for F-009; delivery inside the enclave |
| Reference classes | Customer-entered | Customer-entered | Customer-entered |

## Non-functional requirements
- Performance: an estimator's pending-request list and a request's review view load in ≤ 300 ms p95 at F-001 target scale with 10,000 open requests; scoring an exercise ≤ 1 s p95.
- Security / privacy: as Secure defaults; calibration data is personal data with retention.
- Audit: creating, changing, cancelling and closing requests, submitting and revising answers, accepting estimates, question set changes, and views of others' calibration records are in the trail (F-002), in the transaction of the change.
- Accessibility: WCAG 2.1 AA (Q3); exercises have no time limits and are fully keyboard-operable.
- Availability: as the platform's services.

## Control mapping (NIST SP 800-53r5)
AC-3, AC-6, AU-2, AU-12, RA-3, SI-10, SI-12.

## Out of scope
- The distribution shape behind an estimate and the simulation (F-005); F-004 previews the implied distribution only.
- Historical data feeds and integrations as reference data (F-011); reference classes here are entered by the customer.
- Delivery of notifications by email or chat (F-009); F-004 queues them.
- Estimators without an account (one-time links).
- Multi-round Delphi elicitation (sharing an anonymous summary of the answers and asking again).
- Weighting experts by anything other than their calibration score (for example, seniority).

## Dependencies
- F-001: the permission catalog gains `estimate.request`, `estimate.submit`, `calibration.take`, `calibration.manage`, `calibration.audit`, and the built-in Estimator role (a catalog version upgrade, F-001-AC on catalog upgrades).
- F-002: audit trail; secrets refusal.
- F-003: scenarios, versions, estimates and their validation; the library's ownership and inheritance; the risk export.
- F-009: notification delivery (the outbox is F-004's).
- F-015: settings (reminder lead time, exercise size, question reuse period, score window and minimum, retention).

## Open Questions
- OQ1. Scoring rules: which calibration measure (proportion of range hits and binary accuracy against confidence, or a proper scoring rule such as Brier), and the thresholds between calibrated, over- and underconfident. Proposed: hit rate for ranges and calibration-in-the-large for binary questions, with a binomial tolerance band at the person's answer count; decided in the design.
- OQ2. Combination methods: which pools and how the result returns to minimum, most likely and maximum. Proposed: linear opinion pools over the answers' implied distributions (equal weight; weights from calibration scores), summarised at the requested confidence; decided in the design with F-005's distribution choice.
- OQ3. Range-width warnings (AC-12): fixed per unit, or relative to reference classes when attached. Proposed: fixed per unit in the design, adjustable later.
- OQ4. Who reviews the shipped question bank's answers and sources before release, and how often it is refreshed. Proposed: reviewed by Robert Former for each release that changes it, like the starter library.

## Change Log
- 2026-11-09: Initial draft; scope decisions (estimate requests to platform users, built-in calibration exercises and scores, combination by named methods, shipped and customer question sets, distribution shape left to F-005, reference classes, calibration visibility) taken with Robert Former.
- 2026-11-09: Approved by Robert Former.
