# F-007 Risk Register — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-13

## Summary
F-007 keeps a living register of the organization's risks, tied to the analyses that quantify them. A register risk names a risk in business terms, has an owner and a business unit, and covers one or more F-003 scenarios. Its quantified exposure is the simulation results its owner has pinned as current (F-005), so the register says exactly which analysis each number comes from and when that analysis has gone stale. Exposure rolls up by business unit as a simulated loss distribution, not a sum of scores. Each risk carries a treatment plan: the decision (mitigate, transfer, avoid or accept), the actions with owners and due dates, and the control set it expects to reach. Accepting a risk is decided in F-008; F-007 records that acceptance is the chosen treatment.

## Users & roles affected
- **Risk owner** (`register.edit`, `treatment.edit`): creates and maintains risks at their business units, pins analyses, plans and tracks treatment.
- **Risk analyst** (`register.view`, `analysis.run`): runs the analyses that risks pin, and reads the register.
- **CISO, risk committee, executive viewer** (`register.view`, `treatment.view`): read risks, exposure and roll-ups at the business units they can see.
- **Auditor** (`register.view`, `treatment.view`): sees which analysis supported each number and every change to a risk.

## User stories

### F-007-R-01 Register risks
**As a** risk owner, **I want** to record a risk in business terms and link the scenarios that analyse it, **so that** the register and the analyses stay one thing.

**Acceptance criteria (EARS):**
- F-007-AC-01: WHEN a holder of `register.edit` at a business unit creates a risk THE SYSTEM SHALL record its title, description, owner (a user who can see the business unit), business unit and category, and SHALL give it the state open.
- F-007-AC-02: THE SYSTEM SHALL let a holder of `register.edit` link scenarios they can see in the risk's business unit and its subtree to the risk, and unlink them, and SHALL refuse to link a scenario that is linked to another open risk, so that no loss is counted twice in a roll-up.
- F-007-AC-03: THE SYSTEM SHALL keep every change to a risk (its fields, its scenarios, its pins, its treatment, its state) as a version with who made it, when and why, and SHALL show a risk's history and the difference between two versions.
- F-007-AC-04: WHEN a holder of `register.edit` closes a risk with a reason THE SYSTEM SHALL keep it, with its history, its last exposure and its scenarios, read-only until it is reopened; closing frees its scenarios to be linked elsewhere.
- F-007-AC-05: THE SYSTEM SHALL keep risks with their business unit (moving a risk moves its versions and treatment, refusing a move that would leave any linked scenario outside the new business unit's subtree) and SHALL treat a risk as business-unit-owned data under F-001's row-level security.

### F-007-R-02 Quantified exposure
**As a** risk owner, **I want** to choose which analysis stands for each risk, **so that** every number in the register is deliberate and traceable to its run.

- F-007-AC-06: THE SYSTEM SHALL let a holder of `register.edit` pin, for each linked scenario, one succeeded run of one of its versions and a control set of that run as the scenario's current analysis, and SHALL record who pinned it and why.
- F-007-AC-07: THE SYSTEM SHALL give a risk's exposure as the pinned result when it has one scenario, and otherwise as an aggregate of its scenarios' pinned results (F-005-AC-18), with the summary (mean, percentiles, chance of any loss), the loss exceedance curve and each scenario's contribution, stating the independence assumption.
- F-007-AC-08: THE SYSTEM SHALL mark a risk's exposure as stale WHEN a linked scenario has no pin, a pinned run is of an older version than the scenario's latest, a pinned result is older than a setting allows, or a linked scenario is archived; and SHALL say which of these applies.
- F-007-AC-09: THE SYSTEM SHALL show, for the business units a user can see, the share of open risks whose exposure is current, and list those that are stale or unquantified.
- F-007-AC-10: WHEN a linked scenario gets a newer succeeded run THE SYSTEM SHALL show that one is available, and SHALL change the pin only when a holder of `register.edit` adopts it.

### F-007-R-03 Business unit roll-ups
**As a** CISO, **I want** the combined exposure of a business unit and its subtree, **so that** I can see where risk concentrates and how it changes.

- F-007-AC-11: THE SYSTEM SHALL compute, on request of a holder of `register.view` at a business unit, the roll-up of its subtree's open risks as an F-005 aggregate of their pinned results, giving its summary, its loss exceedance curve and each risk's contribution, and SHALL keep each roll-up with the time it was computed and the pins it used.
- F-007-AC-12: THE SYSTEM SHALL mark a roll-up as stale WHEN a risk in it has changed its pins, been closed or added since, or any of its risks' exposure is stale, and SHALL say how many risks it covers and how many it leaves out as unquantified.
- F-007-AC-13: THE SYSTEM SHALL include in a roll-up only risks every one of whose pinned results the requester can see, and say when risks are excluded or aggregated (F-001-AC-26); a restricted business unit below the requester's SHALL contribute by its roll-up mode (F-001-AC-62): Excluded, left out and counted as such; Aggregate only, its mean exposure only, labelled, never its risks, scenarios or distribution; Full, as its risks.
- F-007-AC-14: THE SYSTEM SHALL list a business unit's open risks ordered by mean annualized loss or by the 90th percentile, with each risk's share of the roll-up.

### F-007-R-04 Treatment plans
**As a** risk owner, **I want** to record how each risk will be treated and track the actions, **so that** decisions and their progress are visible and evidenced.

- F-007-AC-15: THE SYSTEM SHALL let a holder of `treatment.edit` at a risk's business unit record its treatment decision (mitigate, transfer, avoid or accept) with a rationale, and, for mitigate, the control set of each linked scenario the treatment is expected to reach.
- F-007-AC-16: THE SYSTEM SHALL show, for a mitigated risk with pinned runs that include its target control sets, the expected exposure after treatment beside the current one, and the reduction, from the same runs (F-006 comparisons).
- F-007-AC-17: THE SYSTEM SHALL let a holder of `treatment.edit` add actions to a plan, each with a title, an owner, a due date and a state (planned, in progress, done, cancelled with a reason), and SHALL flag actions past their due date that are not done.
- F-007-AC-18: WHEN the treatment decision is accept THE SYSTEM SHALL record that an acceptance is needed and show its state from F-008 once it exists; F-007 SHALL NOT itself approve acceptance.

### F-007-R-05 Finding and reading risks
**As a** risk committee member, **I want** to find and read risks quickly, **so that** meetings can work from the register.

- F-007-AC-19: THE SYSTEM SHALL list the risks a user can see with filters for business unit (with subtree), owner, category, state, treatment decision, staleness and overdue actions, sortable by exposure, and SHALL open each risk with its scenarios, pins, exposure (with the F-006 views of its result), treatment and history.
- F-007-AC-20: THE SYSTEM SHALL meet WCAG 2.1 AA on every F-007 page.

### F-007-R-06 Access and audit
**As a** security officer, **I want** the register protected and every change recorded, **so that** it can serve as evidence (S6).

- F-007-AC-21: THE SYSTEM SHALL show risks, treatment and roll-ups only to holders of `register.view` (treatment details: `treatment.view`) at the business units they belong to, under F-001's row-level security, and SHALL require `register.edit` or `treatment.edit` there for changes.
- F-007-AC-22: THE SYSTEM SHALL record in the audit trail (F-002), in the change's transaction, each risk created, changed, moved, closed and reopened, each scenario linked or unlinked, each pin set or adopted, each treatment decision and action changed, and each roll-up computed, with the actor, the business unit and the reason where one is required.

## Non-functional requirements
- Performance: the register list of 10,000 open risks across 2,000 business units opens within 1 s p95 for a user who sees them all; a risk's page within 1 s; a roll-up of 500 risks computes within 30 s.
- Security / privacy: risks, versions, pins, treatment and roll-ups are BU-owned data under row-level security; restricted business units follow F-001's roll-up modes.
- Audit: as AC-22; events in the catalog (F-001 T-37) and in the trail in the change's transaction.
- Availability: roll-ups run as jobs and survive restarts; a failed roll-up is recorded and retried, never left running.
- Deployment modes: identical in SaaS, self-hosted and air-gapped.
- Secure defaults: the stale-analysis age is an F-015 setting with bounds; closing and moving need a reason.

## Control mapping (NIST SP 800-53r5)
To be proposed with the tasks.

## Out of scope
- Risk appetite and tolerance, and flagging exposure above them (F-008 or later).
- Approving and expiring risk acceptances (F-008).
- Notifications of stale analyses or overdue actions (F-009).
- Reports and exports of the register, and importing an existing register (F-010, F-011).
- Review cadences for risks.
- Qualitative or scored risks without scenarios (a risk without a pinned analysis is listed as unquantified, not scored).
- Correlation between risks in roll-ups (independence is assumed and stated, as in F-005).

## Dependencies
- F-003: scenarios, versions, control sets, archive and move; F-005: runs, aggregates, engine versions; F-006: result views and comparisons.
- F-001: `register.*` and `treatment.*` permissions (catalog version 3), the Risk Owner role, row-level security, restricted business units and roll-up modes (T-30), users for owners.
- F-002: audit trail; F-015: settings.
- F-008: acceptance state shown on accepted risks.

## Open Questions
- OQ1. Pinning with several scenarios (AC-07): the risk pins one run and control set per scenario and the service makes the F-005 aggregate when the pins change; F-005 aggregates need equal iteration counts. Proposed: pins with unequal iterations are allowed, and the exposure aggregate is refused until they match, with the risk shown as stale ("iterations differ").
- OQ2. The pinned control set: the scenario's current set by default. Proposed: yes; another set may be pinned only with a reason, and the register shows it.
- OQ3. Categories (AC-01): a fixed list, or an administrator-managed list. Proposed: an administrator-managed list at the root (a setting-like list owned by `register.edit` at the root), starting with a short default list.
- OQ4. Stale age (AC-08): Proposed: setting `register.analysis_max_age_days`, default 365, bounds 30 to 730.
- OQ5. Who may compute a roll-up (AC-11): it runs an aggregate on the engine. Proposed: any holder of `register.view` at the business unit, rate-limited per business unit, since it reads only results they can see; it is recorded as theirs.
- OQ6. Restricted subtrees in roll-ups (AC-13): the Aggregate only form. Proposed: their mean annualized loss total through F-001's roll-up definer functions, labelled "restricted business units (mean only)", added to the roll-up's mean and listed apart, not in its distribution or curve; Full mode includes their pinned results in the aggregate.
- OQ7. Moving scenarios between business units after linking (F-003 move): Proposed: a scenario move that would take a linked scenario outside its risk's subtree is refused with the risk named, unless it is unlinked first.

## Change Log
- 2026-11-13: Initial draft; scope decisions (a risk covers one or more scenarios; owners pin the results that count; business unit roll-ups as simulated aggregates; treatment plans in F-007; appetite, import/export and review cadence left out) taken with Robert Former.
- 2026-11-13: **Approved** by Robert Former, with the open questions' proposals as stated (to be settled in the design).
