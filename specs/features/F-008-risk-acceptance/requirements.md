# F-008 Risk Acceptance Lifecycle — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-15

## Summary
F-008 manages the lifecycle of a risk acceptance: a request to accept a register risk (F-007) as it stands, its review and approval by people whose authority matches the size of the risk, its expiry, and its renewal. The authority is set by exposure tiers: the risk's mean annualized loss places it in a tier, and the tier says how far up the business unit tree the approvers must sit and how many are needed. Every acceptance has an expiry date and lapses on it unless renewed through the same review. An accepted risk goes back to review when a newer analysis puts it in a higher tier, and is flagged when its exposure goes stale. Every step is recorded as audit evidence, and the register shows each risk's acceptance state.

## Users & roles affected
- **Risk owner** (`acceptance.request`, with `register.edit` and `treatment.edit`): requests acceptance of a risk whose treatment decision is accept, renews it, withdraws a pending request.
- **Approver** (`acceptance.approve`, privileged): reviews requests in their business units at the tier's level, approves or rejects them, revokes acceptances.
- **CISO, risk committee** (`acceptance.approve` at higher business units): approve the larger risks the tiers send to them.
- **Auditor, executive viewer** (`acceptance.view`): read acceptances and their evidence.
- **Platform administrator** (`settings.change`, F-015): sets the tiers and the maximum duration within their bounds.

## User stories

### F-008-R-01 Request acceptance
**As a** risk owner, **I want** to ask for a risk to be accepted as it stands, with my reasons and an expiry, **so that** the decision is made by the right people and recorded.

**Acceptance criteria (EARS):**
- F-008-AC-01: WHEN a holder of `acceptance.request` at a risk's business unit requests acceptance of an open risk whose treatment decision is accept THE SYSTEM SHALL record the request with its justification, any conditions, a proposed expiry date, the risk's exposure at the time (its mean annualized loss and the analyses pinned for it) and the tier that exposure falls in.
- F-008-AC-02: IF the risk's exposure is not current (stale, unquantified or computing), the treatment decision is not accept, the proposed expiry is later than the maximum duration allows, or the risk already has a pending request THEN THE SYSTEM SHALL refuse the request and say why.
- F-008-AC-03: THE SYSTEM SHALL let the requester withdraw a pending request with a reason.

### F-008-R-02 Review and approval by tier
**As an** approver, **I want** the requests that need my authority sent to me with the evidence, **so that** the size of a risk decides who accepts it.

- F-008-AC-04: THE SYSTEM SHALL place each request in an exposure tier by the risk's mean annualized loss; each tier names the business unit level at which approvers must hold `acceptance.approve` (the risk's business unit, an ancestor a given number of levels up, or the root) and the number of approvals needed (one or two). For a risk inside a restricted business unit, the level never leaves its restricted subtree: an ancestor beyond it, and the root, are the top of that subtree (amended 2026-11-15).
- F-008-AC-05: THE SYSTEM SHALL accept a decision on a request only from a holder of `acceptance.approve` at the tier's business unit or above it, who is neither the requester nor the risk's owner; two approvals SHALL come from two different people.
- F-008-AC-06: WHEN an approver approves or rejects a request THE SYSTEM SHALL record the decision with a rationale; an approval MAY shorten the expiry, and a rejection ends the request.
- F-008-AC-07: WHEN a request has the approvals its tier needs THE SYSTEM SHALL make the acceptance active until its expiry date, and show it on the risk (F-007-AC-18).
- F-008-AC-08: THE SYSTEM SHALL show each approver the pending requests they may decide, with the risk, its exposure and the analyses it rests on, the justification and the conditions.

### F-008-R-03 Expiry and renewal
**As a** risk committee, **I want** every acceptance to end on a date unless it is reviewed again, **so that** no acceptance outlives the reasons for it.

- F-008-AC-09: WHEN an active acceptance reaches its expiry date THE SYSTEM SHALL end it as expired and show the risk as no longer accepted.
- F-008-AC-10: THE SYSTEM SHALL queue notices to the risk owner and the requester before an acceptance expires and when it expires, for F-009 to deliver.
- F-008-AC-11: THE SYSTEM SHALL let a holder of `acceptance.request` request renewal of an active acceptance before it expires; the renewal SHALL be placed in a tier and approved as a new request, and WHEN it is approved THE SYSTEM SHALL replace the acceptance it renews without a gap, the old one remaining active until then.
- F-008-AC-12: THE SYSTEM SHALL bound every expiry by a maximum duration, an F-015 setting with bounds.

### F-008-R-04 Back to review when the risk changes
**As an** approver, **I want** an acceptance I approved to come back to review when the risk grows beyond my authority, **so that** acceptances keep matching the risk.

- F-008-AC-13: WHEN an accepted risk's current exposure falls in a higher tier than the one its acceptance was approved in THE SYSTEM SHALL suspend the acceptance and open a review that needs the higher tier's approvals; WHEN those are given THE SYSTEM SHALL make it active again, and WHEN it is rejected THE SYSTEM SHALL end it.
- F-008-AC-14: WHILE an accepted risk's exposure is stale THE SYSTEM SHALL flag its acceptance as needing review, leaving it in force.
- F-008-AC-15: THE SYSTEM SHALL let an approver who could approve it revoke an active or suspended acceptance with a reason.

### F-008-R-05 Evidence and visibility
**As an** auditor, **I want** to see who accepted each risk, on what evidence, until when, **so that** acceptances can be relied on.

- F-008-AC-16: THE SYSTEM SHALL keep each acceptance's full history: the request, the exposure and analyses it was based on, every decision with its approver and rationale, suspension, renewal, revocation, withdrawal and expiry, and SHALL keep it after the acceptance ends.
- F-008-AC-17: THE SYSTEM SHALL show acceptances only to holders of `acceptance.view` at the risk's business unit, under F-001's row-level security, and SHALL require `acceptance.request` or `acceptance.approve` there for changes.
- F-008-AC-18: THE SYSTEM SHALL record in the audit trail (F-002), in the change's transaction, each request, withdrawal, decision, activation, suspension, renewal, revocation and expiry, with the actor, the business unit and the reason where one is given.
- F-008-AC-19: THE SYSTEM SHALL list the acceptances a user can see, filterable by state (pending, active, suspended, needing review, expired, ended), by business unit with its subtree and by how soon they expire, and SHALL let the register filter risks by acceptance state.
- F-008-AC-20: THE SYSTEM SHALL meet WCAG 2.1 AA on every F-008 page.

## Non-functional requirements
- Performance: an approver's pending requests and the acceptance list open within 1 s p95 with 10,000 acceptances across 2,000 business units; an acceptance's page within 1 s.
- Security / privacy: acceptances are business-unit-owned data under row-level security; `acceptance.approve` is privileged (F-001); separation of duties holds (requester, owner and approver differ; F-001's built-in rule keeps `analysis.edit` and `acceptance.approve` apart).
- Audit: as AC-18; events in the catalog and in the trail in the change's transaction.
- Availability: expiry, suspension and notices are processed by a job that survives restarts and catches up after an outage; an acceptance past its expiry is never shown as active.
- Deployment modes: identical in SaaS, self-hosted and air-gapped.
- Secure defaults: the shipped tiers send every acceptance to an approver, larger ones higher and to two approvers; the maximum duration is bounded.

## Control mapping (NIST SP 800-53r5)
To be proposed with the tasks.

## Out of scope
- Delivering notices by email or webhook (F-009); F-008 queues them.
- Risk appetite and tolerance statements beyond the tiers.
- Exceptions to configuration settings (F-015 has its own) and to control requirements (F-013).
- Reports and exports of acceptances (F-010).
- Tracking the conditions of an acceptance as tasks; they are recorded as text (treatment actions are F-007's).
- Accepting anything but a register risk.

## Dependencies
- F-007: risks, their treatment decision accept, their exposure and its status, the register's pages (AC-18 shows the acceptance state).
- F-001: `acceptance.request`, `acceptance.approve`, `acceptance.view` (catalog version 1), the Risk Owner and Approver roles, separation of duties, row-level security, the business unit tree.
- F-015: the tier and duration settings; F-002: audit trail; F-009: delivery of the queued notices.

## Open Questions
- OQ1. The tier setting's shape (AC-04): F-015's settings are scalars. Proposed: three tiers held as scalar settings: the upper bounds of tiers 1 and 2 (mean annualized loss, in the installation currency), and for each tier its level and its number of approvals; defaults: tier 1 up to 100,000 at the risk's business unit, one approval; tier 2 up to 1,000,000 at its parent, one approval; tier 3 above at the root, two approvals. Bounds keep every tier at one approval or more and tier 3 at the root.
- OQ2. Maximum duration (AC-12): Proposed: setting `acceptance.max_duration_days`, default 365, bounds 30 to 730.
- OQ3. Notices (AC-10): Proposed: 30, 14 and 7 days before expiry and on expiry, to the owner and the requester; as F-015's exception notices, queued in an outbox for F-009.
- OQ4. The treatment decision changing from accept while an acceptance is in force (not a re-review trigger, decided 2026-11-15). Proposed: the acceptance stays, flagged as needing review, as for a stale exposure.
- OQ5. The risk closed or moved while accepted (not a re-review trigger, decided 2026-11-15). Proposed: closing the risk ends its acceptance (nothing left to accept); a move keeps it, flagged as needing review, since the approvers' business units may differ.
- OQ6. Which approvers count for a two-approval tier (AC-05). Proposed: both at the tier's business unit or above it, two different people, neither the requester nor the owner.
- OQ7. Using F-001's approval engine (T-26) or F-008's own records for the decisions. Proposed: F-008's own versioned records (the decisions are part of the acceptance's evidence, and the tiers and re-review rules are F-008's), settled in the design.

## Change Log
- 2026-11-15: Initial draft. Scope decisions taken with Robert Former: approval authority by configurable exposure tiers; tiers placed by mean annualized loss; every acceptance expires and is renewed by a new approval; re-review when the exposure enters a higher tier (suspended) or goes stale (flagged).
- 2026-11-15: **Approved** by Robert Former, with the open questions' proposals as stated (to be settled in the design).
- 2026-11-15: AC-04 amended (Robert Former): inside a restricted subtree a tier's level stops at its top, since approvers above it cannot see the acceptance (F-001 restricted business units).
