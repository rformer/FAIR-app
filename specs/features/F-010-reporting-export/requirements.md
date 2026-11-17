# F-010 Reporting and export — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-16

## Summary
F-010 turns what the other features hold into reports that people read outside the analysis workspace: risk committees, executives, auditors and the risk owners who answer to them. It has two parts. The first is a **portfolio dashboard** in the app: a business unit subtree's quantified exposure, its largest risks, how much of the register has a current analysis, the state of acceptances and treatment, and how these have moved over time. The second is a small set of **built-in reports**, produced on request or on a schedule as accessible PDF, CSV and a documented JSON format: the risk register, the portfolio, a single risk with its analyses, acceptances, and treatment progress. Every report is a snapshot of what its requester could see when it was made. It says when it was made, by whom, from which data and analyses, and in which currency, and it carries the installation's marking. Reports keep to Open FAIR: exposure is shown as a loss distribution, never as an ordinal score (P1). Restricted business units appear only as their roll-up mode allows. Every report and download is recorded in the audit trail, and report files stay in the platform until someone with the right permission downloads them; scheduled reports announce themselves through an F-009 notice that links back, never by emailing the file.

## Users & roles affected
- **CISO, risk committee, executive viewer** (`report.view`): the dashboard and reports in the app for the business units they can see.
- **Risk owners, analysts, approvers** (`report.view`): the same, for their own business units.
- **Anyone producing report files** (`report.export`, existing, privileged): generates and downloads PDF, CSV and JSON reports, and schedules them.
- **Auditor** (`report.view`, and `report.export` per OQ4): reads reports as evidence, and the audit records of who produced which report.
- **Integrations** (F-001 service accounts with `report.export`): fetch report data for the customer's BI tools through the API.
- **Platform administrator**: sets the report settings through the posture workflow (F-015).

## User stories
### F-010-R-01 The portfolio dashboard
**As a** CISO or risk committee member, **I want** one page that shows a business unit's quantified risk at a glance, **so that** I can see where the exposure is and whether the register is current.

**Acceptance criteria (EARS):**
- F-010-AC-01: WHEN a holder of `report.view` opens the dashboard for a business unit they can see, THE SYSTEM SHALL show, for its subtree and from data they can see: the total exposure from the latest roll-up (F-007), the largest open risks by mean annualized loss, the exposure of each child business unit, the coverage (open risks with a current analysis, stale, and unquantified), acceptances (active, expiring within 30 days, expired, awaiting decision), and treatment (open and overdue actions).
- F-010-AC-02: THE SYSTEM SHALL show every exposure as a distribution: its mean with its 10th and 90th percentiles, and the loss exceedance curve where one is drawn. It SHALL never show an ordinal score, heat map or rating derived from them (P1).
- F-010-AC-03: THE SYSTEM SHALL show the time of the roll-up each figure comes from and mark it when it is stale (F-007-AC-12). WHERE no roll-up exists for the business unit, THE SYSTEM SHALL say so, and a holder of `register.view` there SHALL be able to request one from the dashboard.
- F-010-AC-04: THE SYSTEM SHALL include restricted business units below the viewer's only as their roll-up mode allows (F-001-AC-62), and SHALL say how many risks each figure leaves out and why.
- F-010-AC-05: THE SYSTEM SHALL give every chart on the dashboard a text alternative and a data table (ADR-014), and every figure SHALL link to the register, risk or acceptance it summarizes, where the viewer's own permissions apply.

### F-010-R-02 Trends over time
**As a** risk committee member, **I want** to see how exposure and coverage have changed, **so that** I can tell whether treatment is working.

**Acceptance criteria (EARS):**
- F-010-AC-06: THE SYSTEM SHALL record a portfolio snapshot of each business unit every `report.snapshot_interval_days`: the summary of its latest roll-up (with the roll-up's time), its coverage, and its acceptance and treatment counts. Snapshots SHALL be immutable and kept for `report.snapshot_retention_days`.
- F-010-AC-07: WHEN a viewer opens the dashboard's trend view, THE SYSTEM SHALL chart the business unit's snapshots over a chosen period, and SHALL show a snapshot only to a viewer who sees every risk it was computed from (as F-005 aggregates), restricted units included only by their roll-up mode.

### F-010-R-03 Built-in reports
**As a** risk manager, **I want** standard reports I can take to a committee or an auditor, **so that** I do not rebuild them by hand from screenshots.

**Acceptance criteria (EARS):**
- F-010-AC-08: THE SYSTEM SHALL provide these reports for a business unit subtree, with filters: **Risk register** (each open risk with its owner, category, exposure, exposure status, treatment decision, and acceptance state and expiry; filters by status, owner, category, decision and acceptance state); **Portfolio** (the dashboard's content as a document, for a chosen period); **Acceptances** (by state, those expiring within a chosen number of days, and the decisions in a period with their tier, approvers and reasons); **Treatment** (actions by due date and owner, overdue ones first).
- F-010-AC-09: THE SYSTEM SHALL provide a **Risk** report for one risk: its description, owner and category; each linked scenario with its pinned analysis results (curve, distribution, drivers, control sets, F-006); the inputs' provenance (estimate requests and sources, F-004), without any calibration records; its treatment plan and actions; and its acceptance history.
- F-010-AC-10: THE SYSTEM SHALL state on every report its title, the business unit scope and filters, when it was generated and by whom, the time of the data, the currency (F-003-AC-07), the analysis runs its figures come from with their engine version and digests (F-005), and the installation's marking (`report.marking`) on every page.
- F-010-AC-11: THE SYSTEM SHALL build each report from one consistent read of the data the requester can see at generation, under row-level security, and SHALL say which risks it leaves out (not visible, restricted by roll-up mode, unquantified).

### F-010-R-04 Formats
**As a** report reader, **I want** reports in formats I can read, file and process, **so that** they serve committees, auditors and tools alike.

**Acceptance criteria (EARS):**
- F-010-AC-12: THE SYSTEM SHALL produce each report as PDF that is tagged for assistive technology (headings, reading order, document language and title, tables with header cells, and a text alternative and data table for every chart) and readable without any network access.
- F-010-AC-13: THE SYSTEM SHALL produce the tabular content of each report as CSV (one file per table, with cells a spreadsheet would read as formulas made inert) and the whole report as JSON in a documented, versioned format.
- F-010-AC-14: THE SYSTEM SHALL compute the SHA-256 digest of every report file, show it in the report's listing, and record it in the audit trail, so that a copy can be checked against the record.

### F-010-R-05 Producing and retrieving reports
**As a** holder of `report.export`, **I want** to generate reports and come back for them, **so that** a large report does not tie up my browser.

**Acceptance criteria (EARS):**
- F-010-AC-15: WHEN a holder of `report.export` at the report's business unit requests a report, THE SYSTEM SHALL generate it in the background, show its progress, and keep the files for `report.retention_days`, listed to the requester alone.
- F-010-AC-16: WHERE the setting `export.reason_required` is in force for any business unit in a report's scope (F-015 sets it for restricted subtrees), THE SYSTEM SHALL require a reason when the report is requested, and record it.
- F-010-AC-17: WHEN the requester downloads a report file, THE SYSTEM SHALL re-check that they still hold `report.export` at its business unit and SHALL record the download. IF they no longer do, THEN THE SYSTEM SHALL refuse it.
- F-010-AC-18: IF a report would exceed the limits (OQ11) or a requester has too many reports generating, THEN THE SYSTEM SHALL refuse the request with the limit, before generating anything.

### F-010-R-06 Scheduled reports
**As a** risk committee secretary, **I want** a report produced before every meeting, **so that** the committee always has a current pack.

**Acceptance criteria (EARS):**
- F-010-AC-19: THE SYSTEM SHALL let a holder of `report.export` schedule a built-in report, with its scope, filters and formats, daily, weekly or monthly at a chosen hour (UTC), for themselves (OQ5).
- F-010-AC-20: WHEN a schedule is due, THE SYSTEM SHALL generate the report as its owner can see the data at that moment and SHALL notify the owner through F-009 (a `report.ready` notice linking to the report, with no report content). IF the owner is inactive or no longer holds `report.export` at the schedule's business unit, THEN THE SYSTEM SHALL suspend the schedule and notify the owner.
- F-010-AC-21: IF schedules fell due while the system was down, THEN THE SYSTEM SHALL produce one report per schedule on recovery, not one per missed time.

### F-010-R-07 Data for BI tools
**As a** risk team with its own BI tooling, **I want** the register and portfolio data through the API, **so that** our dashboards use the platform's numbers.

**Acceptance criteria (EARS):**
- F-010-AC-22: THE SYSTEM SHALL let users and service accounts (F-001) with `report.export` request any built-in report's JSON or CSV through the documented API, under the same scope, limits, reason and audit rules as the UI.

### F-010-R-08 Evidence
**As an** auditor, **I want** a record of every report produced and downloaded, **so that** I can show who took which risk data out of the platform.

**Acceptance criteria (EARS):**
- F-010-AC-23: THE SYSTEM SHALL record in the audit trail, in the transaction that makes them, each report requested (its kind, scope, filters, formats and reason), each report generated (its file digests) or failed, each download, and each schedule created, changed, suspended or deleted, with the actor and the business unit.

## Non-functional requirements
- Performance: the dashboard opens within 2 s p95 for a subtree of 10,000 risks. A risk register report of 10,000 risks is generated within 60 s as PDF and within 15 s as CSV or JSON; a Risk report within 30 s; a portfolio report within 60 s. The list of reports opens within 500 ms p95.
- Security / privacy: reports contain only what the requester could see at generation (row-level security, restricted roll-up modes); downloads are re-checked. Generating a report makes no network request (no external fonts, images or services; A7). Values placed in PDF, CSV and JSON are neutralized (no formula cells, no markup, no file names from data). Report files are kept only in the platform's own storage, for their retention, and are never sent by email or webhook. Calibration records (F-004) never appear in reports. `report.export` is privileged.
- Audit: as AC-23; events in the catalog.
- Availability: generation and schedules are jobs that survive restarts and catch up (AC-21); a failed report is reported to its requester and can be requested again.
- Accessibility: the dashboard and report pages meet WCAG 2.1 AA; PDF reports are tagged (AC-12) to Section 508 (Q3; PDF/UA per OQ10).
- Secure defaults: no schedules exist on install; `report.marking` is set; `report.retention_days` is 30; `export.reason_required` is on in restricted subtrees.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Dashboard and reports | Yes | Yes | Yes |
| Report files | Kept in the platform's storage | Same | Same; files leave the enclave only by the customer's own process |
| Scheduled report notices | F-009 (in app, email, webhooks) | Same | Same, inside the enclave |
| BI access | API with service accounts | Same | Same, inside the enclave |

## Control mapping (NIST SP 800-53r5)
To be proposed with the tasks.

## Out of scope
- Heat maps, likelihood-by-impact matrices and ordinal ratings (P1).
- A report designer or customer-defined templates; v1 has the built-in reports only (OQ2).
- Word, PowerPoint and Excel formats (OQ3).
- Emailing or posting report files; scheduled reports send a notice that links back (F-009-AC-05).
- Sending scheduled reports to people other than the schedule's owner (OQ5).
- Regulator-specific disclosures (for example SEC cybersecurity filings) and board narrative writing.
- Direct database or BI connector access; integrations use the API (AC-22).
- Importing an existing register (F-011); OSCAL posture exports (F-015); audit evidence exports (F-002); calibration reports (F-004).

## Dependencies
- F-001: `report.view` and `report.export` (catalog version 1), built-in roles (a catalog version 5 if OQ4 changes them), restricted business units' roll-up modes, service accounts, row-level security.
- F-002: audit trail; F-015: settings (`export.reason_required`, the `report.*` settings), the deployment mode.
- F-005 and F-006: analysis results, their digests and the chart components (ADR-014); F-003: the currency and scenarios; F-004: estimate provenance.
- F-007: the register, roll-ups, coverage and treatment; F-008: acceptances and decisions; F-009: the `report.ready` notice kind.

## Open Questions
- OQ1 (resolved 2026-11-16: as proposed). Dashboards or PDF reports (product vision OQ2)? Proposed: both, as R-01 and R-03: an in-app dashboard for reading, and built-in reports for committees, auditors and filing.
- OQ2 (resolved 2026-11-16: as proposed). Which reports in v1? Proposed: the five in AC-08 and AC-09 (risk register, portfolio, acceptances, treatment, risk), with no customer-defined templates; new reports arrive with later releases.
- OQ3 (resolved 2026-11-16: as proposed). Formats? Proposed: PDF, CSV and JSON (`fair.report.v1`). No Excel, Word or PowerPoint in v1: CSV opens in spreadsheets, and the PDF is the document of record.
- OQ4 (resolved 2026-11-16: as proposed). Permissions? Proposed: `report.view` for the dashboard and reading reports in the app; `report.export` (privileged) for generating files, downloading them, schedules and API access. Today only Platform Admin holds `report.export`; proposed to add it to the built-in Executive Viewer, Risk Analyst and Auditor roles in permission catalog version 5 (re-signed).
- OQ5 (resolved 2026-11-16: as proposed). Who receives scheduled reports? Proposed: the schedule's owner only, generated under their own access at run time. Other committee members schedule their own, so that no one receives data they cannot see. Distribution beyond the platform is the owner's, and every download is recorded.
- OQ6 (resolved 2026-11-16: as proposed). Trend snapshots (AC-06, AC-07)? Proposed: weekly (`report.snapshot_interval_days`, default 7, bounds 1 to 31), kept 3 years (`report.snapshot_retention_days`, default 1,095, bounds 365 to 3,650). Snapshots record each business unit's latest roll-up summary with its time rather than running new simulations; counts are computed at the snapshot.
- OQ7 (resolved 2026-11-16: as proposed). Where does `export.reason_required` apply? F-015 left its enforcement to F-010. Proposed: F-010 registers the setting (business-unit scoped, off by default, on in restricted subtrees through the overlay) and enforces it for every export of risk data: F-010's reports, F-003's risk export and F-006's downloads.
- OQ8 (resolved 2026-11-16: as proposed). Retention of report files? Proposed: `report.retention_days`, default 30, bounds 1 to 365; the files are then deleted, while their audit records and digests remain.
- OQ9 (resolved 2026-11-16: as proposed). The marking (AC-10)? Proposed: `report.marking`, a short text (default "Confidential"), on every PDF page's header and footer, in the JSON's metadata, and as the CSV's first line.
- OQ10 (resolved 2026-11-16: as proposed). PDF accessibility level? F-001's PDF writer is tagged but not PDF/UA, since it uses the standard fonts unembedded. Proposed: reach PDF/UA-1 for F-010's reports (embedded fonts, vector charts with text alternatives), extending the writer and keeping it free of network access.
- OQ11 (resolved 2026-11-16: as proposed). Limits (AC-18)? Proposed: up to 10,000 risks in a report's scope, files up to 100 MiB, at most 3 reports generating per requester, and at most 20 schedules per person.

## Change Log
- 2026-11-16: Initial draft, In Review.
- 2026-11-16: Approved by Robert Former; OQ1 to OQ11 resolved as proposed.
- 2026-11-16: OQ4 amended by Robert Former (T-01): `report.export` is privileged (F-001-AC-54), and adding it to Executive Viewer and Risk Analyst would make their holders privileged users (phishing-resistant MFA, F-001-AC-06). Instead catalog version 5 adds a built-in Report Publisher role (`report.view`, `report.export`), granted beside other roles, and Auditor gains `report.export`. The draft's "today only Platform Admin holds `report.export`" was wrong: no built-in role held it.
- 2026-11-17: AC-22 (Robert Former, T-09): service accounts cannot hold privileged permissions (F-001 AC-36), and `report.export` is privileged. Resolved by amending F-001 AC-36 (T-09b): `report.export` is the one privileged scope a service account may hold, and only through the dual-approval path.
