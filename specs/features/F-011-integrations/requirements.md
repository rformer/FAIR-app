# F-011 Integrations and automation inputs — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-17

## Summary
F-011 brings data the customer already holds into the platform, so that analyses start from the organization's own facts rather than from blank forms, and stay current as those facts change. It answers the product vision's OQ1 with four inputs for v1: an **asset inventory** (assets and their values from a CMDB or asset register), **loss event history** (incidents and losses that become reference classes for calibrated estimates, F-004), an **existing risk register** (a one-time or repeated import of risks kept in spreadsheets or another tool), and **control status** (whether the controls scenarios rely on are in place, from the customer's control or GRC tool). Data arrives in two ways: pushed to the platform's API by the customer's own automation (F-001 service accounts) or uploaded as files, which works in every deployment mode; and, where the customer configures one, pulled on a schedule from a source system by a connector, only from allow-listed hosts and, in air-gapped mode, only inside the enclave. Automation assists and humans decide (P4): incoming data is matched to existing records, checked, and presented as proposed changes; nothing an analysis depends on changes until a person with the right permission accepts it, and because scenarios pin versions (F-003), accepting a change never alters a past result. Every run, change and refusal is recorded, and credentials are kept as files or sealed secrets, never shown again.

## Users & roles affected
- **Platform administrator** (`integration.manage`, existing, privileged): configures integrations, their mappings, schedules and credentials, at a business unit.
- **Risk analysts, library editors** (`library.edit`, `control.edit`): review and accept proposed changes to assets, reference classes and controls in their business units.
- **Risk owners** (`register.edit`): import an existing register into their business units.
- **Integration owners** (`integration.view`, new): see integrations, their runs, errors and proposed changes, without changing them.
- **Customer automation** (F-001 service accounts): pushes records through the API under the scopes it was granted.
- **Auditor:** traces any record back to the integration, run and source record it came from.

## User stories
### F-011-R-01 Configuring an integration
**As a** platform administrator, **I want** to connect a source of data to the platform once, **so that** its records keep arriving without manual work.

**Acceptance criteria (EARS):**
- F-011-AC-01: WHEN a holder of `integration.manage` at a business unit creates an integration, THE SYSTEM SHALL record its input kind (assets, loss events, risks or control status), its delivery (pushed to the API, uploaded as files, or pulled by a connector), the business unit subtree it writes into, its field mapping, and, for a connector, its source, schedule and credentials.
- F-011-AC-02: THE SYSTEM SHALL let an integration write only inside its business unit subtree, and only the record kinds of its input kind; a record naming a business unit outside the subtree SHALL be refused, and an integration inside a restricted subtree SHALL be created only by an administrator who holds `integration.manage` inside it.
- F-011-AC-03: THE SYSTEM SHALL accept a connector's credentials once, keep them encrypted at rest or as files, never return them through the API or the UI, and let an administrator replace or remove them.
- F-011-AC-04: IF a connector's source is not on the allow-list (`integration.allowed_hosts`), resolves to a refused address range, or, in air-gapped mode, lies outside the enclave, THEN THE SYSTEM SHALL refuse to save or run it and record the refusal.
- F-011-AC-05: THE SYSTEM SHALL let an administrator pause, resume and delete an integration; deleting it SHALL keep its runs and the provenance of every record it brought in.

### F-011-R-02 Receiving records
**As an** integration owner, **I want** records checked and matched as they arrive, **so that** bad data is caught before anyone relies on it.

**Acceptance criteria (EARS):**
- F-011-AC-06: WHEN records arrive (an API batch, an uploaded file, or a connector run), THE SYSTEM SHALL validate every record against the input kind's documented format and the integration's mapping, and SHALL report each refused record with its position and reason, without refusing the valid ones.
- F-011-AC-07: THE SYSTEM SHALL match each record to an existing platform record by the source's stable identifier (its external ID) within the integration, and SHALL never match by name or merge records from different integrations.
- F-011-AC-08: THE SYSTEM SHALL record each run: its start and end, its trigger, the records received, valid, refused, unchanged and proposed, and its outcome; and a connector run that fails SHALL be retried by its schedule and reported to the integration's owners through F-009.
- F-011-AC-09: THE SYSTEM SHALL let a dry run of a file or batch show what it would propose without recording any change.

### F-011-R-03 Reviewing proposed changes
**As a** risk analyst, **I want** to see and decide what incoming data would change, **so that** automation never silently changes an analysis (P4).

**Acceptance criteria (EARS):**
- F-011-AC-10: THE SYSTEM SHALL present each new or changed record as a proposed change, showing the current and proposed values side by side, the integration, the run and the source record.
- F-011-AC-11: WHEN a holder of the record's edit permission at its business unit accepts a proposed change, THE SYSTEM SHALL apply it as a new version of the record (F-003), with the integration and source recorded as its provenance, and SHALL mark the scenarios pinned to an older version as having a newer version available (F-003-AC-10), without changing them.
- F-011-AC-12: THE SYSTEM SHALL let the reviewer reject a proposed change with a reason, and SHALL not propose the same source values again until they change at the source.
- F-011-AC-13: WHERE an integration's setting allows it (`auto_accept`, off by default), THE SYSTEM SHALL apply descriptive changes (names, descriptions, external references) without review, but SHALL always hold changes to values, estimates, reference data and control status for review.
- F-011-AC-14: IF a record disappears from a connector's source, THEN THE SYSTEM SHALL propose archiving its platform record rather than archive it, and SHALL say which scenarios and risks use it.

### F-011-R-04 Asset inventory
**As a** risk analyst, **I want** assets and their values from our inventory, **so that** scenarios use the assets the business actually runs.

**Acceptance criteria (EARS):**
- F-011-AC-15: THE SYSTEM SHALL bring in assets with their name, type, description, owner business unit, external reference, and optionally a value as a calibrated range with its basis (F-003), and SHALL create asset library entries or propose new versions of them.
- F-011-AC-16: THE SYSTEM SHALL accept asset groups as named sets of assets from the source, matched by the members' external IDs.

### F-011-R-05 Loss event history
**As a** risk analyst, **I want** our incident and loss history as data, **so that** frequency and magnitude estimates start from what has happened (F-004).

**Acceptance criteria (EARS):**
- F-011-AC-17: THE SYSTEM SHALL bring in loss events with their date, business unit, event type (by the customer's own categories, mapped to the platform's), and optionally loss amounts in the installation currency by loss form, keeping each event's source and external ID.
- F-011-AC-18: THE SYSTEM SHALL let an analyst define a reference class from loss events (a filter by business unit, event type and period) and SHALL compute its counts per period and its loss amounts, proposing a new version of the reference class when the matching events change.
- F-011-AC-19: THE SYSTEM SHALL show loss events only to holders of `library.view` at their business unit, and restricted business units' events only inside their restricted subtree.

### F-011-R-06 Importing a risk register
**As a** risk owner, **I want** to bring our existing register into the platform, **so that** we do not retype it.

**Acceptance criteria (EARS):**
- F-011-AC-20: WHEN a holder of `register.edit` at a business unit imports a register file (CSV, or the documented JSON format), THE SYSTEM SHALL map its columns to the risk's fields, match owners by their email address among the users who may own a risk there, match categories by name, and show the result as a dry run first.
- F-011-AC-21: THE SYSTEM SHALL create the imported risks without scenarios, so the register lists them as unquantified (F-007-AC-09), with the source's reference kept, and SHALL never import ordinal ratings, heat-map positions or scores as exposure (P1); such columns SHALL be kept only as text in the risk's description or refused, as the importer chooses.
- F-011-AC-22: THE SYSTEM SHALL import a register file all or nothing, and a repeated import with the same external IDs SHALL propose changes to the risks it created rather than duplicate them.

### F-011-R-07 Control status
**As a** risk analyst, **I want** to know when a control a scenario relies on is no longer in place, **so that** the analysis is reviewed.

**Acceptance criteria (EARS):**
- F-011-AC-23: THE SYSTEM SHALL bring in, for controls matched by external ID, their implementation status (in place, partially in place, planned, not in place) with the date assessed and the source, and SHALL propose a new version of the control when its status changes.
- F-011-AC-24: WHEN an accepted change makes a control that a scenario's current control set counts as in place no longer in place, THE SYSTEM SHALL mark the scenarios using it as having a newer control version (F-003-AC-10), show on each scenario and on the risks linked to it that a control it relies on is no longer in place, and notify the scenario's owner (F-009); adopting the new version and re-running the analysis makes the exposure current again (F-007-AC-08).

### F-011-R-08 Provenance and evidence
**As an** auditor, **I want** to trace any value to where it came from, **so that** I can rely on the analysis.

**Acceptance criteria (EARS):**
- F-011-AC-25: THE SYSTEM SHALL show, for every record version that came from an integration, the integration, run, source system, external ID, the time received and who accepted it; an estimate or reference class built from integration data SHALL record a source of type `integration` (F-003) naming them.
- F-011-AC-26: THE SYSTEM SHALL record in the audit trail, in the transaction that makes them, each integration created, changed, paused, resumed or deleted, each credential set or removed, each run with its counts, each refused destination, and each proposed change accepted or rejected, with the actor and the business unit.

## Non-functional requirements
- Performance: a batch or file of 10,000 records is validated and matched within 60 s; the proposed changes of a run open within 1 s p95; an accepted batch of 1,000 changes applies within 30 s.
- Security / privacy: integrations write only inside their business unit subtree, under their own audited service principal; credentials are never returned or logged; connectors reach only allow-listed hosts over TLS 1.2 or later with verified certificates, through the same destination checks as F-009 (no redirects, no proxies, internal ranges refused, the checked address dialled); imported text is treated as data (neutralized where it is exported, never interpreted); limits on file size, records per batch and runs per hour; no data leaves the platform through an integration (inputs only).
- Audit: as AC-26; events in the catalog.
- Availability: connector runs are jobs that survive restarts; a failing source does not stop other integrations; a run interrupted midway leaves no partial proposals.
- Accessibility: the integration and review pages meet WCAG 2.1 AA.
- Secure defaults: no integrations exist on install; `integration.allowed_hosts` is empty; `auto_accept` is off; connectors are off in air-gapped mode until an internal host is allow-listed.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| API push and file upload | Yes | Yes | Yes |
| Pull connectors | Allow-listed hosts on the internet or the customer's network (through the customer's connectivity) | Allow-listed hosts | Allow-listed hosts inside the enclave only |
| Credentials | Sealed under a key file | Same | Same |

## Control mapping (NIST SP 800-53r5)
AC-3, AC-4, AC-6, AU-2, AU-3, AU-12, CA-3, CM-6, IA-5, SC-5, SC-7, SC-8, SC-13, SC-28, SI-10, SI-12 (T-21; statements in `compliance/statements/F-011.yaml`, signed off by Robert Former 2026-11-18).

## Out of scope
- Sending data out of the platform to other systems (reports are F-010; notices F-009; SIEM forwarding F-002).
- Vulnerability scanner findings, threat intelligence feeds and telemetry as direct inputs (OQ3).
- Control framework catalogues and crosswalks (F-013); F-011 brings in a control's status, not the framework.
- Fitting probability distributions to data automatically (OQ6).
- A general-purpose ETL or scripting environment; mappings are declarative.
- Writing to the source systems (no bidirectional sync).

## Dependencies
- F-001: `integration.manage`, a new `integration.view`, service accounts, BU scoping, restricted subtrees.
- F-002: audit trail; F-015: settings (`integration.allowed_hosts`, limits), deployment modes.
- F-003: library entries (assets, asset groups, reference classes), controls, versions and pins, newer-version flags, source type `integration`.
- F-004: reference classes as estimate aids; F-007: the register, staleness; F-009: notices and the destination guard.

## Open Questions
- OQ1 (resolved 2026-11-17: as proposed). Which inputs in v1 (product vision OQ1)? Proposed: the four above (assets, loss events, risk register, control status), chosen because each feeds an existing feature without a new model.
- OQ2 (resolved 2026-11-17: as proposed). Which pull connectors ship in v1? Proposed: a generic HTTPS JSON connector (paged GET with a declarative mapping) and a ServiceNow CMDB connector for assets; vendor connectors beyond that follow demand. API push and file upload cover every source in the meantime.
- OQ3 (resolved 2026-11-17: as proposed). Vulnerability data in v1? Proposed: no (the product vision keeps scanning out of scope); customers can bring summarized vulnerability counts in as loss-event-style data later.
- OQ4 (resolved 2026-11-17: as proposed). Review by default (AC-10 to AC-13)? Proposed: yes, everything is proposed; `auto_accept` applies only descriptive fields, per integration, off by default.
- OQ5 (resolved 2026-11-17: as proposed). A new permission `integration.view` (not privileged) for integration owners and auditors, in a permission catalog version 6 (Auditor and Platform Admin gain it)? Proposed: yes (re-sign the catalog).
- OQ6 (resolved 2026-11-17: as proposed). Distribution fitting (F-005 left it here)? Proposed: out of scope for v1; reference classes from loss events (AC-18) feed F-004's estimate aids, and the estimator still gives the range.
- OQ7 (resolved 2026-11-17: as proposed). Loss event visibility (AC-19)? Proposed: loss events are BU-owned records under RLS (`library.view`), like library entries, so restricted units' history stays inside them.
- OQ8 (resolved 2026-11-17: as proposed). Limits? Proposed: files up to 20 MiB, 10,000 records per batch or run, 12 connector runs per integration per hour, 50 integrations per installation.

## Change Log
- 2026-11-17: Initial draft, In Review.
- 2026-11-17: Approved by Robert Former; OQ1 to OQ8 resolved as proposed.
- 2026-11-17: Design approval adds `integration.push` (not privileged) to catalog version 6 beside `integration.view` (OQ5): the permission a service account holds to push batches (design §10, D-OQ1).
- 2026-11-18: Control mapping (T-21): AC-3, AC-4, AC-6, AU-2, AU-3, AU-12, CA-3, CM-6, IA-5, SC-5, SC-7, SC-8, SC-13, SC-28, SI-10, SI-12; statements signed off by Robert Former.
