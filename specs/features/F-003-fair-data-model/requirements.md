# F-003 FAIR Data Model — Requirements
Status: **Approved** | Owner: Robert Former | Last updated: 2026-11-06

## Summary
F-003 defines the risk data every later feature works on: loss scenarios built from Open FAIR (O-RT) concepts — assets, threat communities, threat effects, loss events, the six forms of loss, primary and secondary stakeholders — and the controls that affect them. Analysts build scenarios from reusable library entries, decompose them as far down the FAIR taxonomy as their data supports, and keep every estimate's source and rationale with it. The model is business-unit owned (F-001 row-level security), versioned so any later result can be traced to the exact inputs it used (constitution P3), recorded in the audit trail (F-002), and the basis for estimate capture (F-004), simulation (F-005), the risk register (F-007) and control frameworks (F-013).

## Concepts
- **Loss scenario** (O-RT): a threat community acting against an asset, with a threat effect (loss of confidentiality, integrity or availability), producing a loss event with financial consequences. It is the unit of analysis.
- **The FAIR taxonomy**: Risk is derived from Loss Event Frequency (LEF) and Loss Magnitude (LM). LEF decomposes into Threat Event Frequency (TEF; contact frequency × probability of action) and Vulnerability (threat capability against resistance strength). LM decomposes into primary loss and secondary risk (secondary loss event frequency × secondary loss magnitude). A scenario may be estimated at any level of this tree; lower levels are derived from inputs, not entered twice.
- **Forms of loss**: productivity, response, replacement, fines and judgments, competitive advantage, reputation. Primary loss falls on the organization; secondary loss arises from secondary stakeholders' reactions.
- **Estimate**: a calibrated range (minimum, most likely, maximum) with a confidence level, its rationale and its source (constitution P2). How estimates are captured and calibrated is F-004; F-003 defines what one is and where it attaches.
- **Library**: reusable assets and asset groups, threat communities, loss-form profiles and control definitions, shared within a business unit and its descendants. An entry owned at the root business unit is available to every BU except restricted ones.
- **Asset group**: a named set of assets from the library, analysed as one asset (for example "customer databases"), valued as a whole or as the sum of its members.
- **Control** (here): a safeguard with its effect on FAIR factors (for example, reducing contact frequency, probability of action or threat capability's success, raising resistance strength, or reducing a form of loss). Framework mappings arrive with F-013.

## Users & roles affected
- **Risk analyst**: builds scenarios and library entries (`scenario.edit`, `library.edit`, `control.edit`).
- **Risk owner, approver, executive viewer**: read scenarios in their business units (`scenario.view`, `library.view`, `control.view`).
- **Auditor**: reads scenarios, their versions and history.
- **BU administrator**: none beyond F-001; data follows the BU hierarchy.

## Requirements

### F-003-R-01 Loss scenarios
**As a** risk analyst, **I want** to describe a loss scenario in Open FAIR terms, **so that** analyses are comparable and defensible.

- F-003-AC-01: THE SYSTEM SHALL let a holder of `scenario.edit` at a business unit create a scenario owned by that BU, naming its asset (or asset group), threat community, threat effect (confidentiality, integrity or availability, one or more), loss event description, and an owner.
- F-003-AC-02: THE SYSTEM SHALL let a scenario state its scope in words (what is in and out) and its analysis period, and SHALL refuse a scenario without an asset, a threat community or a threat effect.
- F-003-AC-03: THE SYSTEM SHALL let the analyst choose, for each branch of the FAIR taxonomy, the level at which the scenario is estimated (for example LEF directly, or TEF and Vulnerability, or contact frequency, probability of action, threat capability and resistance strength), and SHALL then require exactly the estimates that level needs, no more and no fewer. Every node of the taxonomy is available.
- F-003-AC-29: THE SYSTEM SHALL let the analyst estimate Vulnerability per scenario either directly, as a probability, or as derived from threat capability against resistance strength, and SHALL record which was chosen.
- F-003-AC-04: THE SYSTEM SHALL let a scenario state primary loss per form of loss, and secondary risk (secondary loss event frequency and secondary loss magnitude per form of loss) per named secondary stakeholder group, and SHALL refuse a form of loss outside the six Open FAIR forms.

### F-003-R-02 Estimates with provenance
**As a** risk analyst, **I want** every number in a scenario to carry its range, confidence, rationale and source, **so that** reviewers can see where it came from.

- F-003-AC-05: THE SYSTEM SHALL store each estimate as a minimum, most likely and maximum with a confidence level, a rationale, and one or more sources (a person, a document, a dataset, an integration), and SHALL refuse an estimate without a rationale or a source.
- F-003-AC-06: THE SYSTEM SHALL refuse an estimate whose values are not ordered (minimum ≤ most likely ≤ maximum), whose probabilities fall outside [0, 1], whose frequencies or magnitudes are negative, or whose unit does not fit the factor (events per year for frequencies; a probability for probability of action and vulnerability; a currency amount for magnitudes; a percentile against the threat community continuum for threat capability and resistance strength).
- F-003-AC-07: THE SYSTEM SHALL express every magnitude in one currency per installation (an installation setting), and SHALL state that currency wherever magnitudes are shown or exported.

### F-003-R-03 Reusable library
**As a** risk analyst, **I want** to reuse assets, threat communities, loss profiles and controls across scenarios, **so that** analyses stay consistent and fast to build.

- F-003-AC-08: THE SYSTEM SHALL let a holder of `library.edit` at a business unit maintain library entries owned by that BU — assets (with type, description and value or value basis), asset groups (their member assets and whether the group is valued as a whole or by its members), threat communities (with a description and threat capability estimate), loss-form profiles (typical magnitudes per form) and controls (with their FAIR effects) — available to scenarios in that BU and its descendants.
- F-003-AC-09: WHEN a scenario uses a library entry, THE SYSTEM SHALL record which version of the entry it used, and a later change to the entry SHALL NOT change the scenario until the analyst adopts the new version.
- F-003-AC-10: WHEN a library entry has a newer version than a scenario uses, THE SYSTEM SHALL show it on the scenario and let the analyst compare and adopt it.
- F-003-AC-11: THE SYSTEM SHALL ship a starter library of generic threat communities (for example cyber criminals, malicious and non-malicious insiders, nation-state actors) and guidance for each of the six forms of loss, written from Open FAIR concepts, which the customer may copy and adapt but not edit in place. It SHALL NOT present any number as industry data: where it shows an example value, the example is labelled as illustrative.

### F-003-R-04 Controls and their effects
**As a** risk analyst, **I want** to attach controls to a scenario with their effect on FAIR factors, **so that** I can compare the current state with proposed treatments (F-005, F-007).

- F-003-AC-12: THE SYSTEM SHALL let a scenario list the controls in place and proposed, each with the FAIR factor it affects and its effect as an estimate (for example a resistance strength, a reduction of contact frequency, or a reduction of a form of loss).
- F-003-AC-13: THE SYSTEM SHALL let an analyst define the scenario's current state and one or more alternative control sets, so that each can be simulated (F-005) and compared.
- F-003-AC-14: THE SYSTEM SHALL let a control carry identifiers in external frameworks as plain references until F-013 provides managed crosswalks.

### F-003-R-05 Versioning and traceability
**As an** auditor, **I want** every analysis input fixed at the version it was run with, **so that** results are explainable and reproducible (P3, A4).

- F-003-AC-15: THE SYSTEM SHALL keep every saved change to a scenario or library entry as a new version with its author, time and a change note, and SHALL never change or delete an earlier version.
- F-003-AC-16: THE SYSTEM SHALL let a simulation (F-005) take a scenario version as a frozen, self-contained input (the scenario with the library versions it uses), identified by a digest that changes whenever any input changes.
- F-003-AC-17: THE SYSTEM SHALL show the differences between any two versions of a scenario or library entry.

### F-003-R-06 Business-unit ownership and visibility
**As a** risk owner, **I want** scenarios to follow the business-unit hierarchy, **so that** each team sees what it should and no more.

- F-003-AC-18: THE SYSTEM SHALL scope every scenario, library entry and control to its owning business unit through F-001's data-layer visibility, including restricted business units and roll-up modes.
- F-003-AC-19: THE SYSTEM SHALL let a holder of `scenario.edit` at both business units move a scenario between them, recorded with a reason, and SHALL refuse a move that would expose a restricted BU's scenario outside its subtree.
- F-003-AC-20: IF a scenario uses a library entry its owning BU cannot see (after a move or a visibility change), THEN THE SYSTEM SHALL flag the scenario and keep using the recorded version until the analyst replaces it.

### F-003-R-07 Lifecycle and audit
**As a** compliance owner, **I want** every change to risk data recorded, **so that** the model is evidence (S4, S6).

- F-003-AC-21: THE SYSTEM SHALL record the creation, change, move, archiving and restoring of every scenario, library entry and control in the audit trail (F-002), with its business unit and the change note.
- F-003-AC-22: THE SYSTEM SHALL let a scenario be archived (read-only, excluded from active lists) and restored, never deleted while any simulation, register entry or acceptance refers to it.
- F-003-AC-23: THE SYSTEM SHALL refuse secrets in free-text fields as the audit trail does (F-002-AC-06), and SHALL bound every text field's length.

### F-003-R-08 Import and export
**As a** risk analyst, **I want** to move scenarios and library entries in and out as files, **so that** I can bring existing analyses and share libraries between instances.

- F-003-AC-24: THE SYSTEM SHALL export scenarios (with the library versions they use) and library entries as a documented, versioned JSON format, filtered to what the requester can see, recorded in the audit trail.
- F-003-AC-25: THE SYSTEM SHALL import that format into a business unit where the importer holds the edit permissions, all or nothing, with a dry run that lists what would be created or changed and every validation failure.

### F-003-R-09 API and user interface
**As a** risk analyst, **I want** to work with scenarios through the web UI and the API, **so that** both people and automation (F-011) can use them.

- F-003-AC-26: THE SYSTEM SHALL provide every capability above through a documented REST API following the platform's API conventions (F-001 T-42).
- F-003-AC-27: THE SYSTEM SHALL provide web pages to build, review and compare scenarios and to manage the library, meeting WCAG 2.1 AA (Q3).
- F-003-AC-28: THE SYSTEM SHALL show, for any scenario, the FAIR taxonomy as estimated (which factors were entered and which will be derived), so a reviewer can see the decomposition at a glance.

## Permissions (F-001 catalog)
F-003 uses the provisional risk-data keys already in the catalog: `scenario.view`, `scenario.edit`, `library.view`, `library.edit`, `control.view`, `control.edit` (OQ5). Assets, asset groups, threat communities and loss-form profiles are library entries under `library.*`; control definitions use `control.*`.

## Secure defaults (ADR-006)
- Risk data is visible only within its business unit's scope from the start; nothing is shared across BUs unless the hierarchy grants it.
- New installations have an empty customer library (the starter library is read-only and copied on demand).
- Exports are recorded and filtered to the requester's scope; imports are all-or-nothing with a dry run.
- Free text is length-bounded and checked for secrets.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Risk data storage | Vendor-operated, per customer instance | Customer's database | Same as self-hosted |
| Starter library | Shipped with the release | In the bundle | In the bundle |
| Import and export | JSON files through the UI or API | Same | Same; files cross the enclave boundary by the customer's own process |
| Currency | Set at installation | Set at installation | Set at installation |

## Non-functional requirements
- Performance: a scenario with its library references loads in ≤ 300 ms p95; lists of 10,000 scenarios in a BU subtree page in ≤ 500 ms p95 (F-001 target scale).
- Security / privacy: all risk data is BU-scoped in the data layer (A6); no secrets in risk data.
- Audit: every change in the trail, in the transaction of the change (F-002).
- Availability: as the platform's services.

## Control mapping (NIST SP 800-53r5)
AC-3, AC-6, AU-2, AU-12, CM-3, RA-3, RA-7, SI-10. Crosswalks to other frameworks are provided by F-013.

## Out of scope
- Capturing and calibrating estimates (F-004), simulation (F-005), results (F-006), the register (F-007), acceptance (F-008).
- Managed control frameworks, crosswalks and control libraries from OSCAL catalogs (F-013).
- Automated inputs from integrations (F-011); F-003 only records a source of type integration.
- Ordinal (high/medium/low) scoring: outputs are distributions (P1).
- Per-business-unit currencies and conversion (OQ3).
- Asset dependencies and links to an external asset inventory (F-011).
- Importing spreadsheets or other FAIR tools' formats; these can come later as converters into the platform's JSON format.

## Dependencies
- F-001 (BU hierarchy, RBAC and data-layer visibility; the permission keys).
- F-002 (audit trail; secrets refusal).
- F-015 (installation settings, for the currency).

## Open Questions
None.

## Resolved
- OQ1: every node of the FAIR taxonomy may be estimated; the analyst picks the level per branch (AC-03) (2026-11-06)
- OQ2: Vulnerability is estimated directly or derived from threat capability against resistance strength, per scenario (AC-29) (2026-11-06)
- OQ3: one currency per installation (AC-07) (2026-11-06)
- OQ4: library entries are shared down the BU tree only; root entries reach every unrestricted BU (AC-08) (2026-11-06)
- OQ5: the provisional keys `scenario.*`, `library.*`, `control.*` are kept (2026-11-06)
- OQ6: the starter library holds generic threat communities and loss-form guidance written from Open FAIR concepts, with no numbers presented as industry data (AC-11) (2026-11-06)
- OQ7: assets are records, and asset groups are in v1; dependencies and inventory links wait for F-011 (AC-01, AC-08) (2026-11-06)
- OQ8: import and export use the platform's own JSON format only (AC-24, AC-25) (2026-11-06)

## Change Log
- 2026-11-06: Initial draft. OQ1 to OQ8 resolved. **Approved** by Robert Former.
