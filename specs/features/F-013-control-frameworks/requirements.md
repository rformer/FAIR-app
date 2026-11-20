# F-013 Control framework library — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-18

## Summary
F-013 connects the platform's controls (F-003), which carry their effect on FAIR factors, to the control frameworks organizations are held to: NIST SP 800-53r5 and its FedRAMP and other baselines, CMMC and NIST SP 800-171, ISO/IEC 27001, the SOC 2 trust services criteria, and others. Frameworks arrive as data, never as code (constitution P5, ADR-004): catalogs and baselines are imported in NIST OSCAL where one exists, and through a simple documented format otherwise. Each of the customer's controls maps to the framework requirements it satisfies, and crosswalks relate one framework's requirements to another's, so a control mapped once shows its coverage across every framework the organization uses. A coverage view answers "which requirements of this baseline have controls, are those controls in place (F-011), and where are the gaps", per business unit. Because controls already carry FAIR effects, F-013 also lets an analyst start from a framework requirement and see which scenarios its control would change, proposing a control set to analyse (P4: a proposal, never a change to an analysis). F-013 does not score compliance or rate risk: coverage is a fact about mappings and implementation status, and risk stays a loss distribution (P1).

## Users & roles affected
- **Framework administrator** (`framework.manage`, existing, privileged): imports, updates and retires frameworks, baselines and crosswalks for the installation.
- **Control owners and risk analysts** (`control.edit`, `control.view`): map their controls to framework requirements, see coverage, and propose control sets from requirements.
- **Compliance staff and auditors** (`control.view`, a new `framework.view`): read frameworks, mappings, crosswalks and coverage, and export them.
- **Risk owners** (`register.view`): see which framework requirements the controls behind their risks address.

## User stories
### F-013-R-01 Frameworks as data
**As a** framework administrator, **I want** to load the frameworks we are held to from their published form, **so that** controls are mapped to the authoritative text and identifiers.

**Acceptance criteria (EARS):**
- F-013-AC-01: WHEN a holder of `framework.manage` imports an OSCAL catalog (JSON), THE SYSTEM SHALL validate it against the pinned OSCAL schema, record the framework with its title, version, publisher, published date and every requirement (identifier, title, statement and parent, including enhancements), and refuse the whole file, naming each problem, if it does not validate.
- F-013-AC-02: WHEN an OSCAL profile (a baseline such as FedRAMP Moderate) is imported, THE SYSTEM SHALL resolve it against an imported catalog and record which requirements the baseline selects, with its parameters where set; a profile whose catalog is not imported SHALL be refused with the catalog it needs.
- F-013-AC-03: THE SYSTEM SHALL accept frameworks that have no OSCAL publication in a documented simple format (CSV or JSON: identifier, title, statement, parent), validated as strictly as OSCAL.
- F-013-AC-04: THE SYSTEM SHALL ship NIST SP 800-53r5, its low, moderate and high baselines, and the FedRAMP baselines as signed release content, available in every deployment mode without network access; and SHALL never ship text it is not licensed to distribute (OQ1).
- F-013-AC-05: WHEN a newer version of an imported framework is imported, THE SYSTEM SHALL keep the earlier version, show which requirements were added, changed, withdrawn or renumbered, and keep existing mappings on the version they were made against until a control owner moves them (AC-09).
- F-013-AC-06: THE SYSTEM SHALL let a framework administrator retire a framework version, which hides it from new mappings and coverage while keeping it and its mappings readable for history.

### F-013-R-02 Mapping controls to requirements
**As a** control owner, **I want** to record which framework requirements each control satisfies, **so that** one control is maintained once and counted everywhere it applies.

**Acceptance criteria (EARS):**
- F-013-AC-07: WHEN a holder of `control.edit` at a control's business unit maps the control to a framework requirement, THE SYSTEM SHALL record the mapping with its strength (fully satisfies, partially satisfies, supports), an optional rationale, the author and time, as part of the control's versioned record (F-003); a control SHALL map to many requirements and a requirement to many controls.
- F-013-AC-08: THE SYSTEM SHALL replace F-003's plain framework references (F-003-AC-14) with mappings: on upgrade, a reference whose framework and identifier match an imported requirement SHALL be offered to the control owner as a proposed mapping, and the rest kept as references.
- F-013-AC-09: WHEN a framework version a control is mapped against is superseded, THE SYSTEM SHALL show the control as having mappings to an older version and propose the equivalent requirements in the new version, which the control owner accepts or rejects.

### F-013-R-03 Crosswalks
**As a** compliance lead, **I want** frameworks related to each other, **so that** coverage of one shows what it means for another.

**Acceptance criteria (EARS):**
- F-013-AC-10: WHEN a holder of `framework.manage` imports a crosswalk (an OSCAL mapping, or the simple format: source requirement, target requirement, relationship), THE SYSTEM SHALL record each relationship as one of equal, subset of, superset of or intersects with (NIST IR 8278), with its source and version, and refuse relationships that name requirements not imported.
- F-013-AC-11: THE SYSTEM SHALL show coverage reached through a crosswalk separately from coverage by a direct mapping, naming the crosswalk and relationship, and SHALL never treat an intersecting or superset relationship as full coverage.

### F-013-R-04 Coverage
**As a** compliance lead, **I want** to see which requirements of a baseline are covered, in place, or open, for my business units, **so that** I can plan work and answer auditors.

**Acceptance criteria (EARS):**
- F-013-AC-12: WHEN a user views a framework or baseline for a business unit, THE SYSTEM SHALL list each requirement with the controls mapped to it that the user may see in that subtree, each control's strength and implementation status (F-011), and whether it is covered directly, covered through a crosswalk, or not covered.
- F-013-AC-13: THE SYSTEM SHALL count requirements by state (covered with every mapped control in place, covered with a control not in place, covered only partially or through a crosswalk, not covered) and SHALL never combine them into a score, percentage of compliance or rating.
- F-013-AC-14: THE SYSTEM SHALL compute coverage only from controls the viewer may see (row-level security); restricted business units below the viewer SHALL appear only as their roll-up mode allows (F-001), as counts without their controls.
- F-013-AC-15: THE SYSTEM SHALL export a framework's coverage for a business unit as CSV and as JSON, recording the export in the audit trail, with the reason rule of F-010 (`export.reason_required`).

### F-013-R-05 From requirements to FAIR analysis
**As a** risk analyst, **I want** to start from a framework requirement and see what its control would change in our analyses, **so that** compliance work is prioritised by the loss it avoids.

**Acceptance criteria (EARS):**
- F-013-AC-16: WHEN an analyst opens a framework requirement, THE SYSTEM SHALL show the controls mapped to it, their FAIR effects (F-003), and the scenarios the analyst may see that use those controls, and those whose current control sets do not include them.
- F-013-AC-17: WHEN an analyst chooses a requirement's control for a scenario that does not use it, THE SYSTEM SHALL propose a new version of the scenario with a control set adding the control, for the analyst to review, save and run (F-005); THE SYSTEM SHALL never add a control to a scenario, change a pin, or run an analysis by itself.
- F-013-AC-18: THE SYSTEM SHALL show, on a register risk (F-007), the framework requirements the controls of its linked scenarios address.

### F-013-R-06 Traceability
**As an** auditor, **I want** every framework, mapping and crosswalk change attributable, **so that** coverage claims can be relied on.

**Acceptance criteria (EARS):**
- F-013-AC-19: THE SYSTEM SHALL record in the audit trail, in the transaction that makes them, each framework, baseline or crosswalk imported or retired (with its source file's digest), and each mapping added, changed or removed, with the actor and the business unit.
- F-013-AC-20: THE SYSTEM SHALL keep every version of a framework, baseline, crosswalk and control mapping, so that coverage as of a past date can be reproduced.

## Non-functional requirements
- Performance: importing the 800-53r5 catalog (about 1,200 requirements with enhancements) takes at most 60 s; a baseline's coverage for the root business unit, over 10,000 controls and 50,000 mappings, opens within 2 s p95; a requirement's scenarios open within 1 s p95.
- Security / privacy: imported files are data, validated against pinned schemas, never executed or followed (no remote OSCAL imports or back-matter links fetched, in any mode); limits on file size and counts; frameworks are installation-wide reference data, while mappings follow their control's business unit and row-level security; shipped content is signed and verified like the release's other packages (F-015).
- Audit: as AC-19; events in the catalog.
- Availability: imports run as jobs that survive restarts and apply whole or not at all.
- Accessibility: framework, mapping and coverage pages meet WCAG 2.1 AA.
- Secure defaults: only the shipped frameworks exist on install; no crosswalk is assumed between frameworks; mappings start empty; coverage never claims more than direct, full-strength mappings to controls in place.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Shipped frameworks (800-53r5, baselines, FedRAMP) | Yes | Yes | Yes (in the release, no network) |
| Importing frameworks and crosswalks | File upload | File upload | File upload (no remote fetch) |
| Coverage exports | Yes | Yes | Yes |

## Control mapping (NIST SP 800-53r5)
AC-3, AC-6, AU-2, AU-3, AU-12, PL-10, SC-5, SI-7, SI-10 (T-13; statements in `compliance/statements/F-013.yaml`, signed off by Robert Former 2026-11-19).

## Out of scope
- Compliance scores, maturity ratings, heat maps or any ordinal rating (P1).
- Assessments, test procedures, evidence collection and audit workpapers (a GRC tool's work; control status arrives through F-011).
- Writing a System Security Plan; exporting the customer's control implementations as an OSCAL SSP or component definition (OQ4).
- Shipping copyrighted framework text (ISO/IEC 27001, SOC 2 criteria, CIS) (OQ1).
- Automatically estimating a control's FAIR effect from its framework requirement; effects stay calibrated estimates by people (P2).
- The platform's own OSCAL component definition and its control statements (F-014 and each feature's statements).

## Dependencies
- F-001: `framework.manage` (catalog version 1), a new `framework.view` (OQ3), restricted business units' roll-up modes, row-level security.
- F-003: controls, their versions, effects and plain references (AC-14), scenarios and control sets; F-005 and F-007: runs and risks.
- F-011: controls' implementation status; the import machinery's validation and proposal patterns may be reused.
- F-002: audit trail; F-010: export reasons and the CSV writer's neutralization; F-015: signed release content and settings.

## Open Questions
- OQ1 (resolved 2026-11-18: as proposed). Which frameworks ship? Proposed: NIST SP 800-53r5 with its low, moderate, high and privacy baselines, NIST SP 800-171r3, and the FedRAMP Rev 5 baselines (public domain, published in OSCAL); identifiers only (no text) for nothing else. ISO/IEC 27001, SOC 2 and CIS are imported by customers who hold licences, in the simple format.
- OQ2 (resolved 2026-11-18: as proposed). Crosswalks shipped? Proposed: the NIST-published 800-171r3 to 800-53r5 mapping only; others imported by customers (NIST OLIR or their own), never assumed.
- OQ3 (resolved 2026-11-18: as proposed). A new non-privileged `framework.view` (catalog version 7) for compliance staff and auditors (Auditor gains it), or reuse `control.view`? Proposed: a new permission, since frameworks are installation-wide and not risk data.
- OQ4 (resolved 2026-11-18: as proposed). OSCAL export of the customer's control implementations (an SSP's control implementation section) in v1? Proposed: no; coverage exports as CSV and JSON in v1, OSCAL SSP export a later feature.
- OQ5 (resolved 2026-11-18: as proposed). Mapping strength vocabulary? Proposed: fully satisfies, partially satisfies, supports (a control relevant but not sufficient), kept separate from crosswalk relationships (NIST IR 8278 set relationships).
- OQ6 (resolved 2026-11-18: as proposed). Limits? Proposed: catalog files up to 50 MiB, 20,000 requirements per framework version, 100 framework versions, 200,000 crosswalk relationships, 500 mappings per control.

## Change Log
- 2026-11-18: Initial draft, In Review (F-013 chosen next by Robert Former).
- 2026-11-18: Approved by Robert Former; OQ1 to OQ6 resolved as proposed.
