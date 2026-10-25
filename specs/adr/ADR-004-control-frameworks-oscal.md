# ADR-004 Framework-agnostic control library using OSCAL
Status: Proposed
Date: 2026-10-24

## Context
Customers need flexibility across standards: NIST SP 800-53r5/FedRAMP, CMMC/800-171, ISO 27001, SOC 2 TSC, SOC 1 control objectives, and others. Controls feed FAIR analysis as resistance strength and loss-magnitude modifiers, and they link register entries to compliance obligations.

## Decision
- Control catalogs and profiles are imported as **NIST OSCAL** (JSON) where available. NIST publishes 800-53r5 in OSCAL, and FedRAMP baselines are available as OSCAL profiles. Other frameworks are loaded through a simple mapping format.
- Each customer control maps to one or more framework requirements. Crosswalks are stored as data.
- Controls carry FAIR effect attributes (which factor they influence and an estimated effect range), so automation can propose control-based what-if scenarios.

## Consequences
- Adds feature F-013 (Control framework library).
- OSCAL export of control implementation data becomes possible later as a differentiator.
