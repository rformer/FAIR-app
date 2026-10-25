# Product Vision — FAIR Risk Platform
Status: **Draft**

## Problem
FAIR analyses are slow, spreadsheet-bound, and hard to keep current. Risk registers drift from the analyses that justify them, and risk acceptances expire or lose their owners without anyone noticing.

## Vision
A container-based SaaS application that automates much of the FAIR assessment workflow, keeps a living risk register tied to those analyses, and manages the full lifecycle of risk acceptance.

## Core capability areas
1. **FAIR assessment automation** — scoping, calibrated input capture, Monte Carlo simulation, loss-exceedance curves, control/treatment what-if comparison.
2. **Risk register** — risks linked to scenarios, assets, controls, owners; quantified exposure rolled up by business unit/portfolio.
3. **Risk acceptance lifecycle** — request → review → approval (by authority tied to exposure) → expiry → re-review/renewal, with notifications and audit evidence.

## Users (to confirm)
- Risk analyst — builds and runs analyses
- Risk owner / business leader — reviews, accepts, or treats risk
- CISO / risk committee — portfolio view, approvals above thresholds
- Auditor — read-only evidence access
- Tenant admin — users, SSO, configuration

## Out of scope for v1 (proposed)
- GRC control testing / evidence collection
- Vulnerability scanning (integrations may feed data later)

## Success measures (to confirm)
- Time to complete a standard FAIR analysis
- % of register risks with a current quantified analysis
- % of acceptances renewed or closed before expiry

## Open Questions
- OQ1. Which integrations matter first as automation inputs (e.g., asset inventory, vulnerability data, incident history, control frameworks)?
- OQ2. Reporting needs: board-level dashboards, exportable PDF reports, both?
- OQ3. Acceptance authority rules: fixed approval tiers by annualized loss exposure, or tenant-configurable?

## Change Log
- 2026-10-24 — Initial draft.
