# F-006 Results & Visualization — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-13

## Summary
F-006 draws what F-005 computes. For a simulation run it shows, per control set, the loss exceedance curve, the distribution of annualized loss, the split of loss into primary and secondary and by form of loss, and which inputs drive the result; for an aggregate, its curve, distribution and the contribution of each member. It compares control sets within a run and runs with each other (versions of a scenario, or different scenarios), saying plainly where a comparison is not like for like. Every chart has an accessible equivalent, and each chart can be downloaded as an image and its data as CSV. F-006 computes no new risk numbers of its own beyond reading F-005's stored results; full reports stay in F-010, and risk appetite and tolerance in F-007 and F-008.

## Users & roles affected
- **Risk analyst** (`analysis.view`, `analysis.run`): reads results, compares control sets and runs, downloads charts and data for their work.
- **Risk owner, approver, executive viewer** (`analysis.view`): read results and comparisons at the business units they can see, to decide on treatment.
- **Auditor** (`analysis.view`): sees what a result was computed from (scenario version, engine, digests) beside the charts.

## User stories

### F-006-R-01 The views of a run
**As a** risk analyst, **I want** a run's results drawn, **so that** I can understand and explain the risk without reading tables of percentiles.

**Acceptance criteria (EARS):**
- F-006-AC-01: WHEN a holder of `analysis.view` opens a succeeded run THE SYSTEM SHALL draw its loss exceedance curve (the probability that annual loss exceeds an amount, against the amount) with every control set of the run overlaid and the current set distinguished, the amount axis in the installation currency on a scale the user can switch between linear and logarithmic.
- F-006-AC-02: THE SYSTEM SHALL draw, per control set, the distribution of annualized loss as a histogram over the run's simulated years, marking the mean and chosen percentiles, and SHALL show the probability of a year with no loss separately from the histogram.
- F-006-AC-03: THE SYSTEM SHALL draw, per control set, the annualized loss split into primary and secondary and by form of loss, as amounts and as shares of the total.
- F-006-AC-04: THE SYSTEM SHALL draw, per control set, the inputs that drive annualized loss as a tornado ordered from the strongest (F-005-AC-14), each bar labelled with the input's place in the scenario and its rank correlation.
- F-006-AC-05: WHEN a user points at, focuses or selects a place on the loss exceedance curve THE SYSTEM SHALL show the amount and its probability of being exceeded per control set; and WHEN the user enters an amount THE SYSTEM SHALL show each control set's probability of exceeding it, and WHEN the user enters a probability THE SYSTEM SHALL show each control set's amount at that probability, read from the stored results and not kept.
- F-006-AC-06: THE SYSTEM SHALL show beside the views the run's scenario and version, iterations, seed, engine version and architecture, input bundle and results digests, the convergence figures (F-005-AC-13), the run's warnings, and the statement that inputs are sampled independently (F-005-AC-10).

### F-006-R-02 The views of an aggregate
**As a** risk analyst, **I want** an aggregate's results drawn, **so that** I can show the combined risk of a business unit or a group of scenarios and what makes it up.

- F-006-AC-07: WHEN a holder of `analysis.view` opens a succeeded aggregate THE SYSTEM SHALL draw its loss exceedance curve and annualized loss histogram as for a run, and each member's contribution (its mean and its share of the aggregate's 95th percentile, F-005-AC-18), ordered from the largest.
- F-006-AC-08: THE SYSTEM SHALL show on an aggregate's views its members with their scenarios, versions and control sets, the independence assumption, and, WHERE its members were computed on different engine versions, that fact (F-005-AC-19).

### F-006-R-03 Comparing control sets and runs
**As a** risk owner, **I want** to compare treatments and analyses side by side, **so that** I can decide what to do and see how the risk changed.

- F-006-AC-09: THE SYSTEM SHALL compare each control set of a run with the current set: the difference in mean annualized loss and in the key percentiles, and the distribution of the per-year difference (F-005-AC-12), stated as a reduction or an increase in the installation currency and as a share.
- F-006-AC-10: WHEN a holder of `analysis.view` chooses between two and six succeeded runs or aggregates they can see, one control set each THE SYSTEM SHALL overlay their loss exceedance curves and show their summaries side by side with the differences from the first one chosen.
- F-006-AC-11: WHEN the compared results differ in scenario, scenario version, iterations, seed, engine version or CPU architecture THE SYSTEM SHALL say which on the comparison, and SHALL state that differences between separate runs include sampling noise, unlike control sets of one run, which share their random numbers (F-005-AC-09).
- F-006-AC-12: THE SYSTEM SHALL let a user open a comparison of the runs of a scenario's versions from the scenario's page, and SHALL give every comparison an address that opens the same comparison for anyone who can see all of its results.
- F-006-AC-13: IF a user cannot see one of the results in a comparison THEN THE SYSTEM SHALL show none of the comparison and SHALL not reveal which result is hidden or what it contains.

### F-006-R-04 Accessible views
**As a** user who does not see or cannot point at a chart, **I want** the same information in another form, **so that** I can use the results as fully as anyone.

- F-006-AC-14: THE SYSTEM SHALL give every chart a text alternative that states what it shows and its main values, and a data table with the values it draws, reachable by keyboard and read by screen readers.
- F-006-AC-15: THE SYSTEM SHALL distinguish control sets and runs in charts by more than colour (line style, markers or labels), with colours that meet WCAG 2.1 AA contrast in the light and dark themes.
- F-006-AC-16: THE SYSTEM SHALL let every interaction in AC-05 and AC-10 be done by keyboard, and SHALL meet WCAG 2.1 AA on every F-006 page.

### F-006-R-05 Downloading charts and data
**As a** risk analyst, **I want** to take a chart and its numbers with me, **so that** I can use them in a presentation or my own analysis.

- F-006-AC-17: WHEN a holder of `analysis.view` downloads a chart THE SYSTEM SHALL provide it as SVG and as PNG, with its title, the scenario or aggregate, the control sets, the currency, the run's identifiers and digests, and the independence statement drawn into it.
- F-006-AC-18: WHEN a holder of `analysis.view` downloads a view's data THE SYSTEM SHALL provide it as CSV with the values the chart draws, the run's identifiers and digests, and the currency, with cells that a spreadsheet would read as formulas made inert.
- F-006-AC-19: THE SYSTEM SHALL record in the audit trail (F-002) each download of a chart or data, with the actor, the business unit, the run or aggregate, the view and the format.

### F-006-R-06 Access
**As a** security officer, **I want** results shown only to those entitled, **so that** the visualisations do not become a way around the risk data's protection.

- F-006-AC-20: THE SYSTEM SHALL show F-006's views and downloads only of results the user can see under F-005's rules (F-005-AC-22: `analysis.view` at the run's business unit; an aggregate only when every member is visible), and SHALL answer a request for anything else as if it did not exist.

## Non-functional requirements
- Performance: a run's views (curve, histogram, breakdown and tornado for every control set) appear within 2 s p95 for a run of 1,000,000 iterations with three control sets on the reference node; a comparison of six results within 3 s p95; a chart or CSV download within 2 s.
- Security / privacy: results are BU-owned risk data under row-level security (F-005); F-006 adds no copy of them outside the user's browser and the downloads the user asks for. Downloads are audited. The UI keeps the platform's content security policy (no inline scripts, no third-party origins) and its UI security headers.
- Audit: downloads as AC-19; events in the catalog (F-001 T-37) and in the trail in the request's transaction. Views are not audited (F-005's results are read as any other risk data).
- Accessibility: WCAG 2.1 AA (AC-14 to AC-16), checked by axe in the UI end-to-end tests.
- Deployment modes: identical in SaaS, self-hosted and air-gapped; no external services, fonts or scripts.
- Secure defaults: no settings are proposed; any that arise (for example the histogram's bin count) are F-015 settings with bounds.

## Control mapping (NIST SP 800-53r5)
To be proposed with the tasks.

## Out of scope
- Risk appetite and tolerance curves, and the probability of exceeding them (F-007, F-008); F-006 leaves room to overlay a curve later.
- Reports, PDFs, dashboards across many results, scheduled or emailed output (F-010).
- New statistics beyond F-005's results; re-running or changing a run.
- Saved, named comparisons as stored objects (a comparison's address, AC-12, is enough for v1).
- Business unit roll-ups as managed objects (F-007).

## Dependencies
- F-005: runs, aggregates, their stored summaries, curves, breakdowns, sensitivity, per-year series and per-year differences; `analysis.view`; row-level security for analysis data.
- F-003: scenario names and versions, the installation currency.
- F-002: audit trail; F-001: permissions, the event catalog.
- ADR-003: the web UI (React, React Aria Components); the UI end-to-end harness with Playwright and axe.

## Open Questions
- OQ1. The histogram (AC-02): drawn from the stored per-year series (exact, up to 1,000,000 values per control set), or from bins computed once and stored. Proposed: bins computed by the risk service from the series on request, with a fixed number of bins on a scale that suits the data (linear or logarithmic), cached per run.
- OQ2. Drawing charts: with a charting library, or with the platform's own SVG components. Proposed: our own SVG components (no dependency to vet, full control of accessibility and the content security policy), decided in an ADR in the design.
- OQ3. PNG downloads: rendered in the browser from the SVG, or by the service. Proposed: in the browser, with the download recorded by a call to the service first (AC-19), so the service never renders images.
- OQ4. Permission for downloads: `analysis.view` (as proposed in AC-17, AC-18) or a separate `analysis.export`. Proposed: `analysis.view`, since the downloads hold nothing the user cannot already see, with every download audited.
- OQ5. The comparison's address (AC-12): the result ids and control sets in the URL. Proposed: yes; nothing is stored.
- OQ6. Comparing results across business units: allowed whenever the user sees every result. Proposed: yes.

## Change Log
- 2026-11-13: Initial draft; scope decisions (the four core views with accessible equivalents, comparison within and across runs, appetite deferred to F-007/F-008, chart images and data CSV with full reports in F-010) taken with Robert Former.
- 2026-11-13: **Approved** by Robert Former, with the open questions' proposals as stated (to be settled in the design).
