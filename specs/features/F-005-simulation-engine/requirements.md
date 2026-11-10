# F-005 Monte Carlo Simulation Engine — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-10

## Summary
F-005 turns a scenario into numbers. It runs a Monte Carlo simulation of an F-003 scenario version, through the frozen input bundle (F-003-AC-16), for each of the scenario's control sets, and produces the annualized loss distribution, the loss exceedance curve's data, the breakdown by form of loss, the difference between control sets, which inputs drive the result, and whether the iterations were enough. Runs are asynchronous, immutable and reproducible bit for bit on the same engine version (constitution A4). The engine is the Python analytics engine of ADR-002, behind an internal gRPC contract, and passes a statistical validation suite (Q2). Several scenarios' runs can be combined into one aggregate loss distribution. F-006 draws the results; F-005 computes and stores them.

## Users & roles affected
- **Risk analyst** (`analysis.run`, `analysis.view`): runs simulations of scenarios at their business units, cancels and reproduces runs, reads results, builds aggregates.
- **Risk owner, approver, executive viewer, auditor** (`analysis.view`): read runs, results and aggregates at the business units they can see.
- **Auditor**: verifies that a stored result is what its recorded inputs produce on its engine version.
- **Platform administrator**: sets the simulation settings within their bounds (F-015).

## User stories

### F-005-R-01 Running a simulation
**As a** risk analyst, **I want** to simulate a scenario version for its control sets, **so that** I get a loss distribution for the current state and each alternative.

**Acceptance criteria (EARS):**
- F-005-AC-01: WHEN a holder of `analysis.run` at a scenario's business unit requests a run of a version of the scenario THE SYSTEM SHALL queue a run of that version's input bundle (F-003-AC-16) for every control set of the version, or the ones chosen, with an iteration count within the setting's bounds and a seed given by the analyst or generated, and SHALL record who requested it and when.
- F-005-AC-02: THE SYSTEM SHALL run queued runs without the requester waiting, and SHALL show each run's state (queued, running, succeeded, failed, cancelled) and progress.
- F-005-AC-03: WHILE a run is queued or running THE SYSTEM SHALL let its requester, or a holder of `analysis.run` at its business unit, cancel it with a reason.
- F-005-AC-04: IF a run fails THEN THE SYSTEM SHALL record why and keep no partial results.
- F-005-AC-05: IF the scenario is archived, or the requester already has as many runs queued or running as a setting allows, THEN THE SYSTEM SHALL refuse the request and say why.
- F-005-AC-06: THE SYSTEM SHALL keep runs and their results with the scenario's business unit (moving with it, F-003-AC-19) and SHALL never change or delete a finished run's inputs or results.

### F-005-R-02 The model
**As a** risk analyst, **I want** the simulation to follow the Open FAIR taxonomy and honour my estimates' stated confidence, **so that** the results mean what the inputs say.

- F-005-AC-07: THE SYSTEM SHALL sample every estimate from a Beta-PERT distribution with its mode at the most likely value whose central interval at the estimate's stated confidence runs from its minimum to its maximum, kept within the unit's domain (frequencies and amounts at least 0; probabilities and fractions between 0 and 1; percentiles between 0 and 100); WHERE no such distribution exists for an estimate THE SYSTEM SHALL use the documented fallback and record it on the run with the estimate's place in the scenario.
- F-005-AC-08: THE SYSTEM SHALL compute each simulated year from the scenario's taxonomy levels (F-003 design §3.1): loss event frequency directly, or as threat event frequency times vulnerability; threat event frequency directly, or as contact frequency times probability of action; vulnerability directly, or as the probability that threat capability exceeds resistance strength; the year's loss events drawn from the loss event frequency; each event's primary loss as the sum of its forms of loss; and, per secondary stakeholder group, a secondary loss event with the group's secondary loss event frequency, its loss the sum of the group's forms.
- F-005-AC-09: THE SYSTEM SHALL apply each control set's controls to the factors they affect (reductions of contact frequency, probability of action, threat capability or a form of loss; resistance strength provided), combining several controls on one factor by the documented rule, and SHALL draw the same random numbers for every control set of a run, so that differences between control sets come from the controls and not from sampling noise.
- F-005-AC-10: THE SYSTEM SHALL document the model (sampling, the taxonomy computation, controls, fallbacks, and what the results mean) in a user guide, and SHALL state on every result that inputs are sampled independently.

### F-005-R-03 Results
**As a** risk analyst, **I want** the loss distribution and its parts for each control set, **so that** I can report risk and compare treatments.

- F-005-AC-11: WHEN a run succeeds THE SYSTEM SHALL store, per control set, the annualized loss distribution's summary (mean, standard deviation, minimum, maximum, the 1st, 5th, 10th, 25th, 50th, 75th, 90th, 95th and 99th percentiles, and the probability of any loss in a year), the same summary for the loss event frequency and for the loss per event, the loss exceedance curve as points (annual loss and the probability of exceeding it) dense enough to draw, and the annualized loss split into primary and secondary and by form of loss, in the installation currency.
- F-005-AC-12: THE SYSTEM SHALL store, for each control set against the current one, the difference in mean annualized loss and in the key percentiles, and the distribution of the per-year difference.
- F-005-AC-13: THE SYSTEM SHALL report, per control set, the standard error of the mean annualized loss and intervals for the key percentiles, and SHALL warn on the run WHEN the relative standard error exceeds a setting.
- F-005-AC-14: THE SYSTEM SHALL report, per control set, how strongly each input estimate drives the annualized loss (the change in mean annualized loss when the input moves from the low to the high end of its range, and its rank correlation with the annualized loss), ordered from the strongest.

### F-005-R-04 Reproducibility
**As an** auditor, **I want** to verify that a stored result is what its inputs produce, **so that** results can be relied on as evidence (P3, S6).

- F-005-AC-15: THE SYSTEM SHALL record with every run its input bundle's digest, the seed, the iteration count, the control sets, the engine version, the CPU architecture and the engine image's digest, and a digest of its results.
- F-005-AC-16: WHEN a holder of `analysis.run` asks to reproduce a run THE SYSTEM SHALL run the recorded inputs again and report whether the results' digest matches; IF the engine version or the CPU architecture now differs from the run's THEN THE SYSTEM SHALL say so and not report a mismatch as tampering.
- F-005-AC-17: THE SYSTEM SHALL produce identical results, bit for bit, for the same input bundle, seed, iteration count and control sets on the same engine version and CPU architecture, whatever the CPU model, the number of workers and the order runs are executed in.

### F-005-R-05 Aggregation
**As a** risk analyst, **I want** to combine several scenarios' results, **so that** I can see the loss distribution of a business unit or a group of risks.

- F-005-AC-18: THE SYSTEM SHALL let a holder of `analysis.run` combine succeeded runs of several scenarios they can see (one control set each) into an aggregate whose annualized loss is the per-year sum of its members' under the documented assumption of independence, with the summary, the loss exceedance curve and the contribution of each member.
- F-005-AC-19: THE SYSTEM SHALL record an aggregate's member runs and control sets, keep it immutable, and show it only to someone who can see every member; IF a member run was made on a different engine version THEN THE SYSTEM SHALL say so on the aggregate.

### F-005-R-06 Statistical validation
**As a** platform owner, **I want** the engine checked against known answers, **so that** its numbers can be trusted (Q2).

- F-005-AC-20: THE SYSTEM SHALL include a statistical validation suite, run in CI on every engine change, that checks the samplers against their target quantiles and moments, the taxonomy computation against cases with known answers (for example constant inputs, and a Poisson frequency with a constant magnitude), the control effects, the convergence estimates and the aggregation, each within stated tolerances.
- F-005-AC-21: THE SYSTEM SHALL record with each engine version the validation suite's result, and SHALL refuse to run on an engine version whose validation did not pass.

### F-005-R-07 Access and audit
**As a** security officer, **I want** simulations scoped and recorded like the rest of the risk data, **so that** results are seen only by those entitled and every run is attributable.

- F-005-AC-22: THE SYSTEM SHALL show runs, results and aggregates only to holders of `analysis.view` at the business units they belong to (F-001 row-level security), and SHALL require `analysis.run` there to request, cancel or reproduce a run or create an aggregate.
- F-005-AC-23: THE SYSTEM SHALL record in the audit trail (F-002) each run requested, finished (succeeded or failed), cancelled and reproduced, and each aggregate created, with the actor, the business unit and the input bundle's digest.

## Non-functional requirements
- Performance: a run of 100,000 iterations of a fully decomposed scenario (contact frequency, probability of action, threat capability, resistance strength, six forms of primary loss, two secondary stakeholder groups) with three control sets finishes within 30 s p95 on the reference node; aggregating 100 runs within 10 s; starting a queued run within 5 s while an engine worker is free. Engine workers scale out; a run's results do not depend on how many there are.
- Security / privacy: the engine reads only the input bundles it is sent and writes only results, holds no database credentials and no customer secrets, and talks to the risk service over mutually authenticated TLS (1.2 or later) with FIPS 140-validated cryptography (S2). Its image is hardened and non-root (S5). Results are BU-owned risk data under row-level security.
- Audit: as AC-23; events in the catalog (F-001 T-37) and in the trail in the change's transaction.
- Availability: queued runs survive restarts of the risk service and the engine; a run interrupted by an engine failure is retried or failed, never left running.
- Deployment modes: identical in SaaS, self-hosted and air-gapped; the engine needs no outbound network access (A7).
- Secure defaults: iteration count, concurrency and result retention are F-015 settings with bounds; the defaults favour accuracy (enough iterations for the convergence warning not to fire on typical scenarios).

## Out of scope
- Drawing results (charts, tables, exports): F-006.
- The risk register and its business unit roll-ups as managed objects: F-007; F-005 offers aggregates of chosen runs.
- Choosing a distribution shape per estimate, and fitting distributions to reference classes or other data (F-011).
- Correlation between inputs within a scenario, and dependence between scenarios in an aggregate (independence is assumed and stated).
- Multi-year or time-varying simulation, and loss caps from insurance or contracts.
- Re-running old runs on a newer engine automatically.

## Dependencies
- F-003: the input bundle and its digest (AC-16), control sets (AC-13), the installation currency, scenario archive and move.
- F-001: `analysis.view` and `analysis.run` (catalog), row-level security for a new BU-owned resource type, the Risk Analyst role.
- F-002: audit trail; F-015: settings (iteration bounds, concurrency, convergence threshold, retention).
- F-004: accepted estimates arrive in scenario versions; nothing else.
- ADR-002: Python engine, gRPC contract; ADR-003: job queue and storage.

## Open Questions
- OQ1. What the entered estimates describe. Proposed: the current state, with the current control set in place; an alternative set applies the difference (its added controls' effects, and the removal of current controls it leaves out).
- OQ2. Combining controls on one factor. Proposed: reductions multiply (1 − r₁)(1 − r₂); the strongest resistance strength applies.
- OQ3. The PERT fallback (AC-07) when no PERT has the stated confidence interval, for example a most likely value at a bound or a range at the domain's edge. Proposed: widen to the domain within a documented rule, or plain PERT at the bounds, flagged.
- OQ4. Vulnerability from threat capability and resistance strength (AC-08): per year as one draw of each (a step), or as the probability over the threat community's capability distribution. Proposed: the probability, so vulnerability is a fraction per simulated year.
- OQ5. Iterations: default and bounds. Proposed: default 100,000; between 10,000 and 1,000,000.
- OQ6. Sensitivity method details (AC-14): which low and high (proposed: the input's 5th and 95th percentiles with the others sampled, same seed) and the rank correlation (proposed: Spearman).
- OQ7. Result retention: kept for the scenario's life, or a setting. Proposed: kept with the scenario (needed as evidence for acceptance, F-008).
- OQ8. Where runs are recorded and queued: the risk service (Go) owning runs and results and calling the engine, or a separate service. Proposed: the risk service, with River jobs, results in PostgreSQL and large arrays in the object store.

## Change Log
- 2026-11-10: Initial draft; scope decisions (confidence-honouring Beta-PERT for every estimate, asynchronous runs, core results with sensitivity, aggregation and convergence diagnostics, bit-for-bit reproducibility per engine version) taken with Robert Former.
- 2026-11-10: **Approved** by Robert Former, with the open questions' proposals as stated (to be settled in the design).
- 2026-11-10: AC-15 to AC-17 amended in the design (decided with Robert Former): bit-for-bit identical results on the same engine version and CPU architecture; runs record the architecture, and a reproduction on another architecture is labelled as one on another engine version is.
