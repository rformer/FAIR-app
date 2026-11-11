# F-005 Monte Carlo Simulation Engine — Design
Status: Approved | Owner: Robert Former | Last updated: 2026-11-10
Requirements: `requirements.md` (Approved 2026-11-10) · ADR-002, ADR-003, ADR-013

## 1. Overview
- **The risk service owns runs; the engine only computes.** The risk service (Go) records runs and aggregates in a new schema `analysis`, queues them as River jobs, builds each run's input bundle (F-003 `risk.BuildBundle`), calls the engine, and stores results with their audit events in one transaction. The engine (`fairsim`, Python) is stateless: it receives a bundle and parameters, streams progress and results back, and holds no credentials (ADR-013).
- **One FIPS story.** The engine's channel is mTLS terminated by `engine-gate`, a Go sidecar built with the platform's FIPS module, forwarding over a Unix socket (ADR-013). Results digests are computed in Go.
- **Confidence-honouring sampling.** Every estimate becomes a Beta-PERT with its mode at the most likely value and its central interval at the stated confidence equal to minimum–maximum (§3.1), sampled by inverse CDF from counter-based random numbers (§3.3).
- **Common random numbers, deterministic everywhere it matters.** Every random number is addressed by (seed, quantity, iteration, event), so control sets share draws, workers and chunking do not matter, and a run is bit-for-bit reproducible on the same engine version and architecture (AC-17 as amended, §12).
- **Arrays stay with the summaries.** Each control set's per-year annualized loss array is stored in PostgreSQL next to its summary, under the same row-level security (decided 2026-11-10); aggregation and reproduction use it.

## 2. Components
| Component | Language | Role |
|---|---|---|
| `internal/analysis` | Go | Runs, aggregates, the worker (River), the engine client, results storage and digests |
| `internal/analysisapi` | Go | The analysis API (`api/openapi/analysis.yaml`), mounted by `cmd/risk`; gateway segment `analyses` |
| `cmd/engine-gate` | Go | mTLS (FIPS) to Unix-socket gRPC proxy in the engine pod (ADR-013) |
| `engine/fairsim` | Python 3.12 | The engine: sampling, model, results, sensitivity, aggregation, validation suite, gRPC server on a Unix socket |
| `api/proto/fair/engine/v1/engine.proto` | proto | The engine contract (generated Go into `internal/api/enginev1`, Python into `engine/fairsim/_proto`) |
| `deploy/k8s/engine.yaml` | | Engine Deployment (engine + gate), Service, NetworkPolicy (ingress from the risk service only, no egress) |
| `web/` | | Run and aggregate status on the scenario page (states, progress, warnings); charts are F-006 |

## 3. The model

### 3.1 Confidence-honouring Beta-PERT (AC-07; OQ3)
An estimate gives `lo ≤ ml ≤ hi` at confidence `c` in a unit with domain `[d₀, d₁]` (`events_per_year` and `currency`: `[0, ∞)`; `probability` and `fraction`: `[0, 1]`; `percentile`: `[0, 100]`). The engine finds true bounds `a ≤ lo`, `b ≥ hi` of a Beta-PERT (λ = 4: α = 1 + 4(ml − a)/(b − a), β = 1 + 4(b − ml)/(b − a)) such that `F(lo) = (1 − c)/2` and `F(hi) = (1 + c)/2`, with `d₀ ≤ a` and `b ≤ d₁`. The two equations are solved for `(a, b)` by a damped Newton iteration on the regularized incomplete beta function with a bisection safeguard, to a relative tolerance of 1e-12, deterministic for the same inputs.

Fallbacks, applied in order and recorded on the run with the estimate's pointer and the fallback's code (AC-07):
1. `point`: `lo = hi` — the quantity is the constant `lo`.
2. `domain_low` / `domain_high`: the solution would put `a < d₀` (or `b > d₁`) — that bound is fixed at the domain's edge and the other is solved so the interval holds `c` in total (the tails no longer equal). When both would leave the domain, the low side is tried first.
3. `bounds`: no solution within 200 iterations, or no solution with a bound inside the domain (both bounds would be at it) — a plain Beta-PERT on `[lo, hi]`.

Sampling is by inverse CDF. For speed, each distribution's quantile function is tabulated at 2¹⁶ + 1 equally spaced probabilities and interpolated linearly; cells where interpolation would miss by more than an eighth of the tolerance at their midpoint (the tails, where the density goes to zero) are marked and their draws use the exact inverse. The validation suite bounds the table's error against the exact inverse (`scipy.special.betaincinv`) at 1e-6 of the range (§8 of the guide).

### 3.2 A simulated year (AC-08, AC-09; OQ1, OQ2, OQ4)
For iteration `i`, per control set `s`:
1. **Year-level quantities** are drawn once: every frequency, probability, threat capability or resistance strength estimate the scenario's levels use, each secondary stakeholder group's SLEF, and each control effect of the control sets.
2. **Controls** (OQ1, OQ2). The entered estimates describe the *current* state, with the current control set in place. For a set `s`, controls in `s` but not in the current set are *added*; controls in the current set but not in `s` are *removed*.
   - A reduction `r` of contact frequency, probability of action, threat capability or a form of loss multiplies the factor by `(1 − r)` when added and divides it by `(1 − r)` when removed (`r` capped at 0.999 for removal; probabilities clipped at 1; both flagged when they apply). Several reductions multiply.
   - Resistance strength: the set's strength is the strongest of the entered resistance strength and the added controls' strengths. Removing a control that provides resistance strength is not modelled (the entered estimate already includes it) and is flagged on the run.
   - A control set's per-scenario effect overrides (F-003 §3.5) replace the control's default effect.
3. **Vulnerability** (OQ4): entered directly, or derived as the probability that a threat agent's capability exceeds the resistance strength: `V = 1 − F_TCap(RS / (1 − r_tcap))`, with `F_TCap` the threat capability estimate's CDF and `r_tcap` the combined reduction of threat capability.
4. **Frequencies**: `TEF = CF × PoA` or entered; `LEF = TEF × V` or entered.
5. **Events**: the year's loss events `N ~ Poisson(LEF)`, drawn by inverse CDF from one uniform per year.
6. **Primary loss**: for each event `k < N` and form `f`, a magnitude drawn from the form's estimate (after reductions). For `N > 1,000` the sum over events beyond the first 1,000 is drawn from a normal with the sum's mean and variance (flagged `large_frequency`).
7. **Secondary loss**: for each event and stakeholder group `g`, a secondary loss event occurs if its uniform is below `SLEF_g`; its loss is the sum of the group's forms, drawn per event.
8. **Year totals**: annualized loss `ALE = Σ primary + Σ secondary`, kept with the split by primary/secondary and by form.

Every input is sampled independently (stated on each result, AC-10).

### 3.3 Random numbers (AC-09, AC-17)
`u(seed, q, i, k) ∈ (0, 1)` is Philox4x32-10 keyed by the 64-bit seed, with counter `(i, k, q, 0)` for the 32-bit quantity id `q` (Philox4x32's key is 64 bits, so `q` takes a counter word), turned into a double from 53 bits (`m · 2⁻⁵³`, with `m = 0` read as 1 so that `u` is never 0). `q` is FNV-1a over the quantity's name: the estimate's JSON pointer in the scenario (or `control:<id>/<effect>` for control effects, `events`, `secondary:<g>`), so the same quantity draws the same numbers in every control set, and adding an estimate does not shift any other's draws. The generator is pure NumPy integer arithmetic on `uint32` arrays; its output is checked against the published Philox test vectors.

### 3.4 Results (AC-11 to AC-14; OQ6)
Per control set, from the per-year arrays:
- **Summaries** of ALE, LEF and loss per event (all events of all years): mean and standard deviation (two-pass, `math.fsum`), minimum, maximum, percentiles 1, 5, 10, 25, 50, 75, 90, 95, 99 as order statistics (`inverted_cdf`, no interpolation), and `P(ALE > 0)`.
- **Loss exceedance curve**: 200 annual-loss values, spaced logarithmically from the 0.1st percentile of the positive annual losses to the maximum, each with `P(ALE > x)`, plus the exceedance at every reported percentile.
- **Breakdown**: mean ALE split into primary and secondary and by form of loss (by stakeholder group for secondary).
- **Comparison** (AC-12): for each set against the current one, the difference in mean and in percentiles 50, 90, 95 and 99, and the summary of the per-year difference `ALE_s − ALE_current` (common random numbers make it meaningful).
- **Convergence** (AC-13): standard error of the mean `sd/√n`, relative standard error `SE/mean`, and distribution-free 95% intervals for percentiles 50, 90, 95 and 99 (binomial order-statistic bounds). The warning `not_converged` is raised when the relative standard error exceeds `simulation.convergence_threshold_bp` basis points.
- **Sensitivity** (AC-14; OQ6): for each input (each estimate the scenario uses and each control effect of the set), the change in mean ALE when the input is fixed at its 5th and at its 95th percentile with every other input sampled as before (same seed), over the first `min(iterations, 20,000)` iterations; and the Spearman rank correlation between the input and ALE over all iterations (for event-level inputs, the year's total of that form). Ordered by the absolute swing.

### 3.5 Aggregation (AC-18, AC-19)
Members are succeeded runs, one control set each, all with the same iteration count (refused otherwise). The aggregate's per-year loss is `Σ_m ALE_m[π_m(i)]`, where `π_m` is a permutation of the iterations derived from the aggregate's seed and the member's position, so members never share draws even if their runs share a seed (independence, stated). The aggregate stores the same summaries and curve as a run, and each member's contribution (its mean, and its share of the aggregate's 95th-percentile year). Members on different engine versions are listed on the aggregate.

### 3.6 Engine versions and validation (AC-20, AC-21)
- The engine version is `fairsim`'s release version; the model version (the rules of §3) is part of it. Changing anything that alters results is a new version.
- The validation suite (`fairsim validate`, `engine/fairsim/validation/`) checks, with fixed seeds and stated tolerances: sampler quantiles and moments against the exact Beta-PERT for a grid of estimates, every fallback; the quantile table's error; the Philox vectors; known answers (constant inputs give constant ALE; Poisson frequency λ with constant magnitude m gives mean λm and variance λm²; a reduction r scales the mean by (1 − r); derived vulnerability against numerical integration); convergence intervals' coverage; aggregation of independent members (mean and variance add); and the cross-feature test (§3.3, ADR-013).
- CI runs the suite on every change under `engine/`. The image build runs it again and writes `/engine/validation.json` (suite version, result, date) into the image. At startup the engine runs a short self-check (seconds) and refuses to serve if it fails; `Info` reports the version, architecture and validation record, and the worker refuses to run on an engine whose validation did not pass (the run fails with `engine_not_validated`).
- `profilegen release-check` requires the engine image's validation record to pass.

## 4. Data model (schema `analysis`)

### 4.1 Tables
All BU-owned tables are created with `authz.apply_bu_rls(..., 'analysis')` and get `rlstest` fixtures; writes go through definer functions owned by the bootstrap role `analysis_definer` (`authz.allow_definer`, ADR-007 amendment 3).

| Table | BU-owned | Purpose |
|---|---|---|
| `analysis.run` | yes | id, bu_id (the scenario's), scenario_id, scenario_version, bundle_digest, seed (`numeric`, 0 to 2⁶⁴ − 1), iterations, control_sets (names), requested_by, requested_at, state (`queued`, `running`, `succeeded`, `failed`, `cancelled`), progress (0 to 1), started_at, finished_at, cancel_reason, failure, engine_version, architecture, image_digest, validation, warnings (jsonb), result_digest, reproduces (run id), reproduction (`match`, `mismatch`, `other_version`, `other_architecture`), seq |
| `analysis.result` | yes | run_id, control_set, summary (jsonb: summaries, curve, breakdown, comparison, convergence, sensitivity) |
| `analysis.series` | yes | run_id, control_set, ale (bytea: little-endian float64 per iteration) |
| `analysis.aggregate` | yes | id, bu_id (chosen by the requester), name, seed, iterations, requested_by, state, members count, summary, ale, result_digest, engine_versions, seq |
| `analysis.aggregate_member` | yes | aggregate_id, run_id, control_set, position |

- Finished runs and aggregates are immutable for every role (append-only triggers, PF023); results and series are written only by `analysis.finish_run` for a running run, once.
- `analysis.aggregate` adds to its SELECT policy that every member run is visible to the caller (an invoker subquery under the run table's RLS), so an aggregate is seen only by someone who can see every member (AC-19).
- Runs and aggregates move with their scenario: an `AFTER UPDATE OF bu_id` trigger on `risk.scenario` moves the scenario's runs, results and series (F-003-AC-19; §12).
- River: schema `risk_river` (`db/rivergen -schema risk_river -role app_rw`), job kinds `analysis.simulate` and `analysis.aggregate`.

### 4.2 Functions
`analysis.request_run` (checks the active-run limit per requester, `simulation.max_active_runs`, and the iteration bounds; inserts the run and its job in the caller's transaction), `start_run`, `progress`, `finish_run` (results, series, digest, engine record), `fail_run`, `cancel_run` (requester or `analysis.run` at the BU), `request_aggregate`, `finish_aggregate`. Each takes the caller from the signed DB context and emits its audit event in the transaction (§9).

### 4.3 Limits (denial of service)
Iterations between `simulation.iterations_min` and `simulation.iterations_max`; iterations × control sets ≤ 20,000,000 per run (at most 160 MB of series); at most `simulation.max_active_runs` queued or running runs per requester; aggregates of 2 to 200 members; engine memory bounded by chunks of 10,000 iterations; request bodies 64 KiB.

## 5. API (`api/openapi/analysis.yaml`)
| Method and path | Who | Purpose |
|---|---|---|
| `POST /api/v1/analyses/runs` | analysis.run at the scenario's BU | Request a run: `scenario_id`, `version`, optional `control_sets`, `iterations`, `seed` (AC-01, AC-05) |
| `GET /api/v1/analyses/runs?scenario=` | analysis.view (RLS) | A scenario's runs, newest first (AC-02) |
| `GET /api/v1/analyses/runs/{id}` | analysis.view | State, progress, inputs, engine record, warnings, and per set the summary (AC-02, AC-11 to AC-15) |
| `GET /api/v1/analyses/runs/{id}/series/{set}` | analysis.view | The per-year ALE array (`application/octet-stream`, float64 little-endian) for F-006 |
| `POST …/runs/{id}/cancel` | requester, or analysis.run at the BU | With a reason (AC-03) |
| `POST …/runs/{id}/reproduce` | analysis.run at the BU | A new run with the recorded inputs, compared on success (AC-16) |
| `POST /api/v1/analyses/aggregates` | analysis.run at the chosen BU; members in its subtree and visible | Request an aggregate (AC-18) |
| `GET /api/v1/analyses/aggregates?bu=`, `GET …/{id}` | analysis.view, every member visible | List and read (AC-19) |

Conventions as F-001 §6 (lint-enforced). A run's request is refused 409 `archived` for an archived scenario, 409 `too_many_runs` past the limit, 422 for iterations out of bounds, 503 `engine_unavailable` only when no engine is configured (production requires one, §11).

## 6. Key flows

### 6.1 A run
1. `POST /runs`: check `analysis.run` at the scenario's BU; load the version; build the bundle (F-003) and its digest; `analysis.request_run` (limits, the River job) and `analysis.run_requested` in one transaction.
2. The worker claims the job: `start_run`; `Info` on the engine (version, architecture, validation; refuse unvalidated); `Simulate` with the bundle, seed, iterations, control sets and convergence threshold; progress messages update `progress` (at most once a second); between messages the worker checks for cancellation and cancels the stream.
3. The engine streams per set the summary and the series in 1 MiB chunks, then `done` with warnings. The worker checks the shapes (every set present, `iterations` values, finite numbers), computes the results digest (§6.3) and calls `finish_run` with `analysis.run_succeeded`, in one transaction.
4. Failures: the engine unreachable or the stream broken — the job retries (3 attempts, backoff); a model error (`invalid_bundle`, `engine_not_validated`) fails at once with `analysis.run_failed`. A worker that dies mid-run leaves the job to River's rescuer, which re-runs it from the start (results are deterministic). No partial results are stored (AC-04).

### 6.2 Reproduce (AC-16)
`POST /runs/{id}/reproduce` creates a run with the same scenario version, seed, iterations and control sets and `reproduces = id`. The bundle is rebuilt and must have the recorded digest (else the run fails `bundle_changed`, which cannot happen while versions are append-only and is flagged as integrity). On success the outcome is `match` or `mismatch` when the engine version and architecture are the original's, `other_version` or `other_architecture` otherwise; `analysis.run_reproduced` records it.

### 6.3 Results digest (AC-15)
SHA-256 (Go) over the canonical form (F-003 `canon`, numbers as the shortest round-trip decimal) of `{run inputs, engine version, architecture, per set: summary, SHA-256 of the series bytes}`.

### 6.4 Aggregate
`POST /aggregates` checks `analysis.run` at the chosen BU, that every member run is visible, succeeded, inside the BU's subtree and of equal iterations; inserts the aggregate and its job with `analysis.aggregate_created`. The worker streams the members' series to the engine's `Aggregate` and stores the result with `analysis.aggregate_succeeded` (or `_failed`).

## 7. Settings (F-015)
| Key | Default | Bound | Direction |
|---|---|---|---|
| `simulation.iterations_default` | 100,000 | 10,000 to the max | higher is stricter |
| `simulation.iterations_min` | 10,000 | at least 1,000 | higher is stricter |
| `simulation.iterations_max` | 1,000,000 | at most 2,000,000 | lower is stricter |
| `simulation.max_active_runs` | 5 | 1 to 50 | lower is stricter |
| `simulation.convergence_threshold_bp` | 100 (1%) | 10 to 500 basis points | lower is stricter |

Results are kept with their scenario (OQ7): no retention setting; they are evidence for acceptance (F-008).

## 8. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| S: a client poses as the engine, or calls the engine directly | The gate pins client certificates; the engine listens only on its pod's Unix socket; NetworkPolicy admits only the risk service | `TestSTRIDEF005EngineChannel` |
| T: stored results are altered | Finished runs, results and series append-only for every role; results digest recorded and in the audit event; reproduce re-derives it | `TestSTRIDEF005ResultTamper` |
| T: a client supplies results or forges a run's record | Results are written only by `finish_run`, once, for a running run; the record's engine fields come from `Info`, not the request | `TestSTRIDEF005ResultWrite` |
| T: a faulty or substituted engine produces wrong numbers | Validation in CI and at image build, startup self-check, refusal of unvalidated engines; image digest from the signed release manifest recorded on every run | `TestSTRIDEF005EngineValidation` |
| R: a run or aggregate cannot be attributed | Audited in its transaction with actor, BU and bundle digest | `TestAnalysisAuditEvents` |
| I: results cross business units | RLS (`analysis`) on every table; aggregates visible only with every member | `TestSTRIDEF005Visibility` |
| I: the engine sees or keeps more than needed | It receives the bundle only, holds no database credentials, keeps nothing after a run, has no egress | `TestSTRIDEF005EngineIsolation` |
| D: run floods or huge runs | Per-requester active-run limit, iteration and size bounds, member limits, chunked engine memory, the River queue | `TestAnalysisLimits` |
| E: a viewer runs or cancels simulations | `analysis.run` required; viewers hold only `analysis.view` | `TestSTRIDEF005Escalation` |

## 9. New catalog event types
`analysis.run_requested`, `analysis.run_succeeded`, `analysis.run_failed`, `analysis.run_cancelled`, `analysis.run_reproduced` (attribute `outcome`), `analysis.aggregate_created`, `analysis.aggregate_succeeded`, `analysis.aggregate_failed`; category `risk_data`, BU required, attributes `scenario`, `version`, `bundle_digest`, `result_digest`, `iterations`, `control_sets` as each applies.

## 10. Requirements traceability
| AC | Design | Verification |
|---|---|---|
| AC-01, AC-02, AC-05 | §5, §6.1, §4.2, §4.3 | DB tests of the analysis API; UI status on the scenario page |
| AC-03, AC-04 | §6.1 | DB tests with a fake engine (cancel, retry, failure) |
| AC-06 | §4.1 | DB tests (immutability, move with the scenario) |
| AC-07 | §3.1 | Validation suite (samplers, fallbacks) |
| AC-08, AC-09 | §3.2, §3.3 | Validation suite (known answers, controls); engine unit tests |
| AC-10 | §3.2, guide `docs/guides/simulation.md` | Document review; result field |
| AC-11 to AC-14 | §3.4 | Engine unit tests; validation suite (convergence coverage) |
| AC-15 to AC-17 | §3.3, §6.2, §6.3 | Determinism tests (workers, chunking, CPU features), reproduce DB test |
| AC-18, AC-19 | §3.5, §6.4, §4.1 | Engine tests; DB tests (visibility, members) |
| AC-20, AC-21 | §3.6 | CI job; startup self-check test; worker refusal test |
| AC-22, AC-23 | §4.1, §5, §9 | RLS harness fixtures; STRIDE suite; audit event tests |
| NFR performance | §3.1, §4.3 | `TestBenchmarkGateSimulation` |

## 11. Deployment modes
Identical in SaaS, self-hosted and air-gapped. The engine pod has no egress (NetworkPolicy) and needs nothing outside the cluster. In production the risk service requires `FAIR_ENGINE_ADDR` and its engine client keys (`risk/engine-client`); the gate requires `engine-gate/tls` and the pinned client certificate. `CheckInstall` refuses to start without them, and the deployment-mode matrix covers them.

## 12. Changes to other features
- **F-005 requirements**: AC-17 amended (decided with Robert Former 2026-11-10): identical results "on the same engine version and CPU architecture, whatever the CPU model, the number of workers and the order runs are executed in"; AC-15 also records the architecture, and AC-16 labels a reproduction on another architecture like one on another engine version.
- **F-001**: tables of resource type `analysis` (already in the catalog) with RLS fixtures; bootstrap role `analysis_definer`; key layout gains `engine-gate/tls` and `risk/engine-client` (`iam keys upgrade`); gateway segment `analyses` to the risk service.
- **F-003**: moving a scenario moves its runs (trigger, §4.1); archiving a scenario refuses new runs and keeps old ones.
- **F-015**: five settings (§7); packages 1.5.0. The release manifest records the engine image and its validation record.
- **F-002**: eight catalog event types (§9).
- **F-014**: the component definition gains F-005's statements (T-last).

## 13. Alternatives considered
- grpcio over its embedded BoringSSL: rejected, not a validated module (ADR-013).
- Synchronous runs: rejected; long runs would hold requests and fail on timeouts (decided 2026-11-10).
- Plain PERT at the bounds: rejected; it ignores the confidence F-004 captures and calibrates (decided 2026-11-10).
- Arrays in the object store: rejected for v1; a new required store and visibility checked outside RLS (decided 2026-11-10).
- NumPy's sequential generators: rejected; draws depend on chunking and event counts (ADR-013).
- Exact sampling of every event at any frequency: rejected; unbounded cost for very frequent events; the normal approximation beyond 1,000 events a year is flagged.

## 14. Open items
- Reference node for the performance budget: proposed 8 vCPU, 16 GiB, as F-001's benchmark nodes.
- arm64 images: built and validated like amd64 when F-012 (packaging) adds multi-arch releases; until then the engine image is amd64 only.

## Change Log
- 2026-11-10: Initial draft; decisions (Go FIPS gate for the engine's TLS, ADR-013; bit-for-bit per engine version and architecture; per-year arrays in PostgreSQL) taken with Robert Former; requirements OQ1 to OQ8 settled as proposed.
- 2026-11-10: **Approved** by Robert Former, with ADR-013.
- 2026-11-10: T-01 (decided with Robert Former): the convergence threshold is the integer setting `simulation.convergence_threshold_bp` in basis points (default 100, bounds 10 to 500), since F-015 has no decimal kind. The profiles bound the loosening side (iterations default ≥ 10,000, minimum ≥ 1,000, maximum ≤ 2,000,000, active runs ≤ 50, threshold ≤ 500); the service keeps the other limits. Iterations maximum and active runs map to SC-5.
- 2026-11-10: T-02 (decided with Robert Former): the aggregate's visibility rule is ADR-007 amendment 4 (`authz.restrict_select`: one RESTRICTIVE select policy `bu_restrict` for app_rw, here calling `analysis.members_visible`), since `apply_bu_rls` admits no other policy and a permissive one would widen access. Requests are invoker functions inserting the run with empty per-set result and series rows (the definer role is never granted INSERT, ADR-007 amendment 3); the worker's calls carry an attempt token from `start_run`. The SQL functions emit every §9 event.
- 2026-11-10: T-05 (clarifications, approved with the task): the quantity id is Philox's third counter word (the 64-bit key is the seed); `m = 0` maps to `2⁻⁵³` so uniforms are in (0, 1); quantile-table cells too curved for linear interpolation (the tails) use the exact inverse, which is what makes the 1e-6 bound hold with equally spaced probabilities; when both bounds would leave the domain the low side is fixed first, and `bounds` applies only when neither fix has a solution.
- 2026-11-10: T-06 (clarifications, approved with the task): (1) a reduction of contact frequency or probability of action multiplies the entered threat event or loss event frequency when the scenario does not model that factor (the product is the same); (2) threat capability and resistance strength effects are `effect_not_modelled` when Vulnerability is entered directly; (3) a control in both the current set and another with a different effect (version or override) is the current effect removed and the set's added, flagged `control_effect_changed`, drawing the same random numbers; (4) a form-of-loss reduction applies to that form in primary and secondary loss; (5) threat capability enters only through its CDF (§3.2 step 3), it is not drawn; (6) beyond 1,000 events a year the normal sums draw their uniform at event index 2³² − 1, which no event uses, and secondary loss is approximated per stakeholder group (compound Bernoulli moments); (7) loss per event is summarized over at most 2,000,000 events per control set, the first `e` events of every year for the largest `e` that fits (`loss_per_event_sampled`; unbiased, since a year's events are identically distributed); (8) means are exact sums over the count, correctly rounded (`fairsim.exact`, as `math.fsum`), so they do not depend on chunking; (9) warning codes: the fallback's code (`point`, `domain_low`, `domain_high`, `bounds`), `reduction_capped`, `probability_clipped`, `resistance_removal_not_modelled`, `effect_not_modelled`, `control_effect_changed`, `large_frequency`, `loss_per_event_sampled`, `not_converged`.
- 2026-11-11: T-07 (clarifications, approved with the task): (1) a set's inputs are the estimates the scenario uses and the control effects the set adds or removes (the current set changes none, so lists none); a changed effect is listed once and held at each of its distributions' own percentile; (2) threat capability held at a percentile is a single capability against each year's resistance strength, so the year's Vulnerability is 0 or 1; it has no yearly value, so its Spearman correlation is null (as for an input that does not vary); (3) for a secondary form of loss the yearly value is the year's total of that form in its stakeholder group (exactly sampled events); (4) each set's summary gains `sensitivity`: `iterations`, `low` 0.05, `high` 0.95, `base_mean`, and `inputs` (input, pointer, kind `estimate` or `control_effect`, control, factor, `low` and `high` with value, mean and change, `swing` = |high change − low change|, `spearman`), ordered by swing then name; (5) an aggregate's permutation for a member is the stable order of `u(seed, member:<position>, i)`; its 95th-percentile year is the year holding the `inverted_cdf` order statistic (the first in the stable sort among equal losses); its summary holds `independence`, `iterations`, `members`, `ale`, `curve`, `p95_year` and `contributions` (position, label, mean, share_of_p95_year).
- 2026-11-11: T-08 (clarifications, approved with the task): (1) runs use a pool of worker processes started with `spawn` (`serve --workers N`, default the CPU count); chunks travel as tasks with their bundle, each worker keeps the last two models, at most 2N tasks are in flight, and results are merged in chunk order with exact sums, so any worker count or completion order gives the same bits; (2) the engine checks every request itself: bundle at most 8 MiB, iterations 1 to 2,000,000, iterations × control sets at most 20,000,000, 1 to 100 control sets, threshold 1 to 10,000 bp; refusals and malformed aggregate input are `invalid_bundle` failures, unexpected errors `internal` with no internals in the detail; (3) an engine runs at most two runs at once and answers more with RESOURCE_EXHAUSTED (the worker retries); (4) the socket is created owner-and-group only (umask 007) in a directory the engine's user (65532) can write: an emptyDir in the pod (T-10); (5) progress is sent at most every half second and at the end; its total counts the sensitivity passes; (6) summaries are JSON with sorted keys, compact, NaN and infinities refused; (7) without a readable validation record `Info` reports `passed: false`; (8) the determinism tests also run with NumPy's default dispatch (AVX2 on the CI machine) against the pinned baseline: the results are identical.
- 2026-11-11: T-09 (clarifications, approved with the task): (1) the cross-feature check simulates the F-003 corpus scenario exactly as `risk.BuildBundle` makes it (`engine/fairsim/validation/f003_corpus_bundle.json`, kept equal by the Go test `TestEngineValidationBundle`; `FAIR_UPDATE_GOLDEN=1` regenerates it) for 50,000 iterations and requires the results digest recorded for this engine version and architecture in `engine/fairsim/validation/reference.json` (`python -m fairsim validate --record-reference`): changing results without a new engine version fails the suite; (2) the record holds `suite_version`, `engine_version`, `architecture`, `passed`, `run_at_unix_ms`, `seconds`, `self_check_digest` and per-check `detail`; (3) the startup self-check runs the Philox vectors, a few fits, a table spot check and a 2,000-iteration corpus run whose digest must equal the record's `self_check_digest` (the record must be this engine's version and architecture); a failure refuses to serve (exit 1); a missing record does not stop serving (`Info` reports not passed and the risk service refuses the engine); (4) convergence coverage: 300 samples of 2,000 from a known PERT, each interval covering the true percentile in at least 92% (nominal 95%); (5) the release manifest gains `engine_validation` (image, suite and engine versions, architecture, passed, time, the record's SHA-256), required when it names the engine image; `releasegen manifest -engine-validation FILE` adds it and `profilegen release-check -manifest FILE` requires it passed; the release workflow's `engine-validation` job builds it from the engine image until F-012 publishes the signed manifest with registry digests.
- 2026-11-11: T-10 (clarifications, approved with the task): (1) the channel's certificates are self-signed ECDSA P-256 (397 days), each side pinning the other's by SHA-256 (`risk/engine-client`: `tls.crt`, `tls.key`, `gate.sha256`; `engine-gate/tls`: `tls.crt`, `tls.key`, `client.sha256`); `-kind engine` replaces both and keeps the previous pins, so either side rolls out first; certificates and pins are re-read on every handshake; an expired or unpinned certificate is refused; (2) engine-gate copies the decrypted bytes to the socket unchanged (ALPN h2, at most 64 connections, 10 s handshakes) and parses nothing; a plain HTTP listener on 8081 answers only the kubelet's `/healthz` and `/readyz` (the engine's socket accepts); (3) the gate logs refused handshakes (no event type: §9 has none for the channel); (4) the engine pod has no egress; with OpenBao, the overlay adds its agent's egress to OpenBao (port 8200 and DNS), the agent alone mounting the OpenBao token; (5) the risk service's egress admits the engine's gate on 8444; its CheckInstall requires `FAIR_ENGINE_ADDR` and `FAIR_ENGINE_CLIENT_DIR` in production from now on (used from T-11).
- 2026-11-11: T-11 (decided with Robert Former; with clarifications approved with the task): (1) a run's input bundle is kept with it (migration 0104, decided 2026-11-11): `analysis.run_input`, BU-owned analysis data that only readers with the scenario's read scope may also read (a RESTRICTIVE select policy), append-only, moved with its scenario; `analysis.request_run` now takes the bundle and records its SHA-256 as the run's bundle digest; every run has its input when its transaction commits (a deferred constraint trigger); the worker, which has no DB context of its own (only the gateway mints one), reads the bundle and the run's inputs with its attempt token (`analysis.run_bundle`, `analysis.run_spec`); (2) the worker reports progress at most once a second and stops when told the run is cancelled; gRPC Unavailable, DeadlineExceeded, Aborted, ResourceExhausted, Canceled, Unknown and Internal are retried (3 attempts, then `engine_unavailable`); the engine's failure `internal` is recorded `engine_internal`; malformed results (a missing or repeated set, a series out of order, of the wrong length or with a value not finite or negative, a summary not a JSON object) are `invalid_results`; an attempt has at most 2 hours; each replica runs `FAIR_ANALYSIS_WORKERS` simulations at once (2); (3) the results digest is the canonical form of `{format: fair.analysis-result.v1, run, engine, sets}`, integers kept and every other number written as its shortest round-trip decimal string; (4) the API takes the seed as a decimal string (JSON numbers lose precision past 2^53); a run's control sets default to all of the version's, the current set first; a missing version is 422; a scenario's runs are listed by keyset on `seq` (index `(scenario_id, seq)`); (5) outside production `FAIR_ENGINE_ADDR=unix:///path` reaches an engine's socket without the gate (development and harnesses); `FAIR_ENGINE_IMAGE_DIGEST` gives the image digest recorded on every run.
