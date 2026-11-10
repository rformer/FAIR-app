# F-005 Monte Carlo Simulation Engine — Tasks
Status: **Approved** (Robert Former, 2026-11-10) | Design: Approved 2026-11-10

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites: F-001 (RBAC, `analysis.*` permissions, keys, the gateway), F-002 (audit trail), F-003 (scenarios, input bundles, move and archive), F-015 (settings, release manifest). All are done.
Every task that adds a migration follows the immutability rule. Every new event type gets a catalog entry with the task that first emits it. Every new route is linted by `scripts/openapi-lint.sh`. Every new BU-owned table gets an `rlstest` fixture. Every engine change runs the engine CI job (lint, types, tests, validation suite).

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | F-005 settings (design §7) as `settings.F005Defs()`, bindings, packages 1.5.0; the risk service registers them | AC-01, AC-05, AC-13; §7 | Settings tests (bounds, stricter direction, iterations_min ≤ default ≤ max); release-check passes; the risk service refuses to start on an unbound key | S | Not started |
| T-02 | Schema `analysis` (migration): tables of §4.1 with `apply_bu_rls(..., 'analysis')` (RLS harness fixtures), bootstrap role `analysis_definer` (`scripts/db-bootstrap.sh`), append-only finished runs and aggregates (PF023), the functions of §4.2 with limits (§4.3), the aggregate SELECT policy (every member visible), the move trigger on `risk.scenario`; River schema `risk_river` (`db/rivergen`) | AC-01 to AC-06, AC-19, AC-22; §4 | DB tests: app_rw writes only through the functions; finished runs immutable for every role; limits and bounds refused; moving a scenario moves its runs; an aggregate hidden unless every member is visible; RLS harness passes | L | Not started |
| T-03 | The engine contract `api/proto/fair/engine/v1/engine.proto` (`Info`, `Simulate`, `Aggregate`; progress, result, series chunks, done), generated Go (`internal/api/enginev1`) and Python (`engine/fairsim/_proto`) by `scripts/gen-proto.sh`; the eight catalog entries of §9 | §2, §6.1, §9 | Generated code checked in and reproducible (CI diff check); `TestCatalogMatchesCode` once the events are emitted | S | Not started |

## Phase B — The engine (Python)
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-04 | Python toolchain: `engine/` (package `fairsim`, Python 3.12), `requirements.lock` with hashes, ruff, mypy (strict), pytest; CI job `engine` (lint, types, tests, lock check, SBOM); image target `engine` (Debian 12 minimal base, non-root, read-only root, no shell; `NPY_DISABLE_CPU_FEATURES` pinned to the baseline) | §2; ADR-013 | CI job green; image builds, runs as non-root with a read-only root; SBOM lists every pinned dependency | M | Not started |
| T-05 | Random numbers and sampling: Philox4x32-10 in NumPy (published test vectors), FNV-1a quantity ids, the confidence-honouring Beta-PERT fit with its fallbacks (`point`, `domain_low`, `domain_high`, `bounds`), quantile tables and inverse-CDF sampling | AC-07, AC-09, AC-17; §3.1, §3.3 | Unit tests: test vectors; draws independent of chunking; fitted PERTs hold the stated confidence (to 1e-9) on a grid of estimates and units; each fallback; table error ≤ 1e-6 of the range against `betaincinv` | M | Not started |
| T-06 | The model and results: a simulated year (§3.2: levels, controls added and removed, derived vulnerability, Poisson events, primary and secondary loss, the large-frequency approximation, flags) and the results of §3.4 except sensitivity (summaries, curve, breakdown, comparison, convergence) | AC-08, AC-09, AC-11 to AC-13; §3.2, §3.4 | Unit tests: known answers (constant inputs; λ·m mean and λm² variance; a reduction scales the mean; vulnerability against numerical integration); common random numbers (a set identical to current gives zero difference every year); every flag; result shapes | L | Not started |
| T-07 | Sensitivity and aggregation (§3.4 sensitivity, §3.5) | AC-14, AC-18; §3.4, §3.5 | Unit tests: an input with no effect swings 0; the strongest input orders first; Spearman against a reference; aggregates of independent members add means and variances; permutations stop shared seeds correlating | M | Not started |
| T-08 | The gRPC server on a Unix socket (`Info`, `Simulate` streaming progress, results and series chunks, `Aggregate`), chunked multiprocessing, cancellation, input checks; determinism tests | AC-02, AC-03, AC-15, AC-17; §3.3, §6.1 | Tests: identical results for 1, 2 and 8 workers and any chunk order; under default and pinned CPU features; a cancelled stream stops work; malformed bundles refused (`invalid_bundle`) | M | Not started |
| T-09 | The validation suite (`fairsim validate`, §3.6), the image's validation record (`/engine/validation.json`), the startup self-check, and `profilegen release-check` requiring a passed record in the release manifest | AC-20, AC-21; §3.6 | The suite passes in CI and at image build; a deliberately broken sampler fails it; the engine refuses to serve after a failed self-check; release-check refuses a failed or missing record | M | Not started |

## Phase C — Integration
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-10 | `cmd/engine-gate` (Go, FIPS): mTLS 1.2+ listener, pinned client certificates, forwarding to the engine's Unix socket; keys `engine-gate/tls` and `risk/engine-client` (`keys.Mounts`, `iam keys upgrade`, `-kind engine`); `deploy/k8s/engine.yaml` (engine and gate containers, in-memory socket volume, Service, NetworkPolicy without egress); `CheckInstall` for both | NFR security; §2, §11; ADR-013 | Tests: an unpinned or absent client certificate is refused; TLS below 1.2 refused; the engine container has no listening TCP port; `TestDeploymentModeMatrix` covers the new keys; the NetworkPolicy admits only the risk service | M | Not started |
| T-11 | Runs in the risk service: `internal/analysis` (engine client, River worker: start, `Info` checks, `Simulate`, progress, cancellation, retries, failure, results checks, digest, `finish_run`), API `api/openapi/analysis.yaml` (`POST/GET /analyses/runs`, `GET …/{id}`, `GET …/{id}/series/{set}`, `POST …/{id}/cancel`); gateway segment `analyses`; events | AC-01 to AC-06, AC-11 to AC-15, AC-21 to AC-23; §5, §6.1, §6.3 | DB tests through the API with a fake engine (permissions, 404 and 403, archived 409, too many runs 409, iteration bounds 422, cancel while queued and running, retry then success, model error fails at once, no partial results, unvalidated engine refused, events in the transaction) and one end-to-end test with the real engine | L | Not started |
| T-12 | Reproduce and aggregates: `POST …/runs/{id}/reproduce` (outcomes `match`, `mismatch`, `other_version`, `other_architecture`), `POST/GET /analyses/aggregates`, the aggregate worker | AC-16, AC-18, AC-19, AC-23; §6.2, §6.4 | DB tests: a reproduced run matches on the same engine; a changed engine version or architecture is labelled; aggregates refuse unequal iterations, members outside the BU's subtree or not visible; an aggregate hidden from a viewer missing a member; events | M | Not started |
| T-13 | Run status on the scenario page: request a run (control sets, iterations, seed), runs list with state, progress, warnings and convergence, cancel, reproduce and its outcome; aggregates list and request; the UI harness runs the engine | AC-01 to AC-05, AC-13, AC-16, AC-18; §2 | Playwright and axe (WCAG 2.1 AA) in `scripts/ui-e2e.sh` against the real API and engine | M | Not started |
| T-14 | User guide `docs/guides/simulation.md`: sampling and its fallbacks, the taxonomy computation, controls (added and removed), vulnerability, results and what they mean, convergence, sensitivity, aggregation and independence, reproducibility | AC-10 | Reviewed by Robert Former; every flag and fallback code documented (a test compares the codes in the engine with the guide) | S | Not started |

## Phase D — Gates
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-15 | Benchmark gate `TestBenchmarkGateSimulation`: a fully decomposed scenario, 100,000 iterations, three control sets, with sensitivity, ≤ 30 s p95 on the reference node; aggregating 100 runs ≤ 10 s; a queued run starts within 5 s | Requirements NFR | Bench gate passes in CI | M | Not started |
| T-16 | STRIDE suite for design §8 (`db/tests/stride_f005_test.go`, rows in `TestSTRIDECatalog`) | Q5; §8 | `make test-stride` covers every §8 row | M | Not started |
| T-17 | Control implementation statements `compliance/statements/F-005.yaml`, built into the component definition; against the requirements' control mapping (added 2026-11-10); Robert Former signs off | S1, Q1 | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Definition of Done
- All linked acceptance criteria have passing automated tests.
- Audit events emitted per design §9, each in the catalog.
- API contract updated and linted; the engine contract generated and checked.
- The statistical validation suite passes for the released engine version.
- Security review notes recorded (STRIDE rows and tests).

## Change Log
- 2026-11-10: Initial draft.
- 2026-11-10: **Approved** by Robert Former, with the control mapping added to the requirements.
