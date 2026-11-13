# F-006 Results & Visualization — Tasks
Status: **Approved** (Robert Former, 2026-11-13) | Design: Approved 2026-11-13

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites:
- F-005: runs, aggregates, results, series, the analysis API and its pages.
- F-001: `analysis.view`, the event catalog, the gateway.
- F-002: the audit trail.
- F-003: scenarios and versions.

All of these are done.

Rules for every task:
- No migrations are planned. If a task needs one, it follows the immutability rule.
- A new event type gets its catalog entry with the task that first emits it.
- Every new route is linted by `scripts/openapi-lint.sh`.
- Every UI task runs `scripts/ui-e2e.sh`, with axe on every page it touches.

## Phase A — The service
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | Histograms (§3.1): `analysis.Histogram` (annual loss, log and linear; per-year difference against another set; years with no loss or no difference apart; markers from the stored summaries); `GET /api/v1/analyses/runs/{id}/histogram` and `/aggregates/{id}/histogram` in the contract | AC-02, AC-07, AC-09, AC-20; §3.1, §5 | Unit tests: binning rules (edges, last bin closed, one distinct value, all zero, negative differences), known series; DB tests `TestAnalysisHistogram` (runs, differences, aggregates; 404 unseen; 422 bad set, scale or relative_to; a hidden aggregate member gives 404) | M | Not started |
| T-02 | Comparisons (§3.2): `analysis.Compare` (items parsed and limited, one snapshot under RLS, all or 404, 409 `not_succeeded`, differences from the base, `unlike`, the sampling-noise statement); `GET /api/v1/analyses/compare` | AC-10, AC-11, AC-13, AC-20; §3.2, §5 | DB tests `TestAnalysisCompare` (runs and aggregates mixed, across BUs, every `unlike` field, differences, refusals); `TestSTRIDEF006ComparisonOracle` (one 404 body for hidden and nonexistent items at every position) | M | Not started |
| T-03 | CSV and download records (§3.3, §6.2, §6.3): `analysis.WriteCSV` (metadata block, BOM, CRLF, neutralized text cells, numbers from floats), the `.csv` routes for runs, aggregates and comparisons, `POST /api/v1/analyses/downloads`; catalog entry `analysis.downloaded`; events per business unit in the serving transaction, 503 when the audit cannot be recorded | AC-18, AC-19, AC-20; §3.3, §6, §8 | Unit tests of the writer (`TestAnalysisCSVNeutralized`: names starting `=`, `+`, `-`, `@`, tab, CR; negative numbers stay numbers); DB tests `TestAnalysisCSV` (each view's values equal the JSON's), `TestAnalysisDownloadEvents` (attributes, one per BU of a cross-BU comparison, fail closed with no file), `TestAnalysisResultViewLimits` | M | Not started |

## Phase B — The charts and pages
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-04 | The chart components (ADR-014): `web/src/charts` (`scale.ts`, `curve.ts` for reading the curve (§3.4), `palette.ts` and the `--series-*` tokens, `ExceedanceChart`, `Histogram`, `Bars`, `Tornado`, `ChartFigure` with the text alternative and data table, `export.ts` for SVG and PNG); unit tests run by Node's own test runner (`node --test`, TypeScript by type stripping; no new dependency) in CI's web job | AC-05, AC-14, AC-15, AC-17; §3.4, §4; ADR-014 | `scale.test.ts` (ticks, log and linear), `curve.test.ts` (interpolation, below the first point, above the maximum, the inverse), `palette.test.ts` (3:1 in both themes, styles distinct without colour), `export.test.ts` (no script, `foreignObject`, event attributes or external references; names escaped) | L | Not started |
| T-05 | The run page `/analyses/runs/{id}` (§4): header facts, Exceedance with cursor and lookups, Distribution, Breakdown, Drivers, Control sets; links from the scenario page's runs; downloads (images through `POST /downloads`, CSV links) | AC-01 to AC-06, AC-09, AC-14 to AC-17; §4, §6.1 | `web/e2e/results.spec.ts`: the seeded run's views and values, the keyboard cursor and its live readout, lookups both ways, the data tables, SVG, PNG and CSV downloads with their footers and records, an exported scenario name holding markup stays text, axe | L | Not started |
| T-06 | The aggregate page's charts (exceedance, distribution, contributions; members, independence, mixed engines) and the comparison page `/analyses/compare` ("Add to comparison", "Compare versions" on the scenario page, the unlike notice, "not available" for hidden items) | AC-07, AC-08, AC-10 to AC-13, AC-16; §3.2, §4 | `web/e2e/results.spec.ts` (an aggregate's views; compare versions of the seeded scenario; a shared address opened by a user who cannot see one item shows nothing of it; keyboard only; axe); the UI harness seeds a second version's run | M | Not started |

## Phase C — Assurance
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-07 | Benchmark gate `TestBenchmarkGateResultViews`: a seeded run of 1,000,000 iterations with three control sets; the run's views (GET and three histograms) ≤ 2 s p95; a comparison of six ≤ 3 s p95; each CSV view ≤ 2 s | Requirements NFR; §11 | Bench gate passes in CI | S | Not started |
| T-08 | STRIDE suite for design §7 (`db/tests/stride_f006_test.go`, rows in `TestSTRIDECatalog`) | Q5; §7 | `make test-stride` covers every §7 row | S | Not started |
| T-09 | Control implementation statements `compliance/statements/F-006.yaml`, built into the component definition; the control mapping (design §14: AC-3, AU-2, AU-12, RA-3, SI-10, SI-15) added to the requirements; Robert Former signs off | S1, Q1 | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Definition of Done
- All linked acceptance criteria have passing automated tests.
- `analysis.downloaded` is emitted per design §8 and is in the catalog.
- The API contract is updated and linted.
- axe passes on every F-006 page in the UI end-to-end suite.
- Security review notes are recorded (STRIDE rows and tests).

## Change Log
- 2026-11-13: Initial draft.
- 2026-11-13: **Approved** by Robert Former.
