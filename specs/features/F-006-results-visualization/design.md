# F-006 Results & Visualization — Design
Status: Approved | Owner: Robert Former | Last updated: 2026-11-13
Requirements: `requirements.md` (Approved 2026-11-13) · ADR-003, ADR-014

## 1. Overview
- **Read-only over F-005.** F-006 stores nothing new. It reads F-005's results through the analysis API: per control set, the summaries, the 200-point exceedance curve, the breakdown, the comparison with the current set, convergence and sensitivity; for aggregates, their summary and contributions. It adds three read endpoints to that API: histograms, comparisons and CSV data. Runs are immutable, so anything derived from them is computed when it is asked for.
- **Histograms from the series, on request (OQ1, decided 2026-11-13).** The risk service bins the stored per-year array (up to 1,000,000 float64 values per control set) on each request: milliseconds of work, no new table. API responses stay `Cache-Control: no-store`, like every other risk-data response.
- **Comparisons checked in one place.** A comparison of two to six results is one request. The service returns all of them or answers 404 (AC-13), and it lists which inputs differ (AC-11).
- **Our own SVG charts (ADR-014).** Accessible by construction: a figure, a text alternative, a data table and a keyboard cursor. They are exported in the browser as SVG and PNG, with no change to the content security policy.
- **Every download is audited (AC-19).** CSV is produced by the service, which records `analysis.downloaded` in the transaction that serves it and fails closed. For an image, the browser first records the download with the service, and draws the file only once that succeeds (OQ3). The download's id appears in the file.

## 2. Components
| Component | Change |
|---|---|
| `internal/analysis` | `Histogram` (binning, §3.1), `Compare` (§3.2), `csv.go` (§3.3, the CSV writer with neutralized text cells) |
| `internal/analysisapi` | New routes (§5) on the analysis API; contract `api/openapi/analysis.yaml` |
| `web/src/charts/` | ADR-014: scales, `ExceedanceChart`, `Histogram`, `Bars`, `Tornado`, `ChartFigure`, `export.ts`, `palette.ts`; unit tests |
| `web/src/analysis/` | The run page `/analyses/runs/{id}`, the charts on the aggregate page, the comparison page `/analyses/compare` |
| `web/src/risk/` | The scenario page links each run to its page and offers "Compare versions" (AC-12) |
| `web/src/styles.css` | Series tokens `--series-1` to `--series-6` for the light and dark themes |
| `pkg/audit/catalog.yaml` | `analysis.downloaded` (§7) |

## 3. Derived results

### 3.1 Histograms (AC-02, AC-07, AC-09)
- **Annual loss.** Over the years with a positive loss, in 60 bins. Years with no loss are counted separately, together with their share, and drawn as their own labelled bar beside the histogram (AC-02).
  - `scale=log` (the default) puts the edges at logarithmically equal steps from the smallest positive loss to the largest.
  - `scale=linear` puts them at equal steps from 0 to the largest.
  - With one distinct positive value there is a single bin.
- **Per-year difference** (`relative_to=<set>`). `Δ_i = ALE_set[i] − ALE_ref[i]`, which is meaningful year by year because a run's control sets share their random numbers (F-005 §3.3). The bins are linear over the range of Δ. Years with `Δ = 0` are counted separately, and so are years where both sets lost nothing. A negative Δ is a reduction.
- **The response** carries:
  - `set`, `relative_to`, `scale`, `n`, `zero`, `zero_share`;
  - `edges` (61 values) and `counts` (60);
  - the stored mean and percentiles for the markers (AC-02). For a difference, these come from the comparison's `difference` summary.
- **Counting.** Each value falls in the bin whose lower edge is the largest edge at or below it, and the last bin includes its upper edge. The edges come from Go's `math` (`math.Pow`, `math.Log`) and are sent as JSON numbers. The CSV carries the same values as the chart.
- **Aggregates.** An aggregate's stored `ale` gives its histogram in the same way, with `scale` only.

### 3.2 Comparisons (AC-10, AC-11, AC-13)
- **Items.** Two to six, in order, each `run:<id>:<set>` or `aggregate:<id>`. The control set name is percent-encoded. The first item is the base. A duplicate item is refused with 422.
- **Visibility.** Each item is read under RLS in one database snapshot, with the caller's context. If any item is not visible, the response is 404 `not_found`, the same response whichever item it is and whether or not it exists (AC-13). If any visible item has not succeeded, the response is 409 `not_succeeded`.
- **The response** gives, per item:
  - kind, id, BU, a label (the scenario's name and version and the control set, or the aggregate's name);
  - iterations, seed, engine version and architecture, and the result digest;
  - its ALE summary and curve;
  - its differences from the base (mean and p50, p90, p95, p99), as amounts and as shares of the base.
- **`unlike` and the sampling-noise statement.** `unlike` lists each of `scenario`, `scenario_version`, `iterations`, `seed`, `engine_version` and `architecture` that differ among the items (an aggregate has no scenario or version). `sampling_noise: true` comes with the statement that separate runs draw separate random numbers (AC-11).
- **The address** (AC-12, OQ5) is `/analyses/compare?item=…&item=…`, and nothing is stored. Items may belong to different business units (OQ6). The rule is the same for everyone: everything visible, or nothing.
- **"Compare versions"** (AC-12) on the scenario page opens a comparison of the most recent succeeded run of each of the scenario's six most recent versions that have one, all on the current control set. The page offers to start from a different run per version.

### 3.3 CSV (AC-18)
- **Format.** RFC 4180, UTF-8 with a byte-order mark (so spreadsheets read currency symbols and names correctly), CRLF line ends. The file has a metadata block of `key,value` rows, then a blank row, then the table. The metadata rows are: `download` (its id), `subject`, `id`, `scenario`, `scenario_version`, `control_set` (or `control_sets`), `bundle_digest`, `result_digest`, `engine_version`, `currency`, `independence`.
- **Neutralization.**
  - Every text cell (names, labels, pointers, keys) that begins with `=`, `+`, `-`, `@`, a tab or a carriage return is prefixed with `'`.
  - Numbers are written by the service with `strconv.FormatFloat(v, 'g', -1, 64)` and are never text from a user. A negative difference therefore stays a number, and a name can never become a formula.
- **Views:**

  | Subject | Views |
  |---|---|
  | Run | `summary` (every set: ALE, LEF and loss per event summaries, convergence), `curve` (amount and each set's probability of exceeding it), `histogram` (`set`, `scale`, optional `relative_to`), `breakdown`, `sensitivity` (`set`), `comparison` (each set against the current) |
  | Aggregate | `summary`, `curve`, `histogram`, `contributions` |
  | Comparison | `summary`, with differences from the first item, and `curve` |

  The values are the ones the charts draw.

### 3.4 Reading the curve (AC-05)
- **The curve.** It is the stored points `(x_j, p_j)` merged with the exceedance at each reported percentile (`curve.at`), sorted by amount. Between two points, p is interpolated linearly in `ln x`. Below the first point the answer is "between p₀ and P(ALE > 0)". Above the largest simulated loss it is "no simulated year exceeded it" (0).
- **Amount at a probability q.** The inverse on the same piecewise curve, taking the smallest amount where the curve reaches q. For q at or above P(ALE > 0) the answer is 0.
- **Shown as read from the curve.** The UI labels these values "read from the curve", and gives the exact values at the reported percentiles. Nothing is stored (AC-05). The rules are in `web/src/charts/curve.ts`, with unit tests.

## 4. The UI (`web/src/analysis`, `web/src/charts`)
- **The run page** `/analyses/runs/{id}` (AC-01 to AC-06, AC-09). The scenario page's inline run details link to it. It has a header and five sections:
  - **Header:** scenario and version, state and the facts of AC-06 (iterations, seed, engine version and architecture, digests, convergence, warnings, the independence statement).
  - **Exceedance:** curves for every set, the current set drawn solid. Linear/log switch; cursor; amount and probability lookups.
  - **Distribution:** a histogram per set (set picker), mean and percentile markers, years with no loss beside it; log/linear.
  - **Breakdown:** primary and secondary, and by form, as amounts and shares, per set.
  - **Drivers:** a tornado per set, from the strongest. Each bar shows the low and high change in mean ALE, labelled with the input's place in the scenario (`model.Taxonomy` label and pointer) and its Spearman correlation ("—" when null, F-005 §3.4).
  - **Control sets:** each set against the current one: the differences in mean and percentiles as a reduction or increase and as a share, and the per-year difference histogram (AC-09).
- **The aggregate page** gains exceedance, distribution and contributions sections, plus its members, the independence statement and the mixed-engine notice (AC-07, AC-08).
- **The comparison page** `/analyses/compare` (AC-10 to AC-13). Overlaid curves, a summary table with differences from the first item, and the "unlike" notice and the sampling-noise statement as an alert above the chart. If the request answers 404, the page says only "This comparison is not available to you" (AC-13). "Add to comparison" on run and aggregate pages builds the address.
- **`ChartFigure`** (AC-14) wraps each chart in a `figure` with:
  - a visible caption;
  - an SVG with `role="img"` and an accessible name;
  - a generated text alternative in sentences, for example: "Current: 10% chance of losing more than $2.1M in a year; with MFA rollout: 4%";
  - a "Show data table" toggle, with a table of the drawn values, in the same order as the CSV;
  - the download menu.
- **Telling series apart** (AC-15). Each series has a colour token, a dash pattern, a marker shape and a direct label at its line's end. The colours are checked for 3:1 against the background in both themes (`palette.test.ts`).
- **Keyboard** (AC-16).
  - The exceedance plot is one focusable element. Left and Right move the cursor across the curve points, and Page Up/Down, Home and End move it further. A polite live region reads the amount and every set's probability.
  - The lookups are ordinary labelled fields.
  - The comparison picker and every control are React Aria Components.
  - axe runs on every page in the E2E suite.
- **Downloads** (AC-17, AC-18).
  - **Images:** `POST /api/v1/analyses/downloads` first; on 201 the chart is serialized by `export.ts`, with a footer holding the title, subject, control sets, currency, ids, digests, the independence statement and the download id; PNG at twice the CSS size.
  - **CSV:** a plain link to the service's `.csv` route. The gateway forwards the session, and the route writes the event first.

## 5. API (additions to `api/openapi/analysis.yaml`)
| Method and path | Who | Purpose |
|---|---|---|
| `GET /api/v1/analyses/runs/{id}/histogram?set=&scale=&relative_to=` | analysis.view (RLS) | Histogram of a set's annual loss, or of its per-year difference from another set (§3.1) |
| `GET /api/v1/analyses/aggregates/{id}/histogram?scale=` | analysis.view, every member visible | Histogram of an aggregate's annual loss |
| `GET /api/v1/analyses/compare?item=…` | analysis.view for every item | Comparison (§3.2); 404 if any item is unseen, 409 `not_succeeded`, 422 on bad, duplicate, too few or too many items |
| `GET /api/v1/analyses/runs/{id}/data.csv?view=&set=&scale=&relative_to=` | analysis.view | CSV (§3.3); records `analysis.downloaded` first, 503 `unavailable` if it cannot |
| `GET /api/v1/analyses/aggregates/{id}/data.csv?view=&scale=` | analysis.view, every member visible | As above |
| `GET /api/v1/analyses/compare.csv?item=…&view=` | as compare | As above |
| `POST /api/v1/analyses/downloads` | analysis.view for the subject | Records an image download: `subject` (`run`, `aggregate`, `comparison`), `id` or `items`, `view`, `format` (`svg`, `png`); returns 201 `{download_id}`; the same 404/409 rules; Idempotency-Key; `x-reason-exempt` (a download is not a change) |

- **Conventions:** as F-001 §6 (lint-enforced). Responses are `no-store`.
- **CSV routes:** `Content-Type: text/csv; charset=utf-8` and `Content-Disposition: attachment` with a generated ASCII file name (`run-<id8>-<view>.csv`); no user text goes in headers.
- **Permissions:** `analysis.view` throughout (OQ4). No new permission.
- **`x-audit-events`:** `analysis.downloaded` on the CSV routes and the downloads POST, both declared in the contract.

## 6. Key flows

### 6.1 A run's page
1. The page loads `GET /runs/{id}` (summaries, curves, breakdown, comparison, convergence, sensitivity) and draws the exceedance, breakdown, drivers and control-set sections from it.
2. The distribution section requests `histogram?set=<shown set>`. The control-set section requests `histogram?set=<s>&relative_to=<current>` for the set shown.
3. Each section is drawn when its data arrives; nothing waits for the series of sets that aren't shown.

### 6.2 A CSV download
1. In one transaction under the caller's DB context (`WithDBContext`), the service reads the subject under RLS (404 when unseen).
2. It records `analysis.downloaded` through `audit.WithTx`, once per distinct business unit of the downloaded results.
3. It commits, then streams the CSV.
4. If the event cannot be recorded, the transaction rolls back and the response is 503 `unavailable` with no file (audit fails closed).

### 6.3 An image download
1. The client sends `POST /downloads`. The service checks visibility as for the views, records the event(s) as in §6.2, and returns the `download_id`.
2. Only after the 201 does the browser serialize the chart and save it. A failure shows an error and produces no file.

## 7. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| I: a comparison or histogram shows results of a BU the user cannot see | Every route reads under RLS with the caller's context; aggregates need every member visible (F-005); comparisons are all or nothing | `TestSTRIDEF006Visibility` |
| I: a comparison reveals that a hidden result exists, or which item is hidden | One 404 body for unseen and nonexistent items, whichever position; 409 only for items the caller sees | `TestSTRIDEF006ComparisonOracle` |
| T/E: a downloaded CSV runs formulas in the user's spreadsheet (CSV injection) | Text cells neutralized; numbers written only from floats | `TestAnalysisCSVNeutralized` |
| T/E: a downloaded SVG carries script from a user-chosen name | Names reach the SVG only as React text; serialized SVG is checked to have no `script`, `foreignObject`, event attributes or external references | `web/e2e/results.spec.ts` (export of a scenario named with markup); `export.test.ts` |
| R: data leaves the platform unattributed | CSV routes and image downloads record `analysis.downloaded` with actor, BU, subject, view, format and download id, in the transaction; fail closed | `TestAnalysisDownloadEvents` |
| D: costly requests (histograms of large series, six-way comparisons) | Series size bounded by F-005 (≤ 20,000,000 values per run); comparisons ≤ 6 items; one series read per histogram; the benchmark gate holds the budgets | `TestAnalysisResultViewLimits`, `TestBenchmarkGateResultViews` |
| E: a viewer changes results | Every F-006 route is a read, apart from recording downloads; results stay append-only (F-005) | `TestSTRIDEF006ReadOnly` |

## 8. New catalog event type
`analysis.downloaded`:
- category `risk_data`; BU required (one event per business unit of the downloaded results);
- attributes `download_id`, `subject` (`run`, `aggregate`, `comparison`), `ids`, `view`, `format` (`csv`, `svg`, `png`).

Viewing results is not audited (requirements, NFR Audit).

## 9. Settings
None. The 60 bins, the item limit of 6 and the PNG scale are constants of the release. A need to configure them would add an F-015 setting with bounds.

## 10. Requirements traceability
| AC | Design | Verification |
|---|---|---|
| AC-01, AC-05 | §3.4, §4 | `curve.test.ts`; E2E (cursor by keyboard, lookups) |
| AC-02 | §3.1, §4 | `TestAnalysisHistogram`; E2E |
| AC-03, AC-04 | §4 | E2E (breakdown, tornado against the seeded run) |
| AC-06, AC-08 | §4 | E2E (details, warnings, independence, mixed engines) |
| AC-07 | §3.1, §4 | `TestAnalysisHistogram` (aggregate); E2E |
| AC-09 | §3.1, §4 | `TestAnalysisHistogram` (difference); E2E |
| AC-10, AC-11, AC-12 | §3.2, §4 | `TestAnalysisCompare`; E2E (compare versions, shared address) |
| AC-13, AC-20 | §3.2, §5 | `TestSTRIDEF006Visibility`, `TestSTRIDEF006ComparisonOracle` |
| AC-14 to AC-16 | §4, ADR-014 | axe on every page; E2E by keyboard; `palette.test.ts` |
| AC-17 | §4, §6.3 | E2E (SVG and PNG download, footer, escaped names); `export.test.ts` |
| AC-18 | §3.3, §6.2 | `TestAnalysisCSV`, `TestAnalysisCSVNeutralized` |
| AC-19 | §6.2, §6.3, §8 | `TestAnalysisDownloadEvents` |
| NFR performance | §3.1, §6.1 | `TestBenchmarkGateResultViews` |

## 11. Performance
- **The gate.** `TestBenchmarkGateResultViews` seeds a succeeded run of 1,000,000 iterations with three control sets, and measures:
  - the run's views: its GET plus three histograms, p95 ≤ 2 s;
  - a comparison of six results: p95 ≤ 3 s;
  - each CSV view: ≤ 2 s.
- **The browser's share.** It draws bounded data, at most 210 points per curve, 60 bins per histogram and the scenario's inputs per tornado, so drawing does not grow with iterations.

## 12. Deployment modes
Identical in SaaS, self-hosted and air-gapped. No new services, keys or settings, and no external assets: fonts are the system fonts already in `--font`.

## 13. Changes to other features
- **F-005:** the analysis API gains the §5 routes; the contract and the run page replace the inline details as the place results are read.
- **F-001:** catalog entry `analysis.downloaded` (T-37 rules).
- **F-003:** the scenario page links runs to their pages and offers "Compare versions".
- **F-014:** the component definition gains F-006's statements (last task).

## 14. Proposed control mapping (NIST SP 800-53r5)
AC-3 (access to results), AU-2 and AU-12 (downloads audited), RA-3 (presenting the assessment), SI-10 (request validation), SI-15 (output filtering: CSV neutralization, SVG escaping). To be confirmed with the tasks.

## 15. Alternatives considered
- **A charting library:** rejected in ADR-014.
- **CSV built in the browser:** rejected (decided 2026-11-13). The audit would rely on a well-behaved client, and neutralization would be tested only in the UI.
- **Histograms stored per run:** rejected (decided 2026-11-13). A new table, RLS fixture and immutability rules for a computation that takes milliseconds.
- **Browser caching of histograms:** not adopted. Risk-data responses stay `no-store`.
- **Comparisons assembled in the browser from separate reads:** rejected. The all-or-nothing rule (AC-13) and the "unlike" list belong in one checked place.

## 16. Open items
- The reference node for the performance budget, as in F-005 §14.

## Change Log
- 2026-11-13: Initial draft. Decisions taken with Robert Former: CSV produced by the risk service, audited in its transaction; histograms computed on request. Requirements OQ1 to OQ6 settled as proposed, except that histograms are not cached (responses stay `no-store`). ADR-014 proposed.
- 2026-11-13: **Approved** by Robert Former, with ADR-014.
- 2026-11-13: T-01 (clarifications, approved with the task): (1) `relative_to` must be the run's current control set, and `set` another one: F-005 stores the difference summary (the markers) only against the current set, and AC-09 compares each set with the current one; (2) a run or aggregate the caller sees that has not succeeded answers 409 `not_succeeded`; (3) `both_none` is present only for differences; one distinct value gives one bin with equal edges, nothing to bin gives empty `edges` and `counts`; (4) markers are null when the stored summary has none, and an aggregate's histogram refuses `set` and `relative_to` (422).
- 2026-11-13: T-02 (clarifications, approved with the task): (1) an item's control set is the rest of the value after `run:<id>:` (the query string's own percent-encoding carries it; at most 200 characters); (2) checks run in order: any item unseen or absent (404), then a set that is not the run's (422), then an item without results (409), so no answer depends on which item is hidden; (3) `scenario_name` is null when the caller cannot see the scenario (analysis.view without scenario.view), and the label then says "Scenario"; (4) `unlike` compares the version number alone for `scenario_version`, and `sampling_noise` is false when every item is a set of one run; (5) the snapshot is a read-only REPEATABLE READ transaction begun before the DB context is set (`authz.WithDBSnapshot`, since `WithDBContext`'s first statement would fix the snapshot at READ COMMITTED).
- 2026-11-13: T-03 (clarifications, approved with the task): (1) a run's `histogram` and `sensitivity` views name one `set`; the others cover every set; `relative_to` applies to `histogram` only; (2) each `analysis.downloaded` event names only its business unit's results (`ids`, sorted, space-separated); the target is `analysis_run:<id>` or `analysis_aggregate:<id>`, and a comparison's `analysis_comparison:<download id>`; an aggregate's download is filed under the aggregate's business unit; (3) the download id is a random UUID made by the service: the CSV's `download` row, or the POST's answer for an image; (4) tables are long (one row per set and point, bin or statistic); summary and comparison views list every numeric leaf by dotted path (`percentiles.p50`, `intervals.p50.low`), absent quantities skipped; metadata values are neutralized like cells; (5) Go's CSV writer drops a lone carriage return in CRLF mode, so `\r…` arrives as `'…`; (6) the curve's exact points at the percentiles are stored as `curve.at_percentiles` (§3.4 says `curve.at`).
