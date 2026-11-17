# F-010 Reporting and export — Design
Status: Approved | Owner: Robert Former | Last updated: 2026-11-16
Requirements: `requirements.md` (Approved 2026-11-16) · ADR-005, ADR-006, ADR-007 (amendment 6, §3.3), ADR-012, ADR-014, ADR-015 (new)

## 1. Overview
- **In the risk service (decided 2026-11-16).** The dashboard, report generation, schedules and snapshots run in `cmd/risk`, beside the register and acceptances whose data they read. A new schema `report` is owned through a bootstrap definer role `report_definer`. Report jobs run in the risk service's River schema (`risk_river`, queue `report`); the snapshot, schedule and retention jobs run on its leader. The gateway routes the segment `reports` to the risk upstream. No new image or login role.
- **One document model, three renderers.** A report is first built as a `doc.Document` (metadata, headings, paragraphs, key-value lists, tables, charts with their data tables) from one consistent read of the data. The PDF, CSV and JSON files are rendered from that document only, never from the database, so the three agree.
- **Reads under the requester's own RLS.** The dashboard reads in the request's DB context. A report job reads under a **delegated read-only DB context** for its requester (decided 2026-11-16; §3.3): a token the risk service mints with its own key, which the database honours only inside a read-only transaction and only while that user's report run is in progress. Every existing RLS policy then applies unchanged, for on-request and scheduled reports alike.
- **Files in their own object store (decided 2026-11-16).** Report files go to a report store (`FAIR_REPORT_STORE_*`, `internal/objstore`, ADR-012), versioned but not write-once, so the retention job can delete them. The database keeps each file's key, size and SHA-256 digest, and the trail keeps the digest after the file is gone.
- **PDF/UA (OQ10).** F-001's PDF writer (`internal/report`) is extended to PDF/UA-1: Noto Sans Regular and Bold embedded as CID fonts with ToUnicode maps (decided 2026-11-16), a full structure tree, figures with alternative text, and charts drawn as vector paths by a Go chart module with the same scales and styles as ADR-014's web charts (ADR-015, decided 2026-11-16).
- **Nothing is mailed.** A finished scheduled report queues a `report.ready` notice (F-009) linking to `/reports/{id}`; the file is downloaded there by its requester, with the permission re-checked.

## 2. Components
| Component | Change |
|---|---|
| `db/bootstrap` | Role `report_definer` (NOLOGIN); re-run `scripts/db-bootstrap.sh` |
| `db/migrations` | Schema `report` (§5); `authz.ctx_key.purpose` and the delegated context in `authz.ctx_user()` (ADR-007 amendment 6); snapshot tables under RLS; `report.notice_outbox`; `notify.collect` and `notify.recheck` for `report` |
| `internal/reports` | Readers (one per report kind, over a `pgx.Tx`), the dashboard and trend queries, the River `Worker`, `Jobs` (snapshots, due schedules, retention), limits, `CheckInstall` |
| `internal/reports/doc` | The document model; renderers `CSV` (a ZIP of one CSV per table) and `JSON` (`fair.report.v1`) |
| `internal/report` | The PDF writer, extended: PDF/UA-1, embedded Noto Sans (`fonts/`, with the OFL), Unicode text, figures and vector graphics; F-001's entitlement report keeps working (and becomes PDF/UA too) |
| `internal/report/chart` | ADR-015: loss exceedance curve, histogram, horizontal bars, as PDF vector paths with tagged text |
| `internal/reportapi` | The reports API (§6), contract `api/openapi/report.yaml`, mounted by `cmd/risk` |
| `internal/keys` | Key `risk/report-context` (an HMAC key, `iam keys upgrade`; `rotate -kind report-context`), registered in `authz.ctx_key` with purpose `report` by `iam keys register` |
| `pkg/settings` | `settings.F010Defs()` (§4): `report.*` and `export.reason_required` (BU-scopable); packages 1.9.0 |
| `internal/access/catalog` | Catalog version 5: the built-in Report Publisher role (`report.view`, `report.export`), and `report.export` for Auditor (OQ4 as amended; re-sign) |
| `internal/notify` | Kinds `report.ready`, `report.failed`, `report.schedule_suspended` (source `report`) |
| `internal/riskapi`, `internal/analysisapi` | `export.reason_required` for F-003's risk export and F-006's downloads (OQ7) |
| `internal/gateway` | Segment `reports` → upstream `risk` |
| `deploy/k8s/risk.yaml` | Report store settings and its CA; egress to the report store |
| `web/src/reports` | The dashboard (`/reports`), trends, new report, my reports, a report, schedules |
| `pkg/audit/catalog.yaml` | F-010's events (§8) |
| `docs/formats/fair-report-v1.md` | The JSON format, with its JSON Schema |

## 3. Model
### 3.1 The dashboard (AC-01 to AC-05)
`GET /reports/dashboard?bu=` reads in the caller's DB snapshot (`authz.WithDBSnapshot`) over the register's projection, with the same status SQL as the register list (`register.StatusSQL`, so the coverage agrees with the register):
- **Exposure:** the caller's latest succeeded roll-up of the BU (F-007 roll-ups are their requester's own): its summary's mean, p10, p50, p90 and p99, its curve, its time, its staleness (F-007-AC-12), what it covers and leaves out (F-007-AC-13). With no roll-up, `rollup: null`, and the page offers a request (`POST /register/rollups`, `register.view`).
- **Largest risks:** the 10 open risks with the highest mean annualized loss in the subtree, each with p10 and p90 and its exposure status.
- **By child BU:** each child's open risks, their summed mean (labelled as a sum of means, not a percentile of the total), and, where the caller has a roll-up of the child, its p90.
- **Coverage:** open risks current, stale and unquantified.
- **Acceptances:** active, expiring within 30 days, expired, awaiting decision (F-008 states).
- **Treatment:** open actions and overdue actions (`register.treatment.next_due`).
- **Left out:** risks hidden by RLS are simply absent; restricted BUs below the caller count by their roll-up mode, as roll-ups do (F-001-AC-62): Excluded, none; Aggregate only, counts and summed means through `report.aggregate_counts` (owned by `rollup_definer`, over `authz.rollup_coverage`), never their risks.
Nothing is an ordinal score (AC-02); the page draws the roll-up's curve with ADR-014's `ExceedanceChart` and gives every figure a table and link (AC-05).

### 3.2 Snapshots and trends (AC-06, AC-07; OQ6)
The leader's `reports.Jobs` takes a snapshot every `report.snapshot_interval_days` (`report.take_snapshot()`, `report_definer`, set-based):
- **`report.snapshot_bu`** (one row per BU per snapshot, BU-owned, RLS type `register`, `shared_down => false`): that BU's own open risks (not its subtree), current, stale, unquantified, summed mean, acceptance counts by state, open and overdue actions. A trend for a subtree sums the rows the viewer can see, so RLS decides by construction; restricted BUs in Aggregate-only mode add their counts through `report.aggregate_counts` as in §3.1.
- **`report.snapshot_rollup`** (one row per BU that had a succeeded roll-up since the last snapshot): that roll-up's time, summary (mean and percentiles) and the BUs of every risk it included, plus the aggregate-only BUs it summed. A RESTRICTIVE select policy (`authz.restrict_select`, amendment 4) admits a row only when the viewer's register read scope holds every included risk's BU and their roll-up coverage holds every aggregate-only BU, as `analysis.members_visible` does for aggregates.
Snapshot rows are append-only for every role (PF029) and purged after `report.snapshot_retention_days`. `GET /reports/dashboard/trend?bu=&from=&to=` returns the series; the page charts exposure (where rows are visible) and coverage over time.

### 3.3 Delegated read-only context (ADR-007 amendment 6; decided 2026-11-16)
- `authz.ctx_key` gains `purpose` (`session`, the default and the gateway's; `report`, the risk service's `risk/report-context`).
- `authz.ctx_user()` accepts a `report`-purpose token only when **both**: the transaction is read-only (`current_setting('transaction_read_only') = 'on'`), and a `report.run` row exists with `requested_by` = the token's user, `state = 'running'` and `context_nonce` = the token's nonce. Otherwise it returns no user, so RLS returns nothing and every write function refuses.
- The worker sets the run `running` with a fresh nonce (`report.start_run`, `report_definer`), mints the token (TTL 5 minutes, `authz.MaxContextTTL`; the user's current scope version), reads in `WithDBSnapshot` (READ ONLY, REPEATABLE READ) with the token, and writes results in separate transactions through `report_definer` functions, which take the run id, not a context.
- A scope change during the read makes the token stale (scope version); the read fails and River retries with a new token, so the report always reflects one scope.
- Only `cmd/risk` holds `risk/report-context`; the gateway's key cannot mint report tokens, and report tokens cannot open a session or pass the gateway.

### 3.4 Reports (AC-08 to AC-11; OQ2)
| Kind | Parameters | Contents |
|---|---|---|
| `register` | BU, status, owner, category, decision, acceptance state | One row per open risk: title, owner, category, mean, p10, p90, exposure status, decision, acceptance state and expiry; totals |
| `portfolio` | BU, period | §3.1's dashboard as a document, the trend over the period (§3.2), the roll-up's curve and distribution |
| `acceptances` | BU, expiring within N days, decisions from–to | Acceptances by state; those expiring; the decisions in the period with tier, approvers, decision and reason |
| `treatment` | BU, owner | Actions by due date and owner, overdue first, with each risk's decision |
| `risk` | risk | Description, owner, category; each linked scenario with its pinned run: curve, histogram, breakdown, drivers and control sets (F-006's views); estimate provenance (requests, sources; F-004, no calibration records); the treatment plan and actions; the acceptance history |
Every report's metadata (AC-10): kind, title, scope and filters, generated at and by (display name), data as of (the snapshot's time), currency, each analysis run used with its engine version, seed and input digest, `report.marking`, and what was left out (not visible, restricted by mode, unquantified; AC-11). Readers never select from calibration tables.

### 3.5 Formats (AC-12 to AC-14; OQ3, OQ9, OQ10)
- **PDF:** PDF/UA-1. A structure tree (Document, H1–H3, P, L, Table/THead/TBody/TR/TH(scope)/TD, Figure with Alt and a caption, then the figure's data table), the document language and title (`DisplayDocTitle`), XMP with the PDF/UA identifier, `MarkInfo`, tab order by structure. Noto Sans Regular and Bold are embedded whole as CIDFontType2 (Identity-H) with widths and a ToUnicode map; a character the fonts lack is drawn as U+FFFD and listed in the report's notes. The marking in every page's header and footer (artifacts, with the marking also once in the structure). Deterministic for a given document (fixed IDs and dates from the run).
- **CSV:** a ZIP of `NN-<table>.csv`, one per table, each starting with the marking line, UTF-8 with a BOM, formula cells neutralized (`internal/report.CSV`), plus `manifest.json` (the report's metadata).
- **JSON:** `fair.report.v1`: `{format, metadata, sections[]}`, canonical (sorted keys, F-003's `canon`), documented in `docs/formats/fair-report-v1.md` with a JSON Schema, checked by a golden test.
- Each file's SHA-256 is computed while streaming to the store, stored with the file, shown in the listing, and recorded in `report.generated` (AC-14).
- File names are fixed (`report.pdf`, `report-csv.zip`, `report.json`), never from data.

### 3.6 Runs, reasons, downloads, limits (AC-15 to AC-18; OQ7, OQ8, OQ11)
- **Request:** `POST /reports` (`report.export` at the BU, else 403; 404 without `report.view` there) runs `report.request` in the caller's context: it counts the scope's open risks under RLS (over 10,000: 422 `limit_exceeded`), refuses a fourth running report (409 `too_many_running`), checks the reason rule (below), inserts the run and queues the River job in the same transaction; event `report.requested`.
- **Reason (OQ7):** required when `export.reason_required` is true for any BU in the scope (the BU and its subtree), read from F-015's effective per-BU values (instance, BU overrides, the restricted overlay). Missing: 400 `reason_required`. The same check, with the same helper, guards F-003's `GET /risk/export` and F-006's CSV and image downloads (reason in `X-Fair-Reason`), and their events gain the reason.
- **The job:** reads (§3.3), builds the document, renders the requested formats, streams each to the report store under `reports/<instance>/<run>/<file>` (aborting at 100 MiB: failed `limit_exceeded`), then `report.complete_run` records files, digests and `report.generated` together. River retries 3 times; the last failure marks the run failed (`report.failed`) and, for scheduled runs, queues a `report.failed` notice.
- **List and download:** `GET /reports` lists the caller's own runs (`report.my_runs`); `GET /reports/{id}/files/{format}` checks the caller is the requester and still holds `report.export` at the BU (Cache check and `report.download` in the database), records `report.downloaded` in the transaction, then streams the object (503 with no file if the event cannot be recorded). Another user's run is 404.
- **Retention:** the leader deletes files older than `report.retention_days` (every version of each object), marks them purged (`report.files_purged`, system); the run and its digests stay.

### 3.7 Schedules (AC-19 to AC-21; OQ5)
- `report.schedule`: owner, kind, BU, parameters, formats, cadence (`daily`; `weekly` with a weekday; `monthly` with a day 1–28), hour (UTC), `next_at`, state `active` or `suspended` with a reason. At most 20 per owner (PF030). Created, changed, deleted and resumed by their owner only, with `report.export` at the BU.
- The leader's `Jobs.Schedules` (every minute) runs `report.due_schedules(batch)`: for each schedule with `next_at <= now()`, it re-checks the owner (active, `report.export` at the BU, through `iam.permission_holders`); if so it creates a scheduled run and queues it, else suspends the schedule (`report.schedule_suspended`, notice). Then `next_at` becomes the first time after **now** (so an outage yields one run per schedule, AC-21).
- A scheduled run reads as its owner at run time (§3.3) and, when done, queues `report.ready` to the owner (item type `report`, link `/reports/{id}`; F-009 composes it minimally).

### 3.8 API for BI tools (AC-22)
The same endpoints serve service accounts (F-001 T-33): `POST /reports` with `formats: ["json"]` or `["csv"]`, poll `GET /reports/{id}`, fetch the file. No separate data API, so scope, limits, reasons and audit are the same. A service account holds `report.export` only as an approved scope (F-001 AC-36 as amended by T-09b, decided 2026-11-17): the one privileged scope a service account may have, through the `service_account.scopes` approval, never at once.

## 4. Settings (F-015)
| Key | Kind | Default | Bounds | Stricter | Notes |
|---|---|---|---|---|---|
| `report.marking` | string | `Confidential` | 1–60 characters | non-empty | On every page and file (OQ9) |
| `report.retention_days` | int | 30 | 1–365 | lower | Report files (OQ8) |
| `report.snapshot_interval_days` | int | 7 | 1–31 | lower | OQ6 |
| `report.snapshot_retention_days` | int | 1,095 | 365–3,650 | higher | OQ6 |
| `export.reason_required` | bool | false | — | true | BU-scopable; the restricted overlay's default is true (F-015 §6.6) |
Packages 1.9.0 (57 settings); tests that need a later release use a synthetic 1.10.0.

## 5. Data model (schema `report`, owned through `report_definer`)
| Table | Purpose | Access |
|---|---|---|
| `report.run` | id, requested_by, bu_id, kind, params, formats, reason, schedule_id, state (`queued`, `running`, `succeeded`, `failed`), progress, context_nonce, data_as_of, left_out, failure, times | Definer only; `report.my_runs`, `report.get_run` for the requester |
| `report.file` | run_id, format, object key, version id, size, sha256, purged_at | Definer only |
| `report.schedule` | §3.7 | Definer only; `report.my_schedules` |
| `report.snapshot` | id, taken_at | Readable by app_rw |
| `report.snapshot_bu` | snapshot_id, bu_id, counts | Definer only; returned by `report.trend` as §3.2 allows (amended) |
| `report.snapshot_rollup` | snapshot_id, bu_id, rollup_id, rollup_finished_at, summary, risk_bus, aggregate_only_bus | Definer only; returned by `report.trend` as §3.2 allows (amended) |
| `report.notice_outbox` | kind, user_id, run_id or schedule_id | Insert by `report_definer`; collected by `notify_definer` |
State rules (PF029): finished runs and files are immutable but for `purged_at`; snapshots never change and are purged whole; schedules change only through their functions (at most 20 live per owner, PF030). No `report` table is BU-owned (amended).

## 6. API (`api/openapi/report.yaml`, `/api/v1/reports`)
| Route | Permission | Notes |
|---|---|---|
| `GET /reports/dashboard?bu=` | `report.view` at the BU | §3.1 |
| `GET /reports/dashboard/trend?bu=&from=&to=` | `report.view` | §3.2 |
| `GET /reports/kinds` | `report.view` anywhere | The catalogue and each kind's parameters |
| `POST /reports` | `report.export` at the BU | 202 with the run; Idempotency-Key; reason (§3.6) |
| `GET /reports`, `GET /reports/{id}` | the requester | State, progress, files with sizes and digests |
| `GET /reports/{id}/files/{format}` | the requester, `report.export` | §3.6 |
| `GET /reports/schedules`, `POST /reports/schedules` | `report.export` at the BU | |
| `GET`, `PUT` (expected_version), `DELETE /reports/schedules/{id}`, `POST …/{id}/resume` | the owner | Reason on delete |
| `GET /reports/bus?permission=` | — | BU pickers, as `risk/bus` |
Conventions as before: operationId = handler; mutating routes declare `x-permission`, `x-audit-events`, Idempotency-Key; ids 404 when not the caller's.

## 7. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| I: a report or the dashboard shows data its requester cannot see | Reads under the requester's own context and existing RLS (request context, or the delegated context bound to their run); restricted BUs by roll-up mode; calibration tables never read | `TestSTRIDEF010Visibility` |
| E, S: the delegated context is used to write, for another user, or outside a run | Purpose-`report` keys held only by the risk service; honoured only in read-only transactions, for the run's requester, with the run's nonce while it is running; scope version checked | `TestSTRIDEF010DelegatedContext` |
| I: report files reach someone else | Runs and files listed and served to their requester only, permission re-checked at download; files in a private store; notices carry links only | `TestSTRIDEF010Files` |
| I: trends leak restricted or hidden data | Snapshot rows under RLS; roll-up rows only to viewers who see every included risk and have the aggregate-only coverage | `TestSTRIDEF010Trends` |
| T: injection through report content | Values only as text in PDF strings and structure; CSV formula cells neutralized; canonical JSON; fixed file names; no external resources in PDFs | `TestSTRIDEF010Injection` |
| T: a report file altered after it left | SHA-256 per file in the listing and in `report.generated` | `TestSTRIDEF010Digests` |
| R: data taken out cannot be attributed | Requests (with reasons), generation, failures, downloads and schedule changes recorded in their transactions; a download fails if its event cannot be | `TestReportAuditEvents` |
| D: huge or many reports exhaust the service | Scope, size, running and schedule limits checked before work; a River queue with bounded workers; schedules catch up once | `TestSTRIDEF010Limits`, `TestBenchmarkGateReports` |

## 8. New catalog event types
`report.requested` (low; kind, scope, filters, formats, reason), `report.generated` (low; files and digests, risk count, left out), `report.failed` (low), `report.downloaded` (high; format, digest, reason), `report.files_purged` (info, system), `report.schedule_created`, `report.schedule_changed`, `report.schedule_deleted`, `report.schedule_resumed` (low), `report.schedule_suspended` (low, system). The catalog's severities are info, low, high and critical; "medium" became low (amended 2026-11-17). F-003's `risk.exported` and F-006's `analysis.downloaded` gain `reason`.

## 9. Requirements traceability
| AC | Design | Verification |
|---|---|---|
| AC-01 to AC-05 | §3.1, §6 | DB tests of the dashboard (counts equal the register's, roll-up modes); Playwright and axe |
| AC-06, AC-07 | §3.2 | DB tests of snapshots and the restrictive policy; Playwright |
| AC-08 to AC-11 | §3.4 | DB tests per kind (content, left out, no calibration data); golden documents |
| AC-12 to AC-14 | §3.5, ADR-015 | Unit tests of the writer, fonts and charts; veraPDF (PDF/UA-1) in CI; CSV and JSON golden files |
| AC-15 to AC-18 | §3.6 | DB tests (requests, reasons per BU, downloads re-checked, limits, retention) |
| AC-19 to AC-21 | §3.7 | DB tests (due schedules, suspension, one catch-up run, notices) |
| AC-22 | §3.8 | API tests with a service account |
| AC-23 | §8 | Audit event tests |
| NFR performance | §3 | `TestBenchmarkGateReports` (10,000 risks: dashboard ≤ 2 s p95, register PDF ≤ 60 s, CSV and JSON ≤ 15 s, risk report ≤ 30 s, portfolio ≤ 60 s, list ≤ 500 ms) |

## 10. Changes to other features
- **F-001:** catalog version 5: Report Publisher, Auditor `report.export` (re-sign); ADR-007 amendment 6 (`authz.ctx_key.purpose`, the delegated context); key `risk/report-context`; the gateway segment `reports`; the entitlement report's PDF becomes PDF/UA through the shared writer.
- **F-003, F-006:** `export.reason_required` on the risk export and the downloads (OQ7).
- **F-009:** kinds `report.ready`, `report.failed`, `report.schedule_suspended`; `notify.collect` reads `report.notice_outbox`; `notify.recheck` checks that a report notice's recipient is its run's requester.
- **F-015:** `export.reason_required` registered and enforced (F-015 §6.6, §12); the `report.*` settings; packages 1.9.0.

## 11. Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Report store | Vendor-operated S3-compatible bucket | Customer's S3-compatible store | Inside the enclave |
| PDF fonts and charts | Embedded, no network | Same | Same |
| Notices | F-009 | Same | Same |
`reports.CheckInstall`: in production the report store settings and its credentials files are required, and the bucket must be versioned (`objstore.CheckBucket` without the WORM requirement).

## 12. Alternatives considered
- **A separate report service:** isolates rendering, but needs a second role with app_rw's read grants over four schemas (decided 2026-11-16 against).
- **Files in PostgreSQL** or **in the audit store:** database and backup bloat, or Object Lock fighting retention (against).
- **Headless Chromium** or **raster charts** for PDFs: a large runtime to vet and poorly tagged output, or blurry charts without vector text (against; ADR-015).
- **Reading in the request** or **captured scopes** for jobs: schedules would need definer-side copies of every table's RLS (against; §3.3).
- **Liberation Sans:** metric-compatible with Helvetica, narrower coverage than Noto Sans (against).

## 13. Open items
- veraPDF runs in CI from a pinned container image, not at runtime.
- Font subsetting, if whole embedded fonts make files too large in practice (each PDF carries about 1 MB of fonts).

## Change Log
- 2026-11-16: Initial draft, In Review. Decided with Robert Former: the risk service, the report store, ADR-015's Go vector charts, Noto Sans, and the delegated read-only context (ADR-007 amendment 6).
- 2026-11-16: Approved by Robert Former, with ADR-015 and the tasks.
- 2026-11-16: T-01 (OQ4 amended, Robert Former): catalog version 5 adds a Report Publisher role rather than giving Executive Viewer and Risk Analyst a privileged permission.
- 2026-11-16: T-03 (amended with Robert Former): the snapshot tables are definer-only, like every `report` table, instead of RLS tables with a restrictive policy, so the retention purge is a plain delete (ADR-007's helpers give a definer no delete). `report.trend` returns only what §3.2 allows, set-based: BU rows in the caller's register read scope (aggregate-only units through `authz.rollup_coverage`), roll-up rows only when every included risk's BU is visible and every aggregate-only BU covered. The visibility rules are unchanged.
- 2026-11-17: T-09: the delegated token lives 5 minutes (`authz.MaxContextTTL`; the database accepts at most 10), and every read is one transaction, so expiry and scope are fixed for the read; `report.start_run` re-checks that the requester is active and holds report.export (else the run fails `no_permission`); objects are keyed `reports/<root BU id>/<run>/<file>`; §8 severities low and high (no "medium" in the catalog). AC-22 conflicted with F-001 AC-36 (no privileged scopes for service accounts): decided with Robert Former that `report.export` becomes the one privileged scope a service account may hold, through dual approval (T-09b, §3.8).
- 2026-11-17: T-11: the risk report's BU is the scope its risk must be visible in (a run fails `not_found` otherwise); its curve and distribution are the pinned control set's (the summary table covers every set); the portfolio report's trend section comes with T-15 (snapshots), and risk counts of aggregate-only units with T-14 (`report.aggregate_counts`).
- 2026-11-17: T-12: the reason travels in `X-Fair-Reason` as percent-encoded UTF-8 (browsers send only Latin-1 in headers) and is recorded in the event envelope's `reason`; an export by id needs it when any exported item's BU has `export.reason_required`, an export of a subtree when any BU in it does. The F-003 and F-006 pages gain a reason prompt with T-17; until then a download in scope of the rule is refused there.
- 2026-11-17: T-15: snapshots count a BU's "computing" risks as stale (the table records current, stale and unquantified); a snapshot's roll-up row records, when its roll-up summed aggregate-only units, every restricted BU below its BU (the roll-up does not keep their ids), so a viewer must cover all of them to see it; the counting runs in `register_definer` and `acceptance_definer` functions (one definer per table), which `report.take_snapshot` calls. The portfolio report's trend is a table: ADR-015's charts have no time series.
