# F-010 Reporting and export — Tasks
Status: **Approved** (Robert Former, 2026-11-16) | Design: Approved 2026-11-16

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites, all done:
- F-001: permissions `report.view` and `report.export`, roll-up modes, service accounts, keys, the gateway, the PDF writer (`internal/report`).
- F-002: the audit trail and `internal/objstore` (ADR-012). F-015: settings, the restricted overlay.
- F-005 and F-006: results, digests, the chart components (ADR-014). F-007: the register, roll-ups, treatment. F-008: acceptances. F-009: notices.

Rules for every task:
- A task that adds a migration follows the immutability rule.
- A new event type gets its catalog entry with the task that first emits it.
- Every new route is linted by `scripts/openapi-lint.sh`.
- Every UI task runs `scripts/ui-e2e.sh`, with axe on every page it touches.
- No test reaches the internet: report store tests use the S3 test server (`scripts/s3-test-server.sh`).

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | Permission catalog version 5 (the built-in Report Publisher role: `report.view`, `report.export`; Auditor gains `report.export`); re-sign | OQ4 (amended); §10 | `TestCatalogVersion5Upgrade` | S | Done (2026-11-16) |
| T-02 | `settings.F010Defs()` (§4: `report.*`, `export.reason_required` BU-scopable with the restricted overlay default true), bindings, packages 1.9.0; the risk service registers them | AC-06, AC-10, AC-15, AC-16; §4 | `TestReportSettings`; the overlay test sees `export.reason_required` | S | Done (2026-11-16) |
| T-03 | Bootstrap role `report_definer`; schema `report` (§5) with PF029 and PF030; RLS on the snapshot tables with fixtures; `report.notice_outbox` | AC-06, AC-15, AC-19; §5 | DB tests: access by role, state rules; `TestRLSHarnessEveryBUOwnedTable` | M | Done (2026-11-16) |
| T-04 | ADR-007 amendment 6: `authz.ctx_key.purpose`, the delegated context in `authz.ctx_user()` (read-only transaction, running run, nonce); key `risk/report-context` (`iam keys upgrade`, `rotate -kind report-context`, `register`) | AC-11, AC-20; §3.3 | DB tests: honoured only read-only, for the run's user and nonce while running, never for writes or the gateway | M | Done (2026-11-16) |
| T-05 | The report store (`FAIR_REPORT_STORE_*`, versioned, not WORM), `reports.CheckInstall` per mode; deploy settings and egress | AC-15; §1, §11 | Contract tests against the S3 test server; `TestDeploymentModeMatrix` rows | S | Done (2026-11-16) |

## Phase B — Documents and formats
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-06 | `internal/reports/doc`: the document model; CSV (a ZIP of tables with the marking line, neutralized cells, manifest) and JSON (`fair.report.v1`, canonical; `docs/formats/fair-report-v1.md` and its schema) | AC-10, AC-13; §3.5 | Unit tests and golden files; schema validation | M | Not started |
| T-07 | The PDF writer to PDF/UA-1: Noto Sans embedded as CID fonts (TrueType reading, widths, ToUnicode), Unicode text, the full structure tree, XMP, headers and footers with the marking; F-001's entitlement report on the new writer | AC-12; §3.5 | Unit tests; veraPDF PDF/UA-1 in CI on sample documents; extracted text equals the input | L | Not started |
| T-08 | ADR-015 charts (`internal/report/chart`): scales ported from `web/src/charts/scale.ts` with shared vectors; curves, histograms, bars as tagged figures with data tables | AC-12; §3.5, ADR-015 | Go and `node --test` suites over the shared vectors; veraPDF on charted documents | M | Not started |

## Phase C — Reports
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-09 | Requests, the River worker and runs: `report.request` (limits, the reason rule over the scope's BUs), the delegated read, rendering, streaming to the store with digests, `report.complete_run`, failures; list, get and download with the re-check; the reports API skeleton (`api/openapi/report.yaml`, gateway segment `reports`) | AC-14 to AC-18, AC-22, AC-23; §3.6, §6, §8 | DB tests through the API (a fake document): reasons per BU, limits, downloads refused after losing the permission, events | L | Not started |
| T-10 | Readers for `register`, `acceptances` and `treatment` (§3.4), with metadata and what is left out | AC-08, AC-10, AC-11; §3.4 | DB tests: content equals the register and acceptance APIs; restricted modes; hidden BUs | M | Not started |
| T-11 | Readers for `risk` and `portfolio` (§3.4): pinned runs' views, provenance without calibration data, treatment and acceptance history; charts | AC-08 to AC-11; §3.4 | DB tests; golden documents; no calibration table read (checked) | M | Not started |
| T-12 | `export.reason_required` on F-003's risk export and F-006's downloads (`X-Fair-Reason`); their events gain `reason` | AC-16; OQ7, §3.6 | DB tests per export | S | Not started |
| T-13 | Retention: purge files after `report.retention_days` (every version), `report.files_purged` | AC-15; OQ8, §3.6 | DB tests with time travel against the S3 test server | S | Not started |

## Phase D — Dashboard, trends, schedules
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-14 | The dashboard API (§3.1) and `report.aggregate_counts` (`rollup_definer`) | AC-01 to AC-04; §3.1 | DB tests: counts equal the register's, the caller's roll-up, restricted modes | M | Not started |
| T-15 | Snapshots and trends (§3.2): `report.take_snapshot` on the leader, the restrictive roll-up policy, purge; `GET /reports/dashboard/trend` | AC-06, AC-07; §3.2 | DB tests: visibility per viewer, append-only, interval and purge | M | Not started |
| T-16 | Schedules (§3.7): API, `report.due_schedules` on the leader, suspension, one catch-up run; notice kinds `report.ready`, `report.failed`, `report.schedule_suspended` and their collection | AC-19 to AC-21; §3.7, §10 | DB tests with time travel; the notices reach the owner only | M | Not started |

## Phase E — Pages and gates
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-17 | Pages `web/src/reports`: the dashboard with trends, new report, my reports, a report with downloads, schedules; the header link; the UI harness seeds reports | AC-01 to AC-07, AC-15 to AC-19; §6 | `web/e2e/reports.spec.ts`; axe on every page | L | Not started |
| T-18 | Benchmark gate `TestBenchmarkGateReports` (10,000 risks: dashboard ≤ 2 s p95, register PDF ≤ 60 s, CSV and JSON ≤ 15 s, risk ≤ 30 s, portfolio ≤ 60 s, list ≤ 500 ms) | NFR; §9 | Bench gate passes | M | Not started |
| T-19 | STRIDE suite for design §7 (`db/tests/stride_f010_test.go` and unit tests, rows in `TestSTRIDECatalog`) | §7 | `make test-stride` covers every §7 row | M | Not started |
| T-20 | Control implementation statements `compliance/statements/F-010.yaml`; the control mapping added to the requirements; Robert Former signs off | — | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Change Log
- 2026-11-16: Initial draft, In Review.
- 2026-11-16: Approved by Robert Former.
- 2026-11-16: T-01: permission catalog version 5: the built-in Report Publisher role (`report.view`, `report.export`) and `report.export` for Auditor (OQ4 amended); `TestCatalogVersion5Upgrade`, `catalogVersion4`. Needs re-signing.
- 2026-11-16: T-02: `settings.F010Defs()` (`report.marking`, `report.retention_days`, `report.snapshot_interval_days`, `report.snapshot_retention_days`, `export.reason_required` BU-scopable), bindings, packages 1.9.0 with 57 settings (tests use a synthetic 1.10.0); the risk service registers F-010's settings; `TestReportSettings` (the overlay's `export.reason_required` now applies in restricted subtrees).
- 2026-11-16: T-03: bootstrap role `report_definer` (re-run `scripts/db-bootstrap.sh`); migration 0133: schema `report` (run, file, schedule, snapshot, snapshot_bu, snapshot_rollup, notice_outbox), all definer-only (design §3.2 and §5 amended: no RLS tables, scoped reads from T-15), PF029 state rules, PF030 at most 20 live schedules per owner. Test: `TestReportSchema`.
- 2026-11-16: T-04: ADR-007 amendment 6 (migration 0134: `authz.ctx_key.purpose`, `authz.add_ctx_key(id, secret, purpose)`, `authz.ctx_user()` honours report tokens only read-only for a running run with the token's nonce); key `risk/secrets/report-context.{key,id}` (`iam keys init|upgrade`, `rotate -kind report-context`, `check`; `iam keys register` registers it with purpose `report`; retiring counts keys of the same purpose); manifests for every key store; `docs/install/keys.md`. Tests: `TestReportDelegatedContext`, `TestReportContextKeys`.
- 2026-11-16: T-05: `internal/reports` (`CheckInstall`: in production in every mode the report store `FAIR_REPORT_STORE_*` and the report context key; `OpenStore`), `objstore.Store.CheckVersioned` (exists and versioned, Object Lock not required; `ErrNotVersioned`); `cmd/risk` checks the store at startup; `deploy/k8s/risk.yaml` store settings, credentials and egress (TLS 443); mode matrix rows. Tests: `TestCheckInstall`, `TestContractVersionedBucket` (with `FAIR_TEST_S3`).
