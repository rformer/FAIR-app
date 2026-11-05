# F-002 Tamper-Evident Audit Trail — Tasks
Status: **Approved** (Robert Former, 2026-11-04) | Design: Approved 2026-11-04

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites: F-001 (event catalog and emitter, BU scope, approvals, key delivery) and F-015 (settings, findings, Posture page). Both are done.
Every task that adds a migration follows the immutability rule. Every new event type gets a catalog entry. Every new route is linted by `scripts/openapi-lint.sh`.

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | ADR-011 (hash chain plus signed Merkle segment checkpoints). Integrity primitives in `internal/audit/integrity`: record body serialization, leaf and chain hashes, RFC 9162 Merkle tree hash and audit paths, checkpoint statement sign and verify (ECDSA P-256, FIPS module) | AC-07, AC-11; design §4.2 | Unit tests with RFC 9162 vectors and fixed vectors for ours. Property tests: any removal, change, insertion, reordering or truncation of a sequence is detected | M | Done (2026-11-04) |
| T-02 | Schema `audit` (migration): `audit_definer` (bootstrap, non-login), tables of §4.1, `audit.submit` (PF011 on unknown type or missing field), `audit.event_type` synced from the catalog at `iam migrate`, triggers refusing `UPDATE` and `DELETE` on `record` and `checkpoint` | AC-04, AC-08; §4.3 | DB tests: no application role reads or writes `audit` tables. `submit` accepts catalogued events and refuses others. Update and delete are refused even as the owner. Catalog sync is idempotent | M | Done (2026-11-04) |
| T-03 | Envelope `bu_id` and catalog fields `bu` and `attributes`. `audit.Validating` refuses unlisted attributes. Secrets deny-list test over every type. Existing F-001 and F-015 producers pass `bu_id` where the type requires it | AC-06, AC-19 (data); §3 | `TestCatalogMatchesCode` extended to `bu`. Deny-list test over catalog fixtures. Schema test for the envelope | M | Done (2026-11-04) |
| T-04 | F-015 settings for §4.4: bindings, `BuiltinProfiles()` parity, profile packages 1.2.0, the "clearing is loosening" comparator for destination strings (T-13 comparator set and the DB parity test), and the 90-day floor on `audit.retention_online` | AC-24, AC-25, AC-28 (bounds); §4.4 | Binding, parity and package tests. Comparator property and parity tests. A hard-floor refusal test for retention | M | Done (2026-11-04) |

## Phase B — Capture and sequencing
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-05 | `audit` service scaffold: `cmd/audit` and `internal/audit` (config, health, OTel, leader lock), image target, `deploy/k8s/audit.yaml`, the `app_audit` login role (`FAIR_AUDIT_PASSWORD_FILE`), `keys.Audit` (`/keys/audit/checkpoint`) in `iam keys init`, `rotate` and `check`, and `CheckInstall` rules | §2, §6.3, §7 | Service boots in kind. Only one replica holds the leader lock, and the lock fails over. Key-store manifests test. `TestDeploymentModeMatrix` covers the new keys | M | Done (2026-11-04; see design change log: not yet run in kind) |
| T-06 | The `Trail` sink and `audit.WithTx`. The `iam.event_outbox` trigger redirects audit rows to `audit.submit`; pending rows are moved; the worker's audit relay is removed. Posture's emits move into their transactions. iam, posture and the worker record to the trail; JSON lines stay on stdout | AC-01, AC-02, AC-36; §6.1 | DB tests: an event commits if and only if its change commits. Retries with the same id record once. A `submit` failure fails the operation. Every existing SQL producer lands in `intake` (catalog scan) | M | Done (2026-11-04) |
| T-07 | Sequencer: batches from `intake` into `record` (body, `received_at`, `producer` from the DB role, skew flag, root-BU default, chain), `head` locking, late-committing intake rows | AC-03, AC-05, AC-07; §6.2 | DB tests: no gaps, chain valid, `producer` cannot be spoofed through the body, skew flagged. Intake grows while the service is down and drains once it is back, without loss. Benchmark gate at 200/s sustained and 2,000/s for 60 s | M | Done (2026-11-04) |
| T-08 | Object-storage client for S3-compatible stores: put, get, delete, Object Lock retention, legal hold, TLS 1.2+, credentials from files. The library choice is recorded as an ADR if it adds a dependency. A test S3 server is used in CI | §6.3, §6.7, D4 | Contract tests against the test server, including a refused early delete under Object Lock | M | Done (2026-11-04) |
| T-09 | Checkpoints: close segments every 15 minutes and on demand (empty segments included), Merkle root, signed statement, link to the previous checkpoint, an `audit.checkpoint` record, a WORM copy where configured (required in SaaS), `signing_key` rotation | AC-09, AC-10; §6.3 | DB and integration tests: the cadence, the statement verifies with the public key, links hold across a key rotation, the WORM object is written and locked, and SaaS refuses to start without WORM | M | Done (2026-11-04) |

## Phase C — Verification
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-10 | `fair-audit-verify` (`cmd/audit-verify`): `verify-export`, `verify-archive`, `compare`. Standard library and FIPS module only, no network. Shipped in the release and the bundle | AC-11; §11 | Tamper corpus: altered body, removed record, reordered records, forged checkpoint, truncated tail, swapped archive object. Each reports the first failing position. A test proves the tool makes no network calls | M | Done (2026-11-04) |
| T-11 | Continuous verification: incremental every 15 minutes and full daily (archives and WORM comparison included), the `verification` table, `audit.verification_failed` and `audit.verification_recovered`, the Posture finding `audit_integrity` through `posture.audit_finding`, a SaaS SecOps alert, `audit.status()`, and the Posture page Audit trail tile | AC-12, AC-13, AC-14; §6.5 | DB tests: tampering as a superuser is found by the next run and opens a critical finding that only a clean full run resolves. Posture API and UI tests for the tile | M | Done (2026-11-05) |

## Phase D — Reading
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-12 | Read functions (`audit.search`, `history`, `request`, `status`) filtered by `audit.view` scope from the signed DB context. `iam.user_display_names`. Audit API (`/records`, `/records/{seq}` with proof, `/history`, `/requests/{id}`, `/checkpoints`, `/keys`), contract `api/openapi/audit.yaml`, gateway segment `audit`. Reads audited (`audit.searched`, `audit.history_viewed`) | AC-15 to AC-20; §4.3, §5 | DB tests: restricted-BU records are hidden without an assignment there, and root records need root `audit.view`. API tests for each filter and their combination. Every read leaves a record. Unseen ids return 404. Search p95 within budget at target scale | L | Done (2026-11-05) |
| T-13 | Approval evidence: the `approval_id` attribute on events from `/apply` (F-001 and F-015 producers) and `GET /approvals/{id}` | AC-35; §3, §5 | DB test: one approval shows the request, both parties, the decision and the applied change | S | Done (2026-11-05) |
| T-14 | Audit UI (`web/src/audit`): search, history (`/audit?target=` and `?actor=`), request view, approval evidence, record proof (export and hold actions moved to T-15 and T-19, 2026-11-05: their APIs arrive there) | AC-16, AC-18, AC-21, AC-37 | Playwright plus axe (WCAG 2.1 AA) in `scripts/ui-e2e.sh`. The Posture page's audit links open the matching history | M | Done (2026-11-05) |

## Phase E — Export and forwarding
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-15 | Evidence exports: a River job that closes a segment, bundles JSON lines or CSV with proofs, checkpoints, keys and a signed manifest; scope captured at request; `audit.exported` and `audit.export_fetched`; the audit UI's export action (from T-14). Archived ranges moved to T-18, 2026-11-05: nothing is archived before it | AC-32, AC-33, AC-34; §6.6 | DB tests: the bundle verifies with `fair-audit-verify`; scope is respected; the manifest states the filter. 1 million records in ≤ 5 minutes. Playwright plus axe for the export action | M | Done (2026-11-05) |
| T-16 | Syslog forwarder (RFC 5424 over TLS, structured data with seq, chain and segment), per-destination cursors, in-order redelivery, `audit.forward_backlog` and `audit.forward_recovered`, the backlog on the Posture tile. Per-service syslog retired (`FAIR_AUDIT_SYSLOG_*` moves to the audit service) | AC-22, AC-23, AC-24; §6.4 | Integration tests: an outage queues and resumes in order; the backlog threshold alerts once per crossing; plaintext is refused outside development; destination changes go through F-015 | M | Todo |
| T-17 | OTLP log forwarder over gRPC with TLS (`go.opentelemetry.io/proto/otlp`), with the same cursor semantics | AC-22; §6.4 | Integration test against an OTLP test receiver; TLS 1.2 floor test | S | Todo |

## Phase F — Retention
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-18 | Archive: segments past online retention written as signed, Object Lock–protected files, read back and checked, then removed from the database (`audit.archive_segment`), with `audit.records_archived`; exports include archived ranges, read from their segment objects with the export's filter and scope (from T-15) | AC-25, AC-26 (including export); §6.7 | DB and integration tests: archived records disappear from search, stay exportable and pass full verification; a failed upload deletes nothing | M | Todo |
| T-19 | Destruction and legal hold: `audit.hold` added to the permission catalog (privileged; Platform Admin, not Auditor); `/holds` API and UI (the audit UI's hold action, from T-14); `hold_segment` and S3 legal holds; destruction after total retention; `audit.records_destroyed`, `audit.hold_placed` and `audit.hold_released`; verification continues from the first retained checkpoint | AC-27, AC-28, AC-29; §6.7 | DB tests: held segments survive past `destroy_after`; release then destroy; verification passes after destruction; shortening retention is a loosening and never shortens existing locks | M | Todo |
| T-20 | Capacity: storage measured against `audit.storage_quota`, `audit.capacity_warning` at 75% and `audit.capacity_critical` at 90%, the `audit_capacity` finding, fail-closed submit | AC-30, AC-31; §6.8 | DB tests with a small quota: alerts at each threshold; a full store fails the producing operation and drops nothing | S | Todo |

## Phase G — Assurance
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-21 | STRIDE suite for design §8 (`db/tests/stride_f002_test.go`, rows in `TestSTRIDECatalog`). Deployment-mode matrix: air-gapped destinations internal only; SaaS requires WORM | Q5, §7, §8 | `make test-stride` covers every §8 row; `TestDeploymentModeMatrix` and the CI `deployment-modes` jobs pass | M | Todo |
| T-22 | Close the cross-feature items: F-015 design §15 ("expiry is checked against the audit trail", "every step goes to the hash-chained audit"); F-001 AU-2 and AU-12 statements and the F-015 AU-6 statement updated to the trail | F-001-AC-50; F-015 design §15 | Tests named in the updated statements pass; the compliance checks pass | S | Todo |
| T-23 | Control implementation statements `compliance/statements/F-002.yaml` (AU-2, AU-3, AU-3(1), AU-4, AU-5, AU-5(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-7(1), AU-8, AU-9, AU-9(3), AU-9(4), AU-11, AU-12, SI-4), built into the OSCAL component definition; Robert Former signs off | S1, Q1 | `internal/compliance` checks pass; sign-off recorded | S | Todo |

## Definition of Done
- All linked acceptance criteria have passing automated tests.
- Audit events emitted per design §9, each in the catalog.
- API contract updated and linted.
- Security review notes recorded (STRIDE rows and tests).

## Change Log
- 2026-11-04: Initial draft.
- 2026-11-04: **Approved** by Robert Former.
