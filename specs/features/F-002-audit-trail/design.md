# F-002 Tamper-Evident Audit Trail — Design
Status: **Approved** (Robert Former, 2026-11-04) | Requirements: approved 2026-11-04 | Last updated: 2026-11-04
Constitution refs: S1, S2, S4, S6, A5, A6, A7, Q1, Q3, Q5 | ADRs: 003, 005, 006, 007, 011 (proposed with this design)

## 1. Overview
F-002 adds an `audit` service and an `audit` schema. Events still enter through the `audit.Emitter` contract (F-001 T-00a, T-37), but they now land durably in PostgreSQL:
- **In the producer's transaction** when one exists, so an event exists exactly when its change does.
- **In a short transaction of their own** when not.

From there:
1. **Intake.** Producers write events to `audit.intake`. The table has no chain and no ordering, so producers never contend with each other.
2. **Sequencing.** A single sequencer in the audit service moves intake rows into `audit.record`. It gives each one a gap-free position (`seq`) and a hash-chain link to the record before it.
3. **Checkpoints.** Every 15 minutes (and for every export) the sequencer closes a **segment**. A signed checkpoint covers the segment's Merkle root, the chain head and the previous checkpoint. Each checkpoint is itself recorded and forwarded, so a copy always leaves the platform. In SaaS it is also written to object-locked storage.
4. **Verification.** The service re-verifies new records every 15 minutes and the whole retained trail daily. A failure opens a critical Posture finding.
5. **Search, history, export and legal hold.** These are served by the audit API under `/api/v1/audit`. Reads are BU-scoped in the database and are themselves audited.
6. **Forwarding.** Records go to SIEM destinations (syslog over TLS, OTLP) in `seq` order, each destination with its own cursor.
7. **Retention.** Segments older than online retention are written to object storage as signed archive files and removed from the database. Archive objects are destroyed after total retention unless held.
8. **Offline verification.** `fair-audit-verify`, a standalone binary, checks exports, archives and checkpoints without access to the platform.

## 2. Components
| Component | Kind | Responsibility |
|---|---|---|
| `cmd/audit`, `internal/audit` | New service (Go) | Sequencer (leader only), checkpoints, verification, forwarding, retention and archive, audit API |
| `pkg/audit` | Library (existing) | `Emitter` contract and catalog. Adds the `Trail` sink, `WithTx`, and the `bu_id` envelope field |
| `audit` schema | PostgreSQL | Intake, records, checkpoints, holds, exports, verification state. Accessed only through SECURITY DEFINER functions owned by `audit_definer` |
| `cmd/audit-verify` (`fair-audit-verify`) | Standalone binary | Offline verification (AC-11). Shipped with every release and bundle |
| Object storage | S3-compatible (A5) | Archive segments and exports. Checkpoint copies, with Object Lock where required |
| Gateway | Existing | Routes the `audit` segment to the audit service (`gateway.Segments`) |
| Posture service and page | Existing | Shows verification, backlog and capacity status, and integrity findings |
| `web/src/audit` | UI | Audit search, history, request view, approval evidence, exports, holds |

The sequencer and its timers run on one replica, which holds `pg_advisory_lock(audit_leader)`. API handlers run on every replica. If the leader stops, intake keeps accepting and another replica takes the lock (AC-03).

## 3. Event envelope and catalog changes
- `Event` gains `bu_id` (optional UUID): the BU the event concerns.
  - Records without one belong to the root BU, which only root-level `audit.view` can read (AC-19).
  - `event.schema.json` gains the field.
- Catalog entries gain `bu: required | optional`, default `optional`.
  - `required` is set for types whose target is BU-owned, such as assignments, BU changes, BU setting overrides, and every F-003-onward risk-data event.
  - `TestCatalogMatchesCode` checks producers of `required` types pass a BU.
  - Existing F-001 and F-015 producers are updated in T-03.
- Events from an `/apply` of an approval carry the attribute `approval_id` (AC-35).
- **No secrets (AC-06).** Catalog entries list their attribute names. `audit.Validating` refuses any attribute that is not listed. A test runs every type's fixtures through a deny-list check:
  - keys or values that look like tokens, passwords, cookies, PEM blocks or JWTs;
  - the field names `secret`, `password`, `token`, `cookie`, `authorization`.
- New event types are listed in §9.

## 4. Data model (schema `audit`)
### 4.1 Tables
| Table | Purpose | Key columns |
|---|---|---|
| `intake` | Accepted, not yet sequenced | `id bigserial`, `event_id text UNIQUE`, `producer text`, `body jsonb`, `accepted_at timestamptz` (`clock_timestamp()`) |
| `record` | The trail (online part); partitioned by month on `event_time` | `seq bigint PK`, `event_id text UNIQUE`, `event_time`, `received_at`, `producer`, `type`, `category`, `severity`, `actor`, `target`, `bu_id uuid NOT NULL`, `request_id`, `source_ip inet`, `approval_id`, `skew boolean`, `body bytea`, `leaf_hash bytea`, `chain_hash bytea`, `segment bigint` |
| `head` | The single chain head (one row, locked by the sequencer) | `seq`, `chain_hash`, `open_segment` |
| `checkpoint` | Signed segment closes; kept forever, including after destruction | `segment PK`, `seq_from`, `seq_to`, `merkle_root`, `chain_hash`, `prev_checkpoint_hash`, `issued_at`, `key_id`, `signature`, `statement bytea`, `worm_key` |
| `signing_key` | Public checkpoint keys by `key_id` (rotation) | `key_id`, `public_pem`, `active_from`, `retired_at` |
| `archive` | Segments moved to object storage | `segment`, `object_key`, `digest`, `record_count`, `archived_at`, `destroy_after`, `destroyed_at` |
| `hold` | Legal holds (AC-29) | `id`, `filter jsonb`, `reason`, `placed_by`, `placed_at`, `released_by`, `released_at`, `release_reason` |
| `hold_segment` | Segments containing held records (refreshed when a hold changes and at archive) | `hold_id`, `segment` |
| `export` | Evidence exports (AC-32 to AC-34) | `id`, `requested_by`, `filter jsonb`, `scope_bus uuid[]`, `record_count`, `digest`, `checkpoint_segment`, `object_key`, `created_at` |
| `verification` | Verification runs (AC-12, AC-14) | `id`, `kind ('incremental','full')`, `from_seq`, `to_seq`, `started_at`, `finished_at`, `ok`, `failed_at_seq`, `detail` |
| `destination` | Forwarding cursors (AC-23) | `name`, `kind ('syslog','otlp')`, `last_seq`, `last_sent_at`, `last_error` |
| `event_type` | The catalog as data, synced at migrate (as `iam.sync_release` does for permissions) | `type`, `category`, `severities`, `requires`, `bu`, `attributes` |

### 4.2 Integrity structure (ADR-011, proposed)
- **Record body.** `body` is the event serialized once by the sequencer: JSON with sorted keys, no insignificant whitespace, UTF-8. The trail stores and exports these exact bytes, and hashes are computed over them, so verifiers never re-canonicalize.
- **Leaf hash.** `leaf_hash = SHA-256(0x00 ‖ body)`.
- **Chain hash.** `chain_hash = SHA-256(0x01 ‖ prev_chain_hash ‖ seq as 8 bytes, big-endian ‖ leaf_hash)`. The genesis `prev_chain_hash` is `SHA-256("fair-audit-v1" ‖ instance id)`. This chain satisfies S4 and AC-07: removal, alteration, insertion or reordering breaks it.
- **Segment.** A segment is the records between two checkpoints. Its `merkle_root` is the RFC 9162 Merkle tree hash over the segment's leaf hashes.
- **Checkpoint statement.** The statement is `{v:1, instance, segment, seq_from, seq_to, merkle_root, chain_hash, prev_checkpoint_hash, issued_at, key_id}`, serialized the same way as `body`.
  - It is signed with ECDSA P-256 over SHA-256, the same algorithm as posture exports. Its hash links to the next checkpoint.
- **Proof for a filtered export.** A single record is proven by:
  - its body;
  - its Merkle audit path within its segment (at most log₂(segment size) hashes);
  - the signed checkpoint chain.

  Filtered exports therefore stay small (§6.6), and a contiguous range can also be checked by replaying the chain.
- **Truncation and rewrite.** Each checkpoint is recorded as an `audit.checkpoint` record and forwarded (§6.4), and in SaaS also written to object-locked storage (OQ3). Rewriting or truncating the platform's copy therefore no longer matches the external copies; `fair-audit-verify compare` reports the first divergence.

### 4.3 Access model
The access model follows posture's (F-015 design §5):
- **Tables.** `audit_definer`, a non-login bootstrap role, owns the tables. Application roles have no table privileges.
- **`audit.submit(event jsonb)`.** This SECURITY DEFINER function is granted to `app_rw`, `app_gateway`, `app_posture` and `app_audit`. It validates the event against `audit.event_type` and inserts into `intake`. An unknown type or a missing required field raises PF011.
- **Sequencer functions.** `app_audit`, a new login role (bootstrap `FAIR_AUDIT_PASSWORD_FILE`), is granted the sequencer functions `audit.sequence_batch`, `close_segment`, `archive_segment` and `destroy_segment`.
  - These functions check their own preconditions, for example "archived digest recorded" before deleting rows, and "destroy_after passed and no hold" before destruction.
- **Read functions.** `audit.search`, `history`, `request`, `approval_evidence`, `export_rows` and `status` take the caller from the signed DB context (`authz.ctx_user()`, ADR-007). They filter with the user's read scope for resource type `audit` (the `authz.bu_scope_expr('audit','read')` form):
  - a record is visible only when its `bu_id` is in the caller's visible BUs for `audit.view`;
  - restricted BUs therefore require an assignment there (F-001-AC-60, AC-64);
  - root-BU records require `audit.view` at the root (AC-19).
- **No update or delete.** Triggers on `record` and `checkpoint` refuse `UPDATE` and `DELETE` for every role. The exception is the retention function, which deletes archived segments only. Its trigger checks a transaction-local flag that only that function sets (AC-08).
- **What a database superuser could still do.** A superuser can bypass all of this. That is detected rather than prevented: the chain, the external checkpoint copies and the daily full verification catch it (§8).
- **Existing in-database producers.** A `BEFORE INSERT` trigger on `iam.event_outbox` rewrites rows with `topic = 'audit'` into `audit.submit` and skips the outbox insert. All 42 existing SQL producers move to the trail unchanged and in the same transaction.
  - The iam worker's audit relay (`scope.Worker.send`, topic `audit`) is removed.
  - Pending rows are moved by the migration.

### 4.4 Settings (F-015 bindings; profile packages bump to 1.2.0)
| Key | Type | Default (every built-in profile) | Bounds and floor |
|---|---|---|---|
| `audit.retention_online` | duration | 365 days | Longer is stricter. Hard floor 90 days (AC-28) |
| `audit.retention_total` | duration | 2,557 days (7 years) | Longer is stricter. Must be ≥ online |
| `audit.max_clock_skew` | duration | 5 minutes | Shorter is stricter (AC-05) |
| `audit.forward_backlog_alert` | object `{records, age}` | 10,000 records or 15 minutes | Smaller is stricter (AC-23) |
| `audit.syslog_destination`, `audit.otlp_destination` | string (host:port) | empty | Setting or changing a destination is within bounds. Clearing a configured one is a loosening: dual approval and a high-severity event (AC-24) |
| `audit.storage_quota` | bytes | Set at install (F-014 sizing) | — (AC-30) |

- The checkpoint interval (15 minutes) and the verification cadence are constants, not settings, because the requirements allow neither to be loosened.
- `audit.enabled` keeps its hard floor.

## 5. API (`/api/v1/audit`, contract `api/openapi/audit.yaml`)
| Method and path | Permission | Notes |
|---|---|---|
| `GET /records` | `audit.view` | Filters: `from`, `to`, `type`, `category`, `severity`, `actor`, `target`, `bu`, `request_id`, `source_ip`. Cursor pagination on `seq`, newest first. Each row has `integrity` (verified up to here / pending / failed) and display names. Audited as `audit.searched` (AC-15, AC-18, AC-20) |
| `GET /records/{seq}` | `audit.view` | One record with its proof (leaf, path, checkpoint). 404 when unseen |
| `GET /history?target=` / `?actor=` | `audit.view` | Ordered history. The Posture page's `auditHref` lands here through the UI route `/audit?target=` (AC-16, AC-37). Audited as `audit.history_viewed` |
| `GET /requests/{request_id}` | `audit.view` | Every visible record of one request, across services (AC-17) |
| `GET /approvals/{id}` | `audit.view` | Request, decision, both parties, and the applied change's records (attribute `approval_id`) (AC-35) |
| `POST /exports` | `audit.export` | Body: filter, format (`jsonl`, `csv`) and reason. Idempotency-Key required. 202 with the export id. Audited as `audit.exported` (high) (AC-32 to AC-34) |
| `GET /exports/{id}`, `/exports/{id}/bundle` | `audit.export`, requester or root | Bundle download (§6.6). Audited as `audit.export_fetched` |
| `GET /checkpoints?from=&to=`, `GET /keys` | `audit.view` | Checkpoints and public keys for verifiers |
| `GET /holds`, `POST /holds`, `POST /holds/{id}/release` | `audit.hold` (reason required) | AC-29 |
| `GET /status` | `audit.view` at root, or `posture.view` (through the Posture API) | Last verification, backlog per destination, storage use (AC-14, AC-23, AC-30) |

- Display names come from `iam.user_display_names(ids)`, a definer function granted to `app_audit` that returns names only for actors and approvers in records the caller can see.
- The UI pages are the WCAG 2.1 AA gate (AC-21), extending `scripts/ui-e2e.sh` with axe.

## 6. Key flows
### 6.1 Emit (AC-01 to AC-04)
1. A service calls `Emit(ctx, e)`. `audit.Validating` checks the catalog. On failure it emits `audit.invalid_event` (critical) with the original attached, and returns an error, so the operation fails.
2. The `Trail` sink calls `audit.submit`.
   - If `ctx` carries a transaction (`audit.WithTx`), the call runs in it, so the event commits or rolls back with the change. Posture's emits inside transaction closures adopt this.
   - Otherwise it runs in its own short transaction before `Emit` returns.
3. Any error is returned, and the caller fails closed (AC-02). The JSON-lines stdout sink stays (AC-36). Per-service syslog moves to the audit service's forwarder.
4. In-database producers reach `audit.submit` through the `event_outbox` trigger (§4.3) inside their own transaction.
5. `event_id` is the producer's 128-bit id (`Normalize`); the trigger generates one for SQL producers. A retry with the same id is a no-op (`ON CONFLICT DO NOTHING`), so delivery happens exactly once (AC-01).

### 6.2 Sequence (AC-03, AC-05, AC-07)
1. The leader loops. It locks the `head` row, takes up to 500 intake rows (`ORDER BY id`), and for each one:
   - builds `body`, adding `received_at = accepted_at` and `producer`;
   - flags `skew` when `|event_time − accepted_at| > audit.max_clock_skew`;
   - assigns `bu_id`, which defaults to the root BU;
   - computes `leaf_hash` and `chain_hash`, then inserts the record.
2. It deletes the intake rows and updates `head`, all in one transaction.
3. Rows that commit late with lower ids are simply taken in a later batch. Ordering in the trail is the sequencer's order, and `event_time` keeps the original time.
4. If the database is reachable but the audit service is down, intake grows and nothing is lost (AC-03). The backlog of intake rows is reported by `/status` and checked at the capacity thresholds.

### 6.3 Checkpoint (AC-09, AC-10)
1. Every 15 minutes, and whenever an export needs one, the leader closes the open segment. It computes the Merkle root, builds and signs the statement, inserts it into `checkpoint`, and opens the next segment.
2. The leader emits `audit.checkpoint` (info), with the statement and signature as attributes, which forwarding sends to the SIEM.
3. Where write-once storage is configured, which is required in SaaS, it writes `checkpoints/<instance>/<segment>.json` with Object Lock in compliance mode until `destroy_after`.
4. The signing key is read from `/keys/audit/checkpoint/` (`keys.Audit`, created by `iam keys init`, rotated by `iam keys rotate`). The private key is never in the database; public keys are in `signing_key`.
5. A segment with no records still gets a checkpoint, so silence is provable.

### 6.4 Forward (AC-22, AC-23)
1. One goroutine per configured destination reads records after its cursor in `seq` order and sends them:
   - **syslog:** RFC 5424 over TLS (RFC 5425), with structured data `fair@<PEN> seq= chain= segment=`;
   - **OTLP:** logs over gRPC with TLS, with the record body as the log body and seq, chain and segment as attributes.
2. TLS 1.2 is the minimum. CAs are read from files. Plaintext is refused outside development.
3. The cursor advances only after the destination acknowledges. The OTLP export response confirms delivery; syslog over TLS confirms at the TCP level, which is documented as at-least-once.
4. When the backlog exceeds `audit.forward_backlog_alert`, the service emits `audit.forward_backlog` (high) once per crossing and shows it on the Posture page.
5. OTLP uses `go.opentelemetry.io/proto/otlp` with the existing gRPC dependency, not the full SDK.

### 6.5 Verify (AC-12 to AC-14)
- **Incremental, every 15 minutes.** Recompute the leaf and chain hashes from the last verified `seq` to the head. Check the Merkle roots and signatures of newly closed checkpoints, and that checkpoint hashes link.
- **Full, daily.** Archived segments: fetch each object, check its digest against `archive`, and recompute its root against the checkpoint. Online records: replay the chain from the first retained checkpoint. In SaaS, also compare the platform's checkpoints with the WORM copies.
- **Gaps.** `seq` gaps are detected by count and contiguity per segment.
- **On failure:**
  - record a `verification` row with `failed_at_seq`;
  - emit `audit.verification_failed` (critical);
  - open the Posture finding `audit_integrity` (kind `app`, critical, controls AU-9 and AU-6) through `posture.audit_finding(open, detail)`, a new definer function granted to `app_audit`;
  - in SaaS, queue a vendor SecOps alert in `posture.secops_outbox`.
- **Resolution.** A later successful full run resolves the finding (AC-13). Nobody can acknowledge it away; acknowledgement works as for other findings, but resolution needs the check.
- **Posture page.** `audit.status()`, granted to `app_posture`, drives a "Audit trail" tile showing last verified, result, backlog and storage (AC-14, AC-23, AC-30).

### 6.6 Export (AC-32 to AC-34)
1. A River job, run by the audit service on its own queue, does the work:
   - closes a segment (§6.3) so the export is covered by a fresh checkpoint;
   - runs `audit.export_rows` with the requester's scope, which is captured in `scope_bus` at request time;
   - writes the bundle to object storage.
2. The bundle is a ZIP containing:
   - `records.jsonl` (or `records.csv` plus `bodies.jsonl`): the exact bodies;
   - `proofs.jsonl`: per record, its seq, segment and Merkle path;
   - `checkpoints.jsonl`: the chain from the first covered checkpoint to the closing one;
   - `keys.pem`;
   - `manifest.json`: the filter in words and as data, the BU scope, the count, the file digests, the requester, the time and the reason;
   - `manifest.sig`: ECDSA P-256 over the manifest.
3. It emits `audit.exported` (high) with the filter, count and digest. Download emits `audit.export_fetched` (low).
4. Archived ranges are read from their segment objects (AC-26).
5. Throughput target: 1 million records in ≤ 5 minutes, streamed with batched reads.

### 6.7 Retention, archive, destruction, hold (AC-25 to AC-29)
- **Archive (daily).** For each closed segment whose newest `event_time` is older than `audit.retention_online`:
  1. write `segments/<instance>/<segment>.jsonl.zst` (bodies, leaf hashes, the signed checkpoint) with Object Lock until `destroy_after = archived_at + (retention_total − retention_online)`;
  2. read the object back and verify its digest;
  3. record the result in `archive`;
  4. `audit.archive_segment` deletes the segment's rows;
  5. emit `audit.records_archived` (info).

  Archived records are not searchable, but they stay exportable and verifiable.
- **Destroy (daily).** For each archive past `destroy_after` with no `hold_segment` row: delete the object, set `destroyed_at`, and emit `audit.records_destroyed` (high) with the segment and seq range. Checkpoints are kept, so verification starts from the first retained checkpoint (AC-27).
- **Hold.** A hold's filter is evaluated over online records and archive manifests. Matching segments are listed in `hold_segment` and given an S3 legal hold. Releasing a hold removes those, unless another hold also covers the segment. Placing a hold emits `audit.hold_placed` (high); releasing one emits `audit.hold_released` (high).
- **Retention changes.** Shortening a retention setting below the profile value is an F-015 loosening (AC-28). Shortening never shortens Object Lock already applied.

### 6.8 Capacity (AC-30, AC-31)
- The leader measures the `audit` tables (`pg_total_relation_size`) plus intake against `audit.storage_quota` every 5 minutes.
- At 75% it emits `audit.capacity_warning` (high); at 90%, `audit.capacity_critical` (critical). The Posture tile and finding `audit_capacity` follow.
- When `audit.submit` itself fails (for example, the database is out of space), the producer's operation fails (AC-31). No path drops events.

## 7. Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Object storage | Vendor S3-compatible store with Object Lock (compliance mode) | Customer S3-compatible store, bundled or brought | Bundled store inside the enclave |
| WORM checkpoints | Required. `posture.CheckInstall` refuses to start without them | Optional (`FAIR_AUDIT_WORM_BUCKET`) | Optional |
| SIEM | Customer destination, plus a vendor SecOps copy of integrity alerts | Customer destinations | Inside the enclave only (`scanner.InternalOnly` rules apply to destinations) |
| Verifier | Release download | In the bundle | In the bundle |

`TestDeploymentModeMatrix` gains audit keys and checks: `FAIR_AUDIT_PASSWORD_FILE`, `/keys/audit/checkpoint`, object storage, and the WORM rule.

## 8. Security design (STRIDE)
| Threat | Example | Control |
|---|---|---|
| Spoofing | A service submits events as another producer | `producer` comes from the DB role (`session_user`), not from the body. Actors come from the signed DB context or the authenticated service |
| Tampering | A DBA edits or deletes a record | No grants. Triggers refuse it. The chain and Merkle roots break, and the external checkpoint copies differ: detected within 15 minutes (incremental) or 24 hours (full) |
| Tampering | Truncating the tail and re-signing | The signing key is outside the DB. The SIEM and WORM copies of later checkpoints expose it (`compare`) |
| Tampering | Swapping an archive object | Object Lock. Digest in `archive`. The root is checked against the signed checkpoint daily |
| Repudiation | "I never exported that" | Exports, searches and holds are themselves records |
| Information disclosure | An auditor reads restricted-BU before and after values | Scope-filtered definer reads (AC-19). Exports are bound to the requester's scope. No secrets in events (AC-06) |
| Information disclosure | Display names leak through the audit API | Names are returned only for records the caller sees |
| Denial of service | Event flood, or audit service down | Intake absorbs the flood. Capacity alerts. Fail closed rather than drop |
| Elevation of privilege | Using `audit.hold` to keep records forever | `audit.hold` is privileged and every hold is audited high. Holds are reviewed in F-001 access reviews |

The STRIDE rows join `TestSTRIDECatalog` (`db/tests/stride_f002_test.go`).

## 9. New catalog event types
`audit.searched` (low), `audit.history_viewed` (low), `audit.exported` (high), `audit.export_fetched` (low), `audit.checkpoint` (info), `audit.verification_failed` (critical), `audit.verification_recovered` (high), `audit.forward_backlog` (high), `audit.forward_recovered` (info), `audit.capacity_warning` (high), `audit.capacity_critical` (critical), `audit.records_archived` (info), `audit.records_destroyed` (high), `audit.hold_placed` (high), `audit.hold_released` (high). `audit.invalid_event` already exists.

## 10. Requirements traceability
| Requirement / AC | Satisfied by |
|---|---|
| R-01 AC-01 | Event ids, `ON CONFLICT DO NOTHING` (§6.1) |
| AC-02 | `Trail` sink errors fail the operation; in-transaction submit (§6.1) |
| AC-03 | Intake plus sequencer failover (§6.2) |
| AC-04 | `audit.Validating`, `audit.submit` PF011, `audit.invalid_event` (§6.1) |
| AC-05 | `received_at`, `producer`, `skew` (§6.2) |
| AC-06 | Attribute allow-list and deny-list test (§3) |
| R-02 AC-07 | Leaf and chain hashes, Merkle segments (§4.2) |
| AC-08 | Access model and triggers (§4.3) |
| AC-09 | Checkpoints every 15 minutes and per export; key from the key store (§6.3) |
| AC-10 | `audit.checkpoint` forwarded; WORM copy (§6.3) |
| AC-11 | `fair-audit-verify` (§11) |
| R-03 AC-12 to AC-14 | §6.5 |
| R-04 AC-15 to AC-18 | API (§5) |
| AC-19 | Scope-filtered definer reads (§4.3) |
| AC-20 | `audit.searched`, `audit.history_viewed` |
| AC-21 | UI with the axe gate (§5) |
| R-05 AC-22 to AC-24 | §6.4, settings (§4.4) |
| R-06 AC-25 to AC-29 | §6.7, settings (§4.4) |
| R-07 AC-30, AC-31 | §6.8 |
| R-08 AC-32 to AC-34 | §6.6 |
| AC-35 | `/approvals/{id}`, `approval_id` attribute (§3, §5) |
| R-09 AC-36 | Outbox trigger, `Trail` sink in iam, gateway (via SQL), posture and worker; relay removed (§4.3, §6.1) |
| AC-37 | UI route `/audit?target=` over `/history` (§5) |
| Non-functional requirements | Partitioned `record` with indexes on `(event_time)`, `(type, event_time)`, `(actor, event_time)`, `(target, event_time)`, `(request_id)`, `(bu_id, event_time)`; batched sequencing; streamed export. A benchmark gate, as F-001 T-11, at 200/s sustained and 2,000/s bursts |

## 11. The verifier (`fair-audit-verify`)
- `verify-export <bundle.zip>`: checks the manifest signature, the file digests, each record's Merkle path to its checkpoint, and the checkpoint signatures and links.
- `verify-archive <segment objects…> --checkpoints <file>`: recomputes the roots and chains.
- `compare --platform <checkpoints> --external <SIEM export | WORM listing>`: reports the first segment where the copies differ, or one that is missing in either.
- Exit codes: 0 intact, 1 failed (with the first failing position), 2 usage.
- No network access. Its only dependencies are the standard library and the FIPS module.

## 12. Changes to other features
- **F-001.**
  - Envelope `bu_id`, and catalog `bu` and `attributes` (T-37 follow-up).
  - `iam.event_outbox` audit rows are redirected; the worker relay is removed.
  - `audit.hold` is added to the permission catalog (privileged; the Auditor built-in role does **not** get it, Platform Admin does).
  - `keys.Audit` mounts.
  - Gateway segment `audit`.
  - The F-001 AU-2 and AU-12 statements are updated.
- **F-015.**
  - The settings in §4.4: bindings, packages 1.2.0, and `BuiltinProfiles()` parity.
  - Finding check ids `audit_integrity` and `audit_capacity`, and `posture.audit_finding`.
  - The Posture page's Audit trail tile, through `audit.status()`.
  - `CheckInstall` rules for the audit service.
  - The design §15 deferred items close: "expiry is checked against the audit trail" becomes a query over `audit.record`.
- **F-014.** Sizing for `audit.storage_quota`, bundled object storage, and preflight for WORM in SaaS.

## 13. Alternatives considered
- **Hash chain only.** Simple, but a filtered export can be tied to a checkpoint only by shipping every intermediate leaf hash: about 32 bytes × every record in the range, which is gigabytes for a year's export. Merkle segments keep proofs logarithmic. *(D1)*
- **A full transparency log** (one RFC 9162 tree over all records, with consistency proofs). Strongest, but more machinery than needed while checkpoints are chained and copied externally. It can be adopted later without changing record bodies.
- **NATS JetStream as the intake.** That would add a second durable store for audit, and in-transaction emits would no longer be possible, so a committed change could lack its event or the reverse. PostgreSQL intake keeps "event iff change". *(D2)*
- **Sequencing inside iam.** That avoids a new service, but puts the audit store's writer, keys and admin surface in the identity service, which weakens separation (AU-9(4)) and couples their releases. *(D3)*
- **Archive in PostgreSQL** (detached, compressed partitions). That needs no object storage, but gives no Object Lock: WORM would be impossible, and the database would keep growing for 7 years. *(D4)*

## 14. Resolved
- D1: hash chain plus signed Merkle segment checkpoints; recorded as ADR-011 with the first task (2026-11-04)
- D2: PostgreSQL intake in the producer's transaction, one sequencer (2026-11-04)
- D3: a new `audit` service with its own DB role and signing key (2026-11-04)
- D4: archive to S3-compatible object storage with Object Lock (2026-11-04)

## 15. Open items
- The syslog structured-data PEN (private enterprise number) for `fair@<PEN>` must be registered with IANA, or the IANA-reserved example used until then.
- The settings comparator for destination strings ("clearing is loosening") needs the T-13 comparator set extended. That is a small F-015 change, made in this feature's task.

## Change Log
- 2026-11-04: Initial draft. D1 to D4 resolved by Robert Former.
- 2026-11-04: **Approved** by Robert Former.
- 2026-11-04: T-01 implementation notes. ADR-011 accepted. `internal/audit/integrity` (standard library only): `Body`/`IsBody` (sorted keys, compact, no HTML escaping, numbers kept as given), `Leaf`, `Genesis`, `Chain`, `Tree` (RFC 9162 root and inclusion paths, built level by level; checked against the Certificate Transparency vectors and the recursive RFC definition), `VerifyInclusion` (RFC 9162 §2.1.3.2), `Statement` (an empty segment has `seq_to = seq_from − 1`; only the canonical byte form parses), `Sign`/`VerifySignature` (P-256 only), `KeyID`, `VerifyRecords`, `VerifyCheckpoints`, `VerifySegment`. Failures name the first record or segment that does not verify (`*Failure`), which `fair-audit-verify` (T-10) reports.
