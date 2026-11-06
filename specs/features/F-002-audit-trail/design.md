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
| `audit.forward_backlog_records`, `audit.forward_backlog_age` | int; duration | 10,000 records; 15 minutes (an alert when either is crossed) | Smaller is stricter (AC-23) |
| `audit.syslog_destination`, `audit.otlp_destination` | string (host:port) | empty | Setting or changing a destination is within bounds. Clearing a configured one is a loosening: dual approval and a high-severity event (AC-24) |

- `audit.retention_total` below `audit.retention_online` is not refused, because F-015 changes one key at a time. The audit service uses max(total, online) as the total, and the Posture page flags the inconsistency.
- The storage quota (AC-30) is install configuration, not a setting: `FAIR_AUDIT_STORAGE_QUOTA`, sized by F-014. A larger or smaller quota is neither stricter nor weaker.
- Destinations are a new F-015 setting kind, `string`, with the direction `nonempty_is_stricter`: any non-empty value is as strict as any other, and clearing one is a loosening.
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
   - `manifest.sig`: ECDSA P-256 over the manifest, by the checkpoint key (the manifest names its `key_id`).
3. It emits `audit.exported` (high) with the filter, count and digest. Download emits `audit.export_fetched` (low).
4. Archived ranges are read from their segment objects (AC-26).
5. Throughput target: 1 million records in ≤ 5 minutes, streamed with batched reads.

### 6.7 Retention, archive, destruction, hold (AC-25 to AC-29)
- **Archive (daily).** For each closed segment whose newest `event_time` is older than `audit.retention_online`:
  1. write `segments/<instance>/<segment>.jsonl.gz` (bodies, leaf and chain hashes, the signed checkpoint; gzip, so the verifier needs only the standard library) with Object Lock until `destroy_after = archived_at + (retention_total − retention_online)`;
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
- `verify-export [-keys <trusted.pem>] <bundle.zip>`: checks the manifest signature, the file digests, each record's Merkle path to its checkpoint, and the checkpoint signatures and links.
- `verify-archive -checkpoints <file> -keys <trusted.pem> <segment objects…>`: recomputes the roots and chains.
- **Trusted keys.** `-keys` names public keys obtained separately from the evidence; every signature must be by one of them. A bundle's own `keys.pem` vouches only for itself: without `-keys`, `verify-export` uses it, prints the signing key ids and warns that the result is not pinned.
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
- The syslog structured-data PEN (private enterprise number) for `fair@<PEN>` must be registered with IANA. Until then T-16 uses the RFC 5612 documentation number, `fair@32473` (`audit.SyslogPEN`); changing it is a release note for SIEM parsers.
- The settings comparator for destination strings ("clearing is loosening") needs the T-13 comparator set extended. That is a small F-015 change, made in this feature's task.

## Change Log
- 2026-11-04: Initial draft. D1 to D4 resolved by Robert Former.
- 2026-11-04: **Approved** by Robert Former.
- 2026-11-04: T-01 implementation notes. ADR-011 accepted. `internal/audit/integrity` (standard library only): `Body`/`IsBody` (sorted keys, compact, no HTML escaping, numbers kept as given), `Leaf`, `Genesis`, `Chain`, `Tree` (RFC 9162 root and inclusion paths, built level by level; checked against the Certificate Transparency vectors and the recursive RFC definition), `VerifyInclusion` (RFC 9162 §2.1.3.2), `Statement` (an empty segment has `seq_to = seq_from − 1`; only the canonical byte form parses), `Sign`/`VerifySignature` (P-256 only), `KeyID`, `VerifyRecords`, `VerifyCheckpoints`, `VerifySegment`. Failures name the first record or segment that does not verify (`*Failure`), which `fair-audit-verify` (T-10) reports.
- 2026-11-04: T-02 implementation notes (migration 0066, `db/bootstrap/0001_roles.sql`):
  - **Roles.** `audit_definer` is a NOLOGIN bootstrap role, with SET granted to `fair_owner` (as `posture_definer` is).
  - **No foreign key on `bu_id`.** `audit.record.bu_id` has no foreign key: `submit` checks the BU, BUs are never deleted, and a key would tie the trail into `iam.bu`'s TRUNCATE cascade.
  - **Ownership.** `audit_definer` owns the definer functions and also `audit.record`, so `audit.ensure_partition` can add monthly partitions (`record_YYYYMM`). Each partition gets forced RLS and its own TRUNCATE trigger, because statement triggers are not inherited by partitions. The other tables stay owned by `fair_owner`.
  - **RLS.** Every table has RLS forced with one `definer_only` policy, so `fair_owner` sees no rows.
  - **Append-only.** `audit.refuse_change` raises **PF012** on `UPDATE`, `DELETE` and `TRUNCATE` of `record`, `checkpoint` and `signing_key`, except for:
    - `worm_key` and `retired_at`, each set once from NULL with nothing else changing;
    - record deletes while `audit.archiving` is on, which is for T-18.
  - **`audit.submit(jsonb)`** is granted to `app_rw`, `app_posture` and `app_gateway`. It raises **PF011** on:
    - a field outside the envelope, or a non-string scalar field;
    - an unknown or retired type, or a severity the type does not allow;
    - a missing actor, or a missing `requires` field;
    - an invalid `bu_id`, an unknown BU, or no `bu_id` when the type requires one;
    - an invalid `source_ip`, `time` or id;
    - a non-object attributes value, or a non-string attribute;
    - an event over 64 KiB.

    `submit` sets the producer from `session_user`. It fills in a missing id and time, and normalizes the time to UTC with microseconds. A retried event (same id) is a no-op.
  - **Catalog sync.** `audit.sync_event_types(jsonb)` is run by `iam migrate` with `migrate.Release.Events`, built by `audit.(*Catalog).SyncPayload`. It reports what was added, changed, retired and restored; `db.migrated` carries the added and retired types. An empty or malformed catalog is refused (PF004), and `migrate.Run` refuses a release without one.
- 2026-11-04: T-03 implementation notes (migration 0067, `pkg/audit`):
  - **Envelope `bu_id`.** `Event.BUID` and the schema field (a UUID) carry the BU an event concerns.
  - **`bu: required` types.** 24 types are `bu: required`: BU changes, group mappings and mapped assignments, expired assignments, access reviews and service accounts. Their SQL emitters now pass a top-level `bu_id`: `iam.bu_event`, `mapping_event`, `review_event`, `sa_event`, `assignment_expiry_sweep`, and `authz.drain_outbox` for `bu.moved`. Their bodies are otherwise unchanged. `FromOutbox` maps `bu_id`. Setting and overlay events stay optional, because instance-wide values have no BU.
  - **Attribute lists.** Every catalog entry declares `attributes` (`[]` for none). The lists came from every event the full suite produced, plus a reading of the code for the 8 types no test emits.
    - `TestCatalogAttributesMatchCode` checks every literal attribute key written at an emission site against the list: Go `audit.Event` literals, direct SQL payloads, and SQL helper calls (each helper's own keys plus the extra attributes passed to it). That way an untested path cannot fail closed in production on an unlisted name. Keys built at run time are not covered.
    - `event_id`, which `FromOutbox` adds, is reserved and accepted on every type.
  - **Secrets (AC-06).**
    - Names containing `password`, `passwd`, `secret`, `token`, `cookie`, `authorization`, `private_key`, `api_key` or `bearer` are refused by the catalog.
    - Values that look like secrets are refused in attributes, target, reason, before and after: JWTs, PEM private keys, bearer or basic credentials, and the session cookie. `audit.LooksSecret` applies this rule in Go and `audit.looks_secret` in SQL.
    - `TestNoSecretsInEvents` runs every listed attribute of every type through ordinary and secret values.
    - Identifiers that are row ids or hashes of public material are not secrets: `session` (the session's row id; the cookie is stored only as an HMAC), `credential`, `certificate`, `credential_id` (WebAuthn's public id), `thumbprint` and `key_id`.
  - **`audit.submit`** applies the same attribute list and secret rule. `audit.sync_event_types` loads `bu` and `attributes` from the catalog.
- 2026-11-04: Design change for T-04, approved by Robert Former:
  - the backlog threshold becomes two settings, `audit.forward_backlog_records` (int) and `audit.forward_backlog_age` (duration), because F-015 has no object kind;
  - the storage quota is install configuration (`FAIR_AUDIT_STORAGE_QUOTA`), not a setting;
  - total retention below online retention is handled as max(total, online) and flagged, with no cross-setting rule in F-015;
  - destinations use a new F-015 kind, `string` with `nonempty_is_stricter`.
- 2026-11-04: T-04 implementation notes (bindings, `pkg/settings`, migration 0068):
  - **Definitions and packages.** `settings.F002Defs()` holds the seven settings, registered by the audit service (T-05); `ReleaseDefs()` is F-001's plus F-002's, and profilegen builds the packages from it. The profile packages are now 1.2.0, with 27 settings.
  - **Values in every built-in profile.** Online retention defaults to 365 days, with a 90-day hard floor (`"90d"`). Total retention defaults to 2,557 days (7 years).
  - **Bounds.**

    | Setting | FedRAMP Moderate and CMMC | Enterprise Baseline |
    |---|---|---|
    | Online retention | 365 days (AU-11 constraint "in compliance with M-21-31") | 90 days (the floor) |
    | Total retention | 913 days (30 months, M-21-31) | 365 days |
    | Clock skew | 5 minutes | 15 minutes |
    | Backlog | 10,000 records and 15 minutes | 100,000 records and 1 hour |
    | Destinations | Empty by default, no bound | Same |

  - **The `string` kind (F-015 change).** It is limited to 255 bytes with no control characters. In Go it is `settings.KindString`, with direction `NonEmptyIsStricter`. In SQL it is handled by `posture.check_value` and `posture.rank`. The parity and property tests cover it, and profilegen refuses a bound on a string setting.
  - **`loosening_needs_approval` (F-015 change).**
    - The flag lives in the binding, in `Def.LooseningNeedsApproval` and in `setting_def`. A registration may set it but never clear it (PF001).
    - `preview_change` reports `loosening_approval`. `request_change` opens a `settings.loosen` approval (granted by `settings.approve`) and requires an explanation (PF002).
    - `apply_change` reads the approval's kind; `posture_definer` may read `iam.approval_request(id, kind)` for this. An approved loosening within the bound applies as a change with `setting.changed` at high severity, not as an exception, so it does not expire or revert. `Evaluator.ApplyApproved` returns an `Exception` without an ID for it.
    - A change recorded as `requested` that would now loosen such a setting is refused (PF002).
    - `ApplyApproved` takes only changes in `pending_approval`; any other change, or a missing one, is `ErrNotApplicable` and is neither applied nor reported as approved (found by mutation testing).
- 2026-11-04: T-05 implementation notes:
  - **Service.** `cmd/audit`, with image target `audit`; CI builds, smoke-tests (unconfigured, it must refuse to start), scans and signs it. The manifest is `deploy/k8s/audit.yaml`: two replicas; ingress from the gateway only; egress to PostgreSQL and DNS for now.
  - **Database role.** `app_audit` is a bootstrap login role (`FAIR_AUDIT_PASSWORD_FILE`). Migration 0069 gives it the `audit` schema and `audit.submit`. The service checks at startup and in readiness that it cannot read audit tables directly.
  - **Leader election.** `internal/audit.Leader` holds a session advisory lock (`LeaderLockKey`) on one dedicated connection, checks every 5 s that it still holds it, and cancels the leader's work when it is lost. A DB test covers a single holder, a handover when the leader stops, and the step-down when its backend is terminated. `cmd/audit` runs it with no work yet (T-07).
  - **Install checks.** `internal/audit.CheckInstall`: in production the checkpoint key and the JWT keys are required; in production SaaS `FAIR_AUDIT_WORM_BUCKET` is required. Covered by `TestDeploymentModeMatrix`.
  - **Keys** (`internal/keys`):
    - The audit service holds `audit/jwt` (the gateway's public keys; rotation reaches it) and `audit/checkpoint` (`FAIR_AUDIT_CHECKPOINT_KEYS_DIR`: one private key, older keys kept public).
    - `iam keys init` creates both. `iam keys upgrade` adds `audit/` to a directory made before F-002. `iam keys rotate -kind checkpoint` rotates the checkpoint key. `iam keys check` covers all of this.
    - The SaaS, plain-Secret and OpenBao manifests carry the audit entries (`TestDeployManifests`), and `docs/install/keys.md` covers them. `scripts/openbao-e2e.sh` still loads only the F-001 entries: extending it needs a live OpenBao run.
  - **Mutation testing.** 12 of 13 mutants were caught. The one that survived removes the "still held" half of the lock check. That is equivalent in practice, because a session lock is lost only with its connection, and then the same query fails with an error first.
  - **"Boots in kind."** Not run in kind. Verified instead by starting two replicas of the image (read-only root filesystem, all capabilities dropped) against a migrated database: both became ready, one led, and stopping it handed the lead to the other.
- 2026-11-04: T-06 implementation notes (migration 0070, `pkg/audit/trail.go`):
  - **SQL producers.** A `BEFORE INSERT` trigger on `iam.event_outbox` (`audit.from_outbox`, owned by `audit_definer`) hands every `audit` row to `audit.submit` in the producer's transaction and skips the outbox row.
    - The payload is converted by `audit.outbox_event`, as `FromOutbox` did. Top-level nulls are dropped (never nested ones). Null attributes are dropped, and non-string attributes become their JSON text. The row's `created_at` becomes the event time.
    - Pending audit rows were moved by the migration.
    - A refused event (PF011) now fails the SQL change that produced it.
  - **The scope worker.** It relays only NATS topics; an audit row reaching it is an error. Its `Options.Audit` option is gone.
  - **Go producers.**
    - `audit.Trail` submits through a transaction from `audit.WithTx`, or through a short transaction of its own; `Role` takes `SET LOCAL ROLE` first.
    - `audit.WithTrail` records in the trail first and writes to the logs only once the trail has the event; an event the trail refuses is written nowhere else.
    - iam, posture (service and commands), the audit service, `iam migrate` and `iam keys register` / `retire-db-context` record to the trail. The installer commands record as `fair_owner`: migration 0070 grants it `audit.submit`, and the producer is still `app_migrator`.
    - iam's `service.started` now follows the pool, and a failure to record it stops the start.
    - The break-glass CLI's lines stay in the install log only, because its SQL functions already record the same events.
  - **Posture.** 27 emits that report a change made in a transaction now join it (`WithTx`). Three stay outside: the hard-floor refusals and the failed-revert event, which report no change, and the export-mismatch event, whose transaction rolls back with the refusal.
  - **Invalid events.** `audit.Validating` records an event the catalog refuses as `audit.invalid_event` (critical, the original attached, best effort, outside the caller's transaction, and never for a secret-looking original) and still returns the refusal. This replaces the worker's relay fallback.
  - **Tests.**
    - After every test, `checkAuditCatalog` validates every intake body against the Go catalog, checks that every producer is a login role, and fails if any audit row reached the outbox. Together these show that every exercised SQL producer lands in the trail.
    - The DB tests read audit events from `audit.intake`. Attributes are strings now, so nested values are read with `::jsonb`.
    - `TestAuditTrailFromSQLProducers` and `TestAuditTrailFromGo` cover commit and rollback, the conversion, exactly-once retries, refusals failing the caller and the change, and the installer role. `TestWorkerAuditFailsClosed` now shows a refused `bu.moved` rolling back the scope drain.
    - F-001's AU-12 evidence names `pkg/audit:TestValidatingRecordsInvalidEvents` in place of the removed scope test.
  - **Timing.** `db/tests` takes about 10% longer, roughly 630 s. CI's DB test step now has `-timeout 60m`, as `make test-db` does.
  - **Unchanged.** Per-service syslog remains until T-16.
  - **Mutation testing.** All 12 mutants were caught, after adding a check that the outbox row's time becomes the event time.
- 2026-11-04: T-07 implementation notes (migration 0071, `internal/audit/sequencer.go`):
  - **How a batch runs.** Each batch is one transaction.
    1. `audit.sequence_head()` locks the head. On first use it creates it, with a random instance id, seq 0, the ADR-011 genesis and segment 1.
    2. `audit.sequence_pending(n)` drops intake rows whose event is already recorded (a retry arriving after its first copy was sequenced) and returns the oldest `n`.
    3. The leader builds each body in Go: the event plus `received_at` (the intake row's `accepted_at`), `producer` and the resolved `bu_id` (the root BU by default), serialized with `integrity.Body`. It also computes the leaf and chain hashes.
    4. `audit.sequence_append` checks all of it and appends.
  - **What `sequence_append` checks** (PF013 otherwise):
    - the head is where the leader read it;
    - each body equals its intake event plus that row's producer and receipt time and the resolved BU, so neither the producer nor the content can be forged;
    - the leaf and chain hashes are SHA-256 as ADR-011 defines them.

    It derives every column from the body, puts each record in the partition of its event time, flags skew beyond the given `audit.max_clock_skew`, and assigns the open segment. Its comparisons are NULL-safe (`IS DISTINCT FROM`): a test found that a body without `received_at` passed a NULL comparison.
  - **Batches.** 500 events per batch. The leader runs batches back to back while there is a backlog, otherwise every 200 ms.
  - **Settings.** The audit service now registers F-002's settings (retrying until posture is seeded; this was left out of T-05) and reads `audit.max_clock_skew` through `settings.Client`, defaulting to 5 minutes. Migration 0071 grants `app_audit` the posture settings functions.
  - **Tests.** `TestAuditSequencer` covers order, body and columns, numbers kept exactly, skew under the setting and under the default, and dropped retries. `TestAuditSequencerLateAndConcurrent` covers a late-committing producer and two racing sequencers with four producers: no gap, no fork. `TestAuditSequenceAppendRefusesForgeries` covers producer, receipt time, content, BU, id, hashes, a stale head and a missing row. `TestAuditIntakeWaitsForTheSequencer` covers 1,200 events held while the service is down. Every test verifies the whole trail with `internal/audit/integrity` and checks that SQL and Go agree on the genesis.
  - **Benchmark gate.** `TestBenchmarkGateAuditSequencer`, in the CI bench job: 200 events/s for 30 s, then 2,000/s for 60 s. Locally the oldest waiting event was at most 93 ms (target 5 s), and the backlog drained 166 ms after the load.
  - **Mutation testing.** 15 of 16 mutants were caught. The survivor drops the explicit timestamp-validity check, which is equivalent: the cast or `IS DISTINCT FROM` still refuses an invalid or missing receipt time.
- 2026-11-04: T-08 implementation notes (ADR-012, `internal/objstore`):
  - **Client.** minio-go v7.4.1, wrapped in `internal/objstore`. Configuration comes from `<PREFIX>_ENDPOINT`, `_BUCKET`, `_REGION`, `_ACCESS_KEY_FILE`, `_SECRET_KEY_FILE`, `_CA_FILE` and `_PLAINTEXT` (development only). TLS 1.2 is the minimum.
  - **Operations.** `CheckBucket` refuses a bucket without versioning and Object Lock (`ErrNotWORM`). `Put` writes under compliance retention and returns the version. The other operations all name a version: `Get` (bounded) and `Open`, `Digest` (the SHA-256 of what the store returns), `Delete`, `SetLegalHold` / `LegalHold`, `RetainedUntil` (compliance only) and `List` (every version, without delete markers).
  - **Write checksum.** Object Lock writes send `Content-MD5`, the body checksum every S3-compatible store accepts. It checks transport only; the trail's integrity is SHA-256.
  - **Test server.** versitygw v1.9.0, pinned by digest (`scripts/s3-test-server.sh`, TLS with a throwaway CA). MinIO no longer publishes images, and versitygw passed an Object Lock probe, as did RustFS and SeaweedFS. CI's test job starts it, so the contract tests (`FAIR_TEST_S3=1`) run there.
  - **Tests.** They run in FIPS mode and cover: retention enforced and then lapsing, versions, legal hold, delete markers, governance mode refused, a bounded read, and a plain or missing bucket refused. Unit tests cover the configuration refusals and the TLS floor (a TLS 1.1 server is not reached).
  - **Mutation testing.** 8 of 9 mutants were caught. The survivor lowers the client's TLS floor, which is equivalent while Go's own client default is TLS 1.2; the explicit floor stays.
  - **Not yet wired.** The audit service's stores (archive, WORM, exports) are wired with T-09, T-15 and T-18.
- 2026-11-04: T-10 decisions (Robert Former): archives are gzip (`.jsonl.gz`, §6.7), not zstd, so the verifier stays standard-library only (§11); the verifier pins trust with `-keys` and warns when it is not pinned (§11); export manifests are signed by the checkpoint key (§6.6).
- 2026-11-04: T-09 implementation notes (migration 0072, `internal/audit/checkpoint.go`):
  - **Who checks what.** The leader builds the statement, signs it with the checkpoint key (which never enters the database) and passes both to `audit.checkpoint_close`. The database cannot verify the signature, so it checks the statement against the trail instead (PF014 otherwise): version, instance, the open segment, the record range and count, the chain hash at its end, the link to the previous statement (the genesis for segment 1), the Merkle root (recomputed in SQL by `audit.merkle_root`, which a test holds equal to `integrity.Root` for 0 to 33 leaves), a registered and unretired key, an issue time within 60 s, and a signature present. All comparisons are NULL-safe, so a missing field fails. The offline verifier (T-10, T-11) checks the signature.
  - **One transaction.** The close, the opening of the next segment and the `audit.checkpoint` event (statement and signature as attributes, the SIEM copy of AC-10) commit together. The event is recorded in the next segment.
  - **Cadence.** `CheckpointEvery` is a constant 15 minutes, not a setting. `Checkpointer.Close` is also the on-demand close that exports use (T-15). Empty segments close too (`seq_to = seq_from − 1`, root SHA-256 of nothing).
  - **Keys.** The service registers its key at startup (`audit.signing_key_register`; the key id must be the SHA-256 of the PEM's DER). A new key retires the previous one, which then can neither close a segment nor be registered again; retired keys stay for verification. During a rolling rotation the old leader's closes are refused until the new replica leads.
  - **Write-once copies.** With `FAIR_AUDIT_WORM_BUCKET` set (required in SaaS by T-05's install check), the service checks the bucket at startup (refusing one without Object Lock) and copies each checkpoint after commit to `checkpoints/<instance>/<segment>.json` (statement and signature), locked in compliance mode for `audit.retention_total`. `audit.checkpoint_set_worm` records the object key once. Copies that fail stay pending and are retried at the next close (`SaveCopies`, oldest first), so a store outage never blocks a close.
  - **Without a key.** Outside production, with no `FAIR_AUDIT_CHECKPOINT_KEYS_DIR`, the service logs a warning and does not checkpoint; production requires the key (T-05).
  - **Tests.** `TestAuditCheckpoints` covers segments with and without records, the event, a key rotation (the retired key refused for closes and re-registration), and verification of all signatures, links and segments with `internal/audit/integrity`. `TestAuditCheckpointCadence` runs the loop, empty segments included. `TestAuditCheckpointCloseRefusesForgeries` covers 26 forged or malformed statements (a retired key among them), malformed key registrations, the write-once key set once, and other roles refused. `TestAuditCheckpointWORMCopies` (with `FAIR_TEST_S3=1`) covers copies made after a store outage, their content, compliance retention and a refused delete.
  - **Mutation testing.** 14 of 15 mutants were caught; one test case was added for the second survivor (a key id that is neither the key's nor registered). The remaining survivor drops the record-count check in `checkpoint_close`, which is equivalent: the range comes from the head and the last checkpoint, and the sequencer assigns every record to the open segment, so the count cannot differ while the root and chain checks hold. The check stays as defence in depth.
- 2026-11-04: T-10 implementation notes (`internal/audit/evidence`, `cmd/audit-verify`):
  - **Formats.** `internal/audit/evidence` defines every evidence file, and holds the writers the audit service will use (T-15 exports, T-18 archives), so what the service writes is what the verifier reads:
    - a checkpoint, in a checkpoints file or as a write-once copy, is `{"statement", "signature"}` (both base64, `integrity.Checkpoint`);
    - a segment archive is gzip of JSON lines: a header with the format and the segment's checkpoint, then `{"seq", "leaf", "chain", "body"}` per record, the body inline with its exact bytes;
    - an export bundle is a ZIP whose canonical, signed `manifest.json` lists every other file's SHA-256 (nothing unlisted is allowed); proof lines are `{"seq", "segment", "path"}` in record order.
  - **Verification order.** For exports, digests are compared last, so a changed record is reported at its position rather than as a changed file. Records must be in strictly increasing sequence order.
  - **Positions.** Archives report the first failing record (changed, missing, out of order) or the segment (truncated, rehashed, swapped object, checkpoint not the trusted one). Exports report the first failing record or checkpoint. A record removed together with its proof line, or a truncated tail, cannot be placed (the manifest lists no sequence numbers), so it is reported as the count against the signed manifest.
  - **Anchoring.** A checkpoint run starting after segment 1 is anchored on its first statement's signature, and the tool says so. A segment whose previous checkpoint is not given is "insufficient input" (exit 2), not a failure.
  - **compare.** It reads a checkpoints file, a SIEM export (JSON lines of events; `audit.checkpoint` events' statement and signature attributes, other events skipped, repeats tolerated, conflicting repeats refused) or a directory of write-once copies (each must be named for its segment). It reports the first segment, from `-from` to `-to`, missing in one or both copies or with a different statement (naming the fields) or signature.
  - **No network.** `TestNoNetwork` holds the dependencies to the standard library plus `evidence` and `integrity`, with no `net/http`, `crypto/tls`, `os/exec` or similar. It builds the binary and checks its symbol table for anything that opens a socket (dialers, listeners, resolvers, socket system calls, TLS). `net` is linked only for `crypto/x509`'s address parsing.
  - **Shipping.** `scripts/audit-verify-dist.sh` builds six platforms (Linux, macOS and Windows; amd64 and arm64) with the FIPS module, plus `SHA256SUMS`; the release workflow's `audit-verify` job runs the tests and uploads them. The audit image carries `/fair-audit-verify`, so air-gapped bundles have it. `version` prints whether the FIPS module is on.
  - **Tests.** Tamper corpus for archives and exports: altered body (with and without recomputed hashes), removed record, reordered records, truncated tail, forged and removed checkpoints, swapped archive object, a changed manifest, added and missing files, replaced keys, pinning to the wrong keys, duplicate ZIP entries. `TestAuditEvidenceFromTheTrail` builds archives, an export and the SIEM comparison from a real trail (SQL sequencer and checkpointer, with a key rotation), and they verify. The guide for auditors is `docs/operations/audit-verification.md`.
  - **Mutation testing.** 22 mutants: 21 caught, after tests were added for four gaps the first run found (the manifest's instance, segment 1's genesis link, the PEM block type, strict fields). Two of the caught ones add a dialer or an HTTP client to the command, and `TestNoNetwork` fails on each. The survivor drops the export's "not in segment" check, which is equivalent: the inclusion proof refuses an index outside the segment. The check stays for its clearer message.
- 2026-11-05: T-11 implementation notes (migration 0073, `internal/audit/verify.go`):
  - **Who verifies.** The leader verifies in Go with the `integrity` primitives that fair-audit-verify uses. The database only hands over the raw trail through read-only definer functions (`audit.verify_head`, `verify_checkpoints`, `verify_records`, `verify_keys`, `verify_archives`), all read in one repeatable-read, read-only snapshot, so the head, the checkpoints and the records agree.
  - **Incremental (every 15 minutes).** It starts at the last checkpoint a passed run verified (`audit.verification_resume`), checks the new checkpoints (signatures, links, contiguity), each new segment's records (order, segment, leaf, chain, Merkle root), and the open segment up to the head. The last checkpoint must be the segment before the open one, the head's chain hash must match, and no record may lie beyond the head.
  - **Full (daily, and at start when the last one is older).** The same from segment 1, plus archived segments read from their recorded object version and digest (`audit.archive.version_id` is added now, NOT NULL; T-18 fills it), plus, with a WORM store, every version of every write-once copy. A copy must match the platform's checkpoint and be filed under its segment; a recorded copy must exist; a copy with no platform checkpoint means the trail was cut back.
  - **Outcomes.** An integrity failure is recorded with its first record or segment, opens or refreshes `audit_integrity` (`posture.audit_finding`, kind app, critical, AU-9 and AU-6), and emits `audit.verification_failed` (critical) on every failed run. The SaaS SecOps alert is queued only when the finding opens. A passed full run resolves the finding and emits `audit.verification_recovered` (high); incremental passes never resolve it. A run that cannot finish for an operational reason (the database or a store unreachable, archives without a store) is not a verdict: it stays unfinished, and the tile turns overdue if that persists.
  - **Status.** `audit.status()` (granted to `app_posture`) reports the state (`never`, `failed` until a full run passes, `overdue` after 30 minutes without a passed run or 26 hours without a passed full run, `ok`), the last run and last full run, what was verified through, the head, events waiting in intake, checkpoints waiting for their copy, and destinations (filled by T-16 and T-17; storage by T-20). The Posture API serves it at `GET /audit-trail` (`posture.view`), and the Posture page has an Audit trail section; the finding also appears under Drift findings and against AU-9 and AU-6 in the per-control status.
  - **Service.** The leader runs the sequencer, the checkpointer and the verifier together (`runAll`): if one stops, all stop and the leader retries.
  - **Tests.** `TestAuditVerification` (full and incremental ranges, an empty incremental, overdue, other roles refused), `TestAuditVerificationFindsTampering` (thirteen superuser changes, each at its first position: altered bodies in closed and open segments, a body with its leaf rehashed, a stored leaf hash changed alone, a removed record, a truncated tail, the head moved back, a record added past the head, the newest checkpoint removed, a changed statement, a record moved to another segment, a swapped signing key, a key under another id), `TestAuditVerificationEmptyCheckpointRemoved`, `TestAuditVerificationSignedButWrong` (a checkpoint signed by a registered key whose root or chain hash does not match its records), `TestAuditVerificationRecovery` (SaaS alert once, an event per failed run, incremental passes do not resolve, a full pass does), `TestAuditVerificationBookkeeping`, `TestAuditVerificationRun`, `TestAuditVerificationCopiesAndArchives` (S3: archives by version and digest, write-once copies missing, overwritten by a new version, or beyond the platform's checkpoints), `TestPostureAPIAuditTrail`, and a Playwright and axe test of the tile.
  - **Mutation testing.** 28 mutants: 26 caught, after tests were added for the gaps the first run found (an empty segment's checkpoint removed, a record past the head, a leaf hash changed alone, a misfiled write-once copy, a key under another id, and checkpoints signed by a valid key that do not match their records). Two survivors are equivalent: dropping the check that the incremental run's first checkpoint is the last verified one (its absence fails the same segment as missing), and resuming from any run with a verified segment (only passed runs have one; `verification_end` enforces it).
- 2026-11-05: T-12 decision (Robert Former): the search benchmark runs at 10 million records over 12 monthly partitions on the F-001 target-scale tree (2,011 BUs). The NFR's ceiling (200 events/s for 12 months, about 6 billion records) cannot be generated in CI; the benchmark checks that every filter is served by an index, so latency does not grow with volume.
- 2026-11-05: T-12 implementation notes (migration 0074, `internal/auditapi`, contract `api/openapi/audit.yaml`):
  - **Read functions.** `audit.search`, `history`, `request`, `record_proof`, `checkpoints` and `keys`, granted to `app_audit`. They share `audit.read_records`, which takes the caller from the signed DB context and admits a record only when its `bu_id` is in the caller's `audit` read scope, in the smaller of the two scope forms (ADR-007 amendment 1). Restricted BUs need an assignment there, and records filed under the root need `audit.view` at the root (AC-19). A missing, invalid or stale context sees nothing.
  - **Filters.** `from`, `to` (event time), `type`, `category`, `severity`, `actor`, `target`, `bu`, `request_id` and `source_ip` (an address or CIDR range) combine with AND. Unknown keys and malformed values raise PF004 (400). The statement is built per call with only the filters given, so each runs with a plan for its filters. New indexes `(type, seq)`, `(category, seq)`, `(severity, seq)`, `(actor, seq)`, `(target, seq)`, `(bu_id, seq)` and `(request_id, seq)`, plus a GiST index on `source_ip`, serve a filter and the order together.
  - **Order.** Search is newest first with a `before` cursor. History (by target or actor) and request views are in order, oldest first, with an `after` cursor.
  - **Integrity and names (AC-18).** Each row carries `integrity`: `failed` at or after the first position a failed run named since the last passed full run, `verified` up to the last passed run, otherwise `pending`. It also carries `names`, the current display names of the users it names (`actor`, and `approved_by` and `decided_by` attributes). `iam.user_display_names` is granted to `audit_definer` only, not to `app_audit` as §5 suggested, so names are reachable only through the read functions and only for visible records.
  - **Proofs.** `GET /records/{seq}` returns the record and, once its segment is closed, its leaf hash, RFC 9162 path, tree size and the signed checkpoint. The path is computed in the service from the segment's leaves (`audit.record_proof`).
  - **Who may read what.** Every route needs `audit.view` at some BU (else 404). Checkpoints and keys go to any holder, since they carry no record content (`audit.can_read`). `/status` needs `audit.view` at the root. Unseen records, and requests with nothing visible, answer 404 like ones that do not exist.
  - **Reads are recorded (AC-20).** Every read, including a 404, records `audit.searched` (view `records`, `record`, `request`, `checkpoints`, `keys` or `status`) or `audit.history_viewed` (category `access`, severity low), with the filter and the result count, in the read's own transaction. A read that cannot be recorded is answered 503 without data.
  - **Service and gateway.** The audit service serves the API on every replica (`FAIR_JWT_KEYS_DIR`; grants from `authz.Cache` over `grant_snapshot`, now granted to `app_audit`; scope changes over NATS when `FAIR_NATS_URL` is set). The gateway routes `/api/v1/audit/` to an upstream named `audit` in `FAIR_UPSTREAMS`. The audit manifest's egress gains NATS and object storage; the object-storage rule was missing since T-09.
  - **Benchmark.** `TestBenchmarkGateAuditSearch` (CI bench job, now 60 minutes) loads 10 million records in about 6 minutes. p95 at 10 million, budget 2 s: newest with no filter 6 ms; type, category, severity, actor, target, request, source range, type plus actor, and a deep page 10 to 13 ms; one month 14 ms; an auditor of one BU of 2,011: 2 to 33 ms.
  - **Tests.** `TestAuditReadVisibility` (root, BU and restricted-BU auditors; one request across BUs; 404s; status at the root only; the functions without a context), `TestAuditReadFilters` (each filter, combinations, both cursors, refused requests, current display names of actor and approver), `TestAuditReadsAreRecorded` (each view, a 404 read included, and 503 when the trail is down), `TestAuditReadIntegrityAndProof` (pending, verified, failed; a proof verified with the integrity primitives against the signed checkpoint).
  - **Mutation testing.** 27 mutants (visibility in both scope forms, each filter, cursors, integrity, names, proofs, the API's checks and recording): all caught, after tests were added for the four gaps the first run found (an unknown filter refused by the function itself, `from` and `category` cases that change the result, and checkpoints and keys withheld from a context without `audit.view`).
- 2026-11-05: T-13 decision (Robert Former): the trail stamps `approval_id`, rather than each producer setting it. Every feature that consumes approvals is covered, later ones included, without rewriting each consuming function.
- 2026-11-05: T-13 implementation notes (migration 0075, `GET /approvals/{id}`):
  - **The stamp (§3).** `iam.consume_approval` marks its transaction with the approval it used (the transaction-local setting `audit.approval_id`). `audit.submit` adds `approval_id` to each later event of that transaction that does not name one itself. It does so only after `iam.approval_consumed_here` confirms that this transaction consumed the approval (`consumed_at` equals the transaction's start time), so a producer that sets the marker by hand gains nothing. When one transaction consumes several approvals (a profile switch and its conflicts' exceptions), each later event names the approval consumed most recently before it. Events from SQL and from Go (`audit.WithTx`) are stamped alike; events emitted outside the consuming transaction are not.
  - **A reserved attribute.** `approval_id` is reserved like `event_id` (`pkg/audit.ReservedAttributes`; `audit.submit`): it is allowed on every type, and catalog entries no longer list it. Producers may still set it, for example `setting.change_requested` names the approval the request opened, and a value they set is kept.
  - **Approval events by BU.** `iam.approval_audit` now files approval events (requested, approved, rejected, expired, consumed) under the request's BU, so an auditor of that BU sees the whole approval (AC-19). Requests without a BU stay under the root.
  - **Evidence (AC-35).** `audit.approval_evidence(id, after, limit)` returns one approval's visible records in order: its own events (target `approval:<id>`) and every record naming it (`approval_id`). `read_records` gains an `approval_id` filter (not exposed on `/records`) and resolves `requested_by` among the names. `GET /approvals/{id}` returns the approval's kind, target, status and both parties (id and current display name) from its latest event, its `request`, `decision` and `applied` records, and the other records naming it (`changes`), with an `after` cursor. An unknown, malformed or invisible id answers 404. The read records `audit.searched` (view `approval`, target `audit:approval:<id>`, so the evidence never lists its own reads). The export side of AC-35 comes with T-15, whose filters can select an approval's records the same way.
  - **Tests.** `TestAuditApprovalEvidence` covers F-001's un-restriction of a BU: a stamped and a kept value in the applying transaction, forged markers ignored, approval events under the request's BU, the full view for root and BU auditors, paging, a pending approval, 404s, and recorded reads. `TestAuditApprovalEvidencePosture` covers F-015's out-of-bounds change: the request, the decision, the use, and the exception it created, with everything recorded after the use naming the approval.
  - **Mutation testing.** 19 mutants (the marker, the same-transaction check, keeping a producer's value, the reserved attribute, approval events' BU, the filter, names, both halves of the evidence, and the API's id checks, classification, paging, parties and recording): all caught, after a test was added for the one gap the first run found (the use event matches both the target and `approval_id`, and the API's classification hid the duplicate; the function is now checked directly).
- 2026-11-05: T-14 decision (Robert Former): the export and hold actions move to T-15 and T-19, where their APIs (`POST /exports`, `/holds`) arrive and can be tested end to end (tasks.md amended).
- 2026-11-05: T-14 implementation notes (`web/src/audit`):
  - **One route, `/audit`.** The query chooses the view. `?target=` and `?actor=` open the history, oldest first (AC-16; the Posture page's existing `auditHref` links, AC-37). `?request=` is the request view (AC-17), `?approval=` the approval evidence (AC-35), and `?record=` one record with its proof. Otherwise the page shows search, newest first, with the filters as `?view=search&...` (AC-15). Times are entered in the browser's zone and sent as RFC 3339. Every view pages with the API's cursors.
  - **What each record shows (AC-18).** Each row shows the record's position (a link to its proof), time in UTC, type and severity, the actor's current display name beside the id, the target (a link to its history), its request and approval (links), and its integrity as text (Verified, Pending, Failed), with a legend. The record view adds every field, the attributes (users by name), the body as recorded, and the RFC 9162 proof with the signed checkpoint statement, or says that the segment is still open.
  - **Access.** Without `audit.view` the search and history views say so (the API is 404). Unseen requests, approvals and records answer "Not found, or not visible to you".
  - **Serving the app's routes.** The gateway served `FAIR_UI_DIR` with a plain file server, so app routes (`/posture`, and now `/audit`) were 404 outside the UI harness. `gateway.StaticUI` serves files as they are and `index.html` for any other path; a missing `/assets/` file stays 404 (`TestStaticUI`). The primary navigation gains "Audit trail".
  - **Harness.** `TestPostureUIHarness` now records the posture scenario's setting events to the trail, serves the Audit API as upstream `audit`, adds more than a page of records and one request recorded by two services, and alters the closed segment's last record (not record 2), so the earlier posture records stay verified.
  - **Tests.** `web/e2e/audit.spec.ts`, with axe WCAG 2.1 AA on every view (AC-21): Posture links to history and an actor's activity and back; approval evidence with both parties; a record and its proof; search order, paging, time and target filters, a combined filter, and a refused filter; a request across two services with integrity after a failed verification; no access.
  - **Mutation testing.** 10 UI mutants (view choice, names, integrity labels, no-access, paging, parties, the applied step, time conversion, target links, history by actor): all caught, after tests were added for the three gaps the first run found (paging, the time filter, and following a target link).
- 2026-11-05: T-15 decisions (Robert Former):
  - **Archived ranges move to T-18.** Nothing is archived before T-18, which adds reading archived segment objects into exports and tests it with real archives (tasks.md amended; §6.6 step 4 lands there).
  - **One audit store.** `FAIR_AUDIT_STORE_*` (an Object Lock bucket through `internal/objstore`) holds export bundles now and archives from T-18. It is required in production in every mode (`audit.CheckInstall`, `TestDeploymentModeMatrix`); in SaaS it may be the WORM bucket.
  - **River in its own schema.** `db/rivergen` gains `-schema`, `-role` and `-task`; migrations 0076 and 0077 put River in schema `audit_river`, granted to `app_audit` only, so the audit service cannot see or change iam's jobs and iam cannot see its.
- 2026-11-05: T-15 implementation notes (migrations 0076 to 0078, `internal/audit/export.go`, `exportjob.go`, `internal/audit/evidence/exportwriter.go`, `internal/auditapi/exports.go`):
  - **Request (AC-33).** `POST /exports` (`audit.export`; 403 without it, 404 without `audit.view`; Idempotency-Key, `audit.idempotency`) runs `audit.export_request` in the caller's DB context and queues the River job in the same transaction. The scope is captured then: the BUs in the caller's audit read scope (`authz.visible_bus`, so restricted BUs and roll-up modes count exactly as in search) where one of their assignments grants `audit.export` (`iam.grants_within`, which follows the grant across restricted boundaries only within that already-visible set). Granting more later does not widen an export. A filter, format or reason the database refuses is 400.
  - **Shared filters.** `audit.filter_conditions` validates a filter and returns its conditions; `audit.read_records` (search, history, request, approval views) and `audit.export_rows` both use it, so an export matches exactly what the same search shows.
  - **The job (§6.6).** `audit.Exporter.Run` closes a segment with the checkpointer (the export ends at a fresh signed checkpoint), reads the matching records with the captured scope in batches of 10,000 up to that checkpoint, builds each closed segment's tree once (`audit.segment_leaves`) for the Merkle paths, and writes the bundle with `evidence.ExportWriter`. That writer streams the records into the ZIP and spools the proofs (and CSV bodies) to temporary files; it writes what `WriteExport` writes (`TestExportWriter`). The bundle is spooled to `TMPDIR`, stored with `PutStream` under `exports/<instance>/<id>.zip` (locked 30 days), then `audit.export_complete` and `audit.exported` (high: filter, record count, digest, closing checkpoint, format, scope size; actor the requester, their reason) commit together. River retries five times; the last failure marks the export failed and records `audit.exported` with status `failed`.
  - **The manifest (AC-33).** It states the filter as data and in words (`audit.DescribeFilter`), the requester, reason, BU scope, closing checkpoint and file digests. The CSV view (`audit.ExportCSVHeader`) guards spreadsheet formulas; `bodies.jsonl` is what verifies.
  - **Reading and downloading.** `GET /exports/{id}` (recorded as `audit.searched`, view `export`) and `/bundle` are for the requester or a holder of `audit.export` at the root; the download records `audit.export_fetched` before any byte is sent and carries `Content-Digest`. A pending or failed export is 409.
  - **UI.** The search page gains an Export section: format, reason, a status region that follows the export, then the download link and the bundle's SHA-256. A refusal is reported.
  - **Throughput.** `TestBenchmarkGateAuditExport` (bench job): 1,000,000 records over 21 segments, filed under the 1,949 BUs a root auditor sees in the target-scale tree, exported in 10 s (budget 5 minutes); the 113 MiB bundle verifies.
  - **Tests.** `db/tests/audit_export_test.go` and `audit_export_scope_test.go`: the bundle verifies pinned to the trail's keys, records and order, manifest filter and scope, the closing checkpoint, `audit.exported` and `audit.export_fetched`; CSV; scope captured at request, per-BU and restricted-BU auditors, a restricted BU rolled up in `full` mode (search and export agree), who may read and download, refusals, idempotent retries; failure and retry; records sequenced into the open segment; the River job end to end (and schema isolation); the S3 store (`FAIR_TEST_S3`). `web/e2e/audit.spec.ts`: the export by keyboard with axe (its record count equals what the same search shows; the ZIP holds the chosen format), and a refused export.
  - **Mutation testing.** 29 mutants (SQL scope, bounds, visibility and completion; the job's checkpoint, paths, retries and events; the API's refusals and download record; the streaming writer; the UI's polling, filter, format, reason and errors). 28 were caught by the DB, unit and UI tests, after tests were added for the three that survived the first run: completing a ready export again, a record added twice to the writer, and the job's retry path (`audit.RunExportAttempt`). The remaining one, reading only the first batch of 10,000 records, needs more matching records than the regular tests hold; the benchmark gate's count check covers it.
- 2026-11-05: T-16 decisions (Robert Former):
  - **Where forwarding starts.** A destination configured for the first time, or again after being cleared, receives the whole online trail from its oldest record (AC-22: every record). A changed address keeps the cursor, so a moved or renamed SIEM endpoint gets no duplicates.
  - **Per-service syslog retired.** `audit.FromEnv` refuses `FAIR_AUDIT_SYSLOG_ADDR` in every service (fail closed: nobody silently loses a feed they configured). The destination is the setting `audit.syslog_destination`; `FAIR_AUDIT_SYSLOG_CA_FILE` and `FAIR_AUDIT_SYSLOG_PLAINTEXT` (development only) moved to the audit service.
  - **PEN.** `fair@32473`, the RFC 5612 documentation number, until one is registered (§15).
- 2026-11-05: T-16 implementation notes (migration 0079, `internal/audit/forward.go`):
  - **Destination rows.** `audit.destination` gains `address` and `backlog_alerted`. `audit.forward_destination` creates or re-adds a destination at the start of the online trail and keeps the cursor on an address change; `forward_clear` stops it when the setting is cleared (the row stays, address NULL); `forward_advance` moves the cursor forward only and never past the head; `forward_error` records the last failure; `forward_backlog` and `forward_set_alert` drive the alert. `audit.status` adds each destination's address, oldest waiting record and alert.
  - **The forwarder.** `audit.SyslogForwarder` runs on the leader every 5 seconds, and batch after batch (1,000 records) while there is a backlog. It reads the destination through the settings client, records through `audit.verify_records`, and sends each as RFC 5424 with octet counting over TLS 1.2 or later (`audit.SyslogTLS`): facility 10, severity, time and type (MSGID) from the body, APP-NAME `fair-audit`, structured data `[fair@32473 seq chain segment]`, and the body exactly as recorded as MSG. The SIEM's copy of `audit.checkpoint` records is therefore what `fair-audit-verify compare` reads (tested).
  - **Delivery.** Syslog has no acknowledgement, and a write onto a connection the receiver has already closed can still succeed. The first implementation advanced the cursor past such a write and lost a record (found by the outage test). Now a stale connection is replaced before each batch, the batch is one write, and the cursor advances only when the write succeeded and the connection is still up afterwards (a short read probe sees the reset). Otherwise the whole batch is sent again: at least once, in order, never lost.
  - **Backlog (AC-23).** Before and after each batch, waiting records over `audit.forward_backlog_records`, or an oldest waiting record older than `audit.forward_backlog_age`, raises the alert once and records `audit.forward_backlog` (high: address, waiting, oldest, thresholds, last error); back under both clears it once with `audit.forward_recovered`. The Posture page's Audit trail tile shows each destination's address, backlog, "Over threshold", oldest waiting record, last send and last error.
  - **F-001's AU-12 statement.** It cited per-service syslog and its test; it now describes the trail and the audit service's forwarder (`compliance/statements/F-001.yaml`, marked as amended pending re-sign-off).
  - **Air-gapped.** The destination must be internal (`scanner.InternalOnly`); others are refused before anything is sent. The audit egress policy allows 6514.
  - **Tests.** `db/tests/audit_forward_test.go` against an in-process syslog-over-TLS receiver: every record in order with its seq, chain and segment and exact body; an outage queues and resumes in order with nothing lost; the cursor only moves forward; checkpoints round-trip to `compare`; the alert once per crossing by count and by age, and the recovery once; TLS 1.1 refused, a malformed or refused destination gets nothing; the destination through F-015 (set: whole trail; moved: cursor kept; cleared: pending until a second approver, then stopped; set again: whole trail). `internal/audit/forward_test.go`: framing, TLS floor, plain TCP only in development. `pkg/audit`: `FAIR_AUDIT_SYSLOG_ADDR` refuses. `web/e2e/posture.spec.ts`: the tile shows a down destination over threshold.
  - **Mutation testing.** 21 mutants (where a destination starts, re-adding and moving, the cursor's bounds, clearing; the two connection checks, the alert thresholds and guards, framing, the air-gapped check, the TLS floor, plain TCP, the retired variable; the tile). All are caught, after tests were added for the five that survived the first run: a receiver that drops the connection before reading the batch (the check after the batch), a receiver restart between batches that must send cleanly with no recorded error (the check before it), and the address cell on the tile. The two alert guards each cover the other; removing both is caught.
- 2026-11-05: T-17 decision (Robert Former): the OTLP client comes from `go.opentelemetry.io/proto/otlp/collector/logs/v1` as published. That package also holds generated grpc-gateway code, so `github.com/grpc-ecosystem/grpc-gateway/v2` and `google.golang.org/genproto/googleapis/api` become indirect dependencies, unused by the audit service; generating a stub of our own was the alternative. The module requires gRPC v1.84.0 (from v1.83.2).
- 2026-11-05: T-17 implementation notes (`internal/audit/otlp.go`; `forward.go` refactored):
  - **One forwarder, two transports.** T-16's `SyslogForwarder` becomes `audit.Forwarder` (destination row, cursor, backlog alert, air-gapped check, the same semantics for both kinds) with a `Transport`: `SyslogTransport` (T-16's framing and connection checks) and `OTLPTransport`. The audit service runs one forwarder per destination on the leader; each keeps its own cursor (`syslog`, `otlp` rows).
  - **OTLP.** One `ExportLogsServiceRequest` per batch over gRPC with TLS 1.2 or later (`audit.OTLPTLS`: `FAIR_AUDIT_OTLP_CA_FILE`; `FAIR_AUDIT_OTLP_PLAINTEXT` in development only). Resource `service.name` fair-audit and `host.name`; scope `fair-audit-trail`; per record a log record whose body is the record exactly as recorded, its event time, observed time, severity (info INFO, low INFO4, high WARN, critical ERROR, and the text), `event_name` the type, and the attributes `fair.seq`, `fair.chain`, `fair.segment`.
  - **Acknowledgement.** The export response is the acknowledgement: a batch counts only when the export succeeds and the receiver rejects none of it (partial success); otherwise the whole batch is sent again. A failed export drops the gRPC client, so its reconnection backoff does not fail the next attempt after an outage.
  - **Deployment.** The audit egress policy allows 4317; the CA variable is in `deploy/k8s/audit.yaml`. The Posture tile lists the OTLP destination with the syslog one.
  - **Tests.** `db/tests/audit_otlp_test.go` against an in-process OTLP receiver over TLS: every record in order with its attributes and exact body, batches of the configured size, the resource and scope; an outage queues and resumes in order; a refused export (Unavailable) and a partial rejection leave the cursor and send the batch again; TLS 1.1 refused; syslog and OTLP keep separate cursors. `internal/audit/forward_test.go`: `OTLPTLS`, `OTLPRequest`. T-16's tests run unchanged against `SyslogTransport`. `internal/audit/otlp_test.go`: the client's ClientHello offers nothing below TLS 1.2.
  - **Mutation testing.** 16 mutants (partial rejection, dropping the client after a failure, reconnecting on a move, the TLS floor, every record field and the resource and scope, the severity map, the kind, the CA variables, ignoring a failed send). All are caught, after a test was added for a moved OTLP destination, except one: a client configured for TLS 1.0. Under the FIPS 140 module (`GOFIPS140`, mandatory, ADR-006) Go's TLS offers 1.2 or later regardless, so that mutant changes nothing in our builds; the ClientHello test catches it in a build without the module.
- 2026-11-05: T-18 implementation notes (migration 0080, `internal/audit/archive.go`; exports in `export.go`):
  - **What is due.** `audit.archive_candidates`: closed segments with records whose newest event time is older than `audit.retention_online` (now less the setting), oldest first. Segments without records are not archived: there is nothing to move, and their checkpoints stay.
  - **The archiver.** `audit.Archiver` runs on the leader at start and daily, on the audit store. For each due segment it first checks the segment against its signed checkpoint (a segment that does not verify is never archived, so never deleted; the verifier reports it). It then writes `segments/<instance>/<n>.jsonl.gz` (`evidence.WriteSegment`: the signed checkpoint, then every record's exact body with its leaf and chain hashes), locked in compliance mode until `destroy_after` = now + (total − online), with the total at least the online retention and the lock at least a day. It reads the object back: its digest must be that of the bytes written (the same bytes that were checked against the checkpoint; nothing bad is ever written, so nothing bad is locked for years). Only then does `audit.archive_segment` record the archive and delete the segment's rows (under the transaction-local `audit.archiving` flag; the count must be the segment's), in the transaction that records `audit.records_archived` (segment, range, count, object, version, digest, destroy_after). A failure at any step removes nothing.
  - **After archiving.** The records are gone from search, history and the record view. Full verification reads the archive by its recorded version (`Verifier.Archive`, now an interface, given the audit store); without it a full run cannot finish.
  - **Exports (moved here from T-15).** `audit.export_archives` lists the live archives up to the export's checkpoint. The exporter merges each archived segment in before the online records that follow it, so the bundle stays in sequence order. It reads the object by version, checks the recorded digest before parsing, builds the tree from the archive's leaf hashes, and has the database pick the records the export includes (`audit.export_archived`: `audit.record_from_body` derives the columns the sequencer derives, then the export's own filter conditions and captured scope apply). `skew` depended on the setting at sequencing time and is not in a body, so archived records have it empty in the CSV. The manifest's description now says "online or archived".
  - **Tests.** `db/tests/audit_archive_test.go`: nothing before the online retention ends; a due segment is archived, locked until destroy_after, holds the signed checkpoint and every record; its records leave search and the record view; full verification passes from the archive and cannot finish without it; exports across the archive in order, as CSV, in a per-BU auditor's scope; a changed archive is not exported; nothing is archived twice; a failed upload, a bad read-back and an altered segment remove nothing; `audit.archive_segment` refuses a wrong count, a past destruction time, an unclosed or already archived segment and other roles. `TestAuditArchiveS3`: compliance lock until destroy_after, the archive cannot be deleted, full verification from the store.
  - **Mutation testing.** 17 mutants (when a segment is due, the database guards, the export's scope and bounds over archives, the derived columns, the checks before writing and after reading back, the lock, the merge order and proofs). The first run found three gaps, now tested: rows removed behind the database's back (the segment-size check), a segment that does not verify must not be written at all, and a segment an hour before its online retention ends. It also showed that verifying the read-back records again was redundant once the digest matches, so that check was removed. Two survivors are equivalent guards kept as defence in depth: candidates exclude archived segments (they have no rows left), and an export's archives are bounded by its checkpoint (archives are always older).
- 2026-11-05: T-19 decisions (Robert Former):
  - **AC-28 gap fixed here.** Shortening either retention below the profile's value but within its bound applied at once; AC-28 asks for an explanation, a warning, a second approver and a high-severity event. Both retention bindings now set `loosening_needs_approval` (as the SIEM destinations do since T-04): any shortening needs a second approver and is then applied as a change, not an exception. The profile packages are rebuilt at 1.3.0.
  - **Holds are instance-wide.** Placing, listing and releasing a hold needs `audit.hold` at the root; a hold's filter covers the whole trail.
  - **Holds cover later records** matching their filter until released.
  - **Hold UI: place, list, release.** Platform Admins hold `audit.hold` but not `audit.view`, so the holds have their own page, `/audit/holds`, which the search page links to with its applied filters (rather than a section of the search page, which those users cannot open).
- 2026-11-05: T-19 implementation notes (migration 0081, `internal/audit/retain.go`, `internal/auditapi/holds.go`, `web/src/audit/HoldsPage.tsx`):
  - **Permission catalog version 2.** `audit.hold` (action `admin`, privileged) is added for Platform Admin only (`permission-catalog.md` amended; its rows may name a later catalog version). Tests that simulate later releases number them relative to the shipped catalog.
  - **Placing and releasing (AC-29).** `POST /holds` and `POST /holds/{id}/release` (Idempotency-Key, a reason of up to 1,000 characters; 403 for other users of the Audit API, 404 for the rest) run `audit.hold_place` / `audit.hold_release` in the caller's DB context and record `audit.hold_placed` / `audit.hold_released` (high, with the reason) in the same transaction. `GET /holds` lists every hold with its segment count and the people's names.
  - **What a hold covers.** `audit.hold_place` marks the closed online segments with matching records at once (`audit.hold_segment`). `audit.archive_segment` (replaced) marks a segment held by every active hold its records match before they leave the database, so later records are held too; it also records the segment's newest event time. Archived segments are checked by the audit service (`audit.hold_match_archived` over each archive's bodies, with the search's filter conditions), after which the hold is marked checked; until every active hold is checked, nothing is destroyed.
  - **S3 legal holds.** `audit.legal_hold_drift` lists archives whose legal hold differs from what the active holds say; the service sets or clears it on the object and records it (`archive.legal_hold`).
  - **Destruction (AC-27).** `audit.Retainer` (leader, hourly) destroys an archive only when its lock has ended (`destroy_after`), its newest record is older than the total retention in force (a longer retention keeps it longer; shortening never shortens a lock) and no active hold covers it. `audit.destroy_segment` re-checks all of that and records the destruction in the transaction that records `audit.records_destroyed` (high); the object is deleted afterwards and retried until it is gone (`object_removed_at`). Checkpoints are kept: full verification passes after destruction, starting from the first retained record.
  - **Tests.** `db/tests/audit_hold_test.go`: who may place, list and release; refusals; the events; held segments, later matching records included, survive past their lock and total retention while an unheld one is destroyed and recorded; verification passes after each destruction; release clears the legal holds and the segments are destroyed; a hold placed after archiving covers matching archives once checked and blocks all destruction until then; the database refuses to destroy a held segment; neither a shorter retention before the lock ends nor a longer one after it destroys; `TestAuditHoldS3` sets and clears real legal holds and the lock still refuses deletion. `audit_settings_test.go`: shortening either retention needs an explanation and a second approver. `web/e2e/audit.spec.ts`: the search page's link, no access without `audit.hold`, placing by keyboard, the list, releasing in a dialog, with axe.
  - **Mutation testing.** 22 mutants (who may hold; what a hold covers online, at archive time and in archives; each destruction condition; the legal-hold sync; release; the service's retention, deletion and digest check; the API's refusals; the AC-28 approval; the UI's reason, reload and filter). 21 are caught, after tests were added for the four gaps the first run found: a closed segment without matching records must not be held, a later matching record must be held by archiving itself (the hold already checked), a destroyed object must be gone from the store, and a changed archive must stop a hold's check. The survivor is the API's own filter check, which the database repeats (400 either way).
- 2026-11-05: T-20 decisions (Robert Former):
  - **The quota is a hard limit.** At 100% the trail is full: `audit.intake` refuses events (PF015), so every operation that would record one fails in its own transaction and nothing is dropped (AC-31). The audit service's own events (checkpoints, verification, capacity, reads of the trail) are still accepted, so the integrity machinery keeps running while the trail is full.
  - **`FAIR_AUDIT_STORAGE_QUOTA` is required in production** in every mode (`audit.CheckInstall`; sizes such as `200GiB`, `audit.ParseSize`); a malformed value is refused anywhere. Outside production, without it, capacity is not measured (a warning at startup).
- 2026-11-05: T-20 implementation notes (migration 0082, `internal/audit/capacity.go`):
  - **Measuring.** `audit.CapacityMonitor` (leader, every 5 minutes) calls `audit.capacity_measure`: the sum of `pg_total_relation_size` over every table and partition in schema `audit` (indexes and TOAST included; intake too) against the quota, recorded in `audit.capacity` with a level: ok below 75%, warning, critical from 90%, full from 100%.
  - **Alerts (AC-30).** A rise to warning records `audit.capacity_warning` (high); to critical or full, `audit.capacity_critical` (critical, with the level); once per rise, in the measuring transaction. The Posture finding `audit_capacity` (`posture.audit_capacity_finding`; AU-4, AU-5) follows the level: high at warning, critical above, resolved below 75%.
  - **Fail closed (AC-31).** A `BEFORE INSERT` trigger on `audit.intake` (`audit.refuse_when_full`) raises PF015 while the level is full, for every producer but `app_audit`.
  - **Posture page.** `audit.status()` reports `storage` (quota, used, percent, level, measured time); the Audit trail tile shows it, with a warning paragraph from 75%.
  - **Tests.** `db/tests/audit_capacity_test.go` with quotas set from the measured use: ok, the warning once per rise with the finding at high severity, critical with the finding critical, full refusing every other producer's event (SQL and Go producers, nothing written to intake) while the audit service's own events are recorded, the status, and recovery (events accepted, finding resolved). `internal/audit`: `ParseSize`, the quota in `CheckInstall`; `TestDeploymentModeMatrix` includes it. `web/e2e/posture.spec.ts`: the tile shows a storage warning.
  - **Mutation testing.** 11 mutants (each threshold, the percentage, the audit service's exemption, the refusal itself, the finding's severity and resolution, recording once per rise, the critical event, a size unit, the production requirement): all caught.
- 2026-11-05: T-21 implementation notes (`db/tests/stride_f002_test.go`, `strideF002` in `db/tests/stride_test.go`, `Makefile`):
  - **The STRIDE suite.** `TestSTRIDECatalog` now reads §8 too and requires tests for each of its nine rows, every one run by `make test-stride` (which now also tests `internal/audit/integrity` and `internal/audit/evidence`). Most mitigations were already attacked by earlier tests (append-only triggers and grants, verification finding tampering, forged checkpoints, the SIEM and write-once copies with `compare`, archive digests and tamper corpora, scope-filtered reads and exports, recorded reads, exports and holds, capacity and backlog alerts). Four new attack tests cover the gaps: `TestSTRIDEF002ProducerSpoofing` (a body cannot name its producer or receipt time; the recorded producer is always the submitting role; no role writes intake), `TestSTRIDEF002NameLeak` (a per-BU auditor gets no names, or records, of a user who appears only in a restricted BU; `iam.user_display_names` is closed to the application roles), `TestSTRIDEF002ServiceDown` (with no sequencer, 200 events from three producers wait in intake and are then recorded in submission order, none lost) and `TestSTRIDEF002HoldPrivilege` (`audit.hold` is privileged, only Platform Admin holds it, the hold functions are closed to other roles).
  - **Deployment modes.** The rule that air-gapped installs forward inside the enclave only moved from `cmd/audit` to `audit.DestinationCheck(mode, lookup)`, which `TestDeploymentModeMatrix` checks per mode (internal addresses and names accepted, public ones and unresolvable names refused in air-gapped mode; no check otherwise). SaaS requiring the write-once bucket was already in the matrix (T-05). Mutating the rule (no check in air-gapped mode, or always passing) fails the matrix.
- 2026-11-06: T-22 implementation notes (migration 0083; F-015 design change log; `compliance/statements/F-001.yaml`, `F-015.yaml`):
  - **F-015's deferred items.** "Every step goes to the hash-chained audit" holds since T-06. "Expiry is checked against the audit trail" is now a drift check: `audit.exception_expiries` (granted to `posture_definer`) gives each exception's latest recorded expiry, and `posture.drift_scan` reports `exception_expiry_mismatch` (critical) when the exception row differs, at whole seconds as the events record it. It catches an extension even with a valid row MAC (someone acting as `posture_definer`); exceptions without an online record are not compared. The posture drift engine owns the new check (`posture.CheckExpiryTrail`).
  - **Statements.** F-001 AU-2 (the catalog is enforced by the trail) and AU-12 (OTLP, the trail's producers), and F-015 AU-6 (the trail and its pages, the expiry check), each marked as amended pending re-sign-off; every test they name passes and `internal/compliance` passes.
  - **Tests.** `db/tests:TestDriftExceptionExpiryAgainstTrail` (an extension re-signed as `posture_definer` opens the finding; restoring it resolves it; no record, no comparison); F-015's STRIDE rows now name it and `TestAuditApprovalEvidencePosture`. Mutants that never report a mismatch, or compare without the whole-second truncation (which reports every valid exception), both fail it.
- 2026-11-06: T-23 statements drafted (`compliance/statements/F-002.yaml`, status `draft`): one statement for each of the 18 mapped controls, with responsibility per deployment mode, what the customer does where it is shared, and the code and tests that back it. `internal/compliance` checks them (`TestF002Statements`: the controls are exactly the mapping, every path and test exists, the OSCAL output validates and is deterministic) and builds one component definition from F-001, F-002 and F-015. The task is done when Robert Former signs them off.
- 2026-11-06: T-23 statements signed off by Robert Former (`compliance/statements/F-002.yaml` status `approved`). F-002 is complete.
- 2026-11-06: Robert Former re-signed the amendments made during F-002: F-001 AU-2 and AU-12, F-015 AU-6, and the F-001 permission catalog version 2.
