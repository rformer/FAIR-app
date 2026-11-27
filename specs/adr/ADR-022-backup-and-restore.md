# ADR-022 Backup and restore: point-in-time PostgreSQL through our CloudNativePG plugin, object copies keeping retention, separate key snapshots, a declared restore gap
Status: Accepted (Robert Former, 2026-11-26; F-014 T-03, with the F-014 design approved 2026-11-26)
Date: 2026-11-26

## Context
ADR-005 promises a documented backup and restore for self-hosted installations. F-014 R-06 requires backups the customer holds the key to, and restores proven before use (AC-35 to AC-42). The requirements fixed the scope:
- **OQ11:** for bundled dependencies, continuous WAL archiving plus base backups of PostgreSQL for point-in-time recovery, object copies keeping Object Lock, key store snapshots, consistent at a recorded point in time; for brought dependencies, the customer's own backups to documented requirements, verified on restore the same way. NATS JetStream is not backed up: its streams carry notices derived from database outboxes and are re-provisioned. An upgrade requires a verified backup no older than 24 hours.
- **OQ12:** AES-256-GCM under a backup key held in the customer's key store, separate from the platform's service keys; key material only in the key store's own encrypted snapshot, never inside a data backup.
- **OQ13:** after a restore to an earlier point the trail continues from its restored head, and the checkpoints known only from the write-once copies or the SIEM are a declared gap, not a failure.

The design resolved the bundled PostgreSQL mechanism (D-OQ2: CloudNativePG with our CNPG-I plugin `cmd/pgbackup`, with a fallback), the custody of the backup key (D-OQ9), backup freshness as a posture setting (D-OQ10: `backup.max_age_hours`) and numbering after a restore (D-OQ15).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Our CNPG-I plugin with client-side encryption (chosen) | Point-in-time recovery; encryption under the customer's key with FIPS cryptography, before data leaves the cluster | A component of our own to maintain |
| CloudNativePG's barman-cloud | Ready-made | No client-side encryption under a customer key with FIPS cryptography |
| `pg_dump` | Simple, portable | No point-in-time recovery; long restores at target scale |
| Store-side replication only | No copy step | Replicates deletions and corruption; no consistent point with the database |
| Keys inside the data backup | One artifact | Whoever holds a backup holds its keys (OQ12) |

## Decision
- **A backup set is consistent at one recorded point in time *T*** (design §3.11):
  - **PostgreSQL, bundled:** continuous WAL archiving and scheduled base backups through `cmd/pgbackup`, a CloudNativePG plugin (CNPG-I) that encrypts each WAL segment and base-backup stream before writing it to the backup destination; point-in-time recovery to *T*. If CNPG-I cannot carry encrypted WAL archiving when `cmd/pgbackup` is built (T-24), the fallback is an `archive_command` tool in our PostgreSQL image, recorded by amendment here.
  - **PostgreSQL, brought:** the customer's own point-in-time backups to the documented requirements; `fairctl` records *T* and verifies restores the same way.
  - **Object stores** (audit store, WORM copy, report store): a listing of every version written up to *T* (key, version, SHA-256, retain-until, legal hold) and the objects themselves. The stores are append-only and versioned and the database is their index, so the database at *T* and the versions up to *T* restore consistently.
  - **Configuration:** the decisions, the current licence, the install report, the release's `platforms.json`.
  - **Keys, never in a data backup:** the key store's own snapshot (an OpenBao raft snapshot, or `fairctl backup keys` for Kubernetes Secrets), encrypted under a separate key-escrow key and written to a different destination.
  - JetStream is not backed up; restore re-provisions its streams.
- **Format** `fair.backup.v1`: a manifest (set id, installation id, *T*, components, each chunk's SHA-256, the store listings, the release) signed with the installation's backup signing key (ECDSA P-256, generated at install, its public half recorded with the installation); chunks encrypted with AES-256-GCM in the FIPS module under per-set data keys wrapped with the customer's backup key. The backup and key-escrow keys are files the mode's key store delivers only to the backup jobs, with KMS or HSM custody through the store's delivery (D-OQ9). Destinations: an S3 bucket through `internal/objstore`, or a filesystem path, including removable media.
- **Verified after writing:** the manifest signature and every chunk read back and digested; each set recorded in `install.backup`. The drift check `backup_freshness` opens a high finding when the newest verified set is older than `backup.max_age_hours` (default 24, bound 168) or the last scheduled run failed.
- **Restore** verifies the manifest's signature before reading anything, restores keys from the key snapshot, PostgreSQL to *T*, and objects with their recorded retain-until (never shorter) and legal holds, maps the stores' new version identifiers back in the database through audited definer functions (`audit.restore_versions`, `report.restore_versions`), and re-provisions the streams. The installation is `restoring`, and every service answers 503 `installation_closed` except health.
- **Verified before use:** `amcheck` over every platform index and the manifest's row counts; `posture.mac_mismatches()` empty; a full audit verification including archives and WORM copies; every object the database references present with its recorded digest. Any failure keeps the installation closed with the report; success records `restore.verified` and opens it. The installation identifier, licence and keys hold on a new cluster.
- **The restore gap.** On a restore to an earlier point, `fairctl` lists the WORM checkpoint copies after the restored head, verifies their signatures and that they chain from it, and records `audit.restore_gap` through `audit.declare_restore_gap` with the high-severity event `audit.restore_gap_declared`. Numbering resumes after the highest lost sequence and segment, so no number is used twice. The Verifier and `fair-audit-verify` accept a gap only when a gap row covers it and its external copies verify and chain; any other gap stays a failure. This is recorded as an ADR-011 amendment with T-27.
- **Drills:** `docs/operations/restore-drill.md` with `fair.restore-drill.v1` records; the install matrix backs up and restores bundled and brought installations and runs the verification above.

## Consequences
- The customer holds the backup key; a lost backup key or key snapshot means an unrecoverable backup. The backup guide says so.
- A restore to an earlier point loses the work after *T*; the declared gap and the external checkpoint copies are the evidence of what was lost, and tampering with the trail through a restore remains detectable.
- Images roll back on the upgraded schema (expand–contract); the schema before an upgrade comes back only by restore (ADR-005 amendment 2).
- `cmd/pgbackup` is a new image and component with its own SBOM, signatures and tests.
