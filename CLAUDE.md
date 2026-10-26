# CLAUDE.md

This repo is built **spec-first**. Before doing anything, read:
1. `specs/README.md`: where we are and what is next
2. `specs/00-workflow.md`: the rules
3. `specs/01-constitution.md`: non-negotiable principles
4. The feature you are working on: `specs/features/<feature>/requirements.md`, `design.md`, `tasks.md`

## Current position
- F-001 Phase 0 is **done**. Phase 1 is in progress: T-02b and T-03 to T-08 are done.
- **Next: T-09**, then the rest of Phase 1 (to T-12) in task order. Its Verification column defines "done" for each task.

## Working rules
- Implement only tasks that are marked Approved and listed in a `tasks.md`. If a task needs a design change, stop and propose the spec change; don't silently diverge.
- Every commit references task and acceptance-criteria IDs, e.g. `F-001 T-09 (F-001-AC-24, AC-25)`.
- Mark finished tasks Done in `tasks.md` in the same commit.
- Security posture is mandatory (ADR-006):
  - TLS 1.2 is the floor.
  - Builds use the FIPS 140 module (`GOFIPS140=v1.0.0`).
  - App DB roles never bypass RLS.
  - Audit failures fail closed.
  - No secrets in code or environment literals; read them from files.

## Commands
- `make test`: unit tests (race detector, FIPS module)
- `make test-db PGHOST=... PGPORT=... PGUSER=<superuser> PGPASSWORD=...`: database security tests (needs PostgreSQL 16+ and `psql`)
- `make build`: builds `bin/iam`
- `scripts/db-bootstrap.sh` then `make migrate` (`iam migrate`): database setup (see README)

## Notes for Phase 1
- Phase 0 is standard-library only. Phase 1 adds `github.com/jackc/pgx/v5` (done, T-02b), a NATS client and River (ADR-003). `iam migrate` (`internal/migrate`) replaced `scripts/db-migrate.sh` with the same semantics: run as `app_migrator` under `SET ROLE fair_owner`, record SHA-256 checksums, refuse modified migrations. It then applies the release catalog via `iam.sync_release`.
- Migration files are immutable once committed (their checksums are recorded); fix forward with a new migration.
- DB tests need `psql`; without a local server, run them in Docker against `postgres:16` (see README).
- `pkg/settings` is the T-00b stand-in for F-015. Keep its public API stable; F-015 T-16 replaces its backing store.
- `pkg/authz` holds only the contract. T-09 and T-12 implement it.
