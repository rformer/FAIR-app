# CLAUDE.md

This repo is built **spec-first**. Before doing anything, read:
1. `specs/README.md`: where we are and what is next
2. `specs/00-workflow.md`: the rules
3. `specs/01-constitution.md`: non-negotiable principles
4. The feature you are working on: `specs/features/<feature>/requirements.md`, `design.md`, `tasks.md`

## Current position
- F-001 Phase 0 is **done**.
- **Next: F-001 Phase 1 (T-03 to T-12)**, in task order. Its Verification column defines "done" for each task.

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
- `scripts/db-bootstrap.sh` then `scripts/db-migrate.sh`: database setup (see README)

## Notes for Phase 1
- Phase 0 is standard-library only. Phase 1 adds `github.com/jackc/pgx/v5`, a NATS client and River (ADR-003). It also replaces `scripts/db-migrate.sh` with an embedded Go migration runner that keeps the same semantics: run as `app_migrator` under `SET ROLE fair_owner`, record SHA-256 checksums, refuse modified migrations.
- `pkg/settings` is the T-00b stand-in for F-015. Keep its public API stable; F-015 T-16 replaces its backing store.
- `pkg/authz` holds only the contract. T-09 and T-12 implement it.
