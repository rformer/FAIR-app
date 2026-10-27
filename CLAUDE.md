# CLAUDE.md

This repo is built **spec-first**. Before doing anything, read:
1. `specs/README.md`: where we are and what is next
2. `specs/00-workflow.md`: the rules
3. `specs/01-constitution.md`: non-negotiable principles
4. The feature you are working on: `specs/features/<feature>/requirements.md`, `design.md`, `tasks.md`

## Current position
- F-001 Phases 0 and 1 are **done** (T-00a to T-12, plus T-02b).
- F-015 in progress: T-01 to T-04 done (T-04's CMMC mapping and the Enterprise Baseline rationales signed off 2026-10-27).
- F-015 T-05 done: `bindings/` holds one YAML binding per F-001 setting; `pkg/settings.BuiltinProfiles()` holds the same values as reference data and must stay equal to them (test-enforced).
- F-015 T-06 done: `go run ./cmd/profilegen packages` rebuilds `profiles/packages/` (committed, pinned by digest). Changing a binding means bumping that package's version in `profiles/packages.yaml`.
- F-015 T-07 done: `go run ./cmd/profilegen release-check [-online]` is the release gate (`.github/workflows/release.yml`); `profiles/release-checklist.yaml` records the CMMC rule confirmation.
- F-015 T-08 done: schema `posture` (migration 0011) and `cmd/posture`. Application roles have no access to posture tables; everything goes through SECURITY DEFINER functions owned by `posture_definer`, and the service connects as `app_posture` (design §5 access model).
- F-015 T-09 done: `posture.request_change` / `apply_change` / `apply_revert` (database-enforced floor, bounds and classification), row MACs keyed by `posture.mac_key`, `posture.mac_mismatches()` for drift. Out-of-bounds changes fail closed (PF005) until F-001 T-26.
- F-015 T-10 done: `iam migrate` loads the embedded release packages (`posture.sync_packages`); `posture seed` (install-time, audited) and `posture import` (signed, offline). `migrate.Run` takes a `migrate.Release`.
- F-015 T-11 done: `settings.Client` (`pkg/settings/client.go`): services read effective values through `posture.effective_settings()` as `app_rw`, refresh on `posture.setting.changed` or a 30 s version poll, fail closed when stale, and send heartbeats. The T-00b `Registry` is unchanged until T-16.
- F-015 T-12 done: `posture.register_settings` (open to services, never weakens) and `settings.Client.Start` (register, load, refuse to start on any unbound key).
- F-015 T-13 done: property tests for the comparators and strictest-of; Go (`settings.DecodeValue`, `Def.Compare`) and the database (`posture.check_value`, `compare`, `strictest`) must agree, and a parity test enforces it. `set` is deferred until a setting needs it.
- F-001 T-26 done (pulled forward): `iam.request_approval` / `decide_approval` / `consume_approval` (actors from the signed DB context; approver holds the kind's permission) and `internal/approvals`. AC-30's assignment path still refuses rather than routing to approval.
- F-015 T-14 done: `posture.Evaluator` (Change, ApplyApproved) over `posture.request_change` / `apply_change`, which now take the requester from the signed DB context and need `settings.change`; out-of-bounds changes go through F-001 approvals and become exceptions.
- F-015 T-15 done: `FAIR_DEPLOYMENT_MODE` (required in production; must match `posture.set_deployment_mode`); SaaS weakenings are queued by `posture.apply_change` and delivered to a signed SecOps webhook.
- F-015 T-16 done: `settings.Setter` (`posture.Setter`, the evaluator embedded as `app_rw`) and `settings.Client` replace the T-00b stub for writes and reads; the stub's `Registry` remains only for the exception lifecycle until T-17/T-18.
- F-015 T-17 done: exception durations bounded by `exception.max_duration`, renewal before expiry with dual approval (`Evaluator.RequestRenewal` / `ApplyRenewal`), 14/7/1-day notices (`posture.RunNotices`, queued in `posture.notice_outbox` for F-009).
- F-015 T-18 done: auto-revert (`posture.RunReverts`, every 10 s), retries with backoff, critical `revert_failed` finding with hourly escalation; the T-00b `Registry` stand-in is removed.
- F-015 T-19 done: custom profiles (`posture.Profiles`: create from any built-in, per-key edit with justified loosening and floors, view, submit to a `profile.approval`, approve, reopen).
- F-015 T-20 done: custom profile versions and diffs, base-update effects and rebase (weaker base pinned, stricter proposed, `needs_review` blocks submission), JSON and OSCAL export/import (`posture.Profiles`).
- F-015 T-21 done: profile switch (`posture.Switches`: request computes conflicts and loosening, resolve conform/exception, one-transaction activation, cancel, pending view).
- F-015 T-22 done: BU overrides inherit through `iam.bu_closure` (blocked at restricted BUs); `posture.current_value` and the settings snapshot give the strictest-of effective value per BU.
- **Next: F-015 T-23** (`specs/features/F-015-security-posture-profiles/tasks.md`; restricted BU overlay), then the rest of F-015 in task order, except that **F-001 T-26 (dual-approval engine) comes before F-015 T-14** (approved 2026-10-26); then the rest of F-001 (Phase 2 onward). The Verification column defines "done" for each task.

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
- `make build`: builds `bin/iam` (`go build ./cmd/posture` for the posture service)
- `scripts/db-bootstrap.sh` then `make migrate` (`iam migrate`): database setup (see README)

## Notes for Phase 1
- Phase 0 is standard-library only. Phase 1 adds `github.com/jackc/pgx/v5` (done, T-02b), a NATS client and River (ADR-003). `iam migrate` (`internal/migrate`) replaced `scripts/db-migrate.sh` with the same semantics: run as `app_migrator` under `SET ROLE fair_owner`, record SHA-256 checksums, refuse modified migrations. It then applies the release catalog via `iam.sync_release`.
- Migration files are immutable once committed (their checksums are recorded); fix forward with a new migration.
- DB tests need `psql`; without a local server, run them in Docker against `postgres:16` (see README).
- `pkg/settings`: services read with `Client` (register with `Client.Start`) and write through the `Setter` contract (`posture.Setter`); the exception lifecycle lives in `internal/posture`. The T-00b `Registry` stand-in was removed with F-015 T-18.
- `pkg/authz`: `Cache` (implements `Checker`), `DBLoader`, `WithDBContext`, `MintDBContext`, `SubscribeNATS`. Services check actions with `Cache.Check` and run BU-table queries inside `WithDBContext`.
- Every BU-owned table is created in a migration with `SELECT authz.apply_bu_rls('<table>', '<resource_type>')` and gets an `rlstest.Fixture` in `db/tests/rls_harness_test.go`; the CI gate fails otherwise (T-10).
