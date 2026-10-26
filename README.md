# FAIR Risk Platform

A container-native platform for quantitative FAIR risk analysis, a risk register, and the risk-acceptance lifecycle. It is designed for enterprise risk teams and runs either as vendor-operated SaaS or self-hosted, including air-gapped installs.

The project follows a **spec-driven workflow**: nothing is built without approved requirements and an approved design. See [`specs/`](specs/README.md) and [`CLAUDE.md`](CLAUDE.md).

## Status

**F-001 Phase 0 (Foundations) is complete.**

| Task | What | Where |
|---|---|---|
| T-00a | Audit event contract and stub sinks (JSON lines, RFC 5424 syslog over TCP/TLS, memory, fan-out). Sink failures are always surfaced, never dropped. | `pkg/audit` |
| T-00b | Settings registry implementing the F-015 contract (see below) | `pkg/settings` |
| T-00c | CI pipeline (see below) | `.github/workflows/ci.yml`, `Dockerfile` |
| T-01 | `iam` service skeleton (see below) | `cmd/iam`, `internal/` |
| T-02 | Database role model and migration framework (see below) | `db/`, `scripts/` |

**T-00b settings registry** includes:
- strictness ordering for every setting
- the three built-in profiles: FedRAMP Moderate, CMMC L2 (800-171 Rev 2), and Enterprise Baseline
- the hard floor
- tighten-now / loosen-within-bounds / dual-approval rules
- time-limited exceptions with auto-revert and renewal
- SaaS SecOps notification
- fail-closed behavior when audit is unavailable

**T-00c CI** runs gofmt, vet, govulncheck, golangci-lint, race tests in FIPS mode, and Postgres role tests. It then builds the image, verifies it (non-root, read-only filesystem, FIPS on, refuses to start without TLS), produces an SBOM and a Trivy scan, and on `main` pushes the image with a keyless cosign signature and SBOM attestation.

**T-01 `iam` skeleton** provides:
- hardened TLS server: TLS 1.2 hard floor, security headers, timeouts
- `/healthz` and `/readyz`, with readiness checks that never leak dependency errors
- JSON logs and graceful shutdown
- refuses to start without TLS or the FIPS 140 module in production

**T-02 database role model:**
- `fair_owner` and `authz_definer` cannot log in.
- `app_rw` and `app_engine` are NOBYPASSRLS, own nothing, and cannot read the context-key table.
- Migrations are checksummed and refuse to re-apply a modified migration.
- `iam migrate` (T-02b) embeds the migrations, applies them as `app_migrator` under `SET ROLE fair_owner`, and then installs the release permission catalog and built-in roles.
- `iam worker` (T-08) is the scope worker. River jobs (schema `river`) drain the access-change outbox into `authz.user_scope`, publish `iam.scope.changed` to NATS JetStream, and reconcile nightly. It needs `FAIR_DB_PASSWORD_FILE` (app_rw), the libpq variables, `FAIR_NATS_URL` (`tls://` in production) and optionally `FAIR_NATS_CREDS_FILE`. The installer provisions a JetStream stream that captures `iam.scope.changed`.
- The bootstrap script repairs role drift.

Next up is **Phase 1, the authorization core**: the BU closure table, the signed database context (ADR-007), the RLS harness, and the benchmark gate. See `specs/` for the full task list.

## Layout
```
cmd/iam/            iam service entrypoint (`iam migrate` runs migrations)
internal/config     environment config with secure-by-default validation
internal/server     hardened HTTP/TLS server, health and readiness
internal/migrate    embedded migration runner
internal/dbconn     PostgreSQL connection policy (secret files, verified TLS)
internal/scope      scope worker (River jobs, event delivery)
internal/natspub    NATS JetStream publisher
internal/rlstest    RLS negative-test harness for BU-owned tables (T-10)
internal/access     permission catalog and built-in roles
pkg/audit           security event contract and sinks
pkg/settings        security settings registry and change rules (F-015 contract)
pkg/authz           authorization library contract (implementation in Phase 1)
db/bootstrap        role creation (run once by installer/DBA)
db/migrations       schema migrations, embedded in the binary (run as app_migrator)
db/tests            database security, worker and scale tests
db/rivergen         generates River's schema as migrations
scripts/            db-bootstrap.sh
deploy/k8s          reference hardened manifest (Helm/Zarf bundle comes with F-014)
specs/              approved specs (requirements, designs, tasks, ADRs)
```

## Develop

Requirements: Go 1.24+, PostgreSQL 16+ and `psql` (for the DB tests).

```sh
make test       # unit tests, race detector, FIPS 140 module
make build      # bin/iam (FIPS build)

# Run locally without TLS (development only; refused in production)
FAIR_ENV=development FAIR_ALLOW_PLAINTEXT=true FAIR_LISTEN_ADDR=127.0.0.1:8080 ./bin/iam

# Database security tests against a local server (admin connection via libpq vars)
make test-db PGHOST=localhost PGPORT=5432 PGUSER=postgres PGPASSWORD=...
```

Without a local PostgreSQL or `psql`, run the database tests in Docker:

```sh
docker network create fairtest
docker run -d --name fairpg --network fairtest -e POSTGRES_PASSWORD=pgtest postgres:16
docker run -d --name fairnats --network fairtest nats:2.10 -js
docker run --rm --network fairtest -v "$PWD:/src" -w /src \
  -e PGHOST=fairpg -e PGUSER=postgres -e PGPASSWORD=pgtest -e GOFLAGS=-buildvcs=false \
  -e FAIR_TEST_NATS=nats://fairnats:4222 \
  golang:1.24-bookworm sh -c 'apt-get update -qq && apt-get install -y -qq postgresql-client >/dev/null && make test-db'
```

### Database setup (installer / DBA)

```sh
# 1. Roles (passwords come from files, never literals)
PGDATABASE=fair FAIR_MIGRATOR_PASSWORD_FILE=... FAIR_RW_PASSWORD_FILE=... \
FAIR_ENGINE_PASSWORD_FILE=... ./scripts/db-bootstrap.sh

# 2. Migrations and release catalog (as app_migrator). In production the
#    server certificate must be verified: PGSSLMODE=verify-full.
PGDATABASE=fair PGSSLMODE=verify-full FAIR_MIGRATOR_PASSWORD_FILE=... ./bin/iam migrate
```

## Notes
- Phase 0 used only the Go standard library. Phase 1 adds `github.com/jackc/pgx/v5` (T-02b); NATS and River follow (ADR-003).
- GitHub Actions are referenced by tag. Pin them to commit SHAs before the first release (tracked in F-012). Dependabot is configured to keep them current.
- Base images are referenced by tag. Pin them by digest (F-012).
