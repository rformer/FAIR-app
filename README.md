# FAIR Risk Platform

A container-native platform for quantitative FAIR risk analysis, a risk register, and the risk-acceptance lifecycle. It is designed for enterprise risk teams and runs either as vendor-operated SaaS or self-hosted, including air-gapped installs.

The project follows a **spec-driven workflow**: nothing is built without approved requirements and an approved design. See [`specs/`](specs/README.md).

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
- The bootstrap script repairs role drift.

Next up is **Phase 1, the authorization core**: the BU closure table, the signed database context (ADR-007), the RLS harness, and the benchmark gate. See `specs/` for the full task list.

## Layout
```
cmd/iam/            iam service entrypoint
internal/config     environment config with secure-by-default validation
internal/server     hardened HTTP/TLS server, health and readiness
pkg/audit           security event contract and sinks
pkg/settings        security settings registry and change rules (F-015 contract)
pkg/authz           authorization library contract (implementation in Phase 1)
db/bootstrap        role creation (run once by installer/DBA)
db/migrations       schema migrations (run as app_migrator)
db/tests            database security tests
scripts/            db-bootstrap.sh, db-migrate.sh
deploy/k8s          reference hardened manifest (Helm/Zarf bundle comes with F-014)
specs/              pointer to the approved specs
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

### Database setup (installer / DBA)

```sh
# 1. Roles (passwords come from files, never literals)
PGDATABASE=fair FAIR_MIGRATOR_PASSWORD_FILE=... FAIR_RW_PASSWORD_FILE=... \
FAIR_ENGINE_PASSWORD_FILE=... ./scripts/db-bootstrap.sh

# 2. Migrations (as app_migrator)
PGDATABASE=fair FAIR_MIGRATOR_PASSWORD_FILE=... ./scripts/db-migrate.sh
```

## Notes
- Phase 0 uses only the Go standard library. Third-party modules (Postgres driver, NATS, OpenTelemetry) arrive in Phase 1, along with a Go migration runner that replaces `db-migrate.sh` with the same semantics.
- GitHub Actions are referenced by tag. Pin them to commit SHAs before the first release (tracked in F-012). Dependabot is configured to keep them current.
- Base images are referenced by tag. Pin them by digest (F-012).
