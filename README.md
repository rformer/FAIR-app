# FAIR Risk Platform

Spec-driven build of a FAIR risk assessment, risk register and risk acceptance
platform. Specs (constitution, ADRs, feature requirements/design/tasks) live in
the claude.ai Project and are the source of truth.

**Current state:** F-001 Phase 0 (foundations) complete. See
[`docs/phase-0.md`](docs/phase-0.md) for what was built, how each task was
verified, and known gaps.

## Layout

| Path | What |
|---|---|
| `cmd/iam` | iam service: `serve`, `migrate`, `version` |
| `pkg/audit` | Security event schema, `Emitter` interface, NATS JetStream / OTLP / syslog / stdout sinks (T-00a) |
| `pkg/audit/audittest` | Emitter contract suite every sink must pass (F-002 too) |
| `pkg/settings` | Profile-bounded security settings with apply / warn / dual-approval / hard-floor paths (T-00b) |
| `pkg/authz` | Authorization library: `Checker` (fail-closed), `BeginScoped` DB-context transactions (T-01) |
| `internal/iam` | iam config and HTTP server |
| `internal/migrate`, `migrations/` | Forward-only, checksummed migration runner + SQL (T-02) |
| `db/bootstrap/roles.sql` | One-time DB role bootstrap (`fair_owner`, `authz_definer`, `app_migrator`, `app_rw`, `app_engine`) |
| `deploy/k8s` | Dev manifests: restricted PSA namespace, default-deny NetworkPolicy, hardened Deployment, migrate Job |
| `.github/workflows/ci.yml` | Minimal CI (T-00c) |
| `test/integration` | PostgreSQL + NATS integration tests |

## Quick start

Requires Go 1.24+ (CI uses the latest stable Go), PostgreSQL 16+, and
optionally NATS with JetStream.

```sh
make test                   # unit tests
make test-fips              # unit tests in FIPS 140 mode
make build                  # FIPS-mode static binary at bin/iam
make run                    # serve on :8080, audit events to stdout

# Database (once per instance, as an admin role)
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 \
  -v migrator_password="$(openssl rand -base64 32)" \
  -v app_rw_password="$(openssl rand -base64 32)" \
  -v app_engine_password="$(openssl rand -base64 32)" \
  -f db/bootstrap/roles.sql
IAM_MIGRATOR_DATABASE_URL=postgres://app_migrator:...@host/fair ./bin/iam migrate

# Integration tests (use a dedicated test server: roles are cluster-wide)
FAIR_TEST_PG_ADMIN_URL=postgres://admin:pw@127.0.0.1:5432/postgres \
FAIR_TEST_NATS_URL=nats://127.0.0.1:4222 make test-integration

# kind
kind create cluster && make kind-load
```

## Configuration (iam)

| Variable | Default | Notes |
|---|---|---|
| `IAM_HTTP_ADDR` | `:8080` | |
| `IAM_PROFILE` | `fedramp-moderate` | `fedramp-moderate`, `cmmc-l2-r2`, `enterprise-baseline` |
| `IAM_DATABASE_URL` / `_FILE` | — | `app_rw` connection; `_FILE` reads a mounted Secret |
| `IAM_MIGRATOR_DATABASE_URL` / `_FILE` | — | `app_migrator` connection, `migrate` only |
| `AUDIT_SINKS` | `log` | Any of `log,nats,otlp,syslog`; empty is refused (audit is on the hard floor) |
| `NATS_URL` | — | JetStream; events on `audit.<type>`, stream `AUDIT` |
| `AUDIT_OTLP_ENDPOINT` | — | OTLP/HTTP collector, e.g. `https://otel:4318` |
| `AUDIT_SYSLOG_ADDR`, `AUDIT_SYSLOG_NETWORK` | —, `tls` | RFC 5424; `tls`, `tcp` or `udp` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | Traces; unset means no export (no mandatory dependency) |

Under FedRAMP Moderate and CMMC L2, iam refuses to start unless it is running
in FIPS 140 mode (built with `GOFIPS140=v1.0.0`, or `GODEBUG=fips140=on`).
