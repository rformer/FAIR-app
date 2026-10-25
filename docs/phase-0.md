# F-001 Phase 0 — Foundations: build record

Rebuilt 2026-10-25 from the approved F-001 and F-015 specs (the original
Phase 0 archive from 2026-10-24 was not recoverable).

## Tasks

| Task | Delivered | Verification (all passing) |
|---|---|---|
| **T-00a** Audit emitter interface + NATS/OTLP/syslog stub sinks (AC-50) | `pkg/audit`: versioned `Event` schema with validation; `Emitter` interface; `Multi` fan-out that reports (never swallows) sink failures; sinks for NATS JetStream (acked publish, msg-ID de-dup, `audit.<type>` subjects), OTLP/HTTP JSON logs, RFC 5424 syslog over TLS/TCP/UDP with octet-counting framing, and stdout JSON | `audittest.RunContract` (field round-trip, invalid events rejected and never delivered, 25-way concurrency, close semantics) passes for every sink against a fake collector, fake syslog receiver, fake publisher, **and a real NATS JetStream server** |
| **T-00b** Minimal settings module, three profiles, `settings.Set` | `pkg/settings`: typed settings with strictness order; FedRAMP Moderate / CMMC L2 (800-171 Rev 2) / Enterprise Baseline profiles for 15 F-001 keys + 3 platform hard-floor keys; `Set` paths: **apply** (tighten, immediate), **warn** (in-bounds loosening: reason, high-severity audit, posture flag), **dual approval** (out of bounds or always-dual keys; requester ≠ approver; 72 h request expiry; stale-request check; becomes a 90-day exception), **refuse** (hard floor); `RevertExpired` auto-revert; change listeners | 15 tests: every path, self-approval impossible, double approval refused, approval expiry, stale approval, break-glass always dual-approved but disabled immediately, hard floor per profile (FIPS only loosenable under Enterprise Baseline), audit failure blocks the change, unbound key fails startup, property tests on comparator order and floor invariance |
| **T-00c** Minimal CI | `.github/workflows/ci.yml`: tidy/gofmt/vet, golangci-lint v2 (incl. gosec), govulncheck, unit tests with `-race` in FIPS mode with a test that fails if FIPS is off, `GOFIPS140=v1.0.0` build, integration job (Postgres 16 + JetStream), image build with non-root/read-only/FIPS runtime checks, SPDX SBOM; on `main`: push to GHCR, cosign keyless sign, SBOM attestation, build provenance. Actions pinned by SHA; Dependabot for Go, Actions, Docker | Green on GitHub (see [Verification](#verification-2026-10-25)) |
| **T-01** Scaffold `iam` + `authz` | `cmd/iam` (`serve`/`migrate`/`version`), env config with `_FILE` secrets, `/healthz` (never checks deps), `/readyz` (DB + NATS, no error detail leaked), `/version`, security headers, request-ID sanitising, panic recovery, OTel tracing (no-op unless an OTLP endpoint is set, per A7), graceful shutdown with audit; `pkg/authz` with fail-closed `DenyAll` checker and `BeginScoped` (bind-parameter `set_config(..., true)`) | Server/config tests; end-to-end run of the FIPS binary against PostgreSQL 16 and NATS (ready with both checks green, `fips140:true`, 404 for unknown routes, `service.started`/`service.stopped` audited); non-FIPS binary refuses to start under FedRAMP Moderate with a critical `service.start_refused` event. Image built, signed and attested in CI; deployed to kind under restricted Pod Security (see [Verification](#verification-2026-10-25)) |
| **T-02** DB roles + migration framework (AC-27) | `db/bootstrap/roles.sql` (idempotent; no default passwords); `fair_owner` and `authz_definer` NOLOGIN; `app_migrator`, `app_rw`, `app_engine` NOBYPASSRLS, own nothing; migrator reaches owners only by explicit `SET ROLE` (PG16 `INHERIT FALSE`); `authz.ctx_key` owned by `authz_definer`; checksummed, forward-only, advisory-locked runner | 9 integration tests on PostgreSQL 16: `app_rw` sees 0 rows without context (fail closed); `SET row_security=off` errors instead of bypassing; cannot disable/unforce RLS, drop policies, grant itself BYPASSRLS, read or write `authz.ctx_key`, alter/drop tables, create tables or schemas, `SET ROLE` to owners, or read migration metadata; even `fair_owner` cannot read the HMAC key; owner roles cannot log in; no object owned by a login role; `BeginScoped` is transaction-local and injection-safe; tampered/edited migrations and newer-than-binary databases are refused; a failing migration rolls back completely; bootstrap re-runs cleanly |

## Things to know

- **Go toolchain.** The rebuild targeted Go 1.24, which is past end of support, so `go.mod` now requires Go 1.26 (matching the Dockerfile) and dependencies were raised past the vulnerabilities govulncheck reported (pgx 5.11.0, nats.go 1.55.0, OpenTelemetry 1.47.0, x/net 0.61.0, x/text 0.43.0, grpc 1.84.0). Dependabot keeps them current.
- **go.sum.** Every entry was verified against `proxy.golang.org` / `sum.golang.org`; all matched.
- **Phase 0 stand-ins**, each replaced by a later task without changing callers: `DenyAll` checker → T-12 grant snapshot; settings in memory with hand-written profile values → F-015 (T-16, OSCAL-generated packages); in-memory approvals → T-26; audit stub sinks → F-002 hash-chained store.
- **RLS probe.** The T-02 tests use a stand-in policy on the raw `authz.ctx` value. The HMAC-verifying `authz.visible_bus()` and `authz.apply_bu_rls()` are T-09.
- **OpenShift.** Remove `runAsUser`/`runAsGroup` from the pod spec so the restricted SCC can assign a UID; the image runs under any non-root UID.
- **Role names are cluster-wide.** Two platform instances must not share one PostgreSQL cluster until role names are made instance-specific (note for F-014 bring-your-own Postgres).

## Verification (2026-10-25)

Checks run after the rebuild, on a Windows workstation (Go 1.27, Docker 29.9, kind 0.33) and on GitHub Actions.

| Check | Result |
|---|---|
| Unit tests, normal and FIPS mode (`GODEBUG=fips140=on`, `FAIR_REQUIRE_FIPS=1`) | Pass; `TestFIPSMode` fails as intended with FIPS off |
| Integration tests, FIPS mode, PostgreSQL 16.15 + NATS 2.11 JetStream | All 10 pass (9 DB, JetStream contract suite) |
| Image (`docker build`) with CI's run flags (`--read-only --cap-drop=ALL --security-opt no-new-privileges`) | UID 65532, `/healthz` 200, `fips140:true`, security headers present, unknown route 404, `service.started` / `service.stopped` audited, clean exit on stop; 33.6 MB |
| GitHub CI (`rformer/FAIR-app`) | lint, govulncheck, test (`-race`, FIPS), integration, image all green. First run surfaced 5 golangci-lint findings and reachable dependency vulnerabilities; both fixed |
| Image signing and provenance | Pushed to `ghcr.io/rformer/fair-iam`; cosign keyless signature, SPDX SBOM attestation, GitHub SLSA v1 build provenance (needs a public repo on a personal account) |
| kind (Kubernetes 1.37), `namespace.yaml` + `iam.yaml` | 2/2 replicas ready under PSA `restricted` with no warnings; UID 65532, read-only root FS, no SA token; `/healthz` and `/readyz` 200 |
| PSA enforcement | Non-compliant pod rejected for all four `restricted` violations |
| NetworkPolicy (kindnet) | Other namespace → iam blocked; gateway pod blocked by default-deny egress until egress is allowed, then 200; non-gateway pod in `fair` blocked by iam ingress |

Not covered yet: `migrate-job.yaml` and iam's database connection in-cluster (needs PostgreSQL in the cluster and the URL Secrets), and iam's egress rules (the distroless image has no shell to probe from).

## Next

Phase 1 (authorization core): T-03 → T-12, with T-11 as the performance gate.
