# F-012 Platform engineering — Tasks
Status: **Approved** (Robert Former, 2026-11-20) | Design: Approved 2026-11-20

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites, all done:
- F-001 T-00c (minimal CI, SBOM, keyless signing for `iam`), T-41 (keys as files per mode), T-34/T-35 (break-glass).
- F-015: the signed release manifest (`internal/releasemanifest`, `cmd/releasegen`), the release gate (`profilegen release-check`), the deployment-mode matrix.
- F-005: the engine image and its validation record. F-002: `fair-audit-verify`, write-once storage.

Rules for every task:
- No test reaches a cloud: infrastructure code is verified by `tofu validate`, `tofu test` with mock providers and Checkov; a first apply in a GovCloud sandbox is a recorded manual step (T-14).
- No secret, token or customer data in a pipeline, log, telemetry export or fixture.
- Every new action, image or dependency is pinned (T-01 enforces it from then on).
- Workflow changes are checked with `actionlint` locally and run in CI before the task is Done.

## Phase A — Build gates and images
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | `cmd/pincheck` (actions by commit, images by digest, dependency hashes); pin every action and base image; Dependabot for actions, Go, npm, Docker; `pincheck` a required check | AC-03; §3.1 | `TestPinsEnforced` over fixtures; CI green with the check | M | Done |
| T-02 | Required checks: `ui-e2e` in CI (larger runner, D-OQ1), `pip-audit`, `npm audit`; daily re-scan of main and supported releases opening issues; branch protection as code (`infra/github/`, OpenTofu GitHub provider) | AC-01, AC-02, AC-04; §3.1 | CI runs; `tofu test` of the protection rules | M | Not started |
| T-03 | One image matrix over every Dockerfile target (adds `posture`); `scripts/image-check.sh` (non-root, read-only, no shell, capabilities, FIPS, plaintext refused, engine without OpenSSL); `security/vuln-exceptions.yaml` with expiry read by `internal/vulnex` for the Trivy gate | AC-05 to AC-07; §3.2 | `TestImageMatrixCoversDockerfile`, `internal/vulnex` tests; CI image jobs green | M | Not started |

## Phase B — Supply chain and releases
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-04 | SBOM completeness checks for every image; keyless signing and SBOM attestation for every image; SLSA Build L3 provenance via the SLSA generator | AC-08; §3.3 | CI on main: `cosign verify` and `verify-attestation` for every image | M | Not started |
| T-05 | Reproducible builds (SOURCE_DATE_EPOCH, trimpath, buildx timestamp rewrite, version from the tag); a double-build job comparing digests (weekly on main, every release) | AC-10; §3.3 | The job passes on main | M | Not started |
| T-06 | `internal/kmssign` (ECDSA P-256 through AWS KMS, same format as file keys); `releasegen sign -kms` and `releasegen verify`; cosign KMS signing on tags; `scripts/verify-release.sh` (online and `-offline`), `docs/security/verify.md` | AC-08, AC-09; §3.3 | `internal/kmssign` tests against a fake KMS signer; `verify-release.sh -offline` run in CI on a test-key-signed fixture release | M | Not started |
| T-07 | Release pipeline: build twice and compare, push by digest to staging, sign (keyless and KMS), manifest with registry digests (signed), profile packages re-signed, release gate, bench, notes (`releasegen notes`), publish (copy to the release repository, GitHub release with every artifact and `SHA256SUMS`) | AC-11, AC-12; §3.4 | A dry-run release of a `v0.0.0-test` tag in CI (publishing to a test repository) | L | Not started |
| T-08 | Upgrade test (`db/tests/upgrade_test.go`): from the previous two minor releases (the first release only, D-OQ3) with representative data; expand–contract check (the previous release's binaries start and answer smoke requests on the upgraded schema); a release job | AC-13, AC-21; §3.4.1 | `TestUpgradeFromPreviousReleases` | L | Not started |

## Phase C — Telemetry
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-09 | ADR-017; `pkg/telemetry` (OTLP over TLS, off by default, sampling), instrumentation of HTTP (`internal/server`), pgx, River, NATS, audit forwarding, engine calls, notification deliveries; readiness checks for object storage, the engine and key files | AC-22, AC-25; §3.7 | `pkg/telemetry` tests (no-op without an endpoint, no egress); metrics and spans asserted with an in-memory exporter | L | Not started |
| T-10 | Attribute allow-list and redaction; `TestTelemetryRedaction` over the risk, register, estimate and report flows (spans, metrics and logs carry no risk data, tokens or emails) | AC-23; §3.7 | `TestTelemetryRedaction` | M | Not started |
| T-11 | `deploy/observability/`: Collector configurations (SaaS, self-hosted), SLO burn alerts, dashboards; `docs/operations/runbooks/` one per alert | AC-24, AC-25; §3.7 | `TestAlertsHaveRunbooks`; `promtool check rules`; Collector config validates | M | Not started |

## Phase D — SaaS infrastructure and fleet
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-12 | ADR-016; `infra/` layout, state backend, the Organization (accounts, OUs, SCPs), security, shared (ECR mirror, KMS release key and its sign-only role) and ops accounts; CI `infra` job (`tofu fmt`, `validate`, `test` with mocks, Checkov FedRAMP Moderate) | AC-14, AC-15; §3.5 | `tofu test` (SCP and key-policy invariants); Checkov clean | L | Not started |
| T-13 | Instance module: VPC, EKS (private, FIPS nodes), RDS PostgreSQL 16, S3 (audit WORM, stores, replication), KMS keys per purpose, Secrets Manager and the External Secrets Operator (F-001 T-41 layout), DNS, certificates, WAF | AC-14, AC-15; §3.5 | `tofu test` (encryption, Object Lock compliance, force_ssl, no public routes, isolation); Checkov clean | L | Not started |
| T-14 | Onboarding and decommissioning through `infra/instances/*.tfvars` pull requests (plan in the PR, apply after approval), the daily drift job, retention on decommissioning; a recorded first apply in a GovCloud sandbox account | AC-14, AC-16, AC-17; §3.5 | Drift job dry run in CI; sandbox apply record in `docs/operations/` | M | Not started |
| T-15 | Fleet templates (`deploy/fleet/`): Flux sources with cosign verification of the signed per-release OCI manifests (published by the release), instance overlays, migration ordering, notification events; admission policy (Sigstore policy-controller); `scripts/admission-e2e.sh` on kind | AC-18, AC-19; §3.6 | `admission-e2e.sh`: signed release admitted, unsigned or wrong-source image refused; Flux reconciles a test instance | L | Not started |
| T-16 | `cmd/fleetctl` (`status`, `promote`): rings, soak times, health and SLO gates, maintenance windows, stop on failure; rollback by pinning the previous release | AC-20, AC-21; §3.6 | `cmd/fleetctl` tests over a fixture fleet and fake health sources | M | Not started |

## Phase E — Evidence, access, security, statements
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-17 | `cmd/evidence`: pull requests, approvers (never the author), check runs, attestations, deployments per instance; signed JSON and CSV with gaps as findings | AC-26; §3.8 | `cmd/evidence` tests over recorded API fixtures | M | Not started |
| T-18 | Just-in-time access: `access/` request schema, `cmd/accessctl` (time-bound IAM Identity Center assignments and EKS access entries, expiry), the operator role without data-plane rights (in `infra/`) | AC-27; §3.9 | `cmd/accessctl` tests with fake AWS clients; `tofu test` for the role's denied actions | M | Not started |
| T-19 | STRIDE suite for design §6 (rows in `TestSTRIDECatalog`) | §6 | `make test-stride` covers every §6 row | M | Not started |
| T-20 | Control implementation statements `compliance/statements/F-012.yaml`; the control mapping added to the requirements; Robert Former signs off | — | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Change Log
- 2026-11-19: Initial draft, In Review.
- 2026-11-20: Approved by Robert Former.
- 2026-11-20: T-01 done: `cmd/pincheck` (`internal/pincheck`: actions by full commit with a version comment, the SLSA generator by release tag; images by digest in workflows, Dockerfiles (ARG defaults resolved, stages and `fair-*` local images exempt) and scripts (docker run, pull, create, `--image=`, `*IMAGE*=` defaults, `image:`); `go.sum` beside `go.mod`, hashes on every engine lock entry, `package-lock.json` beside every `package.json`, no `npm install`); every action and image pinned; `.github/dependabot.yml`; the `lint` job runs it. Before it, the CI gates were made to pass again (no green run in the last 100): gofmt, and 143 golangci-lint findings, among them the engine mTLS pin check moved from `VerifyPeerCertificate` to `VerifyConnection` (resumed sessions are checked too) and a self-comparison in a test. `TestPinsEnforced`, `TestRepositoryPinned`.
