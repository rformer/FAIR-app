# F-012 Platform engineering — Design
Status: Approved | Requirements version: 2026-11-19 (Approved) | Last updated: 2026-11-20

## 1. Overview
F-012 completes the build side the earlier features started and adds the SaaS operations side:
- **One pipeline, all gates** (R-01). `ci.yml` already runs the unit, database, STRIDE, bench, deployment-mode, engine, proto, OpenAPI, image and web jobs. F-012 makes the UI end-to-end suite (axe) a required check, pins every action by commit and every base image by digest (enforced by a check), adds Dependabot, and turns branch protection into code.
- **Every image hardened alike** (R-02). One image job builds every Dockerfile target (adding `posture`, missing today) with the same checks: non-root, read-only root, no shell, capabilities dropped, FIPS reported, production refuses plaintext. Trivy fails on fixable high or critical findings, with expiring exceptions in `security/vuln-exceptions.yaml`.
- **Supply-chain evidence** (R-03). Each image gets an SPDX SBOM (Syft), a keyless Sigstore signature and SBOM attestation (main and tags), SLSA Build L3 provenance (the SLSA generator's isolated reusable workflow), and on tags a second signature and attestations with the **release key in AWS KMS** (ECDSA P-256, FIPS 140-validated HSM; OQ6), whose public key ships in every bundle. Builds are reproducible (SOURCE_DATE_EPOCH, `-trimpath`, buildx timestamp rewriting); the release builds twice and compares digests.
- **Releases** (R-04). A tag builds everything once, pushes images by digest, writes the release manifest naming every image by registry digest, signs the manifest and profile packages with the KMS key (a KMS signer behind `releasegen sign`), runs the release gate, runs upgrade tests from the two previous minor releases, generates release notes from the migrations, packages and catalogs, and publishes a GitHub release with every artifact and its signatures.
- **SaaS from code** (R-05, ADR-016). OpenTofu in `infra/`: an AWS Organization in GovCloud (US) with one account per customer instance, an operations account, a shared-services account (registry mirror, KMS release key, logging), service control policies, and per instance: VPC, EKS, RDS PostgreSQL 16, S3 buckets (the write-once audit bucket, the audit and report stores), KMS keys, Secrets Manager with the External Secrets Operator, Route 53 and certificates. Plans run policy checks (Checkov) and `tofu test` with mock providers in CI; a daily drift job runs `tofu plan -detailed-exitcode` per account.
- **GitOps and fleet** (R-06, ADR-016). Flux in each instance's cluster reconciles from a private fleet repository: each instance pins a release and its overlay; rings (vendor, canary, general) advance by pull requests that a promotion tool (`cmd/fleetctl`) opens only after the previous ring has been healthy for its soak time and inside each instance's maintenance window. The Sigstore policy-controller admits only images signed by the release key with matching provenance.
- **Telemetry** (R-07, ADR-017). A small `pkg/telemetry` sets up OpenTelemetry metrics and traces, exported over OTLP with TLS to a Collector when `FAIR_OTEL_ENDPOINT` is set (off by default), with HTTP, database, job and NATS instrumentation and an allow-list of attributes. Logs stay structured JSON (slog) with trace ids. For SaaS, the Collector forwards to Prometheus-compatible metrics, Loki and Tempo in the operations account, with SLO alerts and runbooks.
- **Evidence and access** (R-08). `cmd/evidence` assembles, per period and instance, the chain pull request → approver → pipeline run → signed artifacts → deployment (from the fleet repository's history and Flux events), as signed JSON and CSV. Operator access is just-in-time: a pull request to the fleet repository's `access/` with an expiry, approved by a second operator, applied by an access controller as a time-bound IAM Identity Center assignment, never with standing access and never to risk data without F-001 break-glass and the customer's consent.

## 2. Components & responsibilities
| Component | Location | Responsibility |
|---|---|---|
| CI pipeline | `.github/workflows/ci.yml` | Pull-request and main gates (§3.1) |
| Release pipeline | `.github/workflows/release.yml` | Release build, signing, gates, publishing (§3.4) |
| Pin check | `cmd/pincheck` | Fails on unpinned actions, base images, or dependencies without hashes (AC-03) |
| Image checks | `scripts/image-check.sh` | Hardening, FIPS, no-shell, plaintext refusal per image (AC-05, AC-06) |
| Vulnerability exceptions | `security/vuln-exceptions.yaml`, `internal/vulnex` | Expiring, justified exceptions read by the scan step (AC-07) |
| KMS signer | `internal/kmssign` | ECDSA P-256 signing through AWS KMS (`releasegen sign -kms`; the AWS SDK for Go v2, ADR-018), same signature format as file keys |
| Release notes | `cmd/releasegen notes` | Notes from migrations, packages, catalog and settings diffs (AC-12) |
| Upgrade test | `db/tests/upgrade_test.go` | Migrates from the two previous minor releases' schemas and data (AC-13, AC-21) |
| Verification | `scripts/verify-release.sh`, `docs/security/verify.md` | Online and offline verification of signatures, SBOMs and provenance (AC-09) |
| Infrastructure | `infra/` (OpenTofu) | Organization, accounts, instance stack, policies, drift (§3.5) |
| Fleet | `deploy/fleet/` (templates), fleet repository (private) | Flux sources and Kustomizations, rings, overlays (§3.6) |
| Promotion | `cmd/fleetctl` | Ring promotion with health gates and maintenance windows (AC-20) |
| Admission | `deploy/fleet/policy/` | Sigstore policy-controller ClusterImagePolicy (AC-19) |
| Telemetry | `pkg/telemetry` | OpenTelemetry setup, instrumentation, attribute allow-list (§3.7) |
| Operations config | `deploy/observability/` | Collector configs (SaaS, self-hosted), alert rules, dashboards; runbooks in `docs/operations/runbooks/` |
| Evidence | `cmd/evidence` | Change evidence export (AC-26) |
| Access controller | `cmd/accessctl` | Applies and expires just-in-time access (AC-27) |

## 3. Design
### 3.1 Pull-request gates (AC-01 to AC-04)
- Required checks: `test` (unit, race, FIPS), `test-db` (full DB suite), `stride`, `deployment-modes`, `ui-e2e` (new in CI: the harness and Playwright with axe), `engine`, `proto`, `openapi`, `lint`, `pincheck`, `images` (§3.2), `infra` (§3.5). `bench` runs on main and in the release.
- Branch protection as code (`infra/github/`, OpenTofu GitHub provider): required checks, one approving review from a code owner who is not the last pusher, no force pushes, linear history, signed commits on `main`.
- Pins (`cmd/pincheck`): every `uses:` is a 40-hex commit with a version comment; every `FROM` and `docker run` image in the repository has an `@sha256:` digest; `go.sum` present for every module; `engine/` locks carry hashes; `web/` and `tools/` use `npm ci` with lock files. Dependabot updates actions, Go modules, npm and Docker digests weekly.
- Vulnerabilities: `govulncheck` (Go), `pip-audit` (engine locks), `npm audit --omit=dev` (web), Trivy (images). A scheduled daily job re-scans main and the supported releases and opens an issue for each new fixable high or critical finding (AC-04's "within one day").

### 3.2 Images (AC-05 to AC-07)
One matrix job over every Dockerfile target: `iam`, `gateway`, `posture`, `posture-scanner`, `fips-probe`, `audit`, `risk`, `notify`, `integrate`, `engine-gate`, `engine`. `scripts/image-check.sh <image> <component>` checks `Config.User` is 65532, starts the image read-only with all capabilities dropped and `no-new-privileges`, checks that no `/bin/sh` or package manager exists (`docker run --entrypoint /bin/sh` fails; file list has none), reads the FIPS flag from the startup log (Go services), checks that a production start without TLS or keys exits non-zero, and, for `engine`, that the dpkg records list no OpenSSL (F-005). A test asserts the matrix covers every target in the Dockerfile.

### 3.3 Supply chain (AC-08 to AC-10)
- **SBOM:** Syft SPDX JSON from the image (Go modules from build info, Debian packages from dpkg records, Python from the engine's site-packages). A check confirms every Go module in `go.mod` and every engine lock entry appears.
- **Signatures:** keyless (`cosign sign`, Fulcio identity = the workflow on `main` or a tag) on main and tags; on tags also `cosign sign --key awskms:///alias/fair-release` (GitHub OIDC to a role in the shared-services account that may only `kms:Sign` with that key, conditioned on the release workflow and a `v*` tag).
- **Provenance:** `slsa-framework/slsa-github-generator`'s container workflow (SLSA Build L3: isolated, non-falsifiable), uploaded as an in-toto attestation; on tags the same predicate is also attested with the KMS key, so it verifies offline.
- **Offline verification:** the bundle (F-014) carries `release/cosign.pub`, the signatures and attestations as OCI referrers and as files; `scripts/verify-release.sh -offline` runs `cosign verify --key cosign.pub --offline --insecure-ignore-tlog` and `cosign verify-attestation` for SPDX and SLSA, then checks the release manifest's signature (`releasegen verify`). Online verification also checks the keyless signature against the workflow identity.
- **Reproducibility:** `SOURCE_DATE_EPOCH` from the commit time, `-trimpath -buildvcs=false` plus the version from the tag, buildx `rewrite-timestamp=true`, pinned bases; the release builds every image twice on separate runners and fails if any digest differs.

### 3.4 Releases (AC-11 to AC-13)
Tag `vX.Y.Z` → jobs: `build` (images twice, compare, push by digest) → `sign` (keyless, KMS, SBOM and provenance attestations) → `manifest` (`releasegen manifest` with registry digests, the engine validation record, RBAC hashes; signed with KMS; profile packages re-signed with KMS) → `release-checklist` (as today) → `upgrade` (§3.4.1) → `bench` → `notes` → `publish` (GitHub release: manifest and signature, `cosign.pub`, SBOMs, provenance, OpenAPI bundle, `fair-audit-verify`, the OSCAL component definition, `SHA256SUMS` signed with KMS). Nothing is published unless every earlier job passed; images are pushed to a staging repository and copied to the release repository only by `publish`.
- **3.4.1 Upgrade test:** for each of the two previous minor releases, `db/tests` checks out that release's migrations and seed fixtures (`git worktree` of the tag in CI), migrates a database to it, loads a representative dataset (each feature's fixtures through that release's APIs where practical, direct inserts otherwise), then migrates to the new release and runs the new release's smoke and integrity checks (audit trail verifies, RLS harness, row counts). Rollback compatibility (AC-21): the previous release's service binaries start and pass their readiness and smoke requests against the upgraded schema (migrations follow expand–contract: a release never drops or renames what the previous release reads).
- **Notes:** `releasegen notes -from vA -to vB` lists migrations with their header comments, settings package versions and changed keys, permission catalog version and changes, catalog events added, ADRs added or amended, and `security`-labelled pull requests.
- **Retention:** releases and images are never deleted for 24 months (OQ9); the registry's lifecycle policy enforces it.

### 3.5 SaaS infrastructure (AC-14 to AC-17; ADR-016)
- **Organization:** AWS GovCloud (US) Organization: `management`, `security` (CloudTrail organization trail, GuardDuty, Config, log archive with Object Lock), `shared` (ECR release mirror, KMS release key, build roles), `ops` (observability, fleet automation), and one account per customer instance under an `instances` OU. SCPs: GovCloud regions only, FIPS endpoints only (`aws:...` conditions on endpoint use), deny disabling CloudTrail, GuardDuty or Config, deny leaving the organization, deny unencrypted S3 and RDS, deny public S3.
- **Instance module (`infra/modules/instance`):** VPC (three AZs, private subnets, no internet gateway except through egress controls; VPC endpoints for AWS APIs), EKS (private endpoint, encrypted secrets with the instance KMS key, managed node groups on a FIPS-enabled AMI (Bottlerocket FIPS), IRSA), RDS PostgreSQL 16 (Multi-AZ, encrypted with the instance key, TLS required, PITR 35 days, deletion protection, parameter group with `rds.force_ssl`), S3: `audit-worm` (Object Lock compliance mode, F-002), `audit-store`, `report-store` (versioned), backups replicated to a second GovCloud region; KMS: one key per purpose (database, S3, EKS secrets, Secrets Manager); Secrets Manager entries for every file key (F-001 T-41 layout) delivered by the External Secrets Operator; Route 53 private and public zones; certificates from ACM for the public load balancer and cert-manager with an ACM Private CA for internal TLS; WAF on the public entry.
- **Isolation (AC-15):** a customer instance's account holds only its resources; no peering between instance accounts; the ops account reaches instances only through the Collector's outbound PrivateLink and Flux's pull; KMS key policies name only the instance's roles.
- **Checks:** CI runs `tofu fmt -check`, `tofu validate`, `tofu test` (mock providers: every module's invariants, e.g. Object Lock compliance, `force_ssl`, no public subnets routes), and Checkov with the FedRAMP Moderate policy set; failures block. A daily drift job (OIDC to a read-only role per account) runs `tofu plan -detailed-exitcode`; drift opens an alert (AC-16). Applies run only from the pipeline after the plan was approved in the pull request.
- **Onboarding and decommissioning:** `infra/instances/<customer>.tfvars` (a pull request) creates the account and stack; decommissioning is a pull request marking the instance `retiring`: the pipeline exports the customer's data and the audit trail, keeps the audit bucket for the agreed retention (Object Lock already holds it), then removes the rest and records the change (AC-17).

### 3.6 GitOps and fleet (AC-18 to AC-21; ADR-016)
- **Fleet repository (private):** `instances/<id>/` (release pin, ring, maintenance window, overlay values: hostnames, sizes, settings package), `rings/{vendor,canary,general}.yaml`, `access/` (§3.9). Platform manifests are published per release as a signed OCI artifact (Flux `OCIRepository` with `verify: cosign` against the release key); the instance overlay is a Kustomization over it.
- **Flux:** source-controller, kustomize-controller, notification-controller (events to the ops account for evidence and alerts); no image automation (releases are pinned, never `latest`). Health checks on every Deployment and the migration Job; the iam migration Job runs first (`dependsOn`).
- **Admission:** the Sigstore policy-controller with a `ClusterImagePolicy` requiring, for every image in the platform's namespaces, the KMS release key signature and a SLSA provenance attestation whose builder is the SLSA generator and whose source is this repository at a `v*` tag; third-party images (Flux, policy-controller, External Secrets, cert-manager, the Collector) are mirrored to the shared ECR and admitted by their publishers' keys or keyless identities, pinned by digest. *Amended 2026-11-26 (T-15, decided with Robert Former):* a third-party image that runs in the platform's namespaces (today the OpenTelemetry Collector; `deploy/third-party-images.json`) is verified, when the release mirrors it, against its publisher's exact signing identity and issuer, copied by digest to the release repository's `mirror/<name>` and re-signed with the release key (KMS, or the dry run's test key) like the platform's images; the release's manifests name only the copy, and admission requires the release key for it (`ClusterImagePolicy` `fair-mirror`), with no warn mode. The policy-controller cannot verify the publishers' Sigstore bundle signatures itself.
- **Rings and promotion (`cmd/fleetctl promote`):** for ring N+1, checks every instance in ring N: Flux reports Ready on the release for the soak time (vendor 24 h, canary 72 h), the SLO burn alerts for those instances are silent, the migration Job succeeded; then opens one pull request per instance in ring N+1, each with a merge time inside the instance's maintenance window (merged by the bot only after a human approves the ring's pull request). A failed health check stops the rollout and alerts (AC-20).
- **Rollback (AC-21):** a pull request that pins the previous release; the previous code runs on the upgraded schema (expand–contract, checked by the upgrade test); no down migrations.

### 3.7 Telemetry (AC-22 to AC-25; ADR-017)
- **`pkg/telemetry`:** `Setup(ctx, service, version)` reads `FAIR_OTEL_ENDPOINT`, `FAIR_OTEL_CA_FILE` (TLS 1.2+, FIPS), `FAIR_OTEL_SAMPLE_RATIO`; without an endpoint it installs no-op providers (no egress, AC-25). Metrics and traces over OTLP/gRPC; logs remain slog JSON on stdout with `trace_id`/`span_id` added by a handler wrapper.
- **Instrumentation:** HTTP server middleware in `internal/server` (route pattern, method, status, duration; never the path's ids, query or body), pgx tracer (statement name or the first word of the statement, duration, row count; never arguments), River job metrics (queue, kind, outcome, duration, backlog), NATS publish and consume counts, audit forwarding backlog and capacity (F-002), engine call durations (F-005), notification delivery outcomes (F-009). Readiness already covers dependencies (`/readyz`); F-012 adds the missing checks (object storage, engine, key files present).
- **Redaction (AC-23):** attributes pass an allow-list (`telemetry.Allowed`); span names come from route patterns and fixed strings; a test runs representative API flows (the risk, register, estimate and report APIs) with an in-memory exporter and a log capture, and fails if any exported value contains a scenario name, document content, a token, a password, an email or a value from the risk fixtures.
- **SaaS operations stack:** in each instance, an OpenTelemetry Collector (mirrored, signed image) receives OTLP and scrapes kube-state metrics, forwarding over PrivateLink to the ops account: Prometheus, Loki, Tempo and Grafana self-run on the ops EKS (D-OQ2). `deploy/observability/alerts/` holds SLO burn-rate rules (availability 99.9%, p95 latency per API, job failures, audit forwarding backlog and verification failures, certificate and key expiry within 30 days, backup failures, drift), each with a `runbook_url` to `docs/operations/runbooks/<alert>.md`; a test checks every alert has a runbook and every runbook an alert.
- **Self-hosted:** `deploy/observability/collector-selfhosted.yaml` (receives OTLP, exposes a Prometheus endpoint, optional forwarding the administrator configures); nothing calls the vendor.

### 3.8 Change evidence (AC-26)
`cmd/evidence -from DATE -to DATE [-instance ID]` gathers from the GitHub API (pull requests merged to `main` and the fleet repository, their reviews and approvers, required check runs), the release attestations (by image digest), and Flux deployment events (stored by the ops account's notification receiver in an Object Lock bucket); it pairs each deployment with its release, each release with its commits and pull requests, and checks that each pull request's approver is not its author. Output: JSON (signed with a dedicated evidence key) and CSV, with every gap listed (a deployment without an approved pull request is a finding).

### 3.9 Operator access (AC-27)
- No IAM Identity Center permission set is assigned to people in instance accounts. Access is requested as a pull request adding `access/<request>.yaml` (who, which instance, role `read-only` or `operator`, reason, ticket, duration at most 8 hours), approved by a second operator (code owners); `cmd/accessctl` (in the ops account) creates the time-bound assignment and an EKS access entry for that role, and removes both at expiry; CloudTrail and the evidence export record it.
- The `operator` role can manage workloads but has no `rds-db:connect`, no Secrets Manager read of database credentials and no S3 read of the stores; reading customer data is possible only through the platform's own break-glass (F-001 T-34/T-35), which requires the customer's recorded consent (an approval in the customer's instance) and is audited in the customer's trail.

## 4. Data model
No platform schema changes. Persistent operational data: OpenTofu state (S3 with Object Lock versioning, DynamoDB-style locking through S3 conditional writes), the fleet repository, Flux events and evidence in an Object Lock bucket in the ops account (retained 7 years), CloudTrail in the security account.

## 5. API
No new platform API. Tools: `pincheck`, `releasegen sign -kms|notes|verify`, `fleetctl promote|status`, `evidence`, `accessctl` (command lines, documented in `docs/operations/`).

## 6. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| T: a tampered dependency or action enters a build | Everything pinned by digest or hash; Dependabot updates reviewed; vulnerability gates | `cmd/pincheck` tests, `TestPinsEnforced` |
| S, T: a forged or swapped image runs in SaaS | KMS and keyless signatures, SLSA L3 provenance, admission refuses unsigned or mismatched images | `scripts/admission-e2e.sh` (kind: signed admitted, unsigned and wrong-source refused) |
| T: an image differs from the source it claims | Reproducible builds checked on every release; provenance names the source commit | release job `reproducible`; `TestProvenanceNamesSource` |
| E: the release key is misused | Key in a FIPS HSM (KMS), sign-only role, callable only by the release workflow on a `v*` tag (OIDC conditions); key use logged in CloudTrail | `infra` policy tests (`tofu test`), Checkov |
| I: telemetry or logs leak risk data or secrets | Attribute allow-list; no paths' ids, queries, bodies or arguments; redaction test | `TestTelemetryRedaction` |
| I: one customer's instance reaches another's data | Account per instance, no peering, per-instance keys, SCPs | `infra` module tests (`tofu test`), Checkov |
| E: operators hold standing access to customer data | Just-in-time, second approval, time-bound, no data-plane rights; data only by customer-consented break-glass | `cmd/accessctl` tests, `infra` tests |
| T, R: unreviewed or unattributed production changes | Branch protection as code, GitOps only, evidence export pairs every deployment with an approved PR | `cmd/evidence` tests, `infra/github` tests |
| T: infrastructure drifts from code | Daily drift plans alert; applies only from approved plans | drift job dry run in CI |
| D: a bad release spreads across the fleet | Rings, soak times, health gates, stop on failure, rollback compatibility | `cmd/fleetctl` tests, `TestUpgradeFromPreviousReleases` |

## 7. Requirements traceability
| Requirement / AC | Satisfied by |
|---|---|
| AC-01, AC-02 | §3.1 required checks; bench on main and release |
| AC-03, AC-04 | §3.1 pins, Dependabot, scans, daily re-scan |
| AC-05 to AC-07 | §3.2 image matrix and checks, Trivy exceptions |
| AC-08 to AC-10 | §3.3 SBOM, signatures, provenance, offline verification, reproducibility |
| AC-11 to AC-13 | §3.4 release jobs, notes, upgrade test |
| AC-14 to AC-17 | §3.5 organization, instance module, checks, drift, lifecycle |
| AC-18 to AC-21 | §3.6 Flux, admission, rings, rollback |
| AC-22 to AC-25 | §3.7 telemetry, redaction, alerts, self-hosted |
| AC-26 | §3.8 evidence export |
| AC-27 | §3.9 just-in-time access |

## 8. Alternatives considered
- Terraform instead of OpenTofu: licence (BSL) is a risk for a product shipped to government customers; OpenTofu is drop-in (ADR-016).
- Argo CD instead of Flux: a web console and its RBAC to secure and assess; Flux is pull-only with native cosign verification of OCI sources (ADR-016).
- One shared EKS cluster with a namespace per customer: cheaper, but weaker isolation for FedRAMP and CMMC customers and a shared control plane; account per instance (ADR-001, ADR-016).
- Vendor APM agents: proprietary, call home, harder in air-gapped mode; OpenTelemetry keeps one instrumentation for every mode (ADR-017).
- Kyverno for admission: broader policy engine; the Sigstore policy-controller is narrower and verifies provenance predicates directly.

## 9. New ADRs (proposed with this design)
- **ADR-016 SaaS infrastructure and delivery:** AWS GovCloud (US) Organization with an account per customer instance; OpenTofu; Flux with signed OCI manifests; Sigstore policy-controller; rings with health-gated promotion.
- **ADR-017 Telemetry:** OpenTelemetry for metrics and traces (OTLP, off by default), structured JSON logs with trace ids, an attribute allow-list; SaaS operations stack in a separate account.

## 10. Risks & open questions
- D-OQ1 (resolved 2026-11-20: as proposed): CI cost and time: the UI end-to-end and DB suites take about 30 minutes each; run in parallel on larger runners to meet the 45-minute target. Proposed: GitHub larger runners for `test-db` and `ui-e2e`.
- D-OQ2 (resolved 2026-11-20: as proposed): Amazon Managed Service for Prometheus and Grafana availability and FedRAMP status in GovCloud may change; the ops stack keeps self-run Prometheus and Grafana on the ops EKS as the fallback. Proposed: self-run on the ops EKS from the start, one less service dependency.
- D-OQ3 (resolved 2026-11-20: as proposed): The upgrade test needs representative data from older releases; until two minor releases exist (the first release is v0.1.0), it runs from the first release only. Proposed: accept; the job's matrix grows with releases. Amended 2026-11-20 (T-08, with Robert Former): before the first release, the test upgrades from the baseline commit in `db/upgrade/baseline` (F-011's completion, c06b3ee, so migrations 0160 to 0169 are upgraded over representative data); release tags replace it once one exists.
- D-OQ4 (resolved 2026-11-20: as proposed): The fleet repository and the evidence bucket are outside this repository; their templates and tools live here, and their creation is part of the `infra` bootstrap task. Proposed: accept.
- The infrastructure cannot be applied from this environment; it is verified by `tofu validate`, `tofu test` with mock providers, Checkov and plan review. A first apply in a GovCloud sandbox account is a manual verification step of T-14.

## Change Log
- 2026-11-19: Initial draft, In Review.
- 2026-11-20: Approved by Robert Former; D-OQ1 to D-OQ4 resolved as proposed; ADR-016 and ADR-017 accepted with the design (written by T-12 and T-09).
- 2026-11-26: §3.6 Admission amended with Robert Former (T-15): third-party images in the platform's namespaces are verified against their publisher's identity and re-signed with the release key when mirrored; admission requires the release key for them.
