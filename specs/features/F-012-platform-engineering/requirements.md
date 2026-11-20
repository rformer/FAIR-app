# F-012 Platform engineering — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-19

## Summary
F-012 is how the platform is built, released and run. Every change is built and tested the same way, every service ships as a hardened, FIPS-mode image with an SBOM, a signature and build provenance (constitution S2, S5), and a release is one signed set of artifacts used by both deployment modes (M3, ADR-005). For the vendor-operated SaaS, each customer's dedicated instance (ADR-001) is created and changed only by reviewed infrastructure-as-code and GitOps, so instances are reproducible, upgrades roll safely across the fleet, and every production change carries the approval and build evidence that SOC 1 and SOC 2 reliance needs (S1, S6). Every service reports health, metrics, traces and logs without exposing secrets or risk data. Much of the build side already exists from earlier tasks (F-001 T-00c, F-015, F-005); F-012 makes it complete, uniform and verifiable, and adds the SaaS operations side. Packaging for self-hosted customers (Helm and Zarf bundles, the installer's preflight checks, licences, backup and restore) is F-014's.

## Users & roles affected
- **Platform engineers** (vendor staff): change the code, the pipelines, the infrastructure code and the fleet's desired state, through reviewed pull requests only.
- **SaaS operators and SREs** (vendor staff): run the fleet, watch its health, respond to alerts, promote releases; hold no standing access to customer data.
- **Release managers** (vendor staff): cut and publish releases, holding the release gate.
- **Customer security teams and auditors**: verify the images, SBOMs, signatures and provenance of what they run, and read the vendor's change evidence.
- **Self-hosted administrators**: consume the signed release; collect the platform's health and telemetry into their own tools.

## User stories
### F-012-R-01 Every change built and tested the same way
**As a** platform engineer, **I want** every change built and tested by one pipeline, **so that** nothing reaches a release without passing the same gates.

**Acceptance criteria (EARS):**
- F-012-AC-01: WHEN a pull request is opened or updated, THE SYSTEM SHALL build every component with the FIPS 140 module and run the unit, database, STRIDE, accessibility (UI end-to-end) and deployment-mode suites, and SHALL refuse the merge until all pass and a second engineer approves.
- F-012-AC-02: THE SYSTEM SHALL run the benchmark gates on the main branch and before every release, and SHALL block the release when a gate exceeds its budget.
- F-012-AC-03: THE SYSTEM SHALL pin every build input (base images by digest, Go and Python dependencies by lock file with hashes, pipeline actions by commit), and SHALL refuse a build whose inputs are not pinned.
- F-012-AC-04: WHEN a dependency has a known vulnerability of high or critical severity with a fix available, THE SYSTEM SHALL fail the pipeline for the change that introduces it and report it for existing code within one day of its publication.

### F-012-R-02 Hardened, FIPS-mode images for every service
**As a** customer security team, **I want** every service image hardened the same way, **so that** no component is the weak one.

**Acceptance criteria (EARS):**
- F-012-AC-05: THE SYSTEM SHALL build an image for every deployable component (iam, gateway, posture, posture-scanner, fips-probe, audit, risk, notify, integrate, engine, engine-gate, and any later service) that runs as a non-root user, with a read-only root filesystem, no shell or package manager, and every Linux capability dropped.
- F-012-AC-06: WHEN an image is built, THE SYSTEM SHALL verify that the Go services report the FIPS 140 module enabled and that the engine image carries no cryptographic library outside its approved set (F-005), and SHALL refuse a production start without TLS.
- F-012-AC-07: THE SYSTEM SHALL scan every image and fail the build on a high or critical vulnerability with a fix available, recording accepted exceptions with an expiry and a reason.

### F-012-R-03 Supply chain evidence
**As a** customer security team, **I want** to verify what I run, **so that** I know each image is the vendor's, built from the published source.

**Acceptance criteria (EARS):**
- F-012-AC-08: WHEN an image is published, THE SYSTEM SHALL publish with it an SPDX SBOM listing every package and module it contains, a signature, and a build provenance attestation (SLSA Build Level 3, OQ5) naming the source commit, the pipeline and its inputs, all bound to the image digest.
- F-012-AC-09: THE SYSTEM SHALL let anyone verify an image's signature, SBOM and provenance with documented, standard tools, and SHALL make the same verification possible without network access for air-gapped customers (OQ6).
- F-012-AC-10: THE SYSTEM SHALL produce the same image digest when the same source is built twice with the same pinned inputs, and the release pipeline SHALL check this for every release.

### F-012-R-04 Releases
**As a** release manager, **I want** a release to be one signed, complete set of artifacts, **so that** SaaS and self-hosted customers run exactly the same thing.

**Acceptance criteria (EARS):**
- F-012-AC-11: WHEN a release is tagged, THE SYSTEM SHALL build every artifact (images, the signed release manifest of F-015, the OpenAPI bundle, `fair-audit-verify`, the engine's validation record, the OSCAL component definition) from that tag, run the release gate (`profilegen release-check`), and publish nothing unless every check passes.
- F-012-AC-12: THE SYSTEM SHALL version releases with semantic versions, list in each release's notes the changes, migrations, setting and permission-catalog changes and security fixes it contains, and keep every published release's artifacts available for at least the supported upgrade window (OQ9).
- F-012-AC-13: THE SYSTEM SHALL refuse to publish a release whose database migrations are not forward-only and checksummed, or whose upgrade from each supported earlier release fails in the pipeline's upgrade test.

### F-012-R-05 SaaS instances from code
**As a** SaaS operator, **I want** each customer instance created and changed only by reviewed code, **so that** instances are identical, reproducible and auditable.

**Acceptance criteria (EARS):**
- F-012-AC-14: WHEN a new SaaS customer is onboarded, THE SYSTEM SHALL create its instance (network, Kubernetes cluster or namespace, PostgreSQL, object storage including the write-once audit bucket, encryption keys, secret delivery, DNS and certificates) from infrastructure-as-code (OQ1, OQ2), with no manual console step.
- F-012-AC-15: THE SYSTEM SHALL keep each instance's data, keys and network isolated from every other instance's (ADR-001), with encryption at rest under keys specific to the instance, FIPS-validated endpoints and TLS 1.2 or later on every connection.
- F-012-AC-16: WHEN the deployed infrastructure differs from its code, THE SYSTEM SHALL detect the drift within one day and alert the operators; changes SHALL only be applied from approved code.
- F-012-AC-17: WHEN an instance is decommissioned, THE SYSTEM SHALL remove its resources from code, after keeping the customer's export and the audit trail for the agreed retention, and record the decommissioning as a change.

### F-012-R-06 GitOps and fleet upgrades
**As a** SaaS operator, **I want** each instance's desired state in version control and upgrades rolled out in rings, **so that** a bad release reaches few customers and every change is approved and recorded.

**Acceptance criteria (EARS):**
- F-012-AC-18: THE SYSTEM SHALL hold each instance's desired state (release, settings package, infrastructure parameters) in a version-controlled repository and reconcile the instance to it continuously (OQ3); a change SHALL take effect only by an approved pull request.
- F-012-AC-19: WHEN an image is admitted to a SaaS cluster, THE SYSTEM SHALL verify its signature and provenance against the release's identity and refuse any image that fails.
- F-012-AC-20: WHEN a release is promoted, THE SYSTEM SHALL roll it out in rings (the vendor's own instance, then a canary group, then the rest), each ring advancing only when its instances are healthy for a set soak time, within each customer's maintenance window, and SHALL stop the rollout and alert on a failed health check.
- F-012-AC-21: WHEN an upgrade fails its health checks, THE SYSTEM SHALL let an operator roll the instance back to the previous release's images without data loss (migrations are forward-only and compatible with the previous release's code, F-012-AC-13).

### F-012-R-07 Health and telemetry
**As an** SRE, **I want** every service to report its health, metrics, traces and logs in standard forms, **so that** problems are seen before customers report them.

**Acceptance criteria (EARS):**
- F-012-AC-22: THE SYSTEM SHALL expose liveness and readiness on every service, readiness covering its dependencies (database, NATS, object storage, the engine, keys), and SHALL emit metrics, traces and structured logs through OpenTelemetry (OQ4) with request rates, errors, latencies, job queues and backlogs, and the audit trail's forwarding and capacity.
- F-012-AC-23: THE SYSTEM SHALL never put secrets, tokens, risk data (scenario, register, estimate or analysis content) or personal data beyond user IDs in metrics, traces or operational logs, and SHALL test this.
- F-012-AC-24: WHILE operating SaaS, THE SYSTEM SHALL alert operators on service-level objective burn (availability, latency, failed jobs, audit forwarding and verification, certificate and key expiry, backup failures), each alert linked to a runbook.
- F-012-AC-25: WHERE a deployment is self-hosted or air-gapped, THE SYSTEM SHALL keep telemetry inside the installation (no call home) and let the administrator send it to their own collector.

### F-012-R-08 Change and access evidence
**As a** customer auditor, **I want** evidence of the vendor's change management and operator access, **so that** I can rely on the SaaS controls (SOC 1, SOC 2, FedRAMP).

**Acceptance criteria (EARS):**
- F-012-AC-26: THE SYSTEM SHALL record, for every production change, the pull request, its approver (never its author), the pipeline run, the signed artifacts and the deployment to each instance, and SHALL export this evidence per period and per instance.
- F-012-AC-27: THE SYSTEM SHALL give operators no standing access to customer instances: access is requested, approved by a second operator, limited in time, recorded, and never includes reading customer risk data without the customer's recorded consent (break-glass, F-001).

## Non-functional requirements
- Performance: a pull request's required checks complete within 45 minutes; a release builds and verifies within 2 hours; a new SaaS instance is provisioned within 2 hours; a fleet-wide upgrade of 100 instances completes within one maintenance cycle.
- Security / privacy: least-privilege pipeline identities (short-lived, federated, no long-lived cloud keys); signing identities separate from build identities; secrets only from a secret store; no customer data in pipelines, telemetry or logs.
- Audit: pipeline, infrastructure and deployment changes recorded as in R-08; the platform's own audit trail (F-002) stays separate from operational telemetry.
- Availability: SaaS instances target 99.9% monthly availability; RPO and RTO as OQ8.
- Secure defaults: images run non-root with a read-only root filesystem and no capabilities; production refuses to start without TLS, FIPS or its keys; clusters admit only signed images; telemetry is off the network unless configured.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Images, SBOMs, signatures, provenance | Yes | Yes (pulled from the vendor registry) | Yes (in the bundle, F-014; verified offline, OQ6) |
| Infrastructure-as-code, GitOps, fleet rings | Yes | No (the customer's own tooling; F-014 installs) | No |
| Signature verification at admission | Yes (enforced) | Shipped policy, optional (F-014 preflight) | Shipped policy, optional |
| Telemetry | Vendor's operations stack | Customer's collector | Customer's collector, no egress |
| Change evidence | Vendor's, exportable | Customer's own | Customer's own |

## Control mapping (NIST SP 800-53r5)
To be proposed with the tasks.

## Out of scope
- Helm and Zarf packaging, the installer and its preflight checks, licences, self-hosted upgrades, backup and restore (F-014).
- The platform's application features and their own security controls (each feature).
- A customer-facing status page and support tooling (later).
- Multi-tenant SaaS (ADR-001).
- Clouds other than the one chosen for SaaS v1 (OQ1); the infrastructure code keeps the cloud behind modules so others can follow.

## Dependencies
- F-001 T-00c (minimal CI), F-015 (signed release manifest, release gate, deployment-mode matrix), F-005 (engine image, validation record), F-002 (audit trail, `fair-audit-verify`, write-once storage), F-001 (break-glass, keys per mode).
- F-014 consumes F-012's release artifacts.

## Open Questions
- OQ1 (resolved 2026-11-19: as proposed). Which cloud hosts SaaS v1? Proposed: AWS GovCloud (US), for the FedRAMP Moderate boundary (S1), with managed PostgreSQL, S3 Object Lock and KMS with FIPS endpoints; the infrastructure code keeps cloud specifics in modules so Azure Government can follow.
- OQ2 (resolved 2026-11-19: as proposed). Infrastructure-as-code tool? Proposed: OpenTofu (open licence, Terraform-compatible), with state in the cloud's encrypted object store and locking, and policy checks on every plan.
- OQ3 (resolved 2026-11-19: as proposed). GitOps tool? Proposed: Flux (CNCF graduated, pull-based, no web console to secure, verifies OCI artifacts' cosign signatures natively).
- OQ4 (resolved 2026-11-19: as proposed). Observability stack? Proposed: OpenTelemetry SDKs in the services and an OpenTelemetry Collector; for SaaS, Prometheus-compatible metrics, Grafana, Loki and Tempo in a separate operations account with no customer data; self-hosted gets the Collector configuration and a Prometheus endpoint, nothing else.
- OQ5 (resolved 2026-11-19: as proposed). Provenance level? Proposed: SLSA Build Level 3 through GitHub's isolated reusable provenance workflow, with GitHub artifact attestations; provenance checked at admission in SaaS.
- OQ6 (resolved 2026-11-19: as proposed). Signing for air-gapped verification? Keyless (Sigstore Fulcio and Rekor) needs the public transparency log. Proposed: sign every artifact twice, keyless for public verification and with a release key held in the cloud's HSM-backed KMS whose public key ships in the bundle and is published, so air-gapped customers verify offline.
- OQ7 (resolved 2026-11-19: as proposed). Base images? Proposed: keep `distroless/static` (nonroot) for Go services, which carry their FIPS module in the binary, and the engine's current base; offer hardened images matching DoD Iron Bank requirements later, not in v1.
- OQ8 (resolved 2026-11-19: as proposed). SaaS recovery objectives? Proposed: RPO 15 minutes (continuous database backup with point-in-time recovery, object storage versioning and replication), RTO 4 hours per instance, tested quarterly.
- OQ9 (resolved 2026-11-19: as proposed). Supported upgrade window? Proposed: upgrades supported from each of the two previous minor releases; every published release's artifacts kept for at least 24 months.

## Change Log
- 2026-11-19: Initial draft, In Review (F-013 done; F-012 next by the build order).
- 2026-11-19: Approved by Robert Former; OQ1 to OQ9 resolved as proposed (OQ6: keyless signatures and a KMS-held release key, chosen explicitly).
