# ADR-005 Bundled distribution: vendor-operated SaaS and customer self-hosted
Status: Accepted
Date: 2026-10-24

## Context
Enterprise, federal, and DIB customers may need to run the platform inside their own authorization boundary. That includes their own cloud account, on-prem clusters, or disconnected/air-gapped networks.

## Decision
One artifact set serves both deployment modes:
1. **Vendor-operated SaaS:** a dedicated instance per customer (ADR-001), managed via GitOps.
2. **Customer self-hosted:** the customer installs the same versioned bundle on their own Kubernetes cluster, connected or air-gapped.

**Amendment (2026-10-28, F-015 T-37, approved by Robert Former):** the configured deployment mode (`FAIR_DEPLOYMENT_MODE`, recorded by the installer with `posture.set_deployment_mode`) has three values: `saas`, `self-hosted` and `air-gapped`. `air-gapped` is a self-hosted install with no outside network. It behaves as self-hosted, and in addition the services refuse outbound integrations (such as a vendor SecOps webhook), the scanner probes internal endpoints only, and profile packages arrive only through signed offline import.

### The bundle (per release)
- An umbrella **Helm chart** with feature flags for every bundled dependency.
- All **container images**, **SBOMs**, **signatures**, and **provenance attestations**, in an OCI layout the customer can push to a private registry.
- An **air-gap package**: a single archive with charts, images, and checksums. Zarf is the candidate tooling because it is common in DoD environments.
- **Database migrations**, the **OSCAL control catalogs** (ADR-004), and default content.
- **Documentation:** install, upgrade, backup/restore, hardening, and a **customer responsibility matrix**.

### Dependency rule: everything is either bundled or bring-your-own
| Dependency | Bundled option | Bring-your-own option |
|---|---|---|
| PostgreSQL | CloudNativePG operator | Managed Postgres (RDS, Azure DB, etc.) |
| NATS JetStream | NATS Helm chart | Existing NATS cluster |
| Object storage | S3-compatible store (choose one with clean licensing for redistribution) | AWS S3 or another S3-compatible service |
| Identity | Keycloak | Customer IdP via SAML/OIDC |
| Keys & secrets | OpenBao/Vault, or Kubernetes Secrets with envelope encryption | Cloud KMS, HSM, or the customer's Vault |
| Observability | OTel Collector + optional Prometheus/Grafana | Export via OTLP or syslog to the customer's SIEM/APM |

### Self-hosting requirements
- **No mandatory outbound connectivity.** Licensing, updates, and content work fully offline. Licenses are signed files.
- **Telemetry is off by default** when self-hosted.
- **Platform targets:** upstream Kubernetes, EKS/AKS/GKE, **OpenShift** (non-root, arbitrary UID, restricted SCC), and **RKE2** (STIG-hardened distro).
- **FIPS mode** works when the customer runs FIPS-enabled nodes.
- **Upgrade policy:** forward-only migrations, an N-1 → N upgrade path with tested skip rules, and a documented rollback via backup/restore.
- **Hardened images** run as non-root with read-only root filesystems. Iron Bank submission is optional.

### Compliance implications
- In SaaS mode, the vendor owns the FedRAMP/SOC/ISO boundary.
- In self-hosted mode, the **customer owns the boundary**. The vendor supplies an **OSCAL component definition** and a responsibility matrix, so the customer's SSP and CMMC assessment can inherit control implementation statements.

## Consequences
- Argo CD and Terraform remain vendor-ops tooling. Self-hosted customers install with Helm or Zarf.
- Every feature design must state how it behaves offline and with bring-your-own dependencies.
- New feature F-014 (Distribution, installer & licensing).
- CI must test the full install matrix: bundled versus bring-your-own, and connected versus air-gapped.

## Amendment 2 (2026-11-26, F-014 T-03)
Status: Proposed (pending acceptance by Robert Former; with the F-014 design approved 2026-11-26, §10 items 1 to 3)

**Context.** F-014's design found three statements in this ADR overtaken by later decisions:
- the upgrade policy says "an N-1 → N upgrade path", but F-012 OQ9 (2026-11-19) supports upgrades from each of the two previous minor releases, and `TestUpgradeFromPreviousReleases` tests that window; F-014 OQ10 follows F-012;
- the Consequences name Argo CD and Terraform as vendor-ops tooling, but ADR-016 chose Flux and OpenTofu;
- the dependency table leaves the bundled object store open ("choose one with clean licensing"), and its bundled PostgreSQL row, the CloudNativePG operator, normally holds cluster-scoped rights, against F-014's requirement that the running platform holds no cluster-wide write rights.

**Decision.**
- **Upgrade window.** An upgrade is supported from any patch of the two previous minor releases and from earlier patches of the same minor release, never a downgrade; `fairctl upgrade` refuses another source and names the release to upgrade to first. Migrations stay forward-only. Rollback has two parts: images roll back to the previous release on the upgraded schema (expand–contract, F-012-AC-21); the schema before the upgrade comes back only by restore (ADR-022). Every published release's artifacts are kept for at least 24 months (F-012 OQ9).
- **Vendor-ops tooling.** The first Consequence reads: "Flux and OpenTofu (ADR-016) are vendor-ops tooling. Self-hosted customers install with `fairctl` through the Helm chart, with Zarf as air-gap transport (ADR-019)."
- **Bundled object store.** The object storage row's bundled option is versitygw, rebuilt from source with the FIPS module (ADR-020), with the limits ADR-020 records.
- **Bundled PostgreSQL.** CloudNativePG is kept, with our FIPS PostgreSQL 16 image. Its operator is installed namespace-scoped (`WATCH_NAMESPACE=fair-data`) and holds write rights only in `fair-data`; its CRDs and cluster-scoped read objects are installed by `fairctl` with cluster administration during install, and that residue is listed in the responsibility matrix (F-014 D-OQ2). Backups go through our CloudNativePG plugin (ADR-022).

**Consequences.** The text above the amendments is kept as written; where they differ, this amendment governs.
