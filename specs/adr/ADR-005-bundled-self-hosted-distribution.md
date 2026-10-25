# ADR-005 Bundled distribution: vendor-operated SaaS and customer self-hosted
Status: Accepted
Date: 2026-10-24

## Context
Enterprise, federal, and DIB customers may need to run the platform inside their own authorization boundary. That includes their own cloud account, on-prem clusters, or disconnected/air-gapped networks.

## Decision
One artifact set serves both deployment modes:
1. **Vendor-operated SaaS:** a dedicated instance per customer (ADR-001), managed via GitOps.
2. **Customer self-hosted:** the customer installs the same versioned bundle on their own Kubernetes cluster, connected or air-gapped.

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
