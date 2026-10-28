# ADR-003 Platform stack
Status: **Accepted** (2026-10-24). Amended by ADR-005 for self-hosting.
Date: 2026-10-24

| Concern | Decision | Self-hosted note (ADR-005) |
|---|---|---|
| Frontend | React + TypeScript (Vite) | Served from the platform; no CDN dependency |
| UI components | React Aria Components (accessible, unstyled primitives) with the platform's own design tokens and CSS (amended 2026-10-28, F-015 T-32) | Bundled; WCAG 2.1 AA checked with axe in E2E |
| Charts | Apache ECharts | Bundled with the frontend |
| Primary DB | PostgreSQL 16+ | CloudNativePG bundled, or bring your own managed Postgres |
| Async jobs / events | NATS JetStream | Bundled or bring your own |
| Workflow timers | Go scheduler on Postgres (e.g., River) | No extra dependency |
| Object storage | S3-compatible | Bundled store, or bring your own S3 |
| Identity | Customer IdP via SAML/OIDC; optional bundled Keycloak | Same |
| Secrets & keys | Cloud KMS + External Secrets Operator (SaaS) | OpenBao/Vault, HSM, or customer KMS |
| Deployment | SaaS: Helm + Argo CD + Terraform/OpenTofu | Self-hosted: Helm or Zarf air-gap bundle |
| Reference cloud | AWS commercial plus GovCloud for SaaS; K8s-portable | Upstream K8s, EKS/AKS/GKE, OpenShift, RKE2 |
| Base images | Chainguard or distroless; Iron Bank optional | Non-root, read-only rootfs, OpenShift-compatible |
| Observability | OpenTelemetry → Prometheus/Grafana/Loki | OTLP/syslog export to customer tooling |

## Alternatives retained
- Temporal, if acceptance workflows become complex
