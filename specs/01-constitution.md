# Constitution — FAIR Risk Platform
Status: **Approved baseline** (2026-10-24). Amend only via ADR.

## 0. Market & deployment
- M1. **Target market: enterprise risk teams.**
- M2. **Single-tenant deployment.** Each customer gets a dedicated instance (ADR-001). Business units are a first-class hierarchy that scopes data.
- M3. **Two deployment modes, one artifact set** (ADR-005): vendor-operated SaaS, or customer self-hosted (including air-gapped).

## 1. Product principles
- P1. **FAIR fidelity.** Follow Open FAIR (O-RT, O-RA). Outputs are loss distributions, not ordinal scores.
- P2. **Calibrated estimates.** Every estimate is a range plus a confidence level, with rationale and source.
- P3. **Explainable results.** Every result traces back to its inputs, model version, and run.
- P4. **Automation assists; humans decide.**
- P5. **Framework-agnostic controls.** Control frameworks are imported via OSCAL with crosswalks between them (ADR-004).
- P6. **Customer-configurable, not customer-coded.** Roles, BU visibility, and security settings are configurable within guardrails.

## 2. Architecture principles
- A1. **Container-native.** Runs on any conformant Kubernetes, including OpenShift and RKE2.
- A2. **API-first.** External APIs are REST/OpenAPI; internal services use gRPC.
- A3. **Go for services, Python for the simulation and analytics engine** (ADR-002).
- A4. **Deterministic, reproducible simulations.**
- A5. **Stateless services.** State lives in PostgreSQL, NATS JetStream, and S3-compatible storage (ADR-003).
- A6. **BU scoping is enforced in the data layer** (row-level security).
- A7. **No mandatory external dependencies at runtime** (ADR-005).

## 3. Security & compliance principles
- S0. **Secure by design, secure by default, secure by deployment** (ADR-006). Fresh installs start in their most restrictive sensible state. Loosening a setting is always explicit, justified, audited, and visible. The installer refuses insecure deployments.
- S1. **SaaS mode meets** SOC 1 Type II, SOC 2 Type II, ISO/IEC 27001, CMMC L2, and NIST SP 800-53r5 / FedRAMP Moderate. Self-hosted mode ships an OSCAL component definition and a customer responsibility matrix.
- S2. **FIPS 140-validated cryptography.**
- S3. **Customer IdP via SAML/OIDC with SCIM; MFA enforced.** Least-privilege, BU-scoped RBAC with customizable roles.
- S4. **Tamper-evident, hash-chained audit trail.**
- S5. **Supply chain:** SBOM, signing, provenance, and hardened non-root images.
- S6. **SOC 1:** approval and change-management evidence must be usable for customer ICFR reliance.

## 4. Quality bars
- Q1. Every acceptance criterion has an automated test.
- Q2. The simulation engine passes statistical validation.
- Q3. WCAG 2.1 AA / Section 508 compliance.
- Q4. CI covers the install matrix: bundled vs. bring-your-own, and connected vs. air-gapped.
- Q5. Every feature has a threat model and a "Secure defaults" section.

## Change Log
- 2026-10-24: Initial draft; decisions incorporated; self-hosted distribution added; baseline approved.
- 2026-10-24: Added S0 (secure by design/default/deployment, ADR-006) and P6; S3 updated for SCIM and custom roles.
