# Feature Index
Every feature spec includes **Deployment modes** (SaaS, self-hosted, air-gapped) and **Secure defaults** sections (ADR-006).

**v1 build order:** F-012 (minimal CI) → F-001 Phases 0–1 → F-015 → F-001 remaining phases → F-002 → F-003 onward.

**Current position:** F-015 is **done** (T-01 to T-38, including T-24b). F-001 is **done** apart from T-25 (SCIM vendor interop runs), which is blocked until vendor test tenants and a public deployment exist. Next is **F-002**: its requirements are approved (2026-11-04); the design is next. See `README.md` for the task-level history.

| ID | Feature | Depends on | Status |
|---|---|---|---|
| F-001 | Identity, BU hierarchy & RBAC (SAML/OIDC, MFA, SCIM, custom roles, restricted BUs, RLS) | F-015 (bounds) | **Done** apart from T-25 (blocked: SCIM vendor tenants) |
| F-002 | Tamper-evident audit trail service | F-001 | Requirements: **Approved** (2026-11-04) · Design: next |
| F-003 | FAIR data model (scenarios, assets, threat communities, loss forms, controls) | F-001 | Not started |
| F-004 | Calibrated estimate capture | F-003 | Not started |
| F-005 | Monte Carlo simulation engine (Python; versioned, reproducible) | F-003, F-004 | Not started |
| F-006 | Results & visualization (LEC, ALE distribution, comparisons) | F-005 | Not started |
| F-007 | Risk register (linked to analyses, BU roll-ups) | F-003, F-005 | Not started |
| F-008 | Risk acceptance lifecycle (approval tiers, expiry, renewal) | F-002, F-007 | Not started |
| F-009 | Notifications (SMTP/webhook; offline-capable) | F-008 | Not started |
| F-010 | Reporting & export | F-006, F-007 | Not started |
| F-011 | Integrations / automation inputs | F-003 | Not started |
| F-012 | Platform engineering: CI/CD, FIPS images, SBOM/signing, SaaS IaC + GitOps, observability | — | Not started (CI, images, SBOM and signing so far built under F-001 T-00c and F-015/F-001 tasks) |
| F-013 | Control framework library (OSCAL import, crosswalks, FAIR control effects) | F-003 | Not started |
| F-014 | Distribution, installer & licensing (Helm/Zarf bundles, **preflight checks that refuse insecure installs**, offline licenses, upgrades, backup/restore, OSCAL component definition) | F-012, F-015 | Not started |
| F-015 | Security posture & configuration profiles (OSCAL-driven profiles generated at build time for v1, custom profiles, gated switching, exception auto-revert, BU overlays, app + deployment drift, posture page, OSCAL AR/POA&M export) | F-001 core (Phases 0–1) | **Done** |
