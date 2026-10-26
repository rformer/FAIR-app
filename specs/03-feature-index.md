# Feature Index
Every feature spec includes **Deployment modes** (SaaS, self-hosted, air-gapped) and **Secure defaults** sections (ADR-006).

**v1 build order:** F-012 (minimal CI) → F-001 Phases 0–1 → F-015 → F-001 remaining phases → F-002 → F-003 onward.

**Current position:** F-001 Phase 0 is done (T-00a, T-00b, T-00c, T-01, T-02). F-001 Phase 1, the authorization core, is done (T-02b, T-03 to T-12). **F-015** is in progress: T-01 to T-03 are done, T-04 awaits review of its CMMC mapping table, T-05 to T-08 (bindings, signed profile packages, release checklist gate, `posture` schema and scaffold) are done, as is T-09 (write protection). Next is T-10 (package import and seed). F-001 T-26 (dual-approval engine) is pulled forward to run before F-015 T-14.

| ID | Feature | Depends on | Status |
|---|---|---|---|
| F-001 | Identity, BU hierarchy & RBAC (SAML/OIDC, MFA, SCIM, custom roles, restricted BUs, RLS) | F-015 (bounds) | Requirements · Design · Tasks: **all Approved**. **In Progress:** Phase 0 done (step-up change tracked as F-015 T-24) |
| F-002 | Tamper-evident audit trail service | F-001 | Not started |
| F-003 | FAIR data model (scenarios, assets, threat communities, loss forms, controls) | F-001 | Not started |
| F-004 | Calibrated estimate capture | F-003 | Not started |
| F-005 | Monte Carlo simulation engine (Python; versioned, reproducible) | F-003, F-004 | Not started |
| F-006 | Results & visualization (LEC, ALE distribution, comparisons) | F-005 | Not started |
| F-007 | Risk register (linked to analyses, BU roll-ups) | F-003, F-005 | Not started |
| F-008 | Risk acceptance lifecycle (approval tiers, expiry, renewal) | F-002, F-007 | Not started |
| F-009 | Notifications (SMTP/webhook; offline-capable) | F-008 | Not started |
| F-010 | Reporting & export | F-006, F-007 | Not started |
| F-011 | Integrations / automation inputs | F-003 | Not started |
| F-012 | Platform engineering: CI/CD, FIPS images, SBOM/signing, SaaS IaC + GitOps, observability | — | Not started (minimal CI covered by F-001 T-00c for now) |
| F-013 | Control framework library (OSCAL import, crosswalks, FAIR control effects) | F-003 | Not started |
| F-014 | Distribution, installer & licensing (Helm/Zarf bundles, **preflight checks that refuse insecure installs**, offline licenses, upgrades, backup/restore, OSCAL component definition) | F-012, F-015 | Not started |
| F-015 | Security posture & configuration profiles (OSCAL-driven profiles generated at build time for v1, custom profiles, gated switching, exception auto-revert, BU overlays, app + deployment drift, posture page, OSCAL AR/POA&M export) | F-001 core (Phases 0–1) | Requirements · Design · Tasks: **all Approved**. Ready to build |
