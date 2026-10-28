# Feature Index
Every feature spec includes **Deployment modes** (SaaS, self-hosted, air-gapped) and **Secure defaults** sections (ADR-006).

**v1 build order:** F-012 (minimal CI) → F-001 Phases 0–1 → F-015 → F-001 remaining phases → F-002 → F-003 onward.

**Current position:** F-001 Phase 0 is done (T-00a, T-00b, T-00c, T-01, T-02). F-001 Phase 1, the authorization core, is done (T-02b, T-03 to T-12). **F-015** is in progress: T-01 to T-04 are done (T-04's CMMC mapping signed off), T-05 to T-08 (bindings, signed profile packages, release checklist gate, `posture` schema and scaffold) are done, as are T-09 (write protection), T-10 (package import and seed), T-11 (`settings` library), T-12 (startup registration) and T-13 (strictness comparators). F-001 T-26 (dual-approval engine) is done, pulled forward, and F-015 T-14 to T-16 (change evaluator, SaaS SecOps notification, real registry replacing the F-001 settings stub) are done, which completes Phase B. Phase C has begun: T-17 (exception lifecycle), T-18 (auto-revert), T-19 (custom profiles), T-20 (custom profile versions, export/import, base updates) and T-21 (profile switch) are done, which completes Phase C. Phase D is done apart from T-24b: T-22 (BU overrides with inheritance and strictest-of), T-23 (Restricted BU overlay) and T-24 (the `authz` step-up check) are done; T-24b (session `auth_time`, IdP re-authentication, E2E) waits for F-001 T-13, T-15 and T-16. Phase E has begun: T-25 (app drift engine), T-26 (drift finding lifecycle and event schema) T-27 (`posture-scanner`: read-only client, mTLS gRPC, RBAC and egress verified on kind) and T-28 (10 deployment checks with kind/OpenShift/RKE2 fixtures, signed platform release manifest) T-29 (`fips-probe` with probe-verified or attested node FIPS evidence) and T-30 (Kubernetes-access consent, permission manifest, Not-assessed mapping) are done, which completes Phase E. T-31 (Posture API, with F-001 T-14's internal JWT pulled forward) and T-32 (Posture page UI, the platform's first web UI) are done. Next is F-015 T-33 (OSCAL Assessment Results export).

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
