# Feature Index
Every feature spec includes **Deployment modes** (SaaS, self-hosted, air-gapped) and **Secure defaults** sections (ADR-006).

**v1 build order:** F-012 (minimal CI) → F-001 Phases 0–1 → F-015 → F-001 remaining phases → F-002 → F-003 onward.

**Current position:** F-015 is **done** (T-01 to T-38, including T-24b). F-001 is **done** apart from T-25 (SCIM vendor interop runs), which is blocked until vendor test tenants and a public deployment exist. Next is **F-002**: requirements, design and tasks are approved (2026-11-04); T-01 (ADR-011, integrity primitives) T-02 (`audit` schema, `audit.submit`, catalog sync) T-03 (envelope `bu_id`, catalog attribute lists, no secrets) and T-04 (audit settings; F-015 string kind and approval on loosening; packages 1.2.0) T-05 (audit service scaffold, `app_audit`, leader election, checkpoint keys) T-06 (every producer records to the trail in its transaction) T-07 (the sequencer) T-08 (object storage client; ADR-012) T-09 (signed checkpoints, write-once copies) T-10 (`fair-audit-verify`, the offline verifier) T-11 (continuous verification, the audit_integrity finding, the Audit trail tile) T-12 (read functions and the Audit API) T-13 (approval evidence) T-14 (the audit pages) T-15 (evidence exports) T-16 (syslog forwarding) and T-17 (OTLP forwarding) are done; T-18 is next. See `README.md` for the task-level history.

| ID | Feature | Depends on | Status |
|---|---|---|---|
| F-001 | Identity, BU hierarchy & RBAC (SAML/OIDC, MFA, SCIM, custom roles, restricted BUs, RLS) | F-015 (bounds) | **Done** apart from T-25 (blocked: SCIM vendor tenants) |
| F-002 | Tamper-evident audit trail service | F-001 | Requirements · Design · Tasks: **all Approved** (2026-11-04). **In Progress** |
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
