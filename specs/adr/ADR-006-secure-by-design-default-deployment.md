# ADR-006 Secure by design, secure by default, secure by deployment
Status: Accepted. Amended 2026-10-24 (see Amendment 1).
Date: 2026-10-24

## Context
Robert set a product-wide mandate: secure by design, secure by default, and secure by deployment. This aligns with CISA's Secure by Design principles and with the expectations of FedRAMP, CMMC, SOC, and ISO customers.

## Decision

### Secure by design
- Every feature's design.md includes a threat model (STRIDE at minimum), security requirements traced to acceptance criteria, and a control mapping.
- Security controls are built into the product, not sold as paid add-ons. SSO, MFA, SCIM, audit, and RBAC ship in every edition.
- Memory-safe languages are used throughout: Go, Python, and TypeScript.
- Vulnerabilities are handled through a published vulnerability disclosure policy, CVE issuance, and signed advisories.

### Secure by default
- A fresh install starts in its **most restrictive sensible state**. There are no default passwords, nothing is enabled without a stated reason, and MFA is required.
- **Security configuration profiles** are selectable at install: *FedRAMP Moderate*, *CMMC L2*, and *Enterprise Baseline*. The default is FedRAMP Moderate, the strictest. Each profile sets defaults and allowed bounds for configurable security settings.
- Any security-relevant setting stays configurable, but **loosening** it:
  - requires explicit admin action and a reason,
  - emits a high-severity audit event,
  - is shown on a Security Posture page, and
  - warns when the new value falls outside the active profile's bounds.
- Settings that cannot be loosened at all: TLS off, MFA off for privileged roles, audit off, and FIPS off when the FedRAMP or CMMC profile is active.

### Secure by deployment
- The installer runs **preflight checks** and **refuses insecure installs** unless an explicit, logged override is given. Checks include:
  - TLS certificates and protocol versions
  - FIPS-enabled nodes when the profile requires them
  - NetworkPolicies supported
  - Pod security admission set to restricted
  - Encrypted storage classes
  - Secrets not stored in plaintext values files
  - Image signature verification
- The system generates all credentials and keys at install. Nothing ships with shared secrets.
- Hardening guides and STIG-style checklists ship with every release, along with drift detection that reports deviations from the selected profile.

## Consequences
- Adds feature F-015 (Security posture & configuration profiles).
- Adds preflight checks to F-014.
- Every requirements doc includes a "Secure defaults" section.

## Amendment 1 (2026-10-24, via F-015)
- **Custom profiles** may tighten or loosen settings relative to a built-in profile. Loosened values require justification and dual approval, and the profile is labeled "Deviates from <base>".
- **The hard floor** is extended to: TLS ≥ 1.2; audit logging on; MFA required for privileged permissions; FIPS required under FedRAMP- or CMMC-derived profiles; row-level security never disabled or bypassed.
- **Out-of-bounds changes** require an explanation, an explicit warning, dual approval, and a high-severity audit event.
- **All exceptions expire** (default 90 days) and **automatically revert** unless renewed with dual approval.
- **Profile switches** are gated until every conflict is resolved.
- **Profiles are generated from OSCAL.** v1 generates them at build time.
