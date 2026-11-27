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

## Amendment 2 (2026-11-26, F-014 T-03)
Status: Proposed (pending acceptance by Robert Former; with the F-014 design approved 2026-11-26, §10 item 10)

**Context.** "Secure by deployment" says the installer refuses insecure installs "unless an explicit, logged override is given", while constitution S0 says the installer refuses insecure deployments. Amendment 1 made every setting exception expire, but an installer override had no lifecycle: once given, it would hold for good and stay invisible on the Posture page. F-014 OQ4 and OQ5 resolved how overrides work.

**Decision.** "An explicit, logged override" now means an expiring **deployment exception**, and never below the hard floor:
- **No override below the hard floor, in any mode.** A preflight finding on the hard floor (Amendment 1's floor as it applies to a deployment: plaintext or TLS below 1.2 on any platform connection; FIPS-enabled nodes or the database's FIPS mode missing under a FedRAMP- or CMMC-derived profile; an audit store without compliance-mode Object Lock; database roles that are superuser or bypass row-level security; plaintext secrets or key files readable by others; a release that fails verification) refuses the install or upgrade with no override (F-014-AC-19).
- **No override in SaaS at all.** F-012's onboarding and promotion run the same preflight with overrides refused (OQ4).
- **Any other failed check** proceeds only on an override naming the check, the subject and a reason. It is recorded at high severity (`install.preflight_override`, `posture.deployment_exception_created`) and becomes a deployment exception (`posture.deployment_exception`) that expires after the profile's `exception.max_duration` (90 days in every shipped profile), carries a row MAC like setting exceptions, is listed on the Posture page with them, appears in the POA&M, and is reported as "not satisfied, excepted" in the Assessment Results.
- **Renewal** only in the application, with dual approval (`deployment_exception.renew`), for at most `exception.max_duration` again.
- **At expiry** the check is re-run from the scanner's latest result (or marked unverified where Kubernetes access was declined); a still-failing check opens a high finding (`deployment_exception_expired`), and the next upgrade refuses until the check passes or the exception is renewed.
- Admission verification of image signatures, optional for self-hosted per F-012, is such an overridable check.

**Consequences.** Deployment exceptions share F-015's exception lifecycle (notices at 14, 7 and 1 days, MACs, audit) in their own table, since `posture.exception` is keyed by a setting (F-014 D-OQ14; F-015's design amended). An insecure deployment can never be accepted silently or permanently.
