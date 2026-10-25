# F-001 Identity, Business-Unit Hierarchy & RBAC — Requirements
Status: **Approved** (Robert Former, 2026-10-24) | Owner: Robert Former | Last updated: 2026-10-24
Constitution refs: S0, M2, M3, P6, A6, A7, S2, S3, S4, S6 | ADRs: 001, 005, 006

## Summary
This feature establishes who can sign in, how they authenticate, and how the enterprise is organized into business units (BUs). It also defines what each person can see and do within that hierarchy. Access is enforced in the data layer. Customers can tailor roles and BU visibility, but the system ships locked down and keeps every loosening explicit and audited.

## Permission model
- A **permission** is an atomic capability, e.g., `analysis.edit` or `acceptance.approve`. The permission catalog is defined by the platform and versioned.
- A **role** is a named set of permissions. **Built-in roles** are immutable templates. **Custom roles** are defined by the customer (R-15).
- A **role assignment** is a (user or group, role, BU node) triple. It applies to that node and its descendants, *except* where a descendant is restricted (R-16).

### Built-in roles (templates)
| Role | Intent |
|---|---|
| Platform Admin | Instance configuration (IdPs, SCIM, profiles, banners, BU tree). No risk-data access by default. |
| BU Admin | Manages role assignments within their subtree |
| Risk Analyst | Creates and edits scenarios, estimates, and analyses; runs simulations |
| Risk Owner | Owns register entries; requests treatment or acceptance |
| Approver | Approves acceptances (authority limits are defined in F-008) |
| Executive Viewer | Read-only access to analyses, the register, and roll-ups |
| Auditor | Read-only access to in-scope data, audit logs, and entitlement reports |
| Service Account | Non-human identity; API scopes only |

## Requirements

### F-001-R-01 Federated single sign-on
- F-001-AC-01: THE SYSTEM SHALL support SAML 2.0 (SP- and IdP-initiated) and OIDC (authorization code + PKCE).
- F-001-AC-02: THE SYSTEM SHALL support multiple IdPs, with users routed to an IdP by email domain.
- F-001-AC-03: WHEN IdP metadata cannot be fetched from a URL, THE SYSTEM SHALL accept uploaded metadata or a JWKS file.
- F-001-AC-04: THE SYSTEM SHALL validate signature, audience, issuer, and expiry, and SHALL reject unsigned or replayed assertions.

### F-001-R-02 MFA enforcement
- F-001-AC-05: WHEN a federated login lacks MFA evidence (authentication context or AMR claim) AND MFA is required, THE SYSTEM SHALL deny the login and record the reason. MFA SHALL be required by default.
- F-001-AC-06: For the bundled Keycloak, privileged roles SHALL require phishing-resistant MFA (WebAuthn/FIDO2 or PIV/CAC). TOTP for non-privileged users SHALL be off by default and enabled only by a Platform Admin.

### F-001-R-03 Provisioning (SCIM required for v1)
- F-001-AC-07: THE SYSTEM SHALL implement a SCIM 2.0 service provider for Users and Groups, including filtering, PATCH, and bulk deactivation, and SHALL pass a published SCIM conformance test suite against Entra ID, Okta, and Ping.
- F-001-AC-08: SCIM endpoints SHALL authenticate with bearer tokens scoped only to SCIM, which expire and can be rotated.
- F-001-AC-09: Just-in-time provisioning SHALL be **off by default**. When enabled, a just-in-time user SHALL have no roles until a role is mapped or assigned.
- F-001-AC-10: WHEN a user is deactivated via SCIM, THE SYSTEM SHALL terminate the user's sessions and revoke their tokens within 60 seconds.
- F-001-AC-11: WHEN an account has been inactive longer than the configured period (default 90 days), THE SYSTEM SHALL disable it.

### F-001-R-04 IdP group-to-role mapping
- F-001-AC-12: THE SYSTEM SHALL map IdP/SCIM groups to (role, BU node) pairs.
- F-001-AC-13: WHEN a user's group membership changes, THE SYSTEM SHALL recompute mapped assignments and SHALL remove those whose group membership has ended.
- F-001-AC-14: Each assignment SHALL be marked "mapped" or "manual".

### F-001-R-05 BU hierarchy
- F-001-AC-15: THE SYSTEM SHALL maintain one Enterprise root node, with a configurable maximum nesting depth (default 6).
- F-001-AC-16: THE SYSTEM SHALL support create, rename, move, and archive for BU nodes. Hard delete SHALL NOT be permitted.
- F-001-AC-17: WHEN a BU is moved, THE SYSTEM SHALL recalculate inherited access and SHALL audit the old and new parent.
- F-001-AC-18: IF a BU owns active records, THEN THE SYSTEM SHALL block its archive until those records are reassigned.
- F-001-AC-19: THE SYSTEM SHALL support import and export of the BU tree as CSV/JSON.

### F-001-R-06 BU-scoped role assignment
- F-001-AC-20: A user SHALL be able to hold multiple assignments across BU nodes.
- F-001-AC-21: An assignment SHALL apply to its node and descendants, subject to R-16.
- F-001-AC-22: A BU Admin SHALL be able to assign roles only within their subtree, SHALL NOT be able to grant roles containing admin permissions, and SHALL NOT be able to assign roles into restricted BUs unless explicitly granted that right there.
- F-001-AC-23: Assignments SHALL support an optional expiry date. Expired assignments SHALL be removed automatically.

### F-001-R-07 Data-layer access enforcement
- F-001-AC-24: Every BU-owned record SHALL carry a BU identifier. PostgreSQL row-level security SHALL limit access to the caller's effective scope, which SHALL include the restriction rules in R-16.
- F-001-AC-25: An out-of-scope record SHALL be indistinguishable from a nonexistent one (the system returns 404).
- F-001-AC-26: Roll-ups SHALL include only data the caller is permitted to see, and SHALL indicate when data is excluded or aggregated.
- F-001-AC-27: Application database roles SHALL NOT be able to bypass row-level security. Migrations SHALL run under a separate privileged role.

### F-001-R-08 Separation of duties
- F-001-AC-28: Users SHALL NOT be able to create or change their own role assignments.
- F-001-AC-29: THE SYSTEM SHALL provide a configurable separation-of-duties (SoD) rule set expressed as conflicting permission pairs. The default rule SHALL be that an analysis author cannot approve an acceptance that relies on that analysis (enforced in F-008).
- F-001-AC-30: Combining admin permissions with risk-data permissions for one user SHALL require a second Platform Admin's approval.

### F-001-R-09 Session management (configurable within bounds)
- F-001-AC-31: Defaults SHALL be 15 minutes idle and 12 hours absolute. Both SHALL be configurable by a Platform Admin.
- F-001-AC-32: WHEN a session setting is changed to a value outside the active security profile's bounds, THE SYSTEM SHALL require a stated reason, show a warning, emit a high-severity audit event, and flag the change on the Security Posture page (ADR-006).
- F-001-AC-33: Users and admins SHALL be able to view and revoke active sessions.
- F-001-AC-34: THE SYSTEM SHALL display a configurable system-use banner that users must acknowledge. It SHALL be enabled by default.
- F-001-AC-35: Session cookies SHALL be Secure, HttpOnly, and SameSite=Strict. THE SYSTEM SHALL apply CSRF protection to all state-changing requests.

### F-001-R-10 Service accounts & API tokens
- F-001-AC-36: Service accounts SHALL be scoped to a BU node and to explicit API scopes.
- F-001-AC-37: Tokens SHALL expire (default maximum 90 days, configurable within profile bounds), SHALL be shown once, and SHALL be stored only as hashes.
- F-001-AC-38: THE SYSTEM SHALL support OAuth client-credentials and mTLS client authentication.

### F-001-R-11 Break-glass access (disabled by default)
- F-001-AC-39: Break-glass accounts SHALL be **disabled by default**. No break-glass account SHALL exist in a fresh install unless the installer explicitly enables the capability.
- F-001-AC-40: WHEN break-glass is enabled at install, the installer SHALL require a stated reason, SHALL record the enablement in the install log, and SHALL require the account holder to enroll WebAuthn on first use. No shared or default password SHALL ever be issued.
- F-001-AC-41: WHEN break-glass is enabled after install, THE SYSTEM SHALL require a stated reason and a second Platform Admin's approval, and SHALL emit a high-severity audit event.
- F-001-AC-42: WHEN enabled, THE SYSTEM SHALL support at most two local break-glass Platform Admin accounts. These accounts SHALL require WebAuthn MFA and SHALL work when all IdPs are unavailable.
- F-001-AC-43: Every break-glass login SHALL emit a high-severity audit event and a notification on all configured channels.
- F-001-AC-44: Break-glass accounts SHALL NOT have access to risk data.
- F-001-AC-45: Disabling break-glass SHALL take effect immediately, SHALL require no approval, and SHALL terminate any active break-glass sessions.
- F-001-AC-46: WHILE break-glass is disabled, THE SYSTEM SHALL document the IdP-outage recovery path (an operator procedure run with cluster-level access that is itself audited) in the installation and operations guides.

### F-001-R-12 Failed authentication
- F-001-AC-47: WHEN local or break-glass login fails a configurable number of consecutive times (default 3 within 15 minutes), THE SYSTEM SHALL lock the account.

### F-001-R-13 Access reviews
- F-001-AC-48: THE SYSTEM SHALL produce entitlement reports covering user, role (built-in or custom, with its permission list), BU, restricted flag, mapped vs. manual, granted by, granted on, last login, expiry, and break-glass status. Reports SHALL be filterable and exportable as CSV/PDF.
- F-001-AC-49: THE SYSTEM SHALL support recorded access review campaigns in which reviewers certify or revoke each assignment, with every decision audited.

### F-001-R-14 Security events
- F-001-AC-50: THE SYSTEM SHALL emit structured events for authentication, sessions, role and permission changes, BU and restriction changes, break-glass enablement and use, token lifecycle, SCIM operations, and configuration changes. These events SHALL go to the F-002 audit trail and to OTLP/syslog.

### F-001-R-15 Custom roles
**As a** Platform Admin, **I want** to define roles from the permission catalog, **so that** access matches our operating model.
- F-001-AC-51: THE SYSTEM SHALL let a Platform Admin create, clone (from built-in or custom roles), edit, and retire custom roles composed from catalog permissions.
- F-001-AC-52: Built-in roles SHALL NOT be editable or deletable. They SHALL be clonable.
- F-001-AC-53: IF a custom role contains a conflicting permission pair under the active SoD rule set, THEN THE SYSTEM SHALL block saving it unless a second Platform Admin approves an exception, with a reason and an expiry date.
- F-001-AC-54: Permissions classed as *privileged* (admin, approval, export, and audit-log access) SHALL be visibly flagged. Adding one to a role SHALL emit a high-severity audit event.
- F-001-AC-55: Role changes SHALL be versioned. THE SYSTEM SHALL show a before/after diff and the number of users affected before a change is saved.
- F-001-AC-56: A role assigned to anyone SHALL NOT be retired until its assignments are moved to another role.
- F-001-AC-57: WHEN a new platform version adds permissions to the catalog, THE SYSTEM SHALL NOT add them to existing custom roles automatically (deny by default), and SHALL notify admins of the new permissions.
- F-001-AC-58: Custom role definitions SHALL be exportable and importable as JSON, so they can be promoted between instances (e.g., test → production).

### F-001-R-16 Restricted business units
**As a** Platform Admin, **I want** sensitive BUs (e.g., M&A, Legal, special programs) to be shielded from inherited access, **so that** only explicitly authorized people can see their risk data.
- F-001-AC-59: Any BU node SHALL be able to be marked **Restricted**.
- F-001-AC-60: WHEN a BU is Restricted, assignments made at ancestor nodes SHALL NOT inherit into it or its descendants. Access SHALL require an assignment at or below the restricted node.
- F-001-AC-61: The instance setting "New BUs are restricted" SHALL default to **ON**. A Platform Admin SHALL be able to change it.
- F-001-AC-62: Ancestor roll-ups SHALL show a restricted BU's contribution according to a per-BU setting: **Excluded** (the default), **Aggregate only** (totals with no record detail), or **Full**.
- F-001-AC-63: Un-restricting a BU, or loosening its roll-up visibility, SHALL require a stated reason and a second Platform Admin's approval, and SHALL emit a high-severity audit event. Restricting a BU SHALL take effect immediately with no approval.
- F-001-AC-64: Auditors SHALL see restricted BUs only when they hold an explicit assignment there. Entitlement reports SHALL list every restricted BU and everyone with access to it.

## Secure defaults (ADR-006)
| Setting | Default | Loosening |
|---|---|---|
| MFA required | On | Cannot be disabled for privileged permissions |
| Just-in-time provisioning | Off | Admin action + audit |
| TOTP (bundled Keycloak) | Off | Admin action + audit |
| New BUs restricted | On | Admin action + audit |
| Restricted BU roll-up | Excluded | Dual approval + audit |
| Session idle / absolute | 15 min / 12 h | Configurable; out-of-profile values warned and flagged |
| Token maximum lifetime | 90 days | Within profile bounds |
| Login banner | On | Admin action + audit |
| Break-glass accounts | **Disabled** | At install: explicit opt-in + reason. After install: dual approval + audit |

## Non-functional requirements
- Authorization decisions: p95 ≤ 10 ms. Permission and role changes take effect within 60 s.
- All cryptographic operations use FIPS 140-validated modules.
- Failure of one IdP does not affect users of other IdPs. If break-glass is enabled, it remains available.
- Scale: 10k users, 2k BU nodes, 50k assignments, and 200 custom roles per instance.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| IdP | Customer IdP | Customer IdP or bundled Keycloak | Same, with uploaded metadata |
| SCIM | Inbound from customer IdP | Same | IdP must be inside the enclave |
| Break-glass | Off by default; enablement is a customer decision recorded in the onboarding record | Off by default; installer opt-in | Same |
| Break-glass alerts | Email + webhook | Customer SMTP/webhook | Internal relay |
| IdP-outage recovery without break-glass | Vendor operations runbook, customer-approved, audited | Customer operator procedure with cluster access | Same |
| PIV/CAC | Via IdP | Via IdP or Keycloak X.509 | Same |

## Control mapping (NIST SP 800-53r5)
AC-2, AC-2(1), AC-2(2), AC-2(3), AC-2(4), AC-3, AC-3(7), AC-5, AC-6, AC-6(1), AC-6(5), AC-6(9), AC-7, AC-8, AC-11, AC-12, CM-6, CM-7, IA-2, IA-2(1), IA-2(2), IA-2(8), IA-2(12), IA-4, IA-5, IA-8, AU-2, AU-12. Mappings to CMMC, ISO, and SOC are maintained via the F-013 crosswalk.

## Out of scope
- Approval authority limits (F-008)
- Audit storage (F-002)
- Security profile engine and posture page (F-015). F-001 consumes its bounds.
- Installer UX for break-glass opt-in (F-014). F-001 defines the behavior.

## Open Questions
None.

## Resolved
- SCIM required for v1 (2026-10-24)
- Custom roles required (2026-10-24)
- Restricted BUs supported, with secure defaults and customer-adjustable settings (2026-10-24)
- Session defaults confirmed (15 min idle / 12 h absolute), configurable (2026-10-24)
- Break-glass disabled by default (2026-10-24)

## Change Log
- 2026-10-24: Initial draft.
- 2026-10-24: SCIM made mandatory for v1, JIT provisioning off by default; added R-15 (custom roles) and R-16 (restricted BUs); session settings bound to security profiles; added Secure defaults section.
- 2026-10-24: Break-glass disabled by default, with opt-in at install or dual-approved enablement after install; IdP-outage recovery path added; acceptance criteria renumbered (now AC-01 to AC-64).
- 2026-10-24: **Approved** by Robert Former.
