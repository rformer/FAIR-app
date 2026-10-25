# F-015 Security Posture & Configuration Profiles — Requirements
Status: **Approved** (Robert Former, 2026-10-24) | Owner: Robert Former | Last updated: 2026-10-24
Constitution refs: S0, S1, P5, P6, M3, A7 | ADRs: 004, 005, 006

## Summary
F-015 makes the platform secure by default, and makes that status visible. It provides:
- **Security configuration profiles**, built as data from OSCAL baselines.
- A **settings registry**, which every feature uses to declare its security-relevant settings and their bounds.
- A controlled workflow for **changing settings, loosening them, and switching profiles**.
- **Drift detection** for both application settings and the Kubernetes deployment.
- A **Security Posture page**, with **evidence export in OSCAL format**.

Customers can tighten or loosen any setting above the hard floor. Every deviation is explained, approved where required, audited, visible, time-limited, and exported as evidence.

## Concepts
- **Setting:** a security-relevant configuration key registered by a feature. A setting declares its type, default, whether it can be scoped to a business unit (BU), its loosening direction (which values count as weaker), and the control parameters it implements.
- **Profile:** a named set of defaults and allowed bounds for every setting. Profiles ship as versioned, signed **profile packages** generated from OSCAL baselines plus parameter bindings.
- **Built-in profiles (v1):** *FedRAMP Moderate* (the install default), *CMMC L2*, and *Enterprise Baseline*.
- **Custom profile:** a customer-defined profile derived from a built-in one. It may tighten or loosen settings relative to its base.
- **Deviation:** an effective value weaker than the active profile's bound, or a custom-profile value weaker than its base.
- **Exception:** a deviation that has been explicitly accepted, with a reason, an approver, and an expiry.
- **Hard floor:** settings that no profile, override, or exception can weaken (R-08).

## Requirements

### F-015-R-01 Settings registry
- F-015-AC-01: Every feature SHALL register its security-relevant settings in the registry at startup or migration time. Each registration SHALL declare:
  - key and type
  - default for each built-in profile
  - bounds for each profile
  - whether the setting is BU-scopable
  - loosening direction
  - hard-floor flag
  - mapped control parameters (OSCAL parameter IDs)
- F-015-AC-02: THE SYSTEM SHALL reject any change to a registered setting that does not go through the registry change API (`settings.Set`). Direct database writes to registered settings SHALL be blocked at the data layer.
- F-015-AC-03: THE SYSTEM SHALL expose the full registry through the API and on the Posture page, showing for each setting its current value, source, bound, and deviation status.

### F-015-R-02 OSCAL-driven built-in profiles
- F-015-AC-04: Built-in profiles SHALL be generated from OSCAL catalogs and profiles (NIST SP 800-53r5 and the FedRAMP Moderate baseline). Bindings SHALL map OSCAL parameters (for example, the AC-11 lock time or the AC-7 attempt limit) to registry settings.
- F-015-AC-05: Profile packages SHALL be versioned and signed, SHALL ship with each release, and SHALL be importable offline.
- F-015-AC-06: THE SYSTEM SHALL support new profiles (for example, FedRAMP High or DoD IL4/IL5) through import of a new profile package. No code change SHALL be required unless the new profile introduces new settings.
- F-015-AC-07: WHEN a newer version of the active built-in profile is installed, THE SYSTEM SHALL show the differences and SHALL handle any resulting changes under R-05.
- F-015-AC-08: **v1 sequencing:** profile packages SHALL be generated at build time from the published NIST and FedRAMP OSCAL files. Runtime use of the F-013 control library is NOT required for v1. Once F-013 exists, profile generation SHALL migrate to it without changing the package format.

### F-015-R-03 Profile selection at install
- F-015-AC-09: The installer SHALL require the operator to select a profile, with **FedRAMP Moderate** as the default.
- F-015-AC-10: THE SYSTEM SHALL seed all settings from the selected profile and SHALL audit the seeding.

### F-015-R-04 Custom profiles
- F-015-AC-11: A user with `profile.manage` SHALL be able to derive a custom profile from any built-in profile, and to tighten or loosen any setting that is not on the hard floor.
- F-015-AC-12: Each loosened value SHALL require a written justification. Activating a custom profile SHALL require approval by a second, different person holding `profile.approve`.
- F-015-AC-13: THE SYSTEM SHALL show each custom profile's deviations from its base profile and the control parameters they affect. Wherever conformance is displayed or exported, the profile SHALL be labeled **"Deviates from <base>"**.
- F-015-AC-14: Custom profiles SHALL be versioned and diffable, and SHALL be exportable and importable as JSON and as OSCAL profiles.
- F-015-AC-15: WHEN a base profile is updated, THE SYSTEM SHALL show the effect on each derived custom profile. A derived profile SHALL NOT silently inherit any value weaker than the one it currently has.

### F-015-R-05 Switching profiles (gated activation)
- F-015-AC-16: WHEN a profile switch is requested, THE SYSTEM SHALL compute and present every current setting that falls outside the new profile's bounds as a **conflict**.
- F-015-AC-17: THE SYSTEM SHALL NOT activate the new profile until every conflict is explicitly resolved. A conflict is resolved either by conforming the setting to the new bound or, for settings not on the hard floor, by recording an exception with a reason, an approver, and an expiry.
- F-015-AC-18: WHILE a switch is pending, the current profile SHALL remain in force. The Posture page SHALL show the pending switch and its unresolved conflicts.
- F-015-AC-19: Switching to a profile with weaker bounds is a loosening. It SHALL require a justification and dual approval, and SHALL emit a high-severity audit event.

### F-015-R-06 Changing settings
- F-015-AC-20: WHEN a change is within the active profile's bounds, THE SYSTEM SHALL apply it and audit it.
- F-015-AC-21: WHEN a change is outside the active profile's bounds, THE SYSTEM SHALL require a written explanation, show an explicit warning naming the affected controls, and require dual approval. On approval it SHALL apply the change as an exception, emit a high-severity audit event, and flag the exception on the Posture page.
- F-015-AC-22: Tightening a setting SHALL take effect immediately, with no approval required.
- F-015-AC-23: In SaaS mode, any weakening change SHALL also notify the vendor's security operations channel. Vendor approval is NOT required.

### F-015-R-07 Exception lifecycle (auto-revert at expiry)
- F-015-AC-24: Every exception SHALL have an expiry. The default SHALL be 90 days, configurable within the profile's bounds. No exception SHALL be open-ended.
- F-015-AC-25: THE SYSTEM SHALL notify the exception owner and admins 14, 7, and 1 day(s) before expiry.
- F-015-AC-26: An exception SHALL be renewable only before it expires, through a new justification and dual approval. A renewal SHALL create a new exception record linked to the original.
- F-015-AC-27: WHEN an exception expires without renewal, THE SYSTEM SHALL **automatically revert the setting to the active profile's value** (or, for a BU override, to the inherited value), emit a high-severity audit event, notify the owner and admins, and record the revert on the Posture page.
- F-015-AC-28: Reverts SHALL take effect within 60 seconds. IF a revert would end active sessions (for example, a shorter session timeout), THEN those sessions SHALL be terminated at their next request, following the new value, with no grace period.
- F-015-AC-29: IF a revert fails (for example, a dependency is unavailable), THEN THE SYSTEM SHALL retry, raise a critical drift finding, and keep the finding open until the revert succeeds. The setting SHALL NOT remain silently out of bounds.

### F-015-R-08 Hard floor
- F-015-AC-30: The following settings SHALL be on the hard floor, and no profile, custom profile, BU override, or exception SHALL be able to weaken them:
  - TLS disabled or below TLS 1.2
  - audit logging disabled
  - MFA disabled for privileged permissions
  - FIPS mode disabled under any profile derived from FedRAMP or CMMC
  - row-level security disabled or bypassed
- F-015-AC-31: Any attempt to weaken a hard-floor setting SHALL be refused and SHALL emit a high-severity audit event. A custom profile that weakens a hard-floor setting SHALL fail validation.

### F-015-R-09 BU-scoped settings
- F-015-AC-32: Settings flagged as BU-scopable SHALL accept overrides at any BU node. Overrides SHALL inherit down the tree the same way F-001 role assignments do, stopping at restricted BUs.
- F-015-AC-33: Every restricted BU (F-001 R-16) SHALL automatically receive the **Restricted BU overlay**. Its defaults SHALL be:
  - re-authentication within the last 15 minutes before accessing the BU's data
  - `session.network_binding = reauthenticate`
  - a stated reason required for exports
- F-015-AC-34: Customers SHALL be able to edit the overlay and per-BU overrides. Weakening either SHALL follow R-06 and R-07.
- F-015-AC-35: The effective value for a BU being accessed SHALL be the **strictest** of: the instance value, any inherited override, and the BU's own override.

### F-015-R-10 Application drift detection
- F-015-AC-36: THE SYSTEM SHALL continuously compare effective settings against the active profile, taking approved exceptions into account. The comparison SHALL run on every change and at least every 15 minutes.
- F-015-AC-37: WHEN an unapproved deviation is detected, THE SYSTEM SHALL raise a drift finding, emit a high-severity event to the audit trail and the SIEM export, and show the finding on the Posture page.

### F-015-R-11 Deployment drift detection
- F-015-AC-38: In SaaS mode, deployment drift detection SHALL always be on.
- F-015-AC-39: In self-hosted mode, the installer SHALL request a **read-only** Kubernetes role scoped to the platform namespaces, plus any required cluster-level reads, and SHALL list each permission with its purpose.
- F-015-AC-40: IF the customer declines this access, THEN THE SYSTEM SHALL:
  - disable deployment drift detection
  - show a persistent warning on the Posture page
  - audit the decision
  - mark deployment controls as **"Not assessed"** in OSCAL exports

  The customer SHALL be able to grant the access later.
- F-015-AC-41: Deployment checks SHALL include at minimum:
  - pod security admission level
  - presence of NetworkPolicies
  - TLS versions and certificate expiry
  - node FIPS mode, where the profile requires it
  - image signature verification, and running image digests matching the release bundle
  - containers running as non-root with a read-only root filesystem
  - encrypted storage classes
  - secrets referenced from a secrets store rather than set as plaintext values
  - changes to the platform's own RBAC
- F-015-AC-42: Each deployment finding SHALL include a severity, the affected controls, and remediation guidance. Automatic remediation of deployment drift is out of scope for v1.

### F-015-R-12 Security Posture page
- F-015-AC-43: THE SYSTEM SHALL provide a Posture page, visible to holders of `posture.view`, showing:
  - the active profile and its conformance
  - deviations and exceptions, with their owners and expiry dates
  - upcoming expiries and recent auto-reverts
  - pending profile switches and their conflicts
  - drift findings
  - Kubernetes access status
  - per-control status
- F-015-AC-44: Every item on the page SHALL link to its audit history and to its remediation or approval action.

### F-015-R-13 OSCAL evidence export
- F-015-AC-45: THE SYSTEM SHALL export current posture as **OSCAL Assessment Results**, including effective settings per control parameter, drift findings, and "Not assessed" items.
- F-015-AC-46: THE SYSTEM SHALL export open exceptions and deviations as **OSCAL POA&M** items, each with its justification, approver, and expiry.
- F-015-AC-47: Exports SHALL be signed and timestamped, SHALL be reproducible from the audit trail, and SHALL validate against the published OSCAL schemas.
- F-015-AC-48: Exports SHALL reference the platform's OSCAL component definition (F-014).

## Permissions added to the F-001 catalog
`posture.view`, `settings.change`, `settings.approve` (privileged), `profile.manage` (privileged), `profile.approve` (privileged), `posture.export` (privileged), `exception.renew`, `drift.acknowledge`

## Secure defaults
| Setting | Default |
|---|---|
| Install profile | FedRAMP Moderate |
| Weakening a setting | Explanation, warning, dual approval, and high-severity audit |
| Exception expiry | 90 days, then **automatic revert** |
| Expiry notices | 14, 7, and 1 day(s) before expiry |
| Restricted BU overlay | On for every restricted BU |
| Drift scan | On every change, and at least every 15 minutes |
| Deployment drift (SaaS) | Always on |
| Deployment drift (self-hosted) | Requested at install; disabled with a persistent warning if declined |
| Hard floor | TLS ≥ 1.2, audit on, privileged MFA, FIPS (FedRAMP/CMMC-derived profiles), RLS |

## Non-functional requirements
- Setting changes and reverts take effect across all services within 60 s.
- An application drift scan completes in ≤ 30 s at target scale.
- A full OSCAL export completes in ≤ 60 s.
- All signing uses FIPS-validated algorithms.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Profile packages | Delivered with releases | Delivered in the bundle | Imported offline |
| Deployment drift | Always on | Opt-in Kubernetes access; warning if declined | Same as self-hosted |
| Weakening notifications | Customer admins and vendor SecOps | Customer admins | Customer admins (via internal relay) |
| Expiry notices and revert alerts | Email and webhook | Customer SMTP or webhook | Internal relay |
| OSCAL export | Download or API | Same | Same |

## Control mapping (NIST SP 800-53r5)
CM-2, CM-2(2), CM-3, CM-3(1), CM-5, CM-6, CM-6(1), CM-6(2), CM-7, CA-2, CA-5, CA-7, CA-7(4), SI-4, AU-6, PL-2. Crosswalks to other frameworks are provided by F-013.

## Out of scope
- Installer UI and preflight checks (F-014)
- The full OSCAL control library (F-013); v1 uses build-time generation (AC-08)
- Automatic remediation of deployment drift

## Resolved
- Custom profiles may tighten or loosen settings, with labeling and dual approval; FedRAMP High and DoD profiles can be added later via packages (2026-10-24)
- Bounds are derived from OSCAL parameters (2026-10-24)
- Profile switches are gated until every conflict is explicitly resolved (2026-10-24)
- Drift detection covers both application settings and the deployment; self-hosted Kubernetes access is opt-in, with a warning if declined (2026-10-24)
- Weakening any setting requires an explanation, an audit warning, and dual approval (2026-10-24)
- BU scoping is customer-configurable, restrictive by default for restricted BUs (2026-10-24)
- Evidence exports use OSCAL Assessment Results and POA&M (2026-10-24)
- OQ1: hard floor **kept** (2026-10-24)
- OQ2: expired exceptions **automatically revert** (2026-10-24)
- OQ3: SaaS weakening **notifies** vendor SecOps; vendor approval not required (2026-10-24)
- Sequencing: profile packages are generated at build time for v1 (2026-10-24)

## Change Log
- 2026-10-24: Initial draft.
- 2026-10-24: Open questions resolved. Added R-07 (exception lifecycle with automatic revert); added the v1 build-time sequencing criterion (AC-08); renumbered criteria (AC-01 to AC-48).
- 2026-10-24: **Approved** by Robert Former.
