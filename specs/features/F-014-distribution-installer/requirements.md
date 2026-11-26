# F-014 Distribution, installer & licensing — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-26

## Summary
F-014 is how a customer runs the platform inside their own boundary (constitution M3, ADR-005): on their own Kubernetes cluster, connected or air-gapped, from the same signed release the SaaS fleet runs (F-012). A release becomes a Helm chart and an air-gap package that carry every image, dependency, tool and document an install needs, verifiable offline with the release key alone. The installer turns ADR-006's "secure by deployment" into behaviour: it verifies the release, generates every credential and key, records the install-time decisions other features defer to it (deployment mode, security profile, currency, break-glass, the posture scanner's access), and runs preflight checks that refuse an insecure install rather than warn about it. Those checks are the same rules F-015 applies to the running deployment, so a configuration accepted before install is not reported as drift after it, and the reverse. A signed licence file is verified offline and never gates or weakens a security control; when it lapses, no data is lost or hidden. Self-hosted upgrades go forward from the supported earlier releases with the same checks; backup and restore cover the database, the object stores (including the write-once audit archives) and the keys, and a restore is verified, audit trail included, before it is used. Each release publishes the platform's OSCAL component definition and customer responsibility matrix, built from every feature's signed-off control statements, so a customer's System Security Plan and CMMC assessment can inherit them (S1). Uninstalling keeps what retention requires and records what was destroyed.

## Users & roles affected
- **Self-hosted administrators** (customer staff with cluster and database administration rights): verify, install, upgrade, back up, restore and uninstall the platform; act for the installation before any user can sign in.
- **Platform Admins** (in the application): see the install report, licence, backup and preflight status; install a renewed licence (OQ15).
- **Customer security teams and assessors**: review preflight results and overrides before a change window; use the component definition and responsibility matrix in their SSP and assessments.
- **Customer auditors**: rely on the audit trail across upgrades, restores and decommissioning.
- **Vendor licensing staff**: issue licences for an installation; never reach the installation.
- **Release managers** (vendor staff): publish the chart, the air-gap package and the component definition with each release (F-012).

## User stories
### F-014-R-01 A complete, verifiable distribution
**As a** self-hosted administrator, **I want** each release as a chart and an air-gap package that hold everything the platform needs, **so that** I can install it in my own boundary, connected or not, and prove it is the vendor's.

**Acceptance criteria (EARS):**
- F-014-AC-01: WHEN a release is published, THE SYSTEM SHALL publish with it a Helm chart installing every platform component, with an option for each dependency to be bundled or brought (ADR-005's table: PostgreSQL, NATS JetStream, object storage, identity provider, key store, observability), and an air-gap package (OQ1) holding the chart, every image an install of any option can run (the platform's and the bundled third parties'), their SBOMs, signatures and provenance attestations, the signed release manifest, the release public key, the verification tools (F-012-AC-09), `fair-audit-verify` (F-002), the installer (OQ2), the shipped content (profile packages, frameworks, starter library, question bank, network-binding ASN data), the OSCAL component definition and responsibility matrix (R-07) and the documentation (R-09), with a signed list of their digests.
- F-014-AC-02: THE SYSTEM SHALL sign the chart and the air-gap package keylessly and with the release key, like the images (F-012-AC-08, AC-09), so that both verify with the release public key alone and without network access; and the release gate SHALL refuse to publish a chart or package whose images, digests or RBAC differ from the release manifest.
- F-014-AC-03: THE SYSTEM SHALL keep in the chart the hardening of the reference manifests (non-root, read-only root filesystem, capabilities dropped, default-deny network policies, restricted pod security, no service account token unless needed, key files mounted read-only), and the release pipeline SHALL check every option's rendered objects against F-015's deployment checks and refuse a release whose chart would fail one.
- F-014-AC-04: THE SYSTEM SHALL name every image by digest in the chart and the package, so that the images that run are the ones signed whichever registry the administrator pulls them from, and SHALL let the administrator load the package into a private registry without network access to the vendor.
- F-014-AC-05: THE SYSTEM SHALL make an install, an upgrade, a backup and a restore from the air-gap package complete without any outbound connection, and the release pipeline SHALL prove it by installing and upgrading the package in a cluster with no egress (constitution Q4, A7).
- F-014-AC-06: THE SYSTEM SHALL support installation on upstream Kubernetes, EKS, AKS, GKE, OpenShift (restricted security context constraints, arbitrary user IDs) and RKE2, at the Kubernetes versions each release names (OQ14), and the release pipeline SHALL install on each distribution it tests in both bundled and brought configurations (Q4).

### F-014-R-02 The installer
**As a** self-hosted administrator, **I want** one installer that verifies the release, asks for every decision the platform needs and provisions everything the services expect, **so that** a fresh install starts in its most restrictive sensible state with nothing left to configure by hand.

**Acceptance criteria (EARS):**
- F-014-AC-07: WHEN an administrator installs or upgrades, THE SYSTEM SHALL verify the release's signatures, attestations and digests before anything is deployed, offline in air-gapped mode, and SHALL refuse a release that is unsigned, tampered or signed by another key.
- F-014-AC-08: WHEN an administrator installs, THE SYSTEM SHALL require them to state, before anything is deployed: the deployment mode (self-hosted or air-gapped, ADR-005); the security profile, defaulting to FedRAMP Moderate (F-015-AC-09); the installation currency (F-003-AC-07); the first identity provider or the bundled Keycloak (F-001-AC-06); whether the posture scanner receives its read-only Kubernetes access, showing its permission manifest with each permission's purpose (F-015-AC-39, AC-40); how node FIPS mode is evidenced, by the probe or by attestation (F-015-AC-41); and whether break-glass is enabled, off by default and only with a stated reason (F-001-AC-39, AC-40).
- F-014-AC-09: THE SYSTEM SHALL record each install-time decision, and each fact the administrator attests rather than the cluster shows (such as node FIPS mode, cluster-wide pod security or storage encryption), in the install log and, once it exists, the audit trail, and SHALL show attested facts as "attested, not verified" wherever F-015 reports them.
- F-014-AC-10: THE SYSTEM SHALL generate every credential and key at install (database role passwords, service signing keys, the database-context key, the posture MAC key, the audit checkpoint keys, the export and report keys, internal TLS unless the customer's CA issues it) from the FIPS 140 module, deliver them only into the mode's key store (F-001 T-41, `docs/install/keys.md`), and SHALL never print them, write them to chart values, release records or logs, or share one between installations (ADR-006).
- F-014-AC-11: THE SYSTEM SHALL provision what the services require and refuse to create themselves: the database roles, the migrations and release content, the recorded deployment mode, the seeded security profile (audited, F-015-AC-10), the JetStream streams, the object storage buckets with their Object Lock or versioning, the release manifest the scanner reads, and the scanner only where access was granted.
- F-014-AC-12: IF an install is interrupted or a step fails, THEN THE SYSTEM SHALL report which steps completed and SHALL let the administrator resume it, never regenerating an existing key, re-seeding a seeded profile or re-recording a decision, or remove what it created.
- F-014-AC-13: WHEN an install completes, THE SYSTEM SHALL produce an install report (the release, every decision and attestation, every preflight result and override, what was provisioned), readable as text and as a machine-readable file, and SHALL show it to Platform Admins in the application.
- F-014-AC-14: THE SYSTEM SHALL let the whole install run unattended from a decisions file as well as interactively, refusing a decisions file that contains a secret.

### F-014-R-03 Preflight checks that refuse insecure installs
**As a** customer security team, **I want** the installer to refuse an insecure cluster or dependency rather than warn about it, **so that** the platform is never running below the posture we chose.

**Acceptance criteria (EARS):**
- F-014-AC-15: WHEN an administrator installs or upgrades, THE SYSTEM SHALL first run the preflight checks against the target cluster and dependencies, and SHALL refuse to proceed while any check fails, naming for each failure the check, what it found, the affected controls and the remediation.
- F-014-AC-16: THE SYSTEM SHALL check at least: pod security admission enforcing restricted on the platform's namespaces; a network plugin that enforces NetworkPolicies, including default deny; encrypted storage classes for platform volumes; FIPS mode on the nodes where the profile requires it; admission control verifying image signatures; secrets coming from a secret store and none in chart values; TLS 1.2 or later with approved suites and certificates valid for at least 30 days on every platform endpoint; the Kubernetes version and distribution supported.
- F-014-AC-17: THE SYSTEM SHALL also check the dependencies, bundled or brought: PostgreSQL 16 or later, reachable only over verified TLS 1.2 or later, running its cryptography in FIPS mode where the profile requires FIPS, with the platform's roles present and none of them a superuser, an owner of platform tables or able to bypass row-level security; the key store reachable and key files readable by their service only; the audit store supporting compliance-mode Object Lock and the report store versioned (F-002, F-010), and the write-once checkpoint copy present where required (F-002-AC-10); NATS JetStream over TLS 1.2 or later; capacity and quotas for the audit trail and the database at the sized volume (F-002-AC-30, R-09); clocks synchronized within `audit.max_clock_skew`; and, in air-gapped mode, no egress path from the platform's namespaces.
- F-014-AC-18: THE SYSTEM SHALL evaluate every check that F-015's deployment drift detection also runs (F-015-AC-41) by the same rule with the same result, so that a configuration preflight accepts is not then reported as drift and one that drift would report is not accepted; a test SHALL hold the two equal.
- F-014-AC-19: IF a check on the hard floor fails (TLS below 1.2 or plaintext on any platform connection, FIPS on nodes or in the database under a FedRAMP- or CMMC-derived profile, no audit store with Object Lock, a platform role that can bypass row-level security, key material in plaintext values or readable by others, a release that does not verify), THEN THE SYSTEM SHALL refuse the install or upgrade with no override (ADR-006 Amendment 1, F-015-AC-30).
- F-014-AC-20: IF a check not on the hard floor fails, THEN THE SYSTEM SHALL proceed only on an explicit override naming the check and giving a reason, SHALL record it in the install log and the audit trail at high severity, and SHALL make it an expiring deployment exception shown on the Posture page and in the POA&M export (F-015-AC-24, AC-46; OQ5).
- F-014-AC-21: THE SYSTEM SHALL let an administrator run the preflight checks alone, with read-only access and without installing anything, and give the same report, so a security team can review it before a change window.

### F-014-R-04 Offline licensing
**As a** self-hosted administrator, **I want** the licence to be a signed file verified inside my boundary, **so that** licensing never needs a connection, never weakens security and never puts our data at risk.

**Acceptance criteria (EARS):**
- F-014-AC-22: THE SYSTEM SHALL accept a licence only as a file signed by the vendor's licence key (OQ7) and SHALL verify it offline against the public key shipped in the release, in every deployment mode; THE SYSTEM SHALL never contact the vendor to check or report a licence.
- F-014-AC-23: THE SYSTEM SHALL bind each licence to a customer, a licence identifier, the installation it was issued for (OQ6), the deployment modes it permits, its start and end dates and the date its update entitlement ends (OQ8), and SHALL refuse, and record in the audit trail, a licence that is unsigned, altered, for another installation or mode, or not yet valid.
- F-014-AC-24: THE SYSTEM SHALL never make any security control, setting or feature (SSO, MFA, SCIM, audit, RBAC, row-level security, posture, notifications of security events) depend on the licence, and SHALL never loosen a setting or disable a control because of the licence's state (ADR-006).
- F-014-AC-25: WHEN a licence is within 60, 30, 14 and 7 days of its end, THE SYSTEM SHALL notify the Platform Admins (F-009) and show the date to them in the application.
- F-014-AC-26: WHEN a licence ends, THE SYSTEM SHALL keep working fully for a grace period (OQ9) with a notice to every Platform Admin, and WHEN the grace period ends without a new licence, THE SYSTEM SHALL enter a limited state (OQ9) in which it keeps signing users in, showing and exporting all data, recording, verifying and forwarding the audit trail, enforcing and reverting security settings, expiring and renewing risk acceptances, sending notifications, and backing up and restoring, and SHALL never delete, hide or alter data.
- F-014-AC-27: WHEN a valid licence is installed, THE SYSTEM SHALL apply it at once, without a restart or loss of work, and leave the limited state if it was in it.
- F-014-AC-28: THE SYSTEM SHALL record licence installs, replacements, refusals, expiry, the start and end of grace and of the limited state in the audit trail.

### F-014-R-05 Self-hosted upgrades
**As a** self-hosted administrator, **I want** upgrades from the releases we may be running, with the same checks as an install and a way back, **so that** upgrading never leaves the platform insecure, broken or missing data.

**Acceptance criteria (EARS):**
- F-014-AC-29: THE SYSTEM SHALL upgrade an installation from each supported earlier release (F-012-AC-12, OQ10), SHALL refuse an upgrade from any other release naming the release to upgrade to first, and SHALL refuse a downgrade.
- F-014-AC-30: WHEN an upgrade starts, THE SYSTEM SHALL verify the new release (AC-07), run the new release's preflight checks (R-03), check that the licence's update entitlement covers the new release (OQ8), and check that a backup verified within the agreed time exists or take one (OQ11), and SHALL refuse to change anything if one of these fails.
- F-014-AC-31: WHEN an upgrade proceeds, THE SYSTEM SHALL apply the new release's database roles, keys, migrations and release content, streams and buckets, show the changes in the active profile's package (F-015-AC-07), and ask again for the posture scanner's access when its permission manifest changed, before the new services start.
- F-014-AC-32: THE SYSTEM SHALL show the administrator, before an upgrade, the release notes of every release it crosses (migrations, settings and permission catalog changes, scanner permissions, security fixes; F-012-AC-12) and the expected interruption (OQ10).
- F-014-AC-33: IF an upgrade fails after migrations ran, THEN THE SYSTEM SHALL let the administrator roll back to the previous release's images without data loss (migrations forward-only and compatible with the previous release's code, F-012-AC-13, AC-21); a return to the schema before the upgrade SHALL be possible only by restore (R-06, ADR-005).
- F-014-AC-34: THE SYSTEM SHALL record each upgrade's start, outcome and rollback, with both releases, in the audit trail, and the audit trail SHALL verify across the upgrade.

### F-014-R-06 Backup and restore
**As a** self-hosted administrator, **I want** to back up everything the platform keeps and restore it with proof that nothing was lost or altered, **so that** a failure or disaster costs no records and no evidence.

**Acceptance criteria (EARS):**
- F-014-AC-35: THE SYSTEM SHALL back up, on the administrator's schedule and on demand, the database, the object stores (the audit store with its archives and exports, the write-once checkpoint copies where configured, the report store), the key material and the installation's configuration (decisions, licence), consistently, so that they restore to one point in time (OQ11).
- F-014-AC-36: THE SYSTEM SHALL encrypt every backup with FIPS-validated cryptography under a key the customer holds, protect its integrity with a signed digest, write it to a destination the administrator chooses (including removable media in air-gapped installs), and SHALL never put key material in a backup unencrypted or beside the data it protects (OQ12).
- F-014-AC-37: THE SYSTEM SHALL keep the retention dates and legal holds of write-once audit objects through backup and restore, and a restore SHALL never shorten a retention or release a hold (F-002-AC-27, AC-29).
- F-014-AC-38: WHEN a restore completes, THE SYSTEM SHALL check it before anyone may use it: the database's consistency, the posture rows' MACs, a full audit trail verification including archives (F-002-AC-11, AC-26), and every stored object the database references present with its digest; IF a check fails, THEN THE SYSTEM SHALL keep the installation closed and report the failure.
- F-014-AC-39: WHEN a restore returns the audit trail to a point before checkpoints already sent outside the platform (to the SIEM or write-once storage, F-002-AC-10), THE SYSTEM SHALL record the restore in the trail with the restored head and the checkpoints after it, so that the trail stays verifiable and the loss is visible and distinguishable from tampering (OQ13).
- F-014-AC-40: THE SYSTEM SHALL restore onto a new cluster as the same installation, with its licence and keys valid, and record the restore in the audit trail.
- F-014-AC-41: IF a scheduled backup fails or the newest verified backup is older than its schedule allows, THEN THE SYSTEM SHALL raise a finding on the Posture page and notify the Platform Admins (F-009).
- F-014-AC-42: THE SYSTEM SHALL ship a restore drill procedure and record format, and the release pipeline SHALL back up and restore a representative installation, bundled and brought, and pass the AC-38 checks.

### F-014-R-07 OSCAL component definition and responsibility matrix
**As a** customer assessor, **I want** each release to state, in OSCAL, how the platform implements each control and what is left to us, **so that** our SSP and assessments can inherit it.

**Acceptance criteria (EARS):**
- F-014-AC-43: WHEN a release is published, THE SYSTEM SHALL publish, signed and in the air-gap package, the platform's OSCAL component definition built from every feature's control implementation statements (`compliance/statements/`), defining the platform component under `posture.PlatformComponentUUID` and validating against the pinned OSCAL schema.
- F-014-AC-44: THE SYSTEM SHALL refuse to publish a release whose statements include one not signed off, one that fails its checks (controls, responsibilities per mode, the customer's part, evidence that exists), or a feature in the release with none.
- F-014-AC-45: THE SYSTEM SHALL publish with the component definition a customer responsibility matrix built from the same statements, giving for each control and deployment mode whether the provider, the customer or both are responsible and the customer's part, as an accessible document and as CSV and JSON.
- F-014-AC-46: THE SYSTEM SHALL make the Assessment Results and POA&M exports of an installation (F-015-AC-45 to AC-48) reference the component definition of the release it runs, by version and digest, so that each export resolves against a published document.

### F-014-R-08 Uninstall and decommissioning
**As a** self-hosted administrator, **I want** to remove the platform without losing what we must keep, and to destroy data only deliberately and with a record, **so that** retention, legal holds and audit evidence survive the platform.

**Acceptance criteria (EARS):**
- F-014-AC-47: WHEN an administrator uninstalls, THE SYSTEM SHALL remove the platform's workloads and cluster objects and SHALL keep the database, the object stores, the keys and the backups unless the administrator destroys them as AC-49 allows, reporting what it kept.
- F-014-AC-48: THE SYSTEM SHALL let the administrator, before decommissioning, take and verify a final export of the customer's data (F-003, F-010) and an audit evidence export of the whole trail (F-002-AC-32), checked with `fair-audit-verify`, and record the decommissioning in the trail.
- F-014-AC-49: THE SYSTEM SHALL destroy data only by a separate, explicit step that names the installation and is confirmed, SHALL refuse to destroy audit records within the total retention period or under legal hold (F-002-AC-27, AC-29), and SHALL destroy keys only after the data they protect, keeping the public keys needed to verify the retained evidence.
- F-014-AC-50: WHEN decommissioning completes, THE SYSTEM SHALL produce a signed decommissioning record: what was destroyed and when, what is kept and until when, and the digests of the final exports.

### F-014-R-09 Documentation
**As a** self-hosted administrator, **I want** the guides for every task in the release itself, **so that** I can install, harden and operate the platform without the vendor or the internet.

**Acceptance criteria (EARS):**
- F-014-AC-51: THE SYSTEM SHALL ship with each release, versioned with it: install guides per supported distribution and per bundled or brought dependency, air-gapped installation, upgrade, backup and restore, licensing, uninstall and decommissioning, a sizing guide (database, audit storage quota, object stores), a hardening guide with a STIG-style checklist (ADR-006), the identity-provider outage recovery path (F-001-AC-46), the release verification guide and the responsibility matrix.
- F-014-AC-52: THE SYSTEM SHALL document every preflight check by its identifier with what it checks, its controls and its remediation, and a test SHALL fail when a check has no entry or an entry has no check.
- F-014-AC-53: THE SYSTEM SHALL make the documentation readable offline from the air-gap package and meet WCAG 2.1 AA (Q3).

### F-014-R-10 Usable, accessible installer and status
**As an** administrator who uses assistive technology or automation, **I want** the installer and the install, licence and backup status to be usable without sight of colour or a mouse, **so that** nobody is excluded from operating the platform.

**Acceptance criteria (EARS):**
- F-014-AC-54: THE SYSTEM SHALL give every installer prompt, check result and error as plain text that does not rely on colour, layout or animation, with a machine-readable equivalent and documented exit codes, usable by screen readers and in scripts (OQ2).
- F-014-AC-55: THE SYSTEM SHALL show the install report, the licence's state and dates, and the backup and preflight status to Platform Admins in the application, meeting WCAG 2.1 AA.

## Non-functional requirements
- Performance: the preflight checks complete within 5 minutes; an install from the air-gap package into a prepared cluster completes within 60 minutes after the images are in the registry; an upgrade keeps reads available and pauses writes for at most 15 minutes at target scale (OQ10); a restore of a target-scale installation, verification included, completes within 4 hours (as F-012 OQ8).
- Security / privacy: the installer and every tool it ships are built with the FIPS 140 module and verify the release before acting; the installer needs cluster administration only while it runs, and the running platform holds no cluster-wide write rights; generated secrets go only to the key store; the licence key is separate from the release key; nothing in the installer, preflight, licence or backup paths calls the vendor or the internet; install, preflight and backup logs carry no secrets or risk data (tested, as F-012-AC-23).
- Audit: install decisions and attestations, overrides, licence events, upgrades, backups, restores, uninstalls and destruction are events in the catalog (F-001 T-37); events before the trail exists are kept in the install log and recorded in the trail when it starts.
- Availability: install, upgrade and restore are resumable after interruption; a failed upgrade leaves a runnable release (AC-33); backups never stop the platform.
- Accessibility: installer output as AC-54; in-application pages and shipped documentation meet WCAG 2.1 AA and Section 508 (Q3).
- Secure defaults: nothing installs without verifying the release and passing preflight; the default profile is FedRAMP Moderate; break-glass is off; the posture scanner is requested with its permission manifest; telemetry is off and nothing calls home (F-012-AC-25); no default password or shared secret exists; hard-floor checks have no override; an override of any other check expires; data is kept on uninstall unless explicitly destroyed.

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Distribution | Fleet manifests from the release (F-012) | Helm chart from the vendor registry, or the air-gap package | Air-gap package only, loaded into a private registry |
| Release verification | Admission (F-012-AC-19) | By the installer, online or offline | By the installer, offline |
| Preflight checks | The same checks gate onboarding and promotion (OQ4) | Installer, before install and upgrade | Installer, plus no-egress check |
| Licence | OQ16 | Signed file, verified offline | Signed file, verified offline |
| Upgrades | Fleet rings (F-012) | Installer, from supported releases | Installer, from the package |
| Backup and restore | Vendor's (F-012 CP-9) | Installer's backups, or the brought dependency's own (OQ11) | Same, to customer media |
| Component definition and matrix | Published with the release | In the release and package | In the package |
| Bundled Keycloak | Not deployed | Optional | Optional |

## Control mapping (NIST SP 800-53r5)
To be proposed with the tasks.

## Out of scope
- The SaaS fleet's provisioning, delivery, rollouts and backups (F-012).
- Building, signing and attesting images and the release manifest (F-012); F-014 packages and verifies them.
- The deployment checks' rules themselves and drift detection after install (F-015); F-014 runs the same rules before install.
- An OSCAL System Security Plan of the customer's own controls (F-013 OQ4).
- A web-based installer, a Kubernetes operator or an OperatorHub listing in v1 (OQ2).
- Licence issuance tooling and commercial terms beyond what the platform verifies (vendor operations).
- Automatic remediation of failed preflight checks; the installer reports and refuses.
- Iron Bank or other hardened-image programme submission (ADR-005: optional, later).

## Dependencies
- F-012: the signed release (images, SBOMs, signatures, provenance, release manifest, `cosign.pub`, verification tools, notes, upgrade test, the component definition build), forward-only and compatible migrations (AC-13, AC-21), the supported upgrade window (OQ9). F-012 is in progress; F-014's design should start from its released artifacts.
- F-015: deployment checks and their rules (AC-41), profile selection and seeding (AC-09, AC-10), the scanner's permission manifest and consent (AC-39, AC-40), deployment exceptions on the Posture page, the recorded deployment mode, `posture.PlatformComponentUUID`, the Assessment Results and POA&M exports.
- F-001: keys per mode (`iam keys`), database bootstrap and `iam migrate`, break-glass at install (AC-39, AC-40), bundled Keycloak (AC-06), the permission catalog (a new licence permission, OQ15).
- F-002: the audit store and write-once copies, verification and `fair-audit-verify`, retention and legal holds, the storage quota, evidence exports.
- F-003: the installation currency and the data export; F-010: the report store and exports; F-009: notices for licence and backup.
- Every feature's signed-off control statements (`compliance/statements/`).

## Cross-feature commitments
Promises other specs, ADRs and code made to F-014, and where these requirements meet them.
| Commitment (source) | Covered by |
|---|---|
| Umbrella Helm chart with a flag per bundled dependency; OCI images, SBOMs, signatures, provenance; air-gap archive (Zarf candidate); migrations, OSCAL catalogs, default content; docs and responsibility matrix (ADR-005) | AC-01, AC-02, AC-04, AC-45, AC-51; OQ1 |
| Bundled or bring-your-own for every dependency; platform targets incl. OpenShift and RKE2; FIPS with FIPS nodes; CI install matrix (ADR-005, constitution Q4) | AC-01, AC-05, AC-06, AC-16, AC-42; OQ14 |
| Licences are signed files; no mandatory outbound connectivity; telemetry off when self-hosted (ADR-005, A7) | R-04, AC-05; secure defaults |
| Upgrade policy: forward-only migrations, N-1 to N with tested skip rules, rollback by backup/restore (ADR-005) | R-05; OQ10 (flagged) |
| Preflight checks that refuse insecure installs unless explicitly overridden and logged; credentials generated at install; hardening guides and STIG-style checklists (ADR-006) | R-03, AC-10, AC-51; OQ5 (flagged) |
| Installer records the deployment mode (ADR-005 amendment, `posture.set_deployment_mode`) | AC-08, AC-11 |
| Profile selection at install, default FedRAMP Moderate, and the audited seed (F-015-AC-09, AC-10; `posture seed`) | AC-08, AC-11 |
| Scanner permission manifest shown for consent, decision recorded, scanner deployed only if granted, later grant, consent asked again when the manifest changes (F-015-AC-39, AC-40; design §6.8) | AC-08, AC-11, AC-31 |
| Node FIPS by `fips-probe` or installer attestation; attested cluster-wide pod security and storage encryption (F-015 design, `internal/scanner/checks`) | AC-08, AC-09, AC-16 |
| The component definition defines `posture.PlatformComponentUUID`; exports reference it (F-015-AC-48, design) | AC-43, AC-46 |
| First posture MAC key; the `posture.setting.changed` and other JetStream streams provisioned by the installer (F-015 design; `internal/natspub`) | AC-10, AC-11 |
| Live OpenShift and RKE2 runs (F-015 design §15 open item) | AC-06; OQ14 |
| Break-glass opt-in at install with a reason and install log (F-001-AC-39, AC-40; F-001 out of scope: installer UX) | AC-08, AC-09 |
| PostgreSQL's cryptography in FIPS mode for `pgcrypto`, checked in preflight (F-001 design) | AC-17, AC-19 |
| Keycloak not deployed in SaaS; bundled realm for self-hosted (F-001 design, AC-06) | AC-08; deployment modes table |
| Keys delivered by the mode's store; the chart applies the key mounts (F-001 T-41, `deploy/k8s/keys`) | AC-10 |
| Network-binding ASN data bundled with releases (F-001 design) | AC-01 |
| `fair-audit-verify` in the bundle; sizing of `FAIR_AUDIT_STORAGE_QUOTA`; bundled object storage; write-once preflight (F-002 design) | AC-01, AC-17, AC-51; OQ3 |
| Buckets created by the installer (`internal/objstore`) | AC-11 |
| The bundled object store is F-014's decision (ADR-012) | OQ3 |
| Currency set at installation (F-003-AC-07) | AC-08 |
| The component definition assembles every feature's statements (F-005, F-006 designs; every `compliance/statements/*.yaml`; F-013 out of scope) | AC-43, AC-44 |
| The bundle carries `cosign.pub`, signatures and attestations, `verify-release.sh -offline` and its tools (F-012 design §3.3, `docs/security/verify.md`) | AC-01, AC-02, AC-07 |
| Self-hosted admission verification: shipped policy, optional, checked by preflight (F-012 deployment modes) | AC-16, AC-20 (flagged) |
| Helm and Zarf packaging, installer, preflight, licences, upgrades, backup and restore (F-012 out of scope) | R-01 to R-06 |
| "F-014 provides the procedure" for backing up the database and object stores (F-012 CP-9 statement) | R-06, AC-51 |
| Charts preserve the reference manifests' hardening; the migration Job as a pre-install and pre-upgrade hook (`deploy/k8s`) | AC-03, AC-11, AC-31 |
| Re-run the role bootstrap and `iam keys upgrade` on upgrade (README, `docs/install/keys.md`) | AC-31 |
| The identity-provider outage recovery path in the installation guides (F-001-AC-46) | AC-51 |

## Open Questions
- OQ1 (resolved 2026-11-26: as proposed). Package formats? Proposed: the Helm chart published as a signed OCI artifact for connected installs, and a Zarf package for air-gapped installs (common in DoD environments, ADR-005) holding the chart, the images, the tools and the documents; the files a verifier needs (manifest, signatures, `cosign.pub`, `SHA256SUMS`) also readable outside Zarf, so verification does not depend on it.
- OQ2 (resolved 2026-11-26: as proposed). Installer form? Proposed: a command-line installer (a Go binary built with the FIPS module, for Linux, macOS and Windows, in the package) that runs preflight, asks for the decisions, generates keys, provisions and installs through the chart, and also does upgrade, backup, restore, licence and uninstall; the chart's pre-install and pre-upgrade hooks re-run the in-cluster preflight checks so a bare `helm install` also refuses an insecure cluster. No web installer UI in v1; F-015's "installer UI" is this command line, and its results show in the application (AC-13, AC-55).
- OQ3 (resolved 2026-11-26: as proposed). Bundled object store (deferred by ADR-012)? Proposed: chosen in the design with an ADR, by these criteria: compliance-mode Object Lock, legal holds, versioning, TLS 1.2 or later with FIPS-capable cryptography, a licence that allows redistribution (no AGPL), and maintained images we can rebuild and sign; versitygw (Apache-2.0, already the test server) is the first candidate.
- OQ4 (resolved 2026-11-26: as proposed). Do the same preflight checks gate SaaS? Proposed: yes; F-012's onboarding and promotion run the cluster and dependency checks of R-03 against each instance (with F-002's write-once requirement), so the rules are one set across modes; overrides are never allowed in SaaS.
- OQ5 (resolved 2026-11-26: as proposed). Overrides (ADR-006 allows an "explicit, logged override"; constitution S0 says the installer refuses)? Proposed: the hard-floor checks of AC-19 have no override in any mode; any other failed check proceeds only with a named override and reason, recorded at high severity, and becomes a deployment exception with the profile's default exception duration (90 days), renewable only with dual approval in the application; at expiry the check is re-run, a still-failing check opens a high finding, and the next upgrade refuses until it passes or the exception is renewed. Admission verification of image signatures (F-012: optional for self-hosted) is such an overridable check.
- OQ6 (resolved 2026-11-26: as proposed). What identifies an installation? Proposed: the vendor issues the first licence with a new installation identifier; the installer requires that licence and records the identifier, later licences must carry it, and a restore onto a new cluster keeps it (AC-40). Copying a licence to a second installation cannot be detected offline and is a contractual matter.
- OQ7 (resolved 2026-11-26: as proposed). Licence signing key? Proposed: a dedicated ECDSA P-256 key in the vendor's KMS (FIPS 140-validated HSM, as ADR-018), never the release key, its public key shipped in every release; a new licence key ships in a release before licences are signed with it, and releases keep the previous key for verification until every licence it signed has ended.
- OQ8 (resolved 2026-11-26: as proposed). What does a licence limit? Proposed: its term, the installation, the deployment modes, and the update entitlement: releases published after the entitlement ends are refused at upgrade, except patch releases of a minor release the entitlement covered, which are always installable (security fixes are never withheld). No feature editions (security ships in every edition, ADR-006); a named-user count, if a contract has one, is shown and reported, never enforced by refusing sign-in or SCIM provisioning.
- OQ9 (resolved 2026-11-26: as proposed). Grace period and limited state? Proposed: 30 days' grace; in the limited state THE SYSTEM refuses only new simulation runs, new scenarios, library entries, controls and register risks, imports and connector runs (F-011) and new report schedules; everything in AC-26 continues, as do acceptance decisions, treatment updates, reports and exports, so governance and evidence never stop.
- OQ10 (resolved 2026-11-26: as proposed). Upgrade window and interruption? F-012 OQ9 supports upgrades from the two previous minor releases; ADR-005 says N-1 to N. Proposed: follow F-012 (it includes N-1) and note the change in ADR-005; any patch of a supported minor release is a valid starting point; upgrades roll the services with reads available, writes paused at most 15 minutes for migrations at target scale.
- OQ11 (resolved 2026-11-26: as proposed). Backup scope and mechanism? Proposed: for bundled dependencies, the platform's backups (continuous WAL archiving for point-in-time recovery plus base backups of PostgreSQL, object store replication or copies keeping Object Lock, key store snapshots), consistent by a recorded point in time; for brought dependencies, the customer's own backups to documented requirements (point-in-time recovery, Object Lock preserved), with the restore verification of AC-38 run the same way. NATS JetStream is not backed up: its streams carry notifications derived from database outboxes and are re-provisioned on restore. An upgrade requires a verified backup no older than 24 hours.
- OQ12 (resolved 2026-11-26: as proposed). Backup encryption key? Proposed: AES-256-GCM under a backup key held in the customer's key store (OpenBao/Vault, KMS or HSM), separate from the platform's service keys; key material is backed up by the key store's own encrypted snapshot, never inside a data backup.
- OQ13 (resolved 2026-11-26: as proposed). Audit trail after restoring to an earlier point? Proposed: the restored trail continues from its restored head; the restore records an event (high severity) naming the restored head checkpoint and the later checkpoints known from the write-once copies or the SIEM; verification reports that range as a declared, restored gap rather than a failure, and the external checkpoint copies remain the evidence of what was lost.
- OQ14 (resolved 2026-11-26: as proposed). Supported platforms and CI coverage? Proposed: the three newest Kubernetes minor versions at release time; CI installs on upstream Kubernetes (kind), RKE2 and OpenShift (OKD or an OpenShift Local runner, closing F-015's open item), bundled and brought, connected and air-gapped (no egress); EKS, AKS and GKE are supported through upstream conformance and tested before each minor release by a recorded manual run.
- OQ15 (resolved 2026-11-26: as proposed). Permissions? Proposed: permission catalog version 8 adds `license.manage` (privileged; Platform Admin) to install a licence in the application; licence, install report, preflight and backup status are readable with `posture.view`; backup, restore, upgrade and uninstall stay installer actions with cluster access (like emergency break-glass, F-001-AC-46), not application permissions.
- OQ16 (resolved 2026-11-26: as proposed). Licences in SaaS? Proposed: SaaS instances carry a licence too (one artifact set, M3), issued by F-012's onboarding for the contract's term and renewed by the fleet, so the code path is the same in every mode; a SaaS licence's lapse is a vendor operations alert before it reaches customers.
- OQ17 (resolved 2026-11-26: as proposed). What does the component definition cover? Proposed: the platform component only in v1 (`posture.PlatformComponentUUID`); bundled dependencies (PostgreSQL, NATS, the object store, Keycloak, OpenBao) appear in the responsibility matrix as shared responsibilities with their hardening guidance, and may become their own components later.

## Change Log
- 2026-11-26: Initial draft, In Review (F-012 in progress; F-014 next by the build order).
- 2026-11-26: Approved by Robert Former; OQ1 to OQ17 resolved as proposed.
