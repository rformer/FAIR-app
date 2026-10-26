# F-001 Permission Catalog v1
Status: **Approved** (Robert Former, 2026-10-25) | Resolves design D-OQ4 | Feeds T-06 (built-in role seeds)
Requirements: "Permission model", AC-22, AC-29, AC-30, AC-44, AC-51, AC-54, AC-57 | F-015 "Permissions added to the F-001 catalog"

This is the first shipped permission catalog. T-06 commits it as the catalog JSON file (format from T-03, `internal/access/catalog`) and seeds `iam.permission` and the built-in roles from it. A JSON rendering of this draft already passes the T-03 loader.

## Conventions
- **Key:** `<resource_type>.<name>`, lower snake case. `resource_type` is the key prefix.
- **Action** (design §3): `read`, `write`, `approve`, `admin` or `export`.
- **Privileged** (AC-54): every `approve`, `admin` and `export` permission is privileged, and the loader enforces this. `audit.view` (audit-log access) and `entitlement.view` are also marked privileged.
- **Admin permissions** (AC-22, AC-30) are the ones with action `admin`.
- **Risk data** (AC-30, AC-44): each permission carries a required `risk_data` flag (PC-1). It is true exactly for the "Risk data" table below. An `admin` permission can never be risk data, and the loader enforces this.
- **Version:** all keys are `introduced_in: 1`. The catalog stays at version 1 until the first release. After that, every change follows the T-03 upgrade rules: the version is bumped, and new keys are never added to existing custom roles (AC-57).
- **Scope:** permissions are checked at a BU (`authz.Check(principal, permission, buID)`). Instance-wide administration is checked at the Enterprise root.
- **Restricted BUs:** AC-22's "explicitly granted that right there" needs no extra permission. `access.assign` held at an ancestor does not inherit into a restricted BU (AC-60), so assigning roles there requires an assignment at or below that BU.

## Permissions
### Platform administration
| Key | Action | Privileged | Owning feature | Description |
|---|---|---|---|---|
| `idp.view` | read | no | F-001 | View identity provider configuration |
| `idp.manage` | admin | **yes** | F-001 | Configure IdPs, metadata/JWKS upload, MFA evidence rules, home-realm routing |
| `scim.manage` | admin | **yes** | F-001 | Issue, rotate and revoke SCIM tokens; JIT provisioning and inactivity settings |
| `user.view` | read | no | F-001 | View users, groups and their status |
| `user.manage` | admin | **yes** | F-001 | Enable, disable and unlock users |
| `bu.view` | read | no | F-001 | View the BU tree (in-scope nodes only) |
| `bu.manage` | admin | **yes** | F-001 | Create, rename, move, archive, import and export BUs; maximum depth |
| `bu.restrict` | admin | **yes** | F-001 | Restrict and unrestrict BUs, roll-up mode, new-BU default (loosening needs dual approval) |
| `role.view` | read | no | F-001 | View built-in and custom roles and their permissions |
| `role.manage` | admin | **yes** | F-001 | Create, clone, edit, retire, import and export custom roles |
| `access.view` | read | no | F-001 | View role assignments and group mappings |
| `access.assign` | admin | **yes** | F-001 | Create, change and revoke assignments at the BUs where it is held |
| `access.map_groups` | admin | **yes** | F-001 | Manage IdP group-to-role mappings |
| `access.approve` | approve | **yes** | F-001 | Second approval for F-001 dual-approval requests (unrestrict, roll-up loosening, admin plus risk-data combination, SoD exception, break-glass enablement) |
| `sod.manage` | admin | **yes** | F-001 | Edit the separation-of-duties rule set |
| `session.view` | read | no | F-001 | View other users' active sessions |
| `session.revoke` | admin | **yes** | F-001 | Revoke other users' sessions (users revoke their own without a permission) |
| `banner.manage` | admin | **yes** | F-001 | Edit and enable or disable the system-use banner |
| `service_account.manage` | admin | **yes** | F-001 | Create service accounts; issue, rotate and revoke their tokens |
| `breakglass.manage` | admin | **yes** | F-001 | Request enablement of, and disable, break-glass accounts |
| `access_review.manage` | admin | **yes** | F-001 | Create and close access review campaigns |
| `access_review.decide` | approve | **yes** | F-001 | Certify or revoke the assignments routed to the reviewer |
| `entitlement.view` | read | **yes** | F-001 | View entitlement reports, including restricted-BU access listings |
| `entitlement.export` | export | **yes** | F-001 | Export entitlement reports as CSV/PDF |
| `audit.view` | read | **yes** | F-002 | View the audit trail (AC-54: audit-log access is privileged) |
| `audit.export` | export | **yes** | F-002 | Export audit evidence |

### Security posture (from F-015 requirements)
| Key | Action | Privileged | Owning feature | Description |
|---|---|---|---|---|
| `posture.view` | read | no | F-015 | View the Security Posture page |
| `posture.export` | export | **yes** | F-015 | Export OSCAL Assessment Results and POA&M |
| `settings.change` | write | no | F-015 | Request a security setting change through settings.Set |
| `settings.approve` | approve | **yes** | F-015 | Second approval for loosening a setting |
| `profile.manage` | admin | **yes** | F-015 | Create and edit custom profiles; request a profile switch |
| `profile.approve` | approve | **yes** | F-015 | Approve activating a custom profile or a switch |
| `exception.renew` | write | no | F-015 | Request renewal of a setting exception |
| `drift.acknowledge` | write | no | F-015 | Acknowledge a drift finding |

### Platform integrations
| Key | Action | Privileged | Owning feature | Description |
|---|---|---|---|---|
| `notification.manage` | admin | **yes** | F-009 | Configure SMTP/webhook channels and templates |
| `integration.manage` | admin | **yes** | F-011 | Configure automation inputs and their credentials |
| `framework.manage` | admin | **yes** | F-013 | Import OSCAL catalogs and manage crosswalks |

### Risk data (provisional; each owning feature spec refines these)
| Key | Action | Privileged | Owning feature | Description |
|---|---|---|---|---|
| `library.view` | read | no | F-003 | View assets, threat communities and loss forms |
| `library.edit` | write | no | F-003 | Create and edit assets, threat communities and loss forms |
| `scenario.view` | read | no | F-003 | View risk scenarios |
| `scenario.edit` | write | no | F-003 | Create and edit risk scenarios |
| `analysis.view` | read | no | F-004 | View analyses, estimates and results |
| `analysis.edit` | write | no | F-004 | Create and edit analyses and calibrated estimates |
| `analysis.run` | write | no | F-005 | Run simulations |
| `analysis.export` | export | **yes** | F-006 | Export analysis results |
| `control.view` | read | no | F-013 | View controls and their FAIR effects |
| `control.edit` | write | no | F-013 | Edit control implementations and effects |
| `register.view` | read | no | F-007 | View register entries and BU roll-ups |
| `register.edit` | write | no | F-007 | Create and edit register entries |
| `treatment.view` | read | no | F-007 | View treatment plans |
| `treatment.edit` | write | no | F-007 | Create and edit treatment plans |
| `acceptance.view` | read | no | F-008 | View risk acceptances |
| `acceptance.request` | write | no | F-008 | Request, renew or withdraw a risk acceptance |
| `acceptance.approve` | approve | **yes** | F-008 | Approve or reject a risk acceptance (authority limits in F-008) |
| `report.view` | read | no | F-010 | View reports and dashboards |
| `report.export` | export | **yes** | F-010 | Export reports |

## Built-in role templates (input to T-06)
| Role | Permissions |
|---|---|
| Platform Admin | `idp.view`, `idp.manage`, `scim.manage`, `user.view`, `user.manage`, `bu.view`, `bu.manage`, `bu.restrict`, `role.view`, `role.manage`, `access.view`, `access.assign`, `access.map_groups`, `access.approve`, `sod.manage`, `session.view`, `session.revoke`, `banner.manage`, `service_account.manage`, `breakglass.manage`, `access_review.manage`, `entitlement.view`, `entitlement.export`, `posture.view`, `posture.export`, `settings.change`, `settings.approve`, `profile.manage`, `profile.approve`, `exception.renew`, `drift.acknowledge`, `notification.manage`, `integration.manage`, `framework.manage` |
| BU Admin | `bu.view`, `user.view`, `role.view`, `access.view`, `access.assign` |
| Risk Analyst | `scenario.view`, `library.view`, `analysis.view`, `control.view`, `register.view`, `treatment.view`, `acceptance.view`, `report.view`, `library.edit`, `scenario.edit`, `analysis.edit`, `analysis.run`, `control.edit` |
| Risk Owner | `scenario.view`, `library.view`, `analysis.view`, `control.view`, `register.view`, `treatment.view`, `acceptance.view`, `report.view`, `register.edit`, `treatment.edit`, `acceptance.request` |
| Approver | `scenario.view`, `library.view`, `analysis.view`, `control.view`, `register.view`, `treatment.view`, `acceptance.view`, `report.view`, `acceptance.approve` |
| Executive Viewer | `scenario.view`, `library.view`, `analysis.view`, `control.view`, `register.view`, `treatment.view`, `acceptance.view`, `report.view` |
| Auditor | `scenario.view`, `library.view`, `analysis.view`, `control.view`, `register.view`, `treatment.view`, `acceptance.view`, `report.view`, `bu.view`, `user.view`, `role.view`, `access.view`, `entitlement.view`, `entitlement.export`, `audit.view`, `audit.export`, `posture.view` |
| Service Account | _None. API scopes only (AC-36)._ |

Checked mechanically when this draft was generated:
- Every role permission exists in the catalog.
- No built-in role combines `admin` permissions with risk-data permissions (AC-30, AC-44). Platform Admin therefore has no risk-data access, which break-glass accounts rely on.
- No built-in role holds both halves of the default SoD pair, `analysis.edit` and `acceptance.approve` (AC-29).

## Decisions (approved 2026-10-25)
- **PC-1. Risk-data classification.** AC-30 (admin plus risk-data needs dual approval) and AC-44 (break-glass has no risk data) both need the system to know which permissions are risk data. **Decision:** a required `risk_data bool` in the catalog file and in `iam.permission` (design §3 updated; T-03 loader amended).
- **PC-2. BU Admins cannot appoint BU Admins.** The BU Admin role contains `access.assign`, which is an `admin` permission, and AC-22 forbids a BU Admin from granting roles that contain admin permissions. So only a Platform Admin can make someone a BU Admin. This draft treats that as intended.
- **PC-3. Auditor exports.** Auditor gets `entitlement.export` and `audit.export` (evidence for access reviews and SOC/ISO audits), but not `analysis.export` or `report.export`.
- **PC-4. Posture permissions sit with Platform Admin.** The built-in role list in the requirements has no security-officer role. All F-015 permissions therefore go to Platform Admin, and F-015's "second, different person" approvals are satisfied by two Platform Admins. A dedicated role would be a requirements change.
- **PC-5. Risk-data permissions are provisional.** F-003 to F-013 have no specs yet. Their keys here are placeholders that each feature's design may rename or split before the first release, while the catalog is still at version 1.

## Change Log
- 2026-10-25: Initial draft.
- 2026-10-25: **Approved** by Robert Former with PC-1 (`risk_data` flag); PC-2 to PC-5 accepted as drafted.
