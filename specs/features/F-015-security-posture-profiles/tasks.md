# F-015 Security Posture & Configuration Profiles — Tasks
Status: **Approved** (Robert Former, 2026-10-24) | Design: Approved 2026-10-24

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisite: F-001 Phases 0–1 (DB roles, BU closure, approvals interface, event emitter stub).

## Phase A — Profile build pipeline
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | OSCAL model types in Go (catalog, profile, component-definition, assessment-results, POA&M) with schema validation against pinned OSCAL JSON schemas | AC-04, AC-47 | Round-trip tests on NIST sample files | M | Done (2026-10-26) |
| T-02 | `profilegen`: OSCAL profile resolution subset (imports, include/exclude-controls, merge, `set-parameters`, `alters`) | AC-04, D-OQ3 | Conformance vs NIST resolved-profile examples and FedRAMP resolved Moderate baseline | L | Done (2026-10-26) |
| T-03 | Binding file format + validator (types, direction, transcribed values with drift-checked `source` constraints or `platform_choice`, hard floor); build fails on a missing param or changed constraint text | AC-01, AC-04 | Negative tests: missing param, changed constraint text, unconstrained param without `platform_choice`, weaker-than-floor bound | M | Done (2026-10-26) |
| T-04 | Author in-repo OSCAL profiles: Enterprise Baseline; **CMMC L2 from NIST SP 800-171 Rev 2** (`cmmc-l2-r2`), mapped to 800-53r5 parameters | AC-04, D-OQ1 | Mapping table reviewed; package builds | M | In Review (2026-10-26): built; `profiles/cmmc-l2-r2/mapping.md` awaits sign-off |
| T-05 | Bindings for all F-001 settings (sessions, MFA, JIT, banner, token lifetime, network binding, lockout, restricted-BU defaults, break-glass) | AC-01, AC-04 | Every F-001 key resolves in all three profiles | M | Done (2026-10-26) |
| T-06 | Package format, deterministic build, ECDSA P-256 signing, release-manifest pinning | AC-05 | Reproducible digest across builds; tamper test | S | Done (2026-10-26) |
| T-07 | Release checklist automation: confirm CMMC rule's current 800-171 revision; pin OSCAL source digests | AC-06, D-OQ1 | Checklist gate in release pipeline | S | Todo |

## Phase B — Registry, values & change control
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-08 | `posture` service scaffold + schema (`setting_def`, `profile`, `profile_value`, `active_profile`, `setting_value`, `change`, `exception`) | Design §5 | Migrations; RLS where BU-scoped | M | Todo |
| T-09 | Write protection: no DML grants; `apply_change` / `apply_revert` definer functions; `row_mac` with dedicated key | AC-02 | `app_rw` cannot write; direct-edit detected by drift (T-21) | M | Todo |
| T-10 | Package import + signature/schema verification; install-time seed from selected profile (default FedRAMP Moderate) | AC-05, AC-09, AC-10 | Unsigned/tampered package refused; seed audited | S | Todo |
| T-11 | `settings` Go library: `Register`, `Get(key, bu)`, versioned cache, NATS invalidation, 30 s TTL backstop, heartbeat of effective values | AC-01, NFR 60 s | Propagation ≤ 60 s test across 3 services | M | Todo |
| T-12 | Startup registration + "key missing from active package" startup error | AC-01 | Service refuses to start with unbound key | S | Todo |
| T-13 | Strictness comparators per type (duration/int/bool/enum/set) + strictest-of | Design §3, AC-35 | Property tests: comparator total order, floor never violated | S | Todo |
| T-14 | Change evaluator: hard-floor refusal, tighten-immediate, in-bounds apply, out-of-bounds → explanation + control warning payload + dual approval → exception | AC-20 – AC-22, AC-30, AC-31 | Test matrix per path; audit events asserted | M | Todo |
| T-15 | SaaS vendor SecOps notification on weakening | AC-23 | Mode-gated test | S | Todo |
| T-16 | Replace F-001 T-00b settings stub with this service; migrate F-001 keys | Design §12 | F-001 tests pass against real registry | S | Todo |

## Phase C — Exceptions, custom profiles & switching
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-17 | Exception lifecycle: expiry bounds (default 90 d), 14/7/1-day notices, renewal-before-expiry with dual approval | AC-24 – AC-26 | Time-travel tests on DB clock | M | Todo |
| T-18 | Auto-revert job (system actor), ≤ 60 s effect, retry with backoff, critical finding + hourly escalation on failure | AC-27 – AC-29 | Fault-injection test; sessions end on next request after timeout revert | M | Todo |
| T-19 | Custom profiles: clone, per-key editor data (base vs new, direction, controls), justification for loosened keys, validation, `profile.approve` by different person, "Deviates from <base>" label | AC-11 – AC-13 | Functional + self-approval-impossible tests | M | Todo |
| T-20 | Custom profile versioning/diff, JSON + OSCAL profile export/import (import → draft), base-update pinning (never silently weaker) | AC-14, AC-15 | Upgrade simulation: weaker base pinned, stricter proposed | M | Todo |
| T-21 | Profile switch state machine: conflict computation, per-conflict resolution (conform/exception, not on floor), loosening detection + dual approval, atomic activation, pending display | AC-07, AC-16 – AC-19 | Activation blocked with any unresolved conflict; rollback-safe activation | L | Todo |

## Phase D — BU scope & overlay
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-22 | BU overrides with inheritance via `iam.bu_closure` (blocked at restricted BUs) and strictest-of resolution | AC-32, AC-35 | Property tests on random trees | M | Todo |
| T-23 | Restricted BU overlay: auto-apply on `bu.restricted`, editable, weakening via R-06/R-07, removal on unrestrict | AC-33, AC-34 | Overlay present on every restricted BU; weakening requires approval | S | Todo |
| T-24 | **F-001 change:** session `auth_time`; `authz.Check()` returns `ErrStepUpRequired` per `bu.reauth_max_age`; 401 `step_up`; SAML ForceAuthn / OIDC `prompt=login`+`max_age` re-auth | AC-33, Design §6.6 | E2E: stale auth on restricted BU → step-up → access | M | Todo |

## Phase E — Drift detection
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-25 | App drift engine: row-MAC verification, bounds + exceptions check, missed-revert check, service heartbeat comparison; on change + every 15 min | AC-36, AC-37 | Direct DB edit detected; ≤ 30 s at target scale | M | Todo |
| T-26 | `drift_finding` lifecycle (open/acknowledged/resolved), events to audit + SIEM | AC-37, AC-42 | Event schema tests | S | Todo |
| T-27 | `posture-scanner`: separate Deployment, own ServiceAccount, read-only RBAC (no Secrets), mTLS gRPC to `posture`, NetworkPolicy-restricted egress | AC-38, AC-39 | RBAC audit: no write verbs, no secrets; egress test | M | Todo |
| T-28 | Deployment check catalog (10 checks in design §6.8) with severity, controls, remediation text | AC-41, AC-42 | Each check has passing and failing fixtures (kind/k3d, OpenShift, RKE2) | L | Todo |
| T-29 | `fips-probe` DaemonSet (single-file read-only hostPath) **and** installer-attested label path; exports mark "attested, not verified" for the latter | AC-41, D-OQ2 | Both paths tested; OpenShift SCC compatibility | M | Todo |
| T-30 | Kubernetes-access consent model: permission manifest content, granted/declined state, persistent warning, audit, "Not assessed" mapping, later grant | AC-39, AC-40 | Declined path → no scanner, banner, export marks Not assessed | S | Todo |

## Phase F — Posture page & evidence
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-31 | Posture API (design §7) with F-001 permissions and BU-scope filtering | AC-03, AC-43 | Permission tests; restricted-BU overrides hidden from out-of-scope users | M | Todo |
| T-32 | Posture page UI: profile + conformance, deviations/exceptions, upcoming expiries, recent reverts, pending switches, drift, K8s access status, per-control view; links to audit + actions | AC-43, AC-44 | E2E + WCAG 2.1 AA checks | L | Todo |
| T-33 | OSCAL Assessment Results export (observations per parameter, findings, not-assessed, component-definition reference) | AC-45, AC-48 | Validates against pinned schema; deterministic output for same `as_of` | M | Todo |
| T-34 | OSCAL POA&M export for open exceptions/deviations | AC-46 | Schema validation; content matches DB | S | Todo |
| T-35 | Export signing, digest recording, reproducibility from audit snapshot | AC-47 | Re-generate → identical digest | S | Todo |

## Phase G — Hardening
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-36 | STRIDE test suite (package forgery, DB tampering, exception extension, scanner privilege, revert starvation) | Design §8 | Suite green in CI | M | Todo |
| T-37 | Deployment-mode matrix (SaaS / self-hosted / air-gapped offline import, signing keys per mode) | Deployment modes | CI matrix green | M | Todo |
| T-38 | 800-53r5 control implementation statements for F-015 (CM-2/3/5/6/7, CA-2/5/7, SI-4, AU-6, PL-2) | Control mapping | Reviewed statements | S | Todo |

## Definition of Done (F-015)
- All 48 acceptance criteria have passing automated tests
- Profile packages for FedRAMP Moderate, CMMC L2 (Rev 2), and Enterprise Baseline build reproducibly and are signed
- F-001 settings stub replaced; F-001 tests green
- OSCAL exports validate against pinned schemas
- Threat-model suite green; control statements written
