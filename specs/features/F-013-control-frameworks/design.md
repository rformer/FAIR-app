# F-013 Control framework library — Design
Status: Approved | Owner: Robert Former | Last updated: 2026-11-18
Requirements: `requirements.md` (Approved 2026-11-18) · ADR-004, ADR-005, ADR-006, ADR-007

## 1. Overview
- **In the risk service.** Frameworks are reference data for controls, which live there (F-003); F-013 adds no service and no egress. A new schema `framework`, owned through a bootstrap role `framework_definer`, holds frameworks, their versions, requirements, baselines and crosswalks. The API is `internal/frameworkapi` (contract `api/openapi/framework.yaml`, gateway segment `frameworks`), mounted by `cmd/risk`.
- **Frameworks are installation-wide; mappings belong to controls.** Framework tables are definer-only and read through functions by holders of `framework.view`, `control.view` or `control.edit` anywhere (reference data, not risk data). A control's mappings are part of its versioned document (F-003), so they inherit its business unit, row-level security, versions, diffs, provenance and audit with no new write path (AC-07, AC-20).
- **Imports are jobs, whole or nothing.** An uploaded catalog, profile, simple-format framework or crosswalk is validated and staged by a River job in `risk_river` (queue `framework`) and applied in one transaction; a refused file changes nothing and names each problem (AC-01, AC-03, AC-10).
- **Coverage is computed, never scored.** Coverage is a read over the latest version of each visible control's mappings and implementation status, per requirement, with crosswalk-derived coverage reported apart (AC-11 to AC-14). No percentage or rating is produced anywhere (P1).
- **From requirement to analysis by proposal.** The platform shows which scenarios a requirement's controls would change and builds a proposed scenario document with a control set adding the control; the analyst edits, saves and runs it through F-003 and F-005 (AC-16, AC-17; P4).

## 2. Components
| Component | Change |
|---|---|
| `db/bootstrap` | NOLOGIN role `framework_definer`; re-run `scripts/db-bootstrap.sh` |
| `db/migrations` | Schema `framework` (§5); `risk.check_document` checks a control's `mappings` against it; the mapping projection and its RLS; events |
| `internal/framework` | Parsing and validation: OSCAL catalogs and profiles (through `internal/oscal`, OSCAL 1.2.3), the simple format, crosswalks; profile resolution (§3.2); version diffs; limits |
| `internal/framework/content` | Shipped frameworks (OQ1): NIST SP 800-53r5 at 5.2.0 and 5.1.1 (FedRAMP's and 800-171r3's version) and its low, moderate, high and privacy baselines; NIST SP 800-171r3; FedRAMP Rev 5 baselines; the 800-171r3 to 800-53r5 crosswalk from the 800-171r3 catalog's references, as `intersects` (OQ2); built from `third_party/oscal`, embedded in the `iam` binary (covered by its image digest in the signed release manifest), each item's source digest stored |
| `internal/migrate` | `migrate.Release.Frameworks`: `iam migrate` syncs shipped content (`framework.sync_shipped`) |
| `internal/risk/model` | Control `mappings` (framework, version, requirement, strength, rationale), validated in Go and SQL (parity) |
| `internal/frameworkapi` | The API (§6), the import job (`framework.Worker`) |
| `internal/riskapi`, `internal/registerapi` | A proposed scenario with a control added (§3.6); a risk's requirements (AC-18) |
| `internal/access/catalog` | Catalog version 7: `framework.view` (not privileged; Platform Admin, Auditor, Risk Analyst) (OQ3); re-sign |
| `internal/gateway` | Segment `frameworks` → risk |
| `web/src/frameworks` | Frameworks, requirements, crosswalks, coverage, imports; mapping editor in the control editor |
| `pkg/audit/catalog.yaml` | F-013's events (§8) |

## 3. Model
### 3.1 Frameworks, versions and requirements (AC-01 to AC-06)
- **A framework** is a family with a stable key (for example `nist-800-53`), a title and a publisher. **A framework version** is one imported catalog: version label, published date, source (shipped or uploaded), the uploaded file's SHA-256, state (`active`, `retired`), imported by and at.
- **A requirement** is a control or enhancement of a version: its identifier as published (`ac-2`, `ac-2.1`), label (`AC-2(1)`), title, statement text (parts flattened in order, parameters shown as `[Assignment: …]` placeholders), parent, sort order, and whether it is withdrawn (with the identifiers it was incorporated into, from OSCAL `incorporated-into` links).
- **Text licensing (OQ1):** a simple-format import may omit statements (identifiers and titles only); shipped content is public domain.
- **A new version (AC-05):** a diff against the previous active version of the family by identifier: added, changed (title or statement), withdrawn, and renumbered (a withdrawn requirement whose incorporated-into names one target). Mappings stay on the version they name until moved (§3.4).
- **Retire (AC-06):** a version can be retired by `framework.manage`; it is then hidden from mapping pickers and coverage choices, and stays readable.

### 3.2 Baselines (AC-02)
- **A baseline** is an imported OSCAL profile resolved against one imported catalog version (the profile's `import.href` names the catalog by its back-matter resource or title; the importer chooses the version when ambiguous). It records the selected requirement identifiers and parameter values set by the profile.
- **Resolution (v1):** `include-all`, `include-controls` with `with-ids` and `matching` patterns, `exclude-controls`, and `with-child-controls`; `set-parameters` recorded as values; `alters` not applied (the selection is what coverage needs) and reported as such on the import. A profile that imports another profile is resolved recursively to one catalog (depth at most 3). Nothing is fetched: every import names a catalog already in the platform.

### 3.3 The simple format and crosswalks (AC-03, AC-10, AC-11)
- **Simple format** (`fair.framework.v1`, JSON, or CSV with columns `identifier,label,title,statement,parent`): one version per file with its family key, title, version and publisher. Checked as strictly as OSCAL: unique identifiers, parents present, no cycles, bounded lengths.
- **Crosswalks** (`fair.crosswalk.v1`, JSON or CSV `source,target,relationship`; OSCAL mapping collections when the pinned OSCAL version supports them, D-OQ1): a set of relationships between two framework versions, each `equal`, `subset_of`, `superset_of` or `intersects` (NIST IR 8278), with the crosswalk's title, publisher and version. Every source and target must exist (AC-10).
- **Derived coverage (AC-11):** a requirement R is covered through a crosswalk when a visible control maps to R' and the crosswalk says R' `equal` R or R' `superset_of` R; `subset_of` and `intersects` show as partial. Derived coverage is listed with the crosswalk and relationship and never counted as direct.

### 3.4 Mappings (AC-07 to AC-09)
- **In the control document:** `mappings: [{framework, version, requirement, strength, rationale}]`, strength `full`, `partial` or `supports` (OQ5), at most 500 (OQ6). Go validates the shape (`model.Validate`); `risk.check_document` also checks that the framework version and requirement exist and that the requirement is not withdrawn (PF016, problems by pointer), through a definer function owned by `framework_definer`.
- **Projection:** a trigger on `risk.control_version` keeps `framework.control_mapping` (control, version, BU, framework version, requirement, strength, the control's implementation status), BU-owned type `control` under RLS (`authz.apply_bu_rls`), so coverage reads are set-based and respect visibility.
- **References (AC-08):** `GET /controls/{id}/suggested-mappings` matches the control's plain references (F-003-AC-14) to requirements of active versions by framework key and identifier (case and punctuation normalized); the UI offers them in the control editor, and saving the control records them. References stay until the owner removes them.
- **Version moves (AC-09):** for a control mapped to a version that has a newer active version, `GET /controls/{id}/mapping-updates` proposes the equivalents from the version diff (same identifier, or the incorporated-into target); accepting them is saving the control.
- **Events:** saving a control whose mappings changed records `control.mappings_changed` (added and removed, by requirement) in the save's transaction, beside F-003's `control.version_saved`.

### 3.5 Coverage (AC-12 to AC-15)
- **Read:** `framework.coverage(version, baseline, bu)` returns, for each requirement of the version (or of the baseline's selection), the visible controls in the BU subtree mapped to it (direct), the crosswalk-derived controls (§3.3), and a state: `in_place` (a full mapping to a control in place, every full mapping in place), `not_in_place` (mapped, a control not in place), `partial` (only partial, supports or derived mappings), `not_covered`. Counts by state; no score (AC-13).
- **Visibility (AC-14):** the projection is read under RLS; restricted business units below the BU contribute per the roll-up mode (F-001): `aggregate` as counts by state computed by a definer function owned by `rollup_definer`, never listing their controls; `hidden` not at all; the answer says what was left out.
- **Exports (AC-15):** `GET …/coverage.csv` and `.json` (F-010's CSV writer, neutralized cells; `reason` by `export.reason_required` through `internal/reason`), recorded as `framework.coverage_exported` in the request's transaction (503 with no file if it cannot be).

### 3.6 Requirements to analysis (AC-16 to AC-18)
- `GET /requirements/{id}/scenarios`: the controls mapped to the requirement (visible), their effects, and the visible scenarios whose latest version pins one of them in a current control set ("uses it") and those in the controls' BU subtrees that do not ("could use it"), at most 200 each.
- `GET /scenarios/{id}/proposed?add_control={control}[&set={name}]` (risk API): the scenario's latest document with a new control set (a copy of the named or first current set, with the control pinned at its latest version, named "With <control>"), validated, not saved. The UI opens the scenario editor with it; saving is F-003's save; running is F-005's request.
- The register's risk view gains `requirements`: the requirements the controls of its linked scenarios' current sets map to, by framework version, read under RLS.

### 3.7 History (AC-20)
Framework versions, baselines and crosswalks are append-only rows with their source digests; mappings are in control versions. `coverage?as_of=<date>` reads each control's version current at that date and the framework versions active then.

## 4. Settings (F-015)
None. Limits (OQ6) are constants checked in Go and the database: files up to 50 MiB, 20,000 requirements per version, 100 framework versions, 200,000 crosswalk relationships, 500 mappings per control.

## 5. Data model (schema `framework`, owned through `framework_definer`)
| Table | Purpose | Access |
|---|---|---|
| `framework.family` | key, title, publisher | Definer only; read through functions |
| `framework.version` | id, family, version label, published, source, sha256, state, imported by and at, diff summary | Definer only; append-only but `state` (PF033) |
| `framework.requirement` | version, identifier, label, title, statement, parent, ord, withdrawn, incorporated_into | Definer only; immutable |
| `framework.baseline` | id, version, title, source digest, selected identifiers, parameters, state | Definer only |
| `framework.crosswalk` / `framework.relationship` | crosswalk metadata; (crosswalk, source requirement, target requirement, relationship) | Definer only; immutable |
| `framework.import` | id, kind, requested by, file digest, state, problems (at most 1,000), result | Definer only |
| `framework.control_mapping` | control, control version, bu_id, requirement, strength, implementation status | BU-owned, type `control`, RLS; written only by the trigger as `framework_definer` (ADR-007 amendments 3, 5) |
State rules (PF033): versions, requirements, baselines and relationships never change but for a version's or baseline's state; limits (PF034).

## 6. API (`api/openapi/framework.yaml`, the risk service)
| Route | Permission | Notes |
|---|---|---|
| `GET /frameworks`, `GET /frameworks/{family}/versions/{id}`, `…/requirements?q=&parent=`, `GET /requirements/{id}` | `framework.view`, `control.view` or `control.edit` anywhere | Retired versions with `?retired=true` |
| `GET /frameworks/{family}/versions/{id}/diff` | as above | AC-05 |
| `POST /frameworks/imports` (multipart or JSON; kind catalog, profile, simple, crosswalk; `?dry_run=true`) | `framework.manage` at the root | 202; the job validates and applies; `GET /frameworks/imports/{id}` |
| `POST /frameworks/{family}/versions/{id}/retire`, `/baselines/{id}/retire`, `/crosswalks/{id}/retire` | `framework.manage` at the root | Reason |
| `GET /frameworks/baselines`, `GET /frameworks/crosswalks[/{id}]` | read as frameworks | |
| `GET …/versions/{id}/coverage?bu=&baseline=&as_of=`, `…/coverage.csv`, `.json` | `control.view` at the BU | §3.5 |
| `GET /requirements/{id}/scenarios` | `scenario.view` and `control.view` | §3.6 |
| `GET /controls/{id}/suggested-mappings`, `/mapping-updates` | `control.edit` at the control's BU | AC-08, AC-09 |
| `GET /scenarios/{id}/proposed?add_control=` (risk API) | `scenario.edit` at the BU | Not saved |
Conventions as before: operationId = handler; mutating routes declare `x-permission`, `x-audit-events` and Idempotency-Key; ids not visible are 404.

## 7. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| T: a malicious catalog or profile (XXE-like expansion, huge files, deep nesting, links) | JSON only, validated against the pinned OSCAL schema; size, count and depth limits; nothing fetched (no `href` followed, no back-matter resources read); whole-file refusal | `TestSTRIDEF013Imports`, `internal/framework` tests |
| T, E: frameworks changed by someone without `framework.manage`, or shipped content altered | Imports and retirements need `framework.manage` at the root (privileged); framework tables definer-only and immutable (PF033); shipped content embedded and digested in the signed release manifest | `TestSTRIDEF013Frameworks` |
| I: coverage leaks controls of business units the viewer cannot see | The projection under RLS; restricted units only by roll-up mode, as counts; derived coverage only from visible controls | `TestSTRIDEF013Coverage` |
| T: coverage overstates compliance | Only full, direct mappings to controls in place count as in place; derived and partial shown apart; no score | `TestFrameworkCoverage` |
| E: a mapping or proposal changes an analysis | Mappings live in control versions (scenarios keep their pins); proposed scenarios are not saved; nothing runs by itself | `TestSTRIDEF013Proposals` |
| T: injection through framework text | Text stored and shown as data; CSV exports neutralized (F-010); statements rendered as text, never HTML | `TestSTRIDEF013Injection` |
| R: changes not attributable | Imports with file digests, retirements, mapping changes and exports recorded in their transactions | `TestFrameworkAuditEvents` |
| D: large imports or coverage reads exhaust the service | Limits before work; imports as bounded jobs; coverage set-based with the scope read once (F-010 T-18) | `TestSTRIDEF013Limits`, `TestBenchmarkGateFrameworks` |

## 8. New catalog event types
`framework.imported`, `framework.import_refused`, `framework.retired`, `framework.baseline_imported`, `framework.baseline_retired`, `framework.crosswalk_imported`, `framework.crosswalk_retired`, `control.mappings_changed`, `framework.coverage_exported`; categories `configuration` and `risk_data`.

## 9. Requirements traceability
| AC | Design | Test |
|---|---|---|
| AC-01 to AC-06 | §3.1, §3.2, §3.3 | `TestFrameworkImports`, `internal/framework` tests |
| AC-07 to AC-09 | §3.4 | `TestControlMappings` |
| AC-10, AC-11 | §3.3 | `TestCrosswalks` |
| AC-12 to AC-15 | §3.5 | `TestFrameworkCoverage` |
| AC-16 to AC-18 | §3.6 | `TestRequirementScenarios` |
| AC-19, AC-20 | §3.7, §8 | `TestFrameworkAuditEvents`, `TestFrameworkCoverage` (as_of) |
| NFR performance | §3.5 | `TestBenchmarkGateFrameworks` |
| Accessibility | `web/src/frameworks` | `web/e2e/frameworks.spec.ts` (axe) |

## 10. Changes to other features
- **F-001:** catalog version 7 adds `framework.view` (not privileged; Platform Admin, Auditor, Risk Analyst); re-sign.
- **F-003:** the control document's `mappings`; `risk.check_document` checks them; F-003-AC-14's references remain and are offered as mappings (AC-08); `GET /scenarios/{id}/proposed`.
- **F-007:** a risk's `requirements`.
- **F-010:** the CSV writer and export reasons reused; no new report kind (a coverage report is a later feature).

## 11. Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Shipped frameworks | Synced at `iam migrate` | Same | Same (in the release; no network) |
| Imports | Upload | Upload | Upload; no remote OSCAL references fetched in any mode |

## 12. Alternatives considered
- **Mappings in their own table, outside control versions:** rejected; it would need its own versions, history, RLS and audit, and coverage as of a date would need a second history.
- **Full OSCAL profile resolution (alters, merges):** deferred; coverage needs the selection only, and alters change text the platform shows from the catalog.
- **A coverage percentage:** rejected (P1, AC-13).
- **Fetching catalogs from NIST at install:** rejected; shipped content works in every mode, and uploads cover the rest.

## 13. Open items
- D-OQ1: OSCAL mapping collections for crosswalks depend on the OSCAL version `internal/oscal` pins (1.2.3); if that version does not define them, crosswalks are imported in `fair.crosswalk.v1` only, and NIST's published crosswalks are converted at build time.
- D-OQ2: the shipped content's exact versions (800-53r5.1.1 or later patch, 800-171r3, FedRAMP Rev 5 baselines) are fixed when T-04 vendors them, from NIST's and FedRAMP's OSCAL repositories at a pinned commit.

## Change Log
- 2026-11-18: Initial draft, In Review.
- 2026-11-18: Approved by Robert Former.
- 2026-11-19: §2 and §13 amended (T-03, T-04): D-OQ1 resolved (OSCAL 1.2.3 defines mapping collections; T-07 reads them); D-OQ2 resolved (800-53 5.2.0 from oscal-content v1.6.0 and 5.1.1+u4 from v1.3.0, 800-171r3 1.1.0, FedRAMP Rev 5 baselines at the fedramp-resources commit pinned by F-015); the shipped crosswalk is derived from the 800-171r3 catalog's references and typed `intersects`, since NIST gives no relationship type; shipped content is covered by the iam image digest rather than a separate manifest entry.
- 2026-11-19: §6 amended (T-05): every route is under `/api/v1/frameworks` (versions at `/frameworks/versions/{id}`, requirements at `/frameworks/requirements/{id}`, the gateway segment `frameworks`); an import's body is the file with its metadata as query parameters; an uploaded profile selects from the catalog version its request names, and only shipped profiles are resolved through other profiles.
