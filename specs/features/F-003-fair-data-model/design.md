# F-003 FAIR Data Model — Design
Status: **Approved** (Robert Former, 2026-11-06) | Requirements: approved 2026-11-06 | Last updated: 2026-11-06
Constitution refs: P1, P2, P3, A2, A3, A5, A6, S0, S4, Q1, Q3, Q5 | ADRs: 003, 006, 007 (amendment 2, accepted with this design)

## 1. Overview
F-003 adds a `risk` service and a `risk` schema holding the Open FAIR model: loss scenarios, the library (assets, asset groups, threat communities, loss-form profiles) and controls.

- **Documents, versioned.** Every scenario, library entry and control is a head row (identity, owning BU, state) plus append-only versions. A version holds one validated, canonical JSON document (RFC 8785) and its SHA-256 digest. Nothing in a version ever changes (AC-15).
- **Pins.** A scenario version names the exact library and control versions it uses. A newer library version changes nothing until the analyst adopts it (AC-09, AC-10).
- **Frozen input for simulation.** A scenario version plus the versions it pins form a canonical *input bundle*. Its digest identifies the input to F-005 and changes whenever any part of it does (AC-16).
- **BU scoping in the database.** Every table is BU-owned under F-001's row policies (A6). Library entries and controls are also readable from descendant BUs through a new *inherited read* policy (ADR-007 amendment 2), which stops at restricted BUs (OQ4).
- **Validation in two places.** The service validates documents in Go; the database re-checks the invariants that make a version valid (digest, ordering, ranges, units, required estimates) in triggers, and a parity test keeps the two in agreement, as F-015 did for setting values.
- **Every change audited** in its transaction through `audit.WithTrail` (F-002).

## 2. Components
| Component | Kind | Responsibility |
|---|---|---|
| `cmd/risk`, `internal/risk` | New service (Go) | Validation, canonical form, digests, bundles, diff, import and export, starter library sync |
| `internal/riskapi` | API (Go) | `/api/v1/scenarios`, `/library`, `/controls`, `/risk` (contract `api/openapi/risk.yaml`) |
| `risk` schema | PostgreSQL | Heads, versions, pins, starter library, the installation currency. Written as `app_rw` under RLS; checks in triggers |
| `pkg/authz` + migration | Existing | `authz.inherited_bus` and the inherited read policy (ADR-007 amendment 2) |
| Gateway | Existing | Segments `scenarios`, `library`, `controls`, `risk` route to the risk service |
| `web/src/risk` | UI | Scenario list, editor with the taxonomy view, version diff, library and control pages |
| `deploy/k8s/risk.yaml` | Deployment | Same hardening as the other services; keys `risk/jwt` (`keys.Mounts`) |

The risk service is stateless (A5) and connects as `app_rw`, like iam: it needs no role of its own because every table is under RLS and the checks are in triggers, not in definer functions. Its SECURITY DEFINER code is the schema's trigger functions, owned by `risk_definer` (§4.2).

## 3. The model

### 3.1 Taxonomy and levels (AC-03, AC-29, AC-28)
The scenario document holds a tree mirroring O-RT. Each branch states the level it is estimated at; the validator computes the set of required estimates from the levels, and the document must contain exactly that set (AC-03).

| Branch | Levels (choice per scenario) | Estimates required |
|---|---|---|
| Loss event frequency | `lef` | LEF |
| | `tef_vuln` | TEF branch + Vulnerability branch |
| Threat event frequency | `tef` | TEF |
| | `cf_poa` | contact frequency, probability of action |
| Vulnerability (AC-29) | `direct` | Vulnerability (probability) |
| | `derived` | threat capability, resistance strength |
| Primary loss | per form of loss | one magnitude per form the scenario includes |
| Secondary risk | per secondary stakeholder group | SLEF (probability per primary event) + one magnitude per included form |

- Forms of loss are the six Open FAIR forms only (AC-04): `productivity`, `response`, `replacement`, `fines_judgments`, `competitive_advantage`, `reputation`.
- Threat capability may come from the scenario's threat community entry (AC-08) or be entered on the scenario; either way the scenario version pins what it used.
- The taxonomy view (AC-28) is computed from the same level rules: each node is marked *entered*, *derived* or *not used*.

### 3.2 Estimates (AC-05, AC-06)
```json
{"min": 0.5, "ml": 2, "max": 6, "unit": "events_per_year", "confidence": 0.9,
 "rationale": "...", "sources": [{"type": "document", "ref": "IR report 2026-03", "note": "..."}]}
```
- `unit` must fit the factor: `events_per_year` (LEF, TEF, contact frequency), `probability` (probability of action, Vulnerability, SLEF), `currency` (magnitudes; the installation currency, §3.4), `percentile` (threat capability, resistance strength; 0 to 100 against the threat community continuum), `fraction` (a control's reduction of a factor or form of loss, 0 to 1; §3.5).
- `min ≤ ml ≤ max`; probabilities in [0, 1]; frequencies and magnitudes ≥ 0; `confidence` in (0, 1).
- `rationale` is required and non-empty; at least one source, of type `person`, `document`, `dataset` or `integration`.
- Numbers are JSON numbers kept as decimal strings in the canonical form, so the digest never depends on float formatting.

### 3.3 Documents
JSON Schemas (2020-12) in `internal/risk/model/schema/` (`common.json`, `scenario.json`, and `library.json` with one definition per library kind and controls), with `schema_version` in every document. The Go validator (`internal/risk/model`) is the runtime authority; a test runs the schemas over the shared corpus (`modeltest`) so they agree with it:

| Kind | Holds |
|---|---|
| `scenario` | name, description, scope (in and out), analysis period, owner, asset or asset group pin, threat community pin, threat effects (one or more of C, I, A), loss event description, the taxonomy tree with estimates, secondary stakeholder groups, control sets (§3.5) |
| `asset` | name, type, description, value or value basis (an estimate, or text) |
| `asset_group` | name, description, member asset pins, valuation `whole` (its own value) or `members` (sum of members) |
| `threat_community` | name, description, threat capability estimate |
| `loss_profile` | name, description, typical magnitude per form of loss (estimates) |
| `control` | name, description, external references (framework, identifier; plain text, AC-14), effects (§3.5) |

Text limits (AC-23): names 200 characters, single-line fields 1,000, descriptions, scope and rationale 10,000; every text field is refused if `audit.LooksSecret` matches it (Go) and `audit.looks_secret` (database).

### 3.4 Currency (AC-07)
`risk.instance` holds one row with the ISO 4217 code. It is set at install (`risk currency set CODE`, audited `risk.currency_set`) and can be changed only while no stored version contains a magnitude; afterwards the command refuses, because existing magnitudes would silently change meaning. Every API response with magnitudes, every export and every bundle carries the code.

This is an installation setting of the risk service, not an F-015 posture setting: it has no security strength to order, so F-015's bounds and strictest-of do not apply. (The requirements' dependency on F-015 for the currency is amended accordingly; §12.)

### 3.5 Controls and control sets (AC-12, AC-13, AC-14)
- A control's `effects` list the factor each affects and how, as an estimate: `contact_frequency`, `probability_of_action`, `threat_capability` (reduction), `resistance_strength` (the control's strength as a percentile), or a form of loss (reduction).
- A scenario has `control_sets`: exactly one marked `current`, and zero or more alternatives with names. Each entry pins a control version and states `in_place` or `proposed`; the scenario may override the control's default effect for this scenario (with its own rationale and source).
- F-005 simulates each control set as a variant of the same bundle.

## 4. Data model (schema `risk`)

### 4.1 Tables
| Table | BU-owned (resource type) | Purpose |
|---|---|---|
| `risk.scenario` | yes (`scenario`, inactive column `archived_at`) | Head: id, bu_id, current version, archived_at |
| `risk.scenario_version` | yes (`scenario`) | id, version, document (bytea), digest, author, created_at, change_note |
| `risk.library_entry` | yes (`library`, inactive `archived_at`) | Head: id, bu_id, kind (`asset`, `asset_group`, `threat_community`, `loss_profile`), current version, origin (starter key, if copied) |
| `risk.library_version` | yes (`library`) | As scenario_version |
| `risk.control` | yes (`control`, inactive `archived_at`) | Head |
| `risk.control_version` | yes (`control`) | As scenario_version |
| `risk.scenario_pin`, `risk.library_pin` | yes (`scenario`; `library`, shared down) | Filled by trigger from each new scenario version (asset or group, threat community, controls) and asset-group version (members): (version, JSON pointer) → (to kind, id, version). Drive "newer version available" (AC-10), visibility flags (AC-20) and reference counts |
| `risk.starter_entry` | no | The shipped starter library (§6.6). Read-only; synced by `iam migrate` |
| `risk.instance` | no | The currency |

All BU-owned tables are created with `authz.apply_bu_rls` and get `rlstest` fixtures (F-001 T-10 gate). Version tables carry the head's `bu_id` so the same policies apply.

### 4.2 Triggers (the database side of validation)
- **Append-only versions.** `UPDATE` and `DELETE` on version and pin tables are refused, except an update of `bu_id` alone made by the move function (§6.4), which a trigger checks with `risk.moving()` set in the transaction.
- **Version numbering.** A new version must be `current + 1` of its head, and the head's `current_version` moves with it in the same statement pair (optimistic concurrency: a stale `expected_version` fails, AC-15).
- **Document checks** (`risk.check_document(kind, jsonb)`): digest equals SHA-256 of the stored bytes; the bytes are canonical (parsing and re-canonicalising gives the same bytes, checked with a SQL implementation of the RFC 8785 subset we emit: objects with sorted keys, no insignificant whitespace, numbers as emitted by §3.2); `kind` and `schema_version` match; every estimate passes §3.2; the taxonomy contains exactly the required estimates (§3.1); every text field is within its limit and not secret-looking.
- **Pins.** Each pinned (kind, id, version) must exist and be visible to the writer at write time (inherited read included), so an analyst cannot pin what they cannot see.
- **Parity.** `TestRiskValidationParity` runs a generated corpus of valid and invalid documents through the Go validator and `risk.check_document` and requires identical verdicts, as F-015 T-13 does for setting values.

### 4.3 Retention
Versions are kept for the life of the head. Nothing is deleted in v1: scenarios, entries and controls are archived and restored (AC-22). Deletion, if ever added, will check the pin tables and the referring features' tables (F-005 runs, F-007 register, F-008 acceptance).

### 4.4 Access model
- `app_rw`: `SELECT`, `INSERT` on heads, versions and pins; `UPDATE` of heads (current version, archived_at) under RLS. No `DELETE`.
- **Inherited read** (ADR-007 amendment 2): the `SELECT` policy on `library_entry`, `library_version`, `control` and `control_version` admits `bu_id = ANY(authz.inherited_bus(type))` in addition to the scope form. Writes are unchanged: an entry is edited only where the caller holds `library.edit` (or `control.edit`).
- **Pinned versions**: each pin row holds the pinned version's digest and canonical document, copied by the version trigger (which checks the copy against the pinned version, visible to the writer at write time). Versions never change, so the copy cannot drift. A scenario reader therefore sees exactly what the scenario uses under the scenario's own policy, without `library.view` and after a move (AC-20); no privileged reader exists. (Changed from a SECURITY DEFINER `risk.pinned_versions`: RLS policies depend on the signed context, not the role, so a definer function could not read past them.)
- **Starter library**: read by any caller holding `library.view` anywhere (`risk.starter_entries()`); copied into a BU by `library.edit` there.

## 5. API (`api/openapi/risk.yaml`)
Conventions of F-001 T-42: `Idempotency-Key` on mutations, `reason` where the change is significant, 404 for unseen ids, `x-permission`, `x-audit-events`.

| Route | Permission | Notes |
|---|---|---|
| `GET /api/v1/scenarios` | `scenario.view` | Filters: BU, owner, asset, threat community, archived; `authz.NewestQuery` paging |
| `POST /api/v1/scenarios` | `scenario.edit` at the BU | Body: BU and document; 422 lists every validation failure |
| `GET /api/v1/scenarios/{id}` | `scenario.view` | Current version, pins resolved, flags (newer pinned versions, AC-10; pins not visible from the BU, AC-20), taxonomy view (AC-28) |
| `PUT /api/v1/scenarios/{id}` | `scenario.edit` | New version: document, `expected_version`, change note (required) |
| `GET /api/v1/scenarios/{id}/versions[/{v}]` | `scenario.view` | |
| `GET /api/v1/scenarios/{id}/diff?from=&to=` | `scenario.view` | Structured diff (AC-17) |
| `GET /api/v1/scenarios/{id}/versions/{v}/bundle` | `scenario.view` | Canonical input bundle and its digest (AC-16) |
| `POST /api/v1/scenarios/{id}/adopt` | `scenario.edit` | Re-pin listed entries to their current versions as a new version (AC-10) |
| `POST /api/v1/scenarios/{id}/move` | `scenario.edit` at both BUs | Reason required; refused out of a restricted subtree (AC-19) |
| `POST /api/v1/scenarios/{id}/archive`, `/restore` | `scenario.edit` | Reason required |
| `/api/v1/library[...]` | `library.view` / `library.edit` | Same shape: list (with inherited entries, marked), create, get, put, versions, diff, archive, restore; `?kind=` |
| `GET /api/v1/library/starter`, `POST /api/v1/library/starter/{key}/copy` | `library.view` / `library.edit` | AC-11 |
| `/api/v1/controls[...]` | `control.view` / `control.edit` | Same shape |
| `GET /api/v1/risk/settings` | any risk view permission | The currency |
| `POST /api/v1/risk/exports` | `scenario.view` / `library.view` / `control.view` for what is included | Synchronous JSON file (§6.5); audited |
| `POST /api/v1/risk/imports?dry_run=true` | the matching edit permissions at the target BU | All or nothing (§6.5) |

## 6. Key flows

### 6.1 Save a version (AC-05, AC-06, AC-09, AC-15, AC-21, AC-23)
1. The handler checks the permission (`Cache.Check`) at the head's BU.
2. `internal/risk` validates the document against its schema and the §3 rules, resolves pins (every pin must be visible), canonicalises it and computes the digest. Failures return 422 with every failure listed by JSON pointer.
3. In one transaction inside `WithDBContext`: insert the version, advance the head (`expected_version`), triggers re-check, pins are filled, and the audit event (`scenario.version_saved`, with BU, version, digest and change note) is recorded through `audit.WithTx`. Any failure rolls back everything (audit fails closed).

### 6.2 Newer library versions (AC-10)
On read, the service joins the pin tables with the pinned heads' `current_version` (inherited read applies) and reports each pin with a newer version. `adopt` compares the old and new entry versions (§6.3 diff) and saves a scenario version with the new pins; nothing changes otherwise (AC-09).

### 6.3 Diff (AC-17)
A structural diff of two canonical documents: added, removed and changed paths, with estimates shown as old and new triples. Pins are shown as entry name and version changes. Computed in Go; no stored state.

### 6.4 Move a scenario (AC-19, AC-20)
1. The caller needs `scenario.edit` at the source and the destination BU.
2. Refused if the source is inside a restricted subtree and the destination is not inside the same restricted subtree (the nearest restricted ancestor-or-self of each, from `iam.bu_closure`, must be the same; a new `iam.restricted_root(bu)` computes it), so a restricted BU's scenario never leaves it.
3. In one transaction: `risk.moving()` is set, the head and all its versions and pins get the new `bu_id`, and `scenario.moved` is recorded with both BUs and the reason. Versions are otherwise untouched (their digests do not include `bu_id`).
4. Afterwards, any pin whose entry's BU is neither the scenario's BU nor one it inherits from is flagged on the scenario (AC-20). The scenario keeps its recorded versions, held in its pin rows, until the analyst replaces them.

### 6.5 Export and import (AC-24, AC-25)
- Format `fair.risk.v1`: `{format, currency, exported_at, scenarios: [{head, versions}], library: [...], controls: [...]}`, every document in canonical form with its digest. Documented in `docs/formats/fair-risk-v1.md` with a JSON Schema.
- Export takes a selection (ids, or a BU subtree) and includes, for each scenario, the library and control versions it pins. It contains only what the requester can see (RLS); pinned versions the requester can read only through the scenario's pin rows are included from those rows. Recorded as `risk.exported` with counts and the file's digest.
- Import into one target BU: the importer needs the edit permission for every kind included. The file's currency must equal the installation's. Every document is validated as in §6.1; pins resolve to entries in the same file (re-mapped to the new ids) or to existing entries the importer can see, by id and digest. Dry run returns the plan (created and changed items) and every failure; a real import is one transaction, all or nothing, recorded as `risk.imported` plus the per-item creation events.

### 6.6 Starter library (AC-11)
Shipped as JSON in `internal/risk/starter/` (embedded), synced into `risk.starter_entry` by `iam migrate` like the event catalog. Content: generic threat communities (cyber criminals, nation-state actors, malicious insiders, non-malicious insiders, hacktivists, third parties) and guidance per form of loss, written from Open FAIR concepts. Example values, where shown, are marked `illustrative: true` and the UI labels them. Customers copy an entry into a BU (`origin` records the starter key and release); the copy is theirs to edit, the starter entry is never editable.

### 6.7 Archive and restore (AC-22)
Archiving sets `archived_at` (the head becomes read-only: version inserts are refused while archived) and records the event with the reason. Archived rows are inactive for F-001's archive guard, so they do not block archiving their BU; active ones do (F-001 T-31).

## 7. Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Risk service | Vendor-operated | Customer cluster | Customer cluster |
| Currency | Set at installation | Set at installation | Set at installation |
| Starter library | Embedded in the release | Same | Same |
| Import and export | JSON over the API | Same | Same; no outbound calls |

No outbound connections in any mode.

## 8. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| S: an analyst saves under another identity | Author from the signed DB context (ADR-007), never the body | `TestSTRIDEF003Author` |
| T: a version is edited in the database | Append-only triggers; digest re-checked; the trail records each version's digest | `TestSTRIDEF003VersionTamper` |
| T: an invalid document bypasses the service | Triggers re-check every invariant; parity test | `TestRiskValidationParity` |
| T: a pin points at an entry the analyst cannot see | Pin visibility checked by trigger at write | `TestSTRIDEF003PinVisibility` |
| R: a change cannot be attributed | Every change audited in its transaction with BU and change note | `TestRiskAuditEvents` |
| I: a child BU reads a sibling's or a restricted BU's library | Inherited read only up the caller's own ancestors, stopping at restricted BUs; RLS harness fixtures | `TestSTRIDEF003InheritedRead` |
| I: a move leaks a restricted scenario | Move refused out of a restricted subtree | `TestSTRIDEF003RestrictedMove` |
| I: an export leaks unseen data | Export built under the requester's RLS context | `TestSTRIDEF003ExportScope` |
| I: secrets pasted into free text | `looks_secret` in Go and the database | `TestRiskSecretsRefused` |
| D: huge documents or imports | Text limits, document size limit (1 MiB), import size limit (32 MiB), API body limits | `TestRiskLimits` |
| E: a reader without `library.edit` changes the library | Writes use the ordinary own-scope policy; inherited read is `SELECT` only | `TestSTRIDEF003InheritedWrite` |

## 9. New catalog event types
`scenario.created`, `scenario.version_saved`, `scenario.moved`, `scenario.archived`, `scenario.restored`, `library.created`, `library.version_saved`, `library.archived`, `library.restored`, `library.starter_copied`, `control.created`, `control.version_saved`, `control.archived`, `control.restored`, `risk.exported`, `risk.imported`, `risk.currency_set`. All with `bu: required` except `risk.currency_set`.

## 10. Requirements traceability
| AC | Satisfied by |
|---|---|
| AC-01 | §3.3 scenario document; `POST /scenarios`; asset or asset group pin |
| AC-02 | §3.3 scope and period; schema requires asset, threat community, threat effect |
| AC-03 | §3.1 levels; §4.2 required-estimate check |
| AC-04 | §3.1 forms and secondary stakeholders |
| AC-05, AC-06 | §3.2; §4.2 |
| AC-07 | §3.4 |
| AC-08 | §3.3 library kinds; §4.4 inherited read |
| AC-09, AC-10 | §4.1 pins; §6.2 |
| AC-11 | §6.6 |
| AC-12, AC-13, AC-14 | §3.5 |
| AC-15 | §4.2 append-only, numbering; §6.1 |
| AC-16 | §1 bundle; `/bundle`; §3.2 canonical numbers |
| AC-17 | §6.3 |
| AC-18 | §4.1 apply_bu_rls; §4.4 |
| AC-19, AC-20 | §6.4 |
| AC-21 | §9; §6.1 step 3 |
| AC-22 | §6.7; §4.3 |
| AC-23 | §3.3 limits and secrets |
| AC-24, AC-25 | §6.5 |
| AC-26 | §5 |
| AC-27 | `web/src/risk`; axe in `scripts/ui-e2e.sh` |
| AC-28 | §3.1 taxonomy view |
| AC-29 | §3.1 Vulnerability levels |

Performance (requirements NFR): `TestBenchmarkGateRiskScenarios` (10,000 scenarios in a subtree, list ≤ 500 ms p95, load with pins ≤ 300 ms p95) in the bench gate.

## 11. ADR-007 amendment 2: inherited read (accepted)
- `authz.inherited_bus(type)`: the ancestors of the BUs where the caller holds `<type>.view`, excluding BUs already in the visible set, walking up `iam.bu_closure` and stopping at a restricted BU: a restricted BU inherits nothing from above, and nothing above a restricted BU is inherited through it. SECURITY DEFINER, STABLE, owned by `authz_definer`, evaluated once per statement; fail closed (NULL without a valid context).
- The set is small: at most the depth of the tree for each top of the caller's scope.
- Used only by `SELECT` policies of tables registered as *shared down* (`authz.apply_bu_rls(..., shared_down => true)`); the RLS harness exercises it for every such table, including the restricted cases.

## 12. Changes to other features
- **F-001:** ADR-007 amendment 2, `apply_bu_rls`'s `shared_down` option and `iam.restricted_root`; RLS harness fixtures for the risk tables; gateway segments; no new permissions (OQ5).
- **F-002:** catalog entries for §9.
- **F-003 requirements:** the dependency line "F-015 (installation settings, for the currency)" becomes "the risk service's installation setting (design §3.4)"; noted in the requirements' Change Log.
- **Bootstrap:** role `risk_definer` (`scripts/db-bootstrap.sh`).

## 13. Alternatives considered
- **Risk data in the iam service.** Rejected: mixes identity with risk data and widens iam's privileges.
- **Copy library entries into the scenario's BU on use** instead of inherited read. Rejected: entries fork, and AC-10 becomes a synchronisation problem.
- **Normalised rows per version** (estimates, controls and losses as tables). Rejected: many tables to copy per version, and the digest of AC-16 would be computed across them. Documents keep a version one row and one digest; reporting needs (F-007) can use generated views later.
- **Currency as an F-015 setting.** Rejected: it has no security ordering, and changing it after data exists must be refused rather than bounded.

## 14. Open items
- The starter library's text is drafted in T-10 and reviewed by Robert before release.

## Change Log
- 2026-11-06: Initial draft (decisions: new `risk` service; inherited read through ADR-007 amendment 2; canonical JSON versions).
- 2026-11-06: **Approved** by Robert Former, with ADR-007 amendment 2.
- 2026-11-06: T-02: the `fraction` unit for control reductions (§3.2); schema files and the validator's authority stated (§3.3; decided by Robert Former).
- 2026-11-06: T-03: pins in two tables (`scenario_pin` under the scenario's scope, `library_pin` shared down with the group); error codes PF016 (invalid document or pin, missing context), PF017 (stale version, archived or unwritable head), PF018 (append-only); `iam migrate` passes the release's resource types to migrations (`fair.release_resource_types`) so `apply_bu_rls` accepts types the catalog records only after them.
- 2026-11-06: T-03: pinned versions are copied into the pin rows (digest and document) instead of read through a definer function (§4.4; decided by Robert Former).
- 2026-11-06: T-05: heads carry `seq` (the list order) and summary columns kept by the version trigger (every head's name; a scenario's owner, asset and threat community) for list filters (migration 0087); `authz.NewestQuery` takes a constant `Filter`; risk events use a new catalog category `risk_data`; GET `/api/v1/risk/settings` serves the currency.
- 2026-11-09: T-06: list responses mark inherited library entries and controls (`inherited`); `authz.NewestQuery.SharedDown` walks the inherited BUs; scenarios, the library and controls share one set of handlers over a resource description.
