# F-011 Integrations and automation inputs — Design
Status: Approved | Owner: Robert Former | Last updated: 2026-11-17
Requirements: `requirements.md` (Approved 2026-11-17) · ADR-003, ADR-005, ADR-006, ADR-007 (amendments 3 and 5)

## 1. Overview
- **Two services, split by trust (decided 2026-11-17).**
  - A new **`integrate` service** (`cmd/integrate`; its own deployment and database role `app_integrate`, functions only, as `app_notify`). It configures integrations and holds connector credentials, and it is the only pod with egress to the hosts `integration.allowed_hosts` names. Connectors run there: they fetch from the source through the destination guard (F-009's, shared), then submit what they fetched as a batch to the platform's own API, as the integration's service account, through the gateway (§3.3). The gateway segment is `integrations`.
  - The **risk service** receives every batch, whether pushed by customer automation, uploaded as a file, or submitted by a connector. It validates, matches and stages records, and computes proposed changes. Reviewers accept or reject them, and accepting writes the target's new version through the existing risk and register code, in the reviewer's own transaction under RLS. The new routes are `imports`, `proposals` and `loss-events`, plus the register import under `register`. The risk pod gains no egress.
- **One schema, `integration` (decided 2026-11-17)**, owned through a bootstrap role `integration_definer`. Integrations, runs, staged records, external-ID links, proposals and derivations are definer-only. Loss events are a BU-owned table under RLS (type `library`, `shared_down`, inserted only by `integration_definer`; ADR-007 amendment 5).
- **Every input becomes the same thing.** A batch is a list of records of one input kind (`asset`, `asset_group`, `loss_event`, `risk`, `control_status`), in a documented JSON format (`fair.integration.v1`) or CSV with a declarative column mapping. Each record carries the source's stable `external_id`. Matching is by `(integration, external_id)` only (AC-07).
- **Proposals, not writes (P4).** For each valid record the risk service computes the target's proposed document: the current version with the mapped fields replaced, or a new record. It stores the record as a proposal only when that document differs from the current version and from the last rejected one (AC-12). Accepting a proposal applies it as a new version, with its provenance recorded beside it (`integration.applied`). Scenarios keep their pins and see "newer version" (F-003-AC-10).
- **Two exceptions, both designed so that nothing analysed changes silently.**
  - **Loss events** are data, not analysis inputs. They are written directly, and the reference classes derived from them get proposals.
  - **The first import of a register** creates its risks directly, all or nothing, as the importer's own act. They arrive unquantified, with no pins, so no analysis depends on them yet.

## 2. Components
| Component | Change |
|---|---|
| `db/bootstrap` | Roles `app_integrate` (login; `FAIR_INTEGRATE_PASSWORD_FILE`) and `integration_definer` (NOLOGIN); re-run `scripts/db-bootstrap.sh` |
| `db/migrations` | Schema `integration` (§5); `authz.apply_bu_rls('integration.loss_event', 'library', shared_down => true)` with `authz.allow_definer(_insert)`; the control document's `implementation` (§3.7) in `risk.check_document`; `integration.notice_outbox` and F-009's `notify.collect` / `recheck` for source `integration` |
| `internal/egress` | F-009's destination guard moved out of `internal/notify` (unchanged; `notify` imports it) |
| `internal/integration` | Formats and validation per input kind, CSV mappings, matching, proposal computation, derivations, connectors (`http_json`, `servicenow_cmdb`), the connector runner, `CheckInstall` |
| `cmd/integrate`, `internal/integrateapi` | The integrate service and the integrations API (§6.1), contract `api/openapi/integrate.yaml` |
| `internal/importapi` | In the risk service: batches, uploads, runs, proposals, loss events, derivations (§6.2), contract `api/openapi/import.yaml` |
| `internal/registerapi` | The register import (`/register/imports`, §3.6) |
| `internal/risk/model` | Control `implementation` (status, assessed_on, source), optional, validated in Go and SQL (parity) |
| `internal/keys` | Service `integrate`: `integrate/jwt`, `integrate/secrets` (AES-256-GCM key; `iam keys rotate -kind integrate-secrets`); `iam keys upgrade` adds them |
| `pkg/settings` | `settings.F011Defs()` (§4); packages 1.10.0 |
| `internal/access/catalog` | Catalog version 6: `integration.view` (Platform Admin, Auditor) and `integration.push` (§3.3; held as a service-account scope); re-sign |
| `internal/notify` | Kinds `integration.run_failed`, `integration.proposals_waiting`, `control.lapsed` (source `integration`) |
| `internal/gateway` | Segments `integrations` → `integrate`; `imports`, `proposals`, `loss-events` → `risk` |
| `deploy/k8s/integrate.yaml` | Deployment, Service, NetworkPolicy (egress: the database, the gateway, HTTPS to allowed hosts) |
| `web/src/integrations` | Integrations, runs, the review queue, loss events, the register import |
| `pkg/audit/catalog.yaml` | F-011's events (§8) |

## 3. Model
### 3.1 Integrations (AC-01 to AC-05)
- **What an integration is:** a BU, a name, an input kind, a delivery (`push`, `file` or `connector`), a mapping, `auto_accept` (off) and a state (`active`, `paused` or `deleted`, the last kept for provenance). A connector integration also has a connector, its source, a schedule and credentials.
- **Who may manage it:** created, changed, paused, resumed and deleted by holders of `integration.manage` at its BU; read by holders of `integration.view` there. An integration inside a restricted subtree needs that permission inside it (AC-02): grants above a restricted BU do not reach it (F-001).
- **Credentials (AC-03):** the source's credential (a token, or a user and password) and the client secret of the integration's service account (§3.3). Both are sealed with AES-256-GCM under `integrate/secrets` (key id recorded, as F-009 does) and accepted once. They are never returned, only replaced or removed, and decrypted only in the connector runner.
- **Destinations (AC-04):** every source host must match `integration.allowed_hosts`. Each resolved address passes `egress.Guard`: internal and metadata ranges are refused, private ranges are allowed only in air-gapped mode, the checked address is dialled, and there are no redirects or proxies. TLS 1.2 or later is required, with the certificate verified (the customer's CA bundle, `FAIR_INTEGRATE_CA_FILE`). A refusal is recorded (`integration.destination_refused`) and the run fails.

### 3.2 Batches, runs and staging (AC-06 to AC-09)
- **Receiving a batch:** `POST /imports/{integration}/batches` takes `fair.integration.v1` JSON (`{format, kind, complete, records: [...]}`) or, with `Content-Type: text/csv`, CSV mapped by the integration's column mapping. Records are limited to 10,000 per batch, 20 MiB per body and 12 runs per integration per hour (OQ8). The caller needs `integration.push` (a service account, or the integrate service acting as one) or `integration.manage` (an administrator's upload) at the integration's BU.
- **The run:** each batch is a run (`integration.run`). The risk service, in one transaction:
  1. checks every record against its kind's typed Go definition, which is the authority, and against the mapping;
  2. records refusals by position and JSON pointer, keeping at most the first 1,000;
  3. matches the valid records by external ID, ignoring duplicates within the batch (the first wins; later ones are refused);
  4. computes proposals (§3.4);
  5. records the run's counts (received, valid, refused, unchanged, proposed, applied).
  If any step fails, the run fails whole and nothing is staged (NFR availability).
- **Dry runs (AC-09):** `?dry_run=true` does everything except write, and answers the counts and the first 200 proposals.
- **Staged records:** normalized and canonical, with their digest. They are kept 30 days for diagnosis (`integration.records_retention_days`), then purged; the proposals and links remain.
- **Complete batches (AC-14):** a batch marked `complete` (a full snapshot, as connectors send) lets the run propose archiving the linked records it did not contain, with each one's users (scenarios pinning an asset, risks linking those scenarios).

### 3.3 Connectors and the integration's service account (AC-01, AC-08; OQ2)
- **The service account:** a connector integration names an F-001 service account at its BU (created by an administrator as today), and stores its client secret (§3.1). The service account holds `integration.push` and, if `auto_accept` is on, the edit permission of the kind's records at the BU (`library.edit` or `control.edit`).
- **A connector run:** the runner obtains a 10-minute token (`/api/v1/oauth/token`, client_credentials with the service account's client secret) and pushes the batch through the gateway like any other client. A connector's service account authenticates with a client secret: the runner holds no client certificate, so a service account that requires mTLS is refused when the integration is saved (amended 2026-11-18). Scope, limits, RLS and audit are therefore the platform's own, and the integrate service never writes risk data itself.
- **Scheduling:** the integrate service's leader claims due integrations (`integration.claim_due`, `FOR UPDATE SKIP LOCKED`; at most 12 runs per hour, after back-off). A worker:
  1. fetches every page (each bounded in bytes and time; at most 10,000 records in all);
  2. maps them to `fair.integration.v1` with `complete: true`;
  3. submits them;
  4. records the outcome on the integration.
  A failure retries at the next scheduled time with exponential back-off. After three consecutive failures the run raises `integration.run_failed` to the integration's managers (F-009, AC-08).
- **v1 connectors (OQ2):**
  - **`http_json`:** a GET of a JSON array, or an object with a list at a JSON pointer, with paging by `next` URL or offset/limit. It has a declarative field mapping (JSON pointer to field, plus value maps for categories and statuses) and a bearer token or basic credential.
  - **`servicenow_cmdb`:** the Table API for a CMDB class (default `cmdb_ci_business_app`), mapping `sys_id` to the external ID and name, `short_description`, the owning group (mapped to a BU by a table in the mapping) and an optional business value field.
  Both use only `GET`, never write to the source, and follow no links to other hosts. A paging URL is re-checked against the allow-list.

### 3.4 Proposals and review (AC-10 to AC-14)
- **Computing proposals (amended 2026-11-18, decided by Robert Former: merge at review):**
  - A proposal stores the source record's mapped values (its normalized record) and their digest: the pusher often cannot read the target under RLS (a service account with only `integration.push`), and the risk and library tables admit no second definer (ADR-007 amendment 3).
  - The proposed document is the target's current version with the mapped fields replaced (fields the mapping does not name are kept), computed when a reviewer opens or accepts the proposal, under the reviewer's own RLS. For a **new record** it is built from the record and completed with the platform's required fields.
  - A proposal is stored only when its record's digest differs from the link's last applied and last rejected digests (AC-12). A newer proposal for the same link supersedes a pending one. Update proposals carry no `base_version`; accepting takes `expected_version`, the version the reviewer saw.
  - Descriptive fields are name, description and external references. A proposal changing only these is applied at once when `auto_accept` is on and the pusher holds the target's edit permission. Otherwise it waits, as every value, estimate, reference data and status change does (AC-13).
- **Review:** `GET /proposals` lists them, filtered by integration, kind, state and BU. Each shows the current and proposed documents and their diff (F-003's `DiffDocuments`), the integration, the run and the source record.
- **Visibility:** proposals are listed only to holders of the target kind's view permission at the record's BU (`library.view`, `control.view`, `register.view`), through a definer function that checks the caller's read scope. New-record proposals use the record's intended BU.
- **Accept:** `POST /proposals/{id}/accept`, with `expected_version` = the target version the reviewer saw (the merge's base). In the caller's transaction it:
  1. checks the caller holds the target's edit permission at its BU;
  2. writes the new version through the same code as `PUT /library/{id}` (or `/controls/{id}`, `/register/risks/{id}`), or creates the record through the same code as its `POST`, so every check, trigger and event of F-003 and F-007 applies;
  3. records the provenance (`integration.applied`: proposal, run, integration, external ID, target, version, accepted by);
  4. sets the link.
  A target that moved on since gives 409 `stale_version`, and the proposal is recomputed at the next run. Up to 200 proposals can be accepted together, each with its own checks, all or nothing.
- **Reject:** `POST /proposals/{id}/reject` with a reason. The link remembers the rejected digest.
- **Archive proposals (AC-14):** accepting one archives the record through F-003's archive (`risk.set_archived`), with the reason "removed at the source". Its pins elsewhere are unaffected.
- **Waiting proposals:** when a run leaves proposals pending, `integration.proposals_waiting` notifies the holders of the kind's edit permission at the BU, once per run (F-009).

### 3.5 Assets, asset groups and loss events (AC-15 to AC-19)
- **Assets** map to `model.Asset`: name, type, description, value (a calibrated range: min, most likely, max, confidence) and value basis. The owning BU comes from the record's `bu` (a code or id inside the integration's subtree).
- **Asset groups** map to `model.AssetGroup`. Their members are external IDs of assets of the same integration, which must be linked or in the same batch; members are pinned at their current versions when the proposal is accepted.
- **Loss events** go to `integration.loss_event`:
  - Fields: BU, external ID, occurred on (date), event type (the customer's category, mapped by the integration's value map to a type name), a description, and amounts by FAIR form of loss (`model.FormsOfLoss`) as canonical decimals in the installation currency.
  - An event is inserted or updated by `integration_definer` in the run's transaction. A complete batch archives the events it no longer holds.
  - Events are read under RLS as library records (AC-19, OQ7): a viewer sees an event with `library.view` at its BU, and restricted units' events only inside their subtree.
- **Derivations (AC-18):** an analyst with `library.edit` at a reference class's BU sets the class's derivation (`PUT /library/{id}/derivation`): business units (a subtree of the class's BU), event types, a period (from, to, granularity month, quarter or year) and the data kind (`counts` or `losses`, with a form-of-loss filter).
  - Computing it gives the reference class's `data`, counts per period or loss amounts sorted, plus `sources: [{type: integration, ref: "derivation:<id>"}]`.
  - When a run changes matching events, or the analyst changes the derivation, the risk service computes the data. It proposes a new reference class version when the data differs.
  - A derivation counts only events whose restricted root equals the class's BU's (`iam.restricted_root`). An unrestricted class never counts restricted units' events, and a class inside a restricted subtree counts only that subtree.
  - **Derivation proposals (amended 2026-11-18):** a proposal's origin is either an integration and its run (records) or a derivation (`derivation_id`, the reference class), never both. A derivation proposal updates its class, has no external ID, supersedes the class's pending one, and is reviewed and accepted like any other (`library.edit` at the class's BU); its provenance names the derivation. Both an analyst's change of the derivation and a run that changes matching events propose, when the computed data differs from the last computed.

### 3.6 The register import (AC-20 to AC-22)
- **The request:** `POST /register/imports?dry_run=` (`register.edit` at the target BU) takes CSV with a column mapping, or `fair.register-import.v1` JSON. It names a source label, which scopes the external IDs.
- **Mapping:**
  - Columns map to title, description, owner (an email, matched among the users `register.owners(bu)` lists), category (by name) and external ID.
  - An optional column can be kept as text, appended to the description as "Imported <column>: <value>".
  - Columns the importer marks as ratings or scores (likelihood, impact, heat-map position, any ordinal) are refused unless explicitly kept as text (AC-21, P1). They never become exposure.
- **Dry run first:** the dry run answers every row's outcome and problems. The import runs only with the confirmation fingerprint the dry run returned, as F-001's BU move does.
- **The import:** one transaction, all or nothing (AC-22). New external IDs create risks with no scenarios, through the same code as `POST /register/risks`; they are unquantified. External IDs already linked under the same source label become proposals for those risks.
- **Provenance:** links and runs use a per-BU file integration created on first use (`delivery = file`, kind `risk`, name `Register import: <label>`), so the review, provenance and audit are the same as for other integrations.

### 3.7 Control status (AC-23, AC-24)
- **The model:** the control document gains an optional `implementation`: `{status: in_place | partial | planned | not_in_place, assessed_on, source: {type, ref}}`. It is validated by `model.Validate` and `risk.check_document`, held equal by the parity corpus. Controls without it are unchanged.
- **Records:** a `control_status` record names the control's external ID and the implementation. The proposal is a new control version with that `implementation`.
- **When a status lapses:** when an accepted version changes `implementation.status` from `in_place` to anything else, the accept transaction queues `control.lapsed` (`integration.notice_outbox`, through `integration.control_lapsed(control, version)`). It goes to the owner of each scenario whose latest version uses the control as `in_place` in a current control set.
- **Shown on read:** the scenario API's pins and the register's risk view gain `control_lapsed: [{control_id, status, assessed_on}]` for those uses, computed on read from the latest control version.
- **Making it current again:** adopting the new version (F-003 T-07) and re-running makes the exposure current again (F-007-AC-08). Nothing is changed automatically.

### 3.8 Provenance (AC-25)
- **On read:** every library, control and register version read through the risk API gains `provenance` when `integration.applied` has a row for it: the integration (id, name), run, external ID, received and accepted times, and the acceptor's name.
- **In estimates:** a derived reference class's `sources` names the derivation, and an estimate that uses it as a reference class (F-004) carries that source, giving the chain from estimate to reference class to derivation to run to source records.

## 4. Settings (F-015)
| Key | Kind | Default | Bounds | Stricter | Notes |
|---|---|---|---|---|---|
| `integration.allowed_hosts` | set | empty | at most 100 hosts | subset | Every added host needs dual approval (as `notification.allowed_hosts`) |
| `integration.records_retention_days` | int | 30 | 1–365 | lower | Staged records |
Packages 1.10.0 (59 settings). Limits (OQ8) are constants checked in Go and the database: 20 MiB, 10,000 records, 12 runs per hour, 50 integrations.

## 5. Data model (schema `integration`, owned through `integration_definer`)
| Table | Purpose | Access |
|---|---|---|
| `integration.integration` | id, bu_id, name, kind, delivery, mapping, connector (type, source, schedule minutes), service_account_id, auto_accept, state, version, created/changed by and at, next_run_at, failures | Definer only; read through `integration.list` / `get` (view or manage at the BU) |
| `integration.secret` | integration_id, purpose (`source`, `client`), key_id, nonce, ciphertext, set_by, set_at | Definer only; decrypted only by `app_integrate` (`integration.secret_for_run`) |
| `integration.run` | id, integration_id, trigger (`push`, `upload`, `schedule`, `manual`), actor, dry_run, complete, state, counts, refusals (≤ 1,000), started_at, finished_at | Definer only; `integration.runs` |
| `integration.record` | run_id, n, external_id, data (canonical), digest | Definer only; purged after retention |
| `integration.link` | integration_id, external_id, target_type, target_id, last_digest, rejected_digest | Definer only; unique (integration_id, external_id) |
| `integration.proposal` | id, integration_id and run_id, or derivation_id (§3.5), bu_id, target_type, target_id (null for new), action (`create`, `update`, `archive`), base_version, document, digest, descriptive_only, state (`pending`, `accepted`, `rejected`, `superseded`), decided_by, decided_at, reason | Definer only; through `integration.proposals` (the caller's view scope), accept and reject functions |
| `integration.applied` | proposal_id, target_type, target_id, version, accepted_by, accepted_at | Definer only; read by the risk API for provenance |
| `integration.loss_event` | id, bu_id, integration_id, external_id, occurred_on, event_type, description, amounts, archived_at, seq | BU-owned, RLS type `library` (`shared_down`); inserted and updated only by `integration_definer` (amendments 3, 5) |
| `integration.derivation` | reference_class_id, bu_id, filter, data_kind, digest, set_by, set_at | Definer only |
| `integration.notice_outbox` | kind, user_id, integration_id or control_id | Insert by `integration_definer`; collected by `notify_definer` |
State rules (PF031): runs, applied rows and decided proposals are immutable; links change only through the definer's functions; at most 50 integrations that are not deleted (PF032).

## 6. API
### 6.1 Integrations (`api/openapi/integrate.yaml`, `/api/v1/integrations`, the integrate service)
| Route | Permission | Notes |
|---|---|---|
| `GET /integrations`, `GET /integrations/{id}` | `integration.view` or `manage` at the BU | No secrets, only whether each is set |
| `POST /integrations`, `PUT /integrations/{id}` (expected_version) | `integration.manage` at the BU | Kind and BU fixed after creation; the source host checked against the allow-list on save |
| `PUT`, `DELETE /integrations/{id}/credentials/{purpose}` | `integration.manage` | Write-only (AC-03) |
| `POST /integrations/{id}/pause`, `/resume`, `/run`, `DELETE /integrations/{id}` | `integration.manage` | Reason on delete; `/run` queues a connector run now |
| `POST /integrations/{id}/test` | `integration.manage` | Fetches the first page without submitting; answers the count and the first mapping problems |
| `GET /integrations/{id}/runs[/{run}]` | `integration.view` | Counts and refusals |

### 6.2 Imports and review (`api/openapi/import.yaml`, the risk service)
| Route | Permission | Notes |
|---|---|---|
| `POST /imports/{integration}/batches[?dry_run=true]` | `integration.push` or `integration.manage` at the integration's BU | JSON or CSV; 201 with the run (202 is not needed: a batch is processed in the request) |
| `GET /imports/runs/{id}` | `integration.view`, or the run's actor | |
| `GET /proposals`, `GET /proposals/{id}` | the target kind's view permission at the BU | |
| `POST /proposals/{id}/accept`, `/reject`, `POST /proposals/accept` (batch) | the target kind's edit permission at the BU | expected_version; reason on reject |
| `GET /loss-events`, `GET /loss-events/{id}` | `library.view` | Filters: BU, type, period |
| `GET`, `PUT`, `DELETE /library/{id}/derivation` | `library.view` / `library.edit` | Reference classes only |
| `POST /register/imports[?dry_run=true]` | `register.edit` at the BU | §3.6 |
Conventions as before: operationId = handler; mutating routes declare `x-permission`, `x-audit-events` and Idempotency-Key; ids not the caller's are 404.

## 7. Security design (STRIDE)
| Threat | Mitigation | Test |
|---|---|---|
| E: an integration writes outside its scope or kind | BU subtree and kind checked per record in the database; restricted subtrees only by managers inside; accepted changes run under the reviewer's RLS; connectors push as a scoped service account | `TestSTRIDEF011Scope` |
| T, E: imported data changes an analysis silently | Everything but descriptive fields is a proposal; pins never move; accept checks expected_version; derived reference classes are proposals | `TestSTRIDEF011Proposals` |
| I, E: a connector is used to reach internal systems (SSRF) | Allow-list with dual approval; F-009's guard (internal ranges refused, private only air-gapped, the checked address dialled, no redirects or proxies); paging URLs re-checked; egress only from the integrate pod | `TestSTRIDEF011Destinations`, `internal/egress` tests |
| I: credentials disclosed | Sealed under a key file, accepted once, never returned or logged; decrypted only by the runner | `TestSTRIDEF011Secrets` |
| T: injection through imported values | Typed validation per kind; text only as data; CSV formula prefixes neutralized when exported (F-010); canonical JSON; no expression mappings | `TestSTRIDEF011Injection` |
| I: loss events or proposals leak across BUs | Loss events under RLS (library); proposals listed by the target's view scope; derivations within one restricted root | `TestSTRIDEF011Visibility` |
| S: a forged batch or a replayed upload | Batches need a token for a principal holding `integration.push` or `manage`; Idempotency-Key; staged digests; external IDs scoped to their integration | `TestSTRIDEF011Batches` |
| R: changes not attributable | Integration, credential, run, refusal and decision events in their transactions; provenance per version | `TestIntegrationAuditEvents` |
| D: huge or frequent batches exhaust the service | Size, record, run-rate and integration limits before work; bounded pages and timeouts; one run per integration at a time | `TestSTRIDEF011Limits`, `TestBenchmarkGateImports` |

## 8. New catalog event types
`integration.created`, `integration.changed`, `integration.paused`, `integration.resumed`, `integration.deleted`, `integration.credential_set`, `integration.credential_removed`, `integration.run` (with counts), `integration.destination_refused`, `integration.proposal_accepted`, `integration.proposal_rejected`, `integration.derivation_changed`, `register.imported`; categories `configuration` and `risk_data`.

## 9. Requirements traceability
| AC | Design | Test |
|---|---|---|
| AC-01 to AC-05 | §3.1, §3.3, §6.1 | `TestIntegrationsAPI`, `TestSTRIDEF011Destinations`, `TestSTRIDEF011Secrets` |
| AC-06 to AC-09 | §3.2 | `TestImportBatches` |
| AC-10 to AC-14 | §3.4 | `TestProposals` |
| AC-15, AC-16 | §3.5 | `TestImportAssets` |
| AC-17 to AC-19 | §3.5 | `TestLossEvents`, `TestDerivations` |
| AC-20 to AC-22 | §3.6 | `TestRegisterImport` |
| AC-23, AC-24 | §3.7 | `TestControlStatus` |
| AC-25, AC-26 | §3.8, §8 | `TestProvenance`, `TestIntegrationAuditEvents` |
| NFR performance | §3.2 | `TestBenchmarkGateImports` |
| Accessibility | `web/src/integrations` | `web/e2e/integrations.spec.ts` (axe) |

## 10. Changes to other features
- **F-001:** permission catalog version 6 adds `integration.view` (Platform Admin, Auditor) and `integration.push` (not privileged; no built-in role, granted as a service-account scope). The second was not named by the requirements (OQ5); it is how a service account is allowed to push without the privileged `integration.manage` (re-sign).
- **F-003:** the control document's optional `implementation` (§3.7); `provenance` and `control_lapsed` on reads; the starter library unchanged.
- **F-009:** source `integration`, kinds `integration.run_failed`, `integration.proposals_waiting` and `control.lapsed` (mandatory: no; items integration, control, scenario); the destination guard moves to `internal/egress`.
- **F-007:** the register import; risk views show `control_lapsed` from their scenarios.
- **F-010:** none; imported text is neutralized by its CSV writer as any text.

## 11. Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| API push, uploads, register import | Yes | Yes | Yes |
| Connectors | Allow-listed public or customer hosts | Allow-listed hosts | Allow-listed hosts inside the enclave (private ranges) |
| `integrate` service | Deployed | Deployed | Deployed; may be scaled to zero when no connector is configured |

## 12. Alternatives considered
- **Connectors in the notify or risk service:** rejected (decided 2026-11-17). Mixing outbound notices with inbound credentials, or giving the risk pod egress, widens what one compromised pod reaches.
- **The integrate service writing risk data through definer functions:** rejected. Applying under the reviewer's (or the service account's) RLS keeps F-003's and F-007's checks, triggers and events as the single path.
- **Tables in schema `risk`:** rejected (decided 2026-11-17), to keep `risk_definer`'s reach as it is.
- **Proposals for loss events:** rejected. Events are observations, not analysis inputs; the analysis inputs derived from them (reference classes) are proposed.

## 13. Open items
- D-OQ1 (resolved 2026-11-17: approved with the design): `integration.push` as a new permission (§10).
- D-OQ2: the ServiceNow connector is tested against a recorded fixture of the Table API; a live run against a developer instance is an open item, like F-001's IdP runs.

## Change Log
- 2026-11-17: Initial draft, In Review; connectors in a new integrate service and the schema `integration` decided by Robert Former.
- 2026-11-17: Approved by Robert Former, with D-OQ1 (`integration.push`).
- 2026-11-18: §3.4 amended by Robert Former (T-09): proposals hold the source record's values and digest; the merged document and its diff are computed at review and accept, under the reviewer's RLS, since the pusher may not read the target; unchanged means the link's last applied or rejected digest; update proposals carry no base_version.
- 2026-11-18: §3.5 and §5 amended by Robert Former (T-12): derivation proposals have the derivation as their origin instead of an integration and run; analysts' derivation changes and runs both propose.
- 2026-11-18: §3.3 amended by Robert Former (T-17c): connectors use service accounts that authenticate with a client secret; one that requires mTLS is refused at save.
