# F-002 Tamper-Evident Audit Trail — Requirements
Status: **Approved** (Robert Former, 2026-11-04) | Owner: Robert Former | Last updated: 2026-11-04
Constitution refs: S0, S1, S4, S6, M3, A5, A7, Q1, Q3, Q5 | ADRs: 005, 006

## Summary
F-002 is the platform's system of record for security and accountability events. Every event that a service emits under the F-001 event catalog (`pkg/audit/catalog.yaml`) is kept in one append-only trail. The trail is hash-chained, so removing, altering, inserting or reordering any record can be detected, both by the platform and offline by an auditor who does not trust it. Authorized people can search the trail and see the history of any user or object. They can also export signed evidence that holds up for SOC 1/SOC 2 reliance, FedRAMP Moderate and CMMC assessments (S1, S6). The trail keeps events for the configured retention period, forwards them to the customer's SIEM, and never loses an event without saying so.

Today the services emit catalogued events as JSON lines and syslog over TLS (F-001 T-00a and T-37). F-002 takes over storage, integrity, search, export and retention. Services keep emitting through the same `audit.Emitter` contract, and an event that cannot be recorded still fails the operation (ADR-006).

## Concepts
- **Event:** a catalogued security event: its type, severity, actor, target, reason, before and after values, request id, source address and attributes (`pkg/audit/event.schema.json`).
- **Record:** an event as stored in the trail. It adds the trail position, the time the trail received it, and the integrity data that links it to the record before it.
- **Checkpoint:** a signed statement of the trail's state at a position. A copy kept outside the platform lets the trail be checked even if the platform's own storage is compromised.
- **Evidence export:** a signed bundle of records for a time range and filter, with the checkpoints and public material needed to verify it offline.

## Users & roles affected
- **Auditor / Security Officer:** searches the trail, reviews history, exports evidence (`audit.view`, `audit.export`; both privileged, F-001-AC-54).
- **Platform Admin:** sets retention and forwarding within the profile's bounds (`settings.change`, F-015).
- **Every user and service account:** generates records by using the platform.
- **Vendor SecOps (SaaS):** receives integrity alerts.

## Requirements

### F-002-R-01 Complete capture
**As an** auditor, **I want** every catalogued event from every service in one trail, **so that** I can rely on it as the complete record.
- F-002-AC-01: WHEN any platform service emits a catalogued event, THE SYSTEM SHALL record it in the trail exactly once, even if delivery is retried.
- F-002-AC-02: IF an event cannot be durably accepted for the trail, THEN THE SYSTEM SHALL fail the operation that produced it rather than complete it unrecorded.
- F-002-AC-03: WHILE the trail is temporarily unable to store records, THE SYSTEM SHALL hold accepted events durably and record them once it can, without loss and with their original event times.
- F-002-AC-04: THE SYSTEM SHALL refuse to record an event whose type is not in the catalog, or which lacks the fields the catalog requires. It SHALL record the refusal as a high-severity event.
- F-002-AC-05: Each record SHALL carry the event time, the time the trail received it, and the producing service. WHEN the two times differ by more than the configured skew threshold, THE SYSTEM SHALL flag the record.
- F-002-AC-06: Records SHALL NOT contain secrets, credentials, session identifiers or token values. A test SHALL check every catalogued event type for this.

### F-002-R-02 Tamper evidence
**As an** auditor, **I want** any change to the trail to be detectable, **so that** the trail can be trusted as evidence even against privileged insiders.
- F-002-AC-07: Each record SHALL be cryptographically linked to the record before it using FIPS 140-validated algorithms, so that removing, altering, inserting or reordering any record, or truncating the trail, is detectable.
- F-002-AC-08: No application role, service, administrator or API SHALL be able to change or delete a record. Records leave the trail only through retention (R-06).
- F-002-AC-09: THE SYSTEM SHALL issue signed checkpoints at least every 15 minutes and whenever an evidence export is created. Signing keys SHALL be read from files delivered by the deployment mode's key store (F-001 T-41) and SHALL never be readable by application roles.
- F-002-AC-10: THE SYSTEM SHALL send each checkpoint outside the platform's own storage: to the SIEM forwarding stream (R-05) and to write-once storage. Write-once storage SHALL be required in SaaS and optional in self-hosted and air-gapped installs.
- F-002-AC-11: THE SYSTEM SHALL provide a verification tool that, given a range of records and the checkpoints, reports whether the range is intact and, if not, the first position where it fails. The tool SHALL run offline, without access to the platform.

### F-002-R-03 Continuous verification
**As a** Security Officer, **I want** the platform to check its own trail, **so that** tampering or corruption is found quickly, not at audit time.
- F-002-AC-12: THE SYSTEM SHALL verify the trail added since the last check at least every 15 minutes, and the whole retained trail at least daily.
- F-002-AC-13: WHEN verification fails, or a position is missing, THE SYSTEM SHALL emit a critical event, raise a critical finding on the Security Posture page (F-015), and, in SaaS, alert vendor SecOps. The finding SHALL be resolved only by a later successful verification.
- F-002-AC-14: The Security Posture page SHALL show when the trail was last verified and the result.

### F-002-R-04 Search and history
**As an** auditor, **I want** to search the trail and see the history of any user or object, **so that** I can investigate and answer audit requests.
- F-002-AC-15: THE SYSTEM SHALL let a user holding `audit.view` search records by time range, event type, category, severity, actor, target, BU, request id and source address, and combine these filters.
- F-002-AC-16: THE SYSTEM SHALL show the full history of a target (for example `/audit?target=setting:tls.min_version`, as linked from the Posture page) and of an actor, in order.
- F-002-AC-17: THE SYSTEM SHALL show records related by request id together, so that one action can be followed across services.
- F-002-AC-18: THE SYSTEM SHALL show actors and approvers by their current display names alongside their stable ids, and SHALL show each record's integrity status.
- F-002-AC-19: Visibility of records SHALL follow BU scope: a record tied to a BU SHALL be visible only to users holding `audit.view` at that BU, and a restricted BU's records only to users with an assignment there (F-001-AC-60, AC-64). Records not tied to a BU SHALL require `audit.view` at the root BU.
- F-002-AC-20: THE SYSTEM SHALL record each search and each history view as an audit event, with its filters.
- F-002-AC-21: The audit pages SHALL meet WCAG 2.1 AA (Q3).

### F-002-R-05 Forwarding to the customer's SIEM
**As a** Security Officer, **I want** the trail in our SIEM as well, **so that** we can correlate and alert there and keep an independent copy.
- F-002-AC-22: THE SYSTEM SHALL forward every record, with its trail position and integrity data, to configured destinations: syslog over TLS (RFC 5425) and OTLP over TLS. TLS 1.2 SHALL be the minimum.
- F-002-AC-23: WHEN a destination is unavailable, THE SYSTEM SHALL keep records queued and deliver them in order once it is back. WHEN the backlog exceeds the configured threshold or age, THE SYSTEM SHALL emit a high-severity event and show the backlog on the Posture page.
- F-002-AC-24: Adding, changing or removing a destination SHALL be a settings change under F-015 (bounds, approval where required, audited).

### F-002-R-06 Retention and archive
**As a** compliance owner, **I want** records kept for as long as our obligations require and no longer, **so that** we meet AU-11 and records-management rules.
- F-002-AC-25: THE SYSTEM SHALL keep records searchable for the online retention period, and SHALL then move them to the archive for the remainder of the total retention period. Both periods SHALL be F-015 settings bounded by the active profile. Every built-in profile SHALL default to 12 months online and 7 years total.
- F-002-AC-26: Archived records SHALL remain verifiable and exportable, and archived segments SHALL be signed.
- F-002-AC-27: Records SHALL be destroyed only after the total retention period. Destruction SHALL be recorded in the trail, and verification SHALL remain possible from the first retained record onward.
- F-002-AC-28: Shortening a retention period below the active profile's value SHALL be a loosening: explanation, warning, dual approval and a high-severity event (F-015-AC-21). Retention SHALL NOT go below the hard floor of 90 days online.
- F-002-AC-29: A user holding `audit.hold` SHALL be able to place records matching a filter on legal hold, with a reason. Held records SHALL NOT be destroyed until the hold is released, and placing or releasing a hold SHALL be audited at high severity.

### F-002-R-07 Capacity and failure
**As a** Security Officer, **I want** to be warned before the trail runs out of room, **so that** auditing never stops.
- F-002-AC-30: WHEN audit storage reaches 75% of its allocated capacity, THE SYSTEM SHALL emit a high-severity event and show a warning on the Posture page. At 90% it SHALL emit a critical event.
- F-002-AC-31: IF events can be neither recorded nor durably held (AC-03), THEN THE SYSTEM SHALL refuse every operation that would emit one, and SHALL NOT drop events to keep running.

### F-002-R-08 Evidence export
**As an** auditor, **I want** signed exports of the trail, **so that** I can give an external auditor evidence they can check themselves.
- F-002-AC-32: THE SYSTEM SHALL let a user holding `audit.export` export the records matching a search as JSON lines or CSV, with a manifest, the covering checkpoints, a signature, and the public material needed to verify the export with the AC-11 tool.
- F-002-AC-33: Exports SHALL respect the same BU visibility as search (AC-19), and SHALL state the filter used so a reviewer can tell what is and is not included.
- F-002-AC-34: Every export SHALL be recorded in the trail at high severity, with its filter, record count and digest.
- F-002-AC-35: THE SYSTEM SHALL provide approval evidence for change management (S6): for any approval, the request, both parties, the decision, and the resulting change, in one view and in exports.

### F-002-R-09 Adoption by existing services
**As a** platform engineer, **I want** every existing producer on the trail, **so that** F-001 and F-015 meet their own audit requirements.
- F-002-AC-36: The iam, gateway, posture, posture-scanner and worker services, and the database's in-transaction events, SHALL all record to the trail. The T-00a stub sink SHALL be retired, apart from the JSON-lines output kept for log collection.
- F-002-AC-37: The audit-history links on the Posture page (F-015-AC-44) SHALL open the matching history.

## Permissions added to the F-001 catalog
`audit.view` and `audit.export` already exist (privileged). New: `audit.hold` (privileged).

## Secure defaults (ADR-006)
| Setting | Default | Loosening |
|---|---|---|
| Audit logging | On | Hard floor; never off |
| Online retention | 12 months | Below the profile value: dual approval + audit; never below 90 days |
| Total retention | 7 years | Below the profile value: dual approval + audit |
| Checkpoint interval | 15 min | Cannot be lengthened |
| Verification | Incremental every 15 min; full daily | Cannot be turned off |
| SIEM forwarding | Off until a destination is configured; TLS 1.2+ only | Plaintext refused outside development |
| Audit read access | Privileged permissions only; every search audited | Not configurable |

## Non-functional requirements
- Throughput: sustain 200 events per second, with bursts of 2,000 per second for 60 s, at the F-001 target scale.
- Latency: a record is searchable within 5 s of its event (p95).
- Search: p95 ≤ 2 s for indexed filters over the online retention period at target scale.
- Verification: a full daily verification of 12 months of records completes in ≤ 1 hour.
- Export: 1 million records exported in ≤ 5 minutes.
- All hashing and signing use FIPS 140-validated modules. TLS 1.2 is the floor.
- The trail's storage is on the platform's own PostgreSQL and S3-compatible storage (A5), with no mandatory external service (A7).

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| Trail storage | Vendor-operated, per customer instance | Customer's database and object storage | Same as self-hosted |
| Checkpoint copy outside the platform | SIEM stream and vendor write-once storage (required) | SIEM stream; write-once storage if configured | Same as self-hosted, with destinations inside the enclave |
| SIEM forwarding | Customer destination; vendor SecOps copy of integrity alerts | Customer destinations | Destinations inside the enclave |
| Verification tool | Downloadable with the release | In the bundle | In the bundle |
| Integrity alerts | Customer admins and vendor SecOps | Customer admins | Customer admins (via internal relay) |

## Control mapping (NIST SP 800-53r5)
AU-2, AU-3, AU-3(1), AU-4, AU-5, AU-5(1), AU-6, AU-6(1), AU-6(3), AU-7, AU-7(1), AU-8, AU-9, AU-9(3), AU-9(4), AU-11, AU-12, SI-4. Crosswalks to other frameworks are provided by F-013.

## Out of scope
- Defining which events exist. The catalog stays with each feature (F-001 T-37 process).
- Alert rules and correlation. These belong in the customer's SIEM.
- Notification delivery (F-009). F-002 queues alerts for it.
- Application-level history of business records, such as analysis versions (F-003 onward), beyond the security events they emit.

## Dependencies
- F-001: the event catalog and `audit.Emitter`, BU scope and permissions, approvals (T-26), key delivery (T-41).
- F-015: settings and bounds for retention and forwarding, the Posture page and findings, hard floor.
- Closes deferred items: F-001-AC-50 (events reach the F-002 trail), F-015 design §15 ("every step goes to the hash-chained audit") and the F-001/F-015 statements that point to F-002.

## Open Questions
None.

## Resolved
- OQ1: retention defaults are 12 months online and 7 years total in every built-in profile (2026-11-03)
- OQ2: audit records follow BU scope, restricted BUs included (AC-19) (2026-11-03)
- OQ3: write-once checkpoint storage is required in SaaS and optional in self-hosted and air-gapped (AC-10) (2026-11-03)
- OQ4: legal hold is in v1, with the privileged permission `audit.hold` (AC-29) (2026-11-03)
- OQ5: every search and history view is audited, not only exports (AC-20) (2026-11-04)

## Change Log
- 2026-11-03: Initial draft. OQ1 to OQ4 resolved by Robert Former.
- 2026-11-04: OQ5 resolved. **Approved** by Robert Former.
