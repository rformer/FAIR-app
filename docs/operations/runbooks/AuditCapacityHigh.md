# AuditCapacityHigh

Alert rule: `deploy/observability/alerts/audit.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
The audit schema uses 75% or more of its quota. The audit service has recorded `audit.capacity_warning`.

## Impact
None yet. At 100% every audited change is refused (fail closed).

## Where the signal comes from
`backlog_audit_capacity_permille`: the trail's storage in per mille of `FAIR_AUDIT_STORAGE_QUOTA`, from the audit service's capacity monitor (F-002 T-20).

## First checks
1. Is archiving running? Segments past `audit.retention_online` should move to the audit store daily (`audit.records_archived` events; the audit service's `archive` logs).
2. Has the volume grown (a new integration, imports) or did archiving stop (store unreachable, legal hold)?

## Remediation
- Archiving stopped: fix the audit store access (IAM, bucket, TLS) and let the archiver catch up.
- Genuine growth: raise `FAIR_AUDIT_STORAGE_QUOTA` with the database storage through the fleet and `infra/` pull requests.

## Escalation
Ticket to the platform on-call; escalate to the platform engineering lead if it reaches 90% ([AuditCapacityCritical](AuditCapacityCritical.md)).

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
