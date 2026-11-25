# AuditCapacityCritical

Alert rule: `deploy/observability/alerts/audit.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
The audit schema uses 90% or more of its quota (`audit.capacity_critical`, the `audit_capacity` finding).

## Impact
At 100% `audit.intake` refuses every producer but the audit service (PF015): every change in the platform fails, by design, because it cannot be audited.

## Where the signal comes from
As [AuditCapacityHigh](AuditCapacityHigh.md).

## First checks
1. As [AuditCapacityHigh](AuditCapacityHigh.md), urgently: is archiving running, and how fast is the trail growing?

## Remediation
- Restore archiving first; it frees space as it deletes archived rows.
- Raise the quota and the RDS storage through the fleet and `infra/` (an emergency pull request still needs a second operator's approval).
- Never delete audit rows by hand; destruction happens only past the total retention, through the audit service.

## Escalation
Page the platform on-call; escalate to the platform engineering lead at once.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
