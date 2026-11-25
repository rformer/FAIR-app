# AuditForwardingBacklogHigh

Alert rule: `deploy/observability/alerts/audit.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
10,000 or more audit records have been waiting for the customer's SIEM destination for 15 minutes (the default of `audit.forward_backlog_records`). The audit service has also recorded `audit.forward_backlog` and shows it on the Posture page.

## Impact
The customer's SIEM is behind. Nothing is lost: the trail keeps every record and forwarding resumes from its cursor. A long delay can breach the customer's AU-6 review expectations.

## Where the signal comes from
`backlog_audit_forwarding_<destination>` (`syslog`, `otlp`): records not yet forwarded, a gauge from the audit service (`telemetry.Backlog`). No series exists while a destination is not configured.

## First checks
1. The audit service's logs: `{service_name="audit"} |= "forwarding"` names the destination and the error (TLS, connection refused, timeout).
2. Is the backlog still growing ([AuditForwardingStalled](AuditForwardingStalled.md)) or draining after a burst?
3. Is the SIEM endpoint reachable from the audit pod (egress rules, DNS, its certificate against `FAIR_AUDIT_SYSLOG_CA_FILE` / `FAIR_AUDIT_OTLP_CA_FILE`)?

## Remediation
- A burst (a large import, a migration): watch it drain; no action.
- The destination is down or its certificate changed: tell the customer; the address is their setting (`audit.syslog_destination`, `audit.otlp_destination`).

## Escalation
Ticket to the platform on-call; contact the customer when their SIEM is the cause.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
