# AuditForwardingStalled

Alert rule: `deploy/observability/alerts/audit.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
Forwarding to a SIEM destination is not delivering at all.

## Impact
The customer's SIEM receives no audit events; their monitoring of the platform is blind. Records are kept in the trail and will be forwarded when the connection returns.

## Where the signal comes from
As [AuditForwardingBacklogHigh](AuditForwardingBacklogHigh.md): the backlog has not been zero for an hour and is still growing.

## First checks
1. Is the audit service the leader and running (`kubectl -n fair-platform get pods -l app.kubernetes.io/name=audit`; logs `leader`)? Only the leader forwards.
2. The forwarder's last error in the logs (`forwarding`, with the destination).
3. Network: the audit pod's egress, the destination's DNS and TLS.

## Remediation
- Restart nothing blindly: if the leader is stuck, deleting its pod hands the lease to another replica.
- If the destination's address or certificate is wrong, the customer corrects their setting; the cursor is kept across an address change.

## Escalation
Page the platform on-call; tell the customer's security contact within the hour if the cause is not on our side.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
