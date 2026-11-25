# PostureDriftDetected

Alert rule: `deploy/observability/alerts/drift.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
The security settings in force differ from what was approved: a row's MAC does not match, a value is outside its profile's bounds without an exception, the hard floor is crossed, a revert was missed, or a service reports settings that differ from the database.

## Impact
A security control may be weaker than the customer's approved profile; a MAC mismatch can mean someone changed the database outside the platform.

## Where the signal comes from
`fair_audit_events_total{type="posture.drift_detected"}`: the audit event the posture drift check records when it opens a finding (F-015 T-25), counted from the posture service's stdout by the SaaS log agent (`collector-saas-agent.yaml`). The alert keeps firing for 4 hours after the event; the finding stays open on the Posture page until the check resolves it. Infrastructure drift (`tofu plan`) is the daily drift job's (F-012 T-14), not this alert's.

## First checks
1. The Posture page's drift findings (through the customer's administrator, or the `drift.*` events in the customer's SIEM): the kind of drift and the setting.
2. For a heartbeat mismatch: a service running an old release or a stale settings cache (its logs: `settings stale`).
3. For a MAC mismatch: who connected to the database directly (CloudTrail, RDS logs).

## Remediation
- Heartbeat or missed revert: restart the stale service or fix the revert (see [PostureRevertFailed](PostureRevertFailed.md)); the check resolves the finding.
- MAC mismatch or bounds: treat as possible tampering; do not re-sign or edit rows.

## Escalation
Page the platform on-call; a MAC mismatch or an unexplained bounds violation goes to security at once as a possible incident.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
