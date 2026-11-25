# PostureRevertFailed

Alert rule: `deploy/observability/alerts/drift.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
A posture exception expired but its setting could not be put back to the profile's value; the weaker value remains in force.

## Impact
A security setting stays loosened past its approved expiry.

## Where the signal comes from
`fair_audit_events_total{type="setting.revert_failed"}`: the audit event recorded when an expired exception's setting cannot be reverted (F-015 T-18), counted by the SaaS log agent. The posture service also opens a critical `revert_failed` finding and escalates hourly.

## First checks
1. The posture service's logs: `exception revert` and the error (a lock timeout, the database, a refused value).
2. The Posture page's exceptions and the `revert_failed` finding.

## Remediation
- A lock timeout (`posture.RevertLockTimeout`) clears on retry; the revert job retries with back-off every 10 seconds.
- If it keeps failing, the customer's administrator can set the value back through an ordinary change; operators do not change customer settings.

## Escalation
Page the platform on-call; tell the customer's security contact if it is not reverted within the hour.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
