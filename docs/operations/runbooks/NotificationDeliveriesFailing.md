# NotificationDeliveriesFailing

Alert rule: `deploy/observability/alerts/jobs.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
More than 10% of a channel's delivery attempts (email or webhook) over the last 30 minutes were not sent.

## Impact
Users do not get email or webhook notices (in-app notices are unaffected). Retries continue for `notification.retry_hours`; after that a delivery fails for good and a posture finding is opened.

## Where the signal comes from
`notification_deliveries_total{channel, outcome}` (`notification.deliveries`, `notify.Worker`; outcomes `sent`, `retry`, `permanent`, `refused`).

## First checks
1. `refused`: the destination guard refused the address (not in `notification.allowed_hosts`, a private range, or air-gapped rules). That is a configuration matter for the customer's administrator.
2. `retry`: the relay or webhook endpoint is unreachable or answers 5xx: check the notify pod's egress and the destination's status.
3. `permanent`: the relay rejected the message (authentication, recipient). Check the relay settings on the Channels page with the customer.

## Remediation
- Egress: the notify pod is the only one allowed out to SMTP and webhooks; check its NetworkPolicy and the VPC egress controls.
- Customer configuration (relay, allow-list): contact the customer's administrator; operators do not change their settings.

## Escalation
Ticket to the platform on-call; contact the customer through support when the cause is their relay or allow-list.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
