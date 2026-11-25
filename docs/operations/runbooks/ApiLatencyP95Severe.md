# ApiLatencyP95Severe

Alert rule: `deploy/observability/alerts/latency.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
One route's 95th percentile has been above 2.5 seconds over the last hour and the last 5 minutes, with traffic. Requests this slow approach the clients' and the gateway's timeouts.

## Impact
Users see timeouts and retries; retries add load and can spread the slowdown to other routes.

## Where the signal comes from
As [ApiLatencyP95High](ApiLatencyP95High.md).

## First checks
1. Follow the checks of [ApiLatencyP95High](ApiLatencyP95High.md).
2. Check whether several services are slow at once (a shared cause: RDS, NATS, node pressure) or one route only.
3. Check RDS for CPU at 100%, connection exhaustion, storage I/O credits, or a failover.

## Remediation
- A recent release: pin the previous release for the instance.
- A runaway statement: identify it in Performance Insights; cancelling a statement is an operator action on the database and needs the access an incident grants; it never needs reading customer data.
- Capacity: scale through `infra/` (a pull request, applied after approval).

## Escalation
Page the platform on-call; escalate to the platform engineering lead after 30 minutes.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
