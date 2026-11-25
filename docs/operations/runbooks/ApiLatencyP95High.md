# ApiLatencyP95High

Alert rule: `deploy/observability/alerts/latency.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
The 95th percentile of one route's requests has been above 1 second over both the last hour and the last 5 minutes, with at least 3 requests a minute.

## Impact
Pages feel slow for that function. The SLO is 1 second at the 95th percentile per API.

## Where the signal comes from
`http_server_request_duration_seconds_bucket` (`http.server.request.duration`, buckets `telemetry.SecondBuckets`), as `fair:http_request_duration_seconds:p95_rate5m` and `_rate1h` per instance, service and route.

## First checks
1. On the *FAIR service overview* dashboard, compare the route's p95 with the *Database p95 by operation* and *Engine calls p95* panels: is the time spent in the database, the engine or the service?
2. Look for slow traces of the route in Tempo (by `http.route`); spans name the statements' operations.
3. Check RDS Performance Insights for the instance for the top statements and waits.
4. Is it a heavy route by nature (exports, downloads, imports)? Those can be legitimately slow at large sizes.

## Remediation
- A missing index or a per-row scope function: fix forward with a migration and a benchmark gate case (see CLAUDE.md: read the caller's scope once per statement).
- Database contention: look for long transactions and lock waits; scale the instance class through `infra/` if it is capacity.
- If the route is inherently long-running, move it to a job rather than raising the threshold.

## Escalation
Ticket to the owning feature's engineers. If it persists over a day or spreads to many routes, raise with the platform engineering lead.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
