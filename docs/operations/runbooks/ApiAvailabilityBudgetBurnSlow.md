# ApiAvailabilityBudgetBurnSlow

Alert rule: `deploy/observability/alerts/availability.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
A service's 5xx ratio is above 0.3% over a day and 2 hours, or above 0.1% over 3 days and 6 hours: the error budget is being spent faster than it refills, slowly enough not to page.

## Impact
Some requests fail, usually one route or one kind of input. Left alone, the 30-day SLO is missed.

## Where the signal comes from
As [ApiAvailabilityBudgetBurn](ApiAvailabilityBudgetBurn.md): `fair:http_error_ratio:rate<window>`.

## First checks
1. On the *FAIR service overview* dashboard, find the routes with 5xx for the service over the last 3 days.
2. Group the service's error logs in Loki by message: `sum by (msg) (count_over_time({service_name="<job>"} | json | level="ERROR" [1d]))`.
3. Check whether the errors follow a release (compare with the release history).

## Remediation
- Open a ticket with the route, the error messages and the release; fix forward in the code with a test reproducing the failure.
- If one dependency is flaky (object storage, the engine), check its readiness check and the dependency itself.

## Escalation
Ticket to the owning feature's engineers within the next working day. If the burn continues for 3 days, raise it with the platform engineering lead.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
