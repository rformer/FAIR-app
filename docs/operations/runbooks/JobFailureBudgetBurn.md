# JobFailureBudgetBurn

Alert rule: `deploy/observability/alerts/jobs.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
More than 14.4% of a queue's job attempts failed over the last hour and 5 minutes, or more than 6% over 6 hours and 30 minutes, against a 99% success objective.

## Impact
Depending on the queue: analysis runs (`analysis`), reports (`report`), framework imports (`framework`), audit exports, or notifications do not complete. River retries failed jobs, so the work is delayed first and lost only when retries run out.

## Where the signal comes from
`job_duration_seconds_count{job_queue, job_kind, job_outcome}` (`job.duration`, recorded by the `telemetry.River` middleware on every River client), as `fair:job_failure_ratio:rate<window>` per instance, service and queue. Snoozed attempts are left out; failed and cancelled count.

## First checks
1. On the dashboard's *Job attempts by queue and outcome*, find the job kind that fails.
2. Search the service's logs for the kind: `{service_name="<job>"} | json | level="ERROR"`.
3. For `analysis`: is the engine ready (`engine_call_duration_seconds` with `outcome="error"`, the engine-gate pods, the engine's self-check)?
4. For `report`: is the report store reachable (`/readyz` reports it degraded)?

## Remediation
- A dependency down: restore it; the jobs retry on their own.
- A code fault on certain inputs: fix forward; jobs that exhausted their retries can be retried after the fix (River's discarded jobs), by the owning service's documented procedure.

## Escalation
Page the platform on-call; escalate to the owning feature's engineers when the cause is in a job's code.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
