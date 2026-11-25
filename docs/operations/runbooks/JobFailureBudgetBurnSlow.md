# JobFailureBudgetBurnSlow

Alert rule: `deploy/observability/alerts/jobs.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
More than 3% of a queue's job attempts failed over a day and 2 hours, or more than 1% over 3 days and 6 hours.

## Impact
Some jobs are delayed by retries or fail for good; users see slow or failed runs, reports or imports.

## Where the signal comes from
As [JobFailureBudgetBurn](JobFailureBudgetBurn.md).

## First checks
1. Find the failing kind on the dashboard and the common error in the logs.
2. Check whether failures concentrate on one business unit's data (from the error, not from the data) or follow a release.

## Remediation
- Open a ticket with the job kind, error and release; fix forward with a test.

## Escalation
Ticket to the owning feature's engineers within the next working day.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
