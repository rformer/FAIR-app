# EngineCertificateExpiringSoon

Alert rule: `deploy/observability/alerts/expiry.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
One of the engine's pinned mTLS certificates expires within 30 days.

## Impact
When it expires, the risk service cannot reach the simulation engine: analysis runs fail closed.

## Where the signal comes from
The Collector's `tls_check` receiver (`collector-saas.yaml`) reading the public certificates of `keys/engine-gate/tls` and `keys/risk/engine-client`, as `tlscheck_time_left_seconds`. These are the platform's only key material with an end date (`keys.EngineCertValidity`, 397 days); the other keys do not expire and are rotated by policy.

## First checks
1. `iam keys check` on the instance's key set (it fails on an expired certificate).

## Remediation
- Rotate with `iam keys rotate -kind engine` and deliver both new certificates (Secrets Manager entries, synced by the External Secrets Operator), in either order; pins hold the new and the previous certificate, so no restart is needed ([keys.md](../../install/keys.md)).

## Escalation
Ticket to the platform on-call; page if under 7 days.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
