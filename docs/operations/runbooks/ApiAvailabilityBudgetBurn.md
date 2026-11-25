# ApiAvailabilityBudgetBurn

Alert rule: `deploy/observability/alerts/availability.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
A service answers more than 1.44% of its requests with a 5xx over the last hour and the last 5 minutes (14.4 times the 0.1% budget), or more than 0.6% over 6 hours and 30 minutes. At that rate the 30-day error budget of the 99.9% availability SLO is gone in two to five days.

## Impact
Users of the instance see failed pages and API calls. Because FAIR fails closed, a 5xx is often a refusal on purpose: the audit trail cannot record (503), the settings are stale, or a key file is missing.

## Where the signal comes from
`http_server_request_duration_seconds_count` (OpenTelemetry `http.server.request.duration`, every service, `pkg/telemetry`), as the recording rules `fair:http_error_ratio:rate<window>` per instance and service.

## First checks
1. Open the *FAIR service overview* dashboard for the instance and service: which routes fail (*5xx ratio by service*, *Requests by status class*) and since when.
2. Check the deployment: was a release or a fleet promotion rolled out just before (Flux events, `fleetctl status`)?
3. Look at the service's logs in Loki for the window: `{k8s_namespace_name="fair-platform", service_name="<job>"} | json | level="ERROR"`. The message names the failing dependency (database, NATS, settings, audit, engine).
4. Check `/readyz` of the service's pods (`kubectl -n fair-platform get pods`, events, restarts).
5. If every service fails at once, look at the shared dependencies: RDS (CloudWatch), NATS, the gateway.

## Remediation
- A bad release: stop the rollout and pin the previous release for the instance (rollback by pinning, F-012 design §3.6).
- Audit refusals (503 with `audit_unavailable` in the logs): see [AuditCapacityCritical](AuditCapacityCritical.md); the refusal is correct, fix the trail rather than the service.
- Stale settings (`settings stale` in the logs): check the posture service and NATS; services refuse rather than run on unknown settings.
- Database saturation: check RDS CPU, connections and locks; scale the instance class through `infra/` (a pull request), never by console.

## Escalation
Page the platform on-call. If no cause is found within 30 minutes, or customers report it, escalate to the platform engineering lead and open an incident; a data-integrity or security cause goes to security at once.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
