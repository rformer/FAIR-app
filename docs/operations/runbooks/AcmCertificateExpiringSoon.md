# AcmCertificateExpiringSoon

Alert rule: `deploy/observability/alerts/expiry.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
A public certificate managed by ACM (the instance's load balancer) expires within 30 days. ACM renews DNS-validated certificates on its own, so validation is failing.

## Impact
When it expires, customers cannot reach the instance over HTTPS.

## Where the signal comes from
ACM's CloudWatch metric `DaysToExpiry` (namespace AWS/CertificateManager), exported by the CloudWatch exporter (YACE) in the operations account as `aws_certificatemanager_days_to_expiry_minimum`, per instance account.

## First checks
1. The certificate in ACM: its renewal status and the DNS validation record in Route 53.
2. Whether the validation record was changed outside `infra/` (the daily drift job reports it).

## Remediation
- Restore the validation record through `infra/` (a pull request); ACM then renews.

## Escalation
Ticket to the platform on-call; page if under 7 days.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
