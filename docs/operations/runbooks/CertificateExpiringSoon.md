# CertificateExpiringSoon

Alert rule: `deploy/observability/alerts/expiry.yaml`. Severity: warning (ticket). F-012-AC-24.

## Meaning
A cert-manager Certificate expires within 30 days. cert-manager normally renews well before that, so renewal is failing.

## Impact
When it expires, the TLS connections that use it fail closed (TLS 1.2 is the floor; nothing falls back to plaintext).

## Where the signal comes from
cert-manager's own metric `certmanager_certificate_expiration_timestamp_seconds`, scraped by the instance Collector. The certificates are issued by the ACM Private CA for internal TLS.

## First checks
1. `kubectl -n <namespace> describe certificate <name>` and its `CertificateRequest`: the issuer's error.
2. The ACM Private CA issuer's health and IAM permissions (IRSA of cert-manager's issuer).

## Remediation
- Fix the issuer and let cert-manager renew; `cmctl renew` forces a renewal.
- Services re-read their certificates; check the dependents reconnect.

## Escalation
Ticket to the platform on-call; page if under 7 days.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
