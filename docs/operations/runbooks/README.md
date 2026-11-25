# Runbooks

One runbook per alert in `deploy/observability/alerts/` (F-012 T-11, F-012-AC-24); each alert's `runbook_url` names its file, and `TestAlertsHaveRunbooks` (`internal/observability`) checks every alert has a runbook and every runbook an alert. Severity `critical` pages the on-call; `warning` opens a ticket.

| Alert | Severity | Rule file |
|---|---|---|
| [AcmCertificateExpiringSoon](AcmCertificateExpiringSoon.md) | warning | `expiry.yaml` |
| [ApiAvailabilityBudgetBurn](ApiAvailabilityBudgetBurn.md) | critical | `availability.yaml` |
| [ApiAvailabilityBudgetBurnSlow](ApiAvailabilityBudgetBurnSlow.md) | warning | `availability.yaml` |
| [ApiLatencyP95High](ApiLatencyP95High.md) | warning | `latency.yaml` |
| [ApiLatencyP95Severe](ApiLatencyP95Severe.md) | critical | `latency.yaml` |
| [AuditCapacityCritical](AuditCapacityCritical.md) | critical | `audit.yaml` |
| [AuditCapacityHigh](AuditCapacityHigh.md) | warning | `audit.yaml` |
| [AuditForwardingBacklogHigh](AuditForwardingBacklogHigh.md) | warning | `audit.yaml` |
| [AuditForwardingStalled](AuditForwardingStalled.md) | critical | `audit.yaml` |
| [AuditVerificationFailed](AuditVerificationFailed.md) | critical | `audit.yaml` |
| [BackupJobFailed](BackupJobFailed.md) | critical | `backups.yaml` |
| [CertificateExpiringSoon](CertificateExpiringSoon.md) | warning | `expiry.yaml` |
| [EngineCertificateExpiringSoon](EngineCertificateExpiringSoon.md) | warning | `expiry.yaml` |
| [JobFailureBudgetBurn](JobFailureBudgetBurn.md) | critical | `jobs.yaml` |
| [JobFailureBudgetBurnSlow](JobFailureBudgetBurnSlow.md) | warning | `jobs.yaml` |
| [NotificationDeliveriesFailing](NotificationDeliveriesFailing.md) | warning | `jobs.yaml` |
| [PostureDriftDetected](PostureDriftDetected.md) | critical | `drift.yaml` |
| [PostureRevertFailed](PostureRevertFailed.md) | critical | `drift.yaml` |
| [ServiceUnavailable](ServiceUnavailable.md) | critical | `availability.yaml` |
