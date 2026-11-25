# BackupJobFailed

Alert rule: `deploy/observability/alerts/backups.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
A backup job, or the copy of a backup to the second GovCloud region, failed.

## Impact
The recovery objectives (RPO 15 minutes, RTO 4 hours; F-012 OQ8) are at risk for that instance until the next good backup. RDS point-in-time recovery is continuous and separate.

## Where the signal comes from
AWS Backup's CloudWatch metrics `NumberOfBackupJobsFailed` and `NumberOfCopyJobsFailed` (namespace AWS/Backup), exported by the CloudWatch exporter (YACE) in the operations account as `aws_backup_number_of_backup_jobs_failed_sum` and `aws_backup_number_of_copy_jobs_failed_sum`, per instance account.

## First checks
1. AWS Backup's job list in the instance account (through the operator's read-only access): the failed job and its status message.
2. The backup vault's KMS key policy and the backup role, and, for copies, the destination vault in the second region.

## Remediation
- Correct the cause through `infra/` (a pull request); then start an on-demand backup and confirm it completes.
- Record the gap and the recovery in the operations log for the SOC evidence.

## Escalation
Page the platform on-call; escalate to the platform engineering lead if no good backup exists for more than 24 hours.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
