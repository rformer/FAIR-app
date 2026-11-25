# AuditVerificationFailed

Alert rule: `deploy/observability/alerts/audit.yaml`. Severity: critical (pages). F-012-AC-24.

## Meaning
The audit trail's integrity verification (hash chain, Merkle checkpoints, signatures, the write-once copies) failed. The verifier records the failure on every failing run until a full run passes.

## Impact
Possible tampering with, or corruption of, the audit trail: a security incident until shown otherwise. The trail's evidence value for the customer's audits is in doubt.

## Where the signal comes from
`fair_audit_events_total{type="audit.verification_failed"}`: the audit event the verifier records (F-002 T-11), counted from the audit service's stdout by the SaaS log agent (`collector-saas-agent.yaml`). The audit service also opens the `audit_integrity` posture finding and alerts SecOps.

## First checks
1. The Posture page's *Audit trail* section and `GET /api/v1/posture/audit-trail` (through the customer's administrator if needed): the failing sequence, segment and reason.
2. The audit service's log line `audit trail verification failed` (kind, seq, segment, reason).
3. Verify independently with `fair-audit-verify` against the write-once archive copies ([audit-verification.md](../audit-verification.md)); the copies in Object Lock storage cannot be changed.

## Remediation
- Do not try to repair the trail: records, checkpoints and keys are append-only, and the failure is evidence.
- Preserve: keep the database snapshot and the archive versions; place a legal hold if the customer asks (`/api/v1/audit/holds`).
- The finding resolves only when a full verification passes.

## Escalation
Page the platform on-call and security at once; this is a security incident under the incident response plan. The customer is informed as the plan requires.

Operator access to an instance is just-in-time (an `access/` request approved by a second operator, F-012 design §3.9); the `operator` role manages workloads but cannot read the database or the stores. Never read customer data to diagnose: if it seems necessary, stop and escalate (break-glass needs the customer's recorded consent).
