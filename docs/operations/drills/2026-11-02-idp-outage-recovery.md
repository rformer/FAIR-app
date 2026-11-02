# Drill: IdP-outage recovery, 2026-11-02

F-001 T-35 (AC-46). Dry run of [the runbook](../idp-outage-recovery.md).

- **Run by:** `TestIdPOutageRecoveryDrill` (`db/tests/breakglass_test.go`), commit after `40b72fb`.
- **Environment:** PostgreSQL 16 (Docker, `fair-dbtest`), the real gateway and iam API, all
  migrations through 0058, the Enterprise Baseline seeded (lockout threshold 3 for the run).
  No IdP was reachable. The holder's security key was the software authenticator
  `internal/authn/breakglass/webauthntest` (ES256, discoverable, user-verified).
- **Operator tool:** `iam breakglass` code (`breakglass.Command`) on a connection as
  `app_migrator`. The Kubernetes Job template (`deploy/k8s/breakglass-emergency.yaml`) wraps
  the same command. It was not run on a live cluster in this drill; that waits for the live
  OpenShift/RKE2 runs (F-015 design §15).
- **Result:** pass (1.6 s).

## Transcript
```
DRILL 1: installation in use (admin session), break-glass off: f
DRILL 2: install-time enable refused: the installation is in use
DRILL 3: emergency enable refused without -operator and without -reason
DRILL 4: emergency enable by operator Jo Operator: install-log line breakglass.emergency_enabled (critical); one enrollment code printed once
DRILL 5: on under a posture exception expiring within 24 hours; audited critical as operator:Jo Operator; every channel notified
DRILL 6: a second emergency enable while on is refused
DRILL 7: holder ops1 enrolled a security key and signed in with WebAuthn, no IdP involved
DRILL 8: the holder acknowledged the system-use notification, like every session
DRILL 9: as Platform Admin the holder reaches IdP administration (/api/v1/idps) to repair or switch the IdP
DRILL 10: break-glass disabled with no approval: its session ended at once, the accounts are disabled, other sessions unaffected
DRILL 11: final state: break-glass off, ops1 disabled
--- PASS: TestIdPOutageRecoveryDrill (1.56s)
```

## Findings
- The system-use notification also gates a break-glass session (step 8). The runbook says
  so.
- With every IdP down nobody may be able to unlock a locked holder. The runbook gives the
  operator's way back: disable, then the emergency enablement again.
