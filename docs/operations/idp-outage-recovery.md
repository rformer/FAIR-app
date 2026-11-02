# IdP-outage recovery

F-001 AC-46 (T-35). This runbook is for when nobody can sign in because every
identity provider (IdP) is unavailable or misconfigured, and break-glass is
off. If break-glass is already on and a holder has an enrolled key, skip to
[Sign in with break-glass](#3-sign-in-with-break-glass).

The recovery is an operator procedure with **cluster-level access**: it uses
the database migrator's credentials, the same ones `iam migrate` uses. It is
audited three ways:
- the platform audit trail records `breakglass.emergency_enabled` at
  **critical** severity, with the operator's name and the reason;
- every notification channel is notified (the notice outbox, the
  `iam.breakglass.login` events of each sign-in, and in SaaS mode the vendor
  SecOps webhook);
- the Kubernetes API audit log records who created the Job or ran the command.

Break-glass enabled this way **turns itself off after 24 hours**, and its
accounts with it, unless an administrator renews the posture exception with
the usual dual approval.

## Before you start
- Confirm the outage: the IdP status page, or a failed sign-in with
  `authn.login.denied` or IdP errors in the iam logs. A broken IdP
  *configuration* (an expired signing certificate, say) can also be fixed this
  way.
- Open an incident and note its ID; it goes into the reason.
- Choose the holder: one person (at most two) who will sign in. Each needs an
  email address that is **not** an existing account's (for example
  `bg-alice@example.com`; the mailbox need not receive mail), and a FIDO2
  security key or platform authenticator that supports discoverable
  credentials and user verification (a PIN or biometric).
- Who may run it: in a **self-hosted** install, the customer's cluster
  administrator. In **SaaS**, the vendor's on-call operator, on a verified
  request from a named customer administrator (record the request in the
  incident); the customer's SecOps contacts are notified automatically.

## 1. Enable break-glass (operator)
With `kubectl` access to the platform namespace, fill in the placeholders in
`deploy/k8s/breakglass-emergency.yaml` (the image digest and database host as
in `iam.yaml`; your name; `INC-1234: <what is down>`; the holder) and run:

```sh
kubectl -n fair-platform create -f breakglass-emergency.yaml
kubectl -n fair-platform logs -f job/iam-breakglass-emergency
```

Or, from a host with the iam binary and the migrator credentials (the libpq
variables and `FAIR_MIGRATOR_PASSWORD_FILE`, as for `iam migrate`):

```sh
iam breakglass enable -emergency -operator "Jo Operator" \
  -reason "INC-1234: Entra ID outage" -holder "bg-alice@example.com=Alice Example"
```

The output is a JSON install-log line (`breakglass.emergency_enabled`,
`critical`), then one line per holder:
`enrollment code for bg-alice@example.com (user …), valid 24 hours, shown once: fbg_…`.

It refuses when break-glass is already on, without `-operator`, or without
`-reason`.

## 2. Hand over the code (operator)
Give the holder the code **out of band** (in person or by phone; not in the
incident ticket). The code is in the Job's log too: it is single-use and
spent at enrollment, so have the holder enroll now, then delete the Job
(`kubectl -n fair-platform delete job iam-breakglass-emergency`).

## 3. Sign in with break-glass (holder)
1. Open the platform's break-glass page and enter the code to register the
   security key (`/api/v1/auth/breakglass/enroll/begin` and `/finish`). The
   code is then spent.
2. Sign in with the key (`/api/v1/auth/breakglass/login/begin` and `/finish`):
   no email address or IdP is involved. Every sign-in is audited high and
   announced.
3. Acknowledge the system-use notification.

Three failed attempts within 15 minutes (the FedRAMP and CMMC profiles; five
under the Enterprise Baseline) lock the account. With every IdP down there may
be no administrator to unlock it (`POST /api/v1/users/{id}/unlock`), so the
operator runs `iam breakglass disable -reason "..."` and then step 1 again,
which reactivates the holder with a new code and a new key.

The holder is a Platform Admin at the root with **no access to risk data**
(AC-44).

## 4. Restore sign-in (holder)
Under **Identity providers** (`/api/v1/idps`): replace the IdP's metadata or
signing certificate, correct its configuration, or enable a standby IdP (the
bundled Keycloak in a self-hosted install) for the affected email domains.
Then confirm a normal user can sign in.

## 5. Turn break-glass off (holder or any administrator)
`POST /api/v1/breakglass/disable` with a reason (no approval needed). It is
immediate: the setting goes off, the break-glass accounts are disabled and
their sessions end. Without it, break-glass ends by itself when its 24-hour
exception expires.

From the cluster instead: `iam breakglass disable -reason "INC-1234 resolved"`.

## 6. Close the incident
- Export the audit events from the incident window: `breakglass.*`,
  `authn.*`, `idp.*`.
- Record who held break-glass, from when to when, and what changed.
- If break-glass should stay available, enable it the normal way:
  `POST /api/v1/breakglass/enable` and a second administrator's approval
  (AC-41).

## Drill
The procedure is drilled by `TestIdPOutageRecoveryDrill` (`db/tests`), which
runs the operator command, enrolls and signs in with a software
authenticator, reaches IdP administration and disables break-glass. Each run
is recorded under [drills](drills/).
