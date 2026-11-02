# Break-glass at installation

F-001 AC-39, AC-40 (T-34). Break-glass accounts are local Platform Admin
accounts that sign in with a security key (WebAuthn) when every identity
provider is down. They are **off by default**: a fresh installation has none,
and the sign-in routes do not exist.

## Choosing
Most installations leave break-glass off. The documented recovery for an IdP
outage is then an operator procedure with cluster-level access
([IdP-outage recovery](../operations/idp-outage-recovery.md)). Enable it at
install only if your policy wants named holders who can sign in without
cluster access.

## Enabling at install
Run this after `iam migrate` and `posture seed`, before anyone signs in, with
the migrator's credentials:

```sh
iam breakglass enable -reason "DR policy 7.2: two named holders" \
  -holder "bg-alice@example.com=Alice Example" \
  -holder "bg-bob@example.com=Bob Example"
```

- One or two holders (AC-42), each with an address of its own, not an
  existing account's.
- A reason is required. The enablement is written to the install log (the
  JSON line) and the audit trail as `system:installer`.
- Each holder gets a one-time enrollment code, printed once and valid for 24
  hours. Give it to the holder out of band. The holder registers a security
  key with it; there is never a password.
- Break-glass is recorded as a posture exception approved by the installer.
  It lasts `exception.max_duration` (90 days by default) and is renewed, like
  any exception, with a second administrator's approval. When it expires,
  break-glass turns off and its accounts with it.

Once anyone has signed in, this command refuses. From then on, enabling needs
`POST /api/v1/breakglass/enable` and a second administrator's approval
(AC-41), or, during an outage, the emergency procedure.

## Disabling
At any time, with no approval: `POST /api/v1/breakglass/disable` with a
reason, or `iam breakglass disable -reason "..."`. Sessions end at once
(AC-45).
