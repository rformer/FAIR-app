# ADR-007 Signed database context for row-level security
Status: Accepted (Robert Former, 2026-10-24)
Date: 2026-10-24

## Context
Constitution A6 requires BU scoping in the data layer. Standard PostgreSQL row-level security (RLS) trusts whatever identity the application places in a session variable. As a result, an application bug, SQL injection, or a compromised service could impersonate another user and widen data access.

## Decision
- For each request, the gateway mints a **database context token**: `user_id | scope_version | expiry | nonce`, signed with HMAC-SHA-256.
- Services start every transaction with `SET LOCAL authz.ctx = '<token>'`.
- RLS policies call `authz.visible_bus(resource_type)`, a `SECURITY DEFINER STABLE` function owned by a non-login role. The function:
  - verifies the HMAC with a key stored in a table that application roles cannot read;
  - rejects expired tokens and tokens with a stale `scope_version`;
  - returns the caller's BU set from the materialized `authz.user_scope`.
- Policies are written as `bu_id = ANY ((SELECT authz.visible_bus('<type>')))`, so the function is evaluated once per statement.
- Every BU-owned table is created via `authz.apply_bu_rls(table, resource_type)`. The helper enables and forces RLS and installs policies for all four operations.
- Application roles are `NOBYPASSRLS` and own no tables. Migrations run under a separate role.
- **Fail closed:** a missing, invalid, expired, or stale context yields an empty scope.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Signed context (chosen) | Defends against app compromise and SQL injection impersonation; centralized scope logic | More moving parts; key management for the HMAC key |
| Plain RLS with unsigned session variable | Simple, widely used | Trusts the app completely |
| App-only filtering | Simplest | Violates A6; one missed WHERE clause leaks data |

## Consequences
- An HMAC key is required per instance (KMS, Vault/OpenBao, or generated at install), along with a rotation procedure (dual-key validity window).
- Residual risk: a compromised service can replay a token it legitimately received, limited to that user's scope for at most the 5-minute TTL.
- Performance must be benchmarked at target scale (F-001 task T-11).
