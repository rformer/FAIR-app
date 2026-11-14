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

## Amendment 1: scope forms (2026-11-03)
Status: Accepted (Robert Former, 2026-11-03; F-001 T-11d)

**Context.** `bu_id = ANY(visible)` checks each row against the caller's visible BUs one element at a time, because PostgreSQL hashes `= ANY` only for constant arrays. A caller who sees most of 2,000 BUs pays about 2,000 comparisons per row: up to 40 ms for "newest 50 rows" when the newest rows are in BUs they cannot see. The T-11 gate passed only because of where its test users' rows happened to sit.

**Decision.**
- Every BU policy checks the smaller of two sets, chosen and computed when the statement starts:
  - include form: `bu_id = ANY(visible_bus(type, mode))`, as before;
  - exclude form: `bu_id <> ALL(scope_hides(type, mode))`. `authz.scope_hides` returns every BU in `iam.bu` outside the caller's visible set.
- `authz.scope_excludes(type, mode)` chooses the form: true when the caller sees more than half of the BUs. It only counts the stored array, so it is cheap. It returns false for a missing, invalid, expired or stale context.
- The policy is `CASE WHEN (SELECT authz.scope_excludes(t, m)) THEN bu_id <> ALL ((SELECT authz.scope_hides(t, m))::uuid[]) ELSE bu_id = ANY ((SELECT authz.visible_bus(t, m))::uuid[]) END`. All three functions are `SECURITY DEFINER STABLE`, owned by `authz_definer`, and evaluated at most once per statement as InitPlans. Only the chosen branch's set is computed.
- The two forms admit exactly the same rows. The hidden set is derived from the current `iam.bu` at statement time, not stored, so a BU created after the caller's scope was computed is hidden, never visible by default. For writes, archived BUs are not in the visible set, so they are hidden.
- **Fail closed:**
  - An invalid context makes `scope_excludes` false and `visible_bus` empty, so no rows.
  - `scope_hides` returns NULL (never an empty set) without a valid context, so even the exclude branch admits nothing.

**Changed from the proposal.** The proposal stored the complement in `authz.user_scope`, valid only for the BU-tree version it was computed against. Computing it per statement removes that staleness window entirely, for the cost of one hashed set difference over the BU ids when the caller sees most of them.

**Consequences.**
- The policy is no longer an indexable `bu_id = ANY(...)` predicate, so the planner does not use the `bu_id` index for the policy alone. List queries over BU-owned tables use the T-11c helper (`authz.NewestQuery`), which supplies its own per-BU predicate when the caller sees few BUs. Lookups by key and queries filtered by BU use their own indexes as before.
- Each statement verifies the context twice (the chooser and the chosen set) and counts `iam.bu`; the exclude form adds a set difference over the BU ids. The T-11b gate measures this.
- The RLS harness (T-10) requires the form on every BU policy and exercises both forms.

## Amendment 2: inherited read (2026-11-06)
Status: Accepted (Robert Former, 2026-11-06; F-003 design §11)

**Context.** F-003's library entries and controls are shared down the BU tree (F-003 OQ4): an analyst in a child BU uses entries owned by its ancestors. The BU policies admit only the caller's own scope (the BUs where they hold the permission, and their descendants), so a child BU cannot read its parent's entries.

**Decision.**
- `authz.inherited_bus(type)` returns the ancestors of the BUs where the caller holds `<type>.view`, excluding BUs already visible. It walks up `iam.bu_closure` and stops at restricted BUs: a restricted BU inherits nothing from above, and nothing above a restricted BU is inherited through it. It is `SECURITY DEFINER STABLE`, owned by `authz_definer`, and evaluated once per statement. Without a valid context it returns NULL, so it admits nothing.
- Tables registered as *shared down* (`authz.apply_bu_rls(..., shared_down => true)`) add `OR bu_id = ANY(inherited_bus(type))` to their `SELECT` policy only. Insert, update and delete policies are unchanged: an inherited row is never writable.
- The set is small: at most the tree depth for each top of the caller's scope.

**Consequences.**
- The RLS harness (T-10) exercises every shared-down table, including the restricted cases: a sibling's entries, a restricted BU's entries seen from outside, and a restricted BU's own view of its ancestors are all refused.
- Only F-003's `library` and `control` tables use it in v1.

## Amendment 3: sanctioned definer access (2026-11-10)
Status: Accepted (Robert Former, 2026-11-10; F-004 T-04)

**Context.** F-004's estimate requests are scenario data, owned by the scenario's BU under the BU policies. Estimators answer the requests addressed to them while holding `estimate.submit`, not `scenario.view`, so they have no read scope there; the leader's due-date job closes requests with no user context at all. Definer roles are subject to RLS too, so the functions that serve estimators and jobs cannot see or update those rows. F-001 met the same need for roll-ups and the archive guard with policies for one named role each (`bu_rollup`, `bu_guard`), and `authz.apply_bu_rls` refuses any other policy.

**Decision.**
- `authz.allow_definer(table, role)` gives one named definer role read and update access to a registered BU-owned table: policies `bu_definer_select` (`FOR SELECT`) and `bu_definer_update` (`FOR UPDATE`), both `TO <role> USING (true)`, the update `WITH CHECK (true)`; the role is granted `SELECT` and `UPDATE` only, never `INSERT` or `DELETE`.
- The role must be `NOLOGIN`, `NOBYPASSRLS`, named `*_definer`, granted to no login role, and not `rollup_definer` or `bu_guard_definer`. It is recorded in `iam.bu_owned_tables.definer`; one per table.
- `authz.apply_bu_rls` keeps these policies when it re-applies a table's BU policies.
- The role's functions are the only callers. They take the caller from the signed context and enforce who may read or change what (for F-004: the addressed estimator holding `estimate.submit` at the request's BU, checked on every call).

**Consequences.**
- The RLS harness checks the two policies against the registry: the recorded role alone, `true`, the right commands, and no privileges beyond `SELECT` and `UPDATE`.
- Application roles are unaffected: their access remains the BU policies.
- Used for `estimate_definer` on F-004's request tables in v1.

## Amendment 4: restrictive select (2026-11-10)
Status: Accepted (Robert Former, 2026-11-10; F-005 T-02)

**Context.** F-005's aggregates combine simulation runs of several scenarios. An aggregate belongs to the business unit its requester chose, but it must be visible only to a reader who can also see every member run: otherwise it would reveal results of a restricted or other business unit through the sum. The BU policies are permissive, and PostgreSQL ORs permissive policies together, so another permissive policy would widen access rather than narrow it; `authz.apply_bu_rls` refuses any other policy.

**Decision.**
- `authz.restrict_select(table, expression)` adds one policy `bu_restrict` to a registered BU-owned table: `AS RESTRICTIVE FOR SELECT TO app_rw USING (<expression>)`. A restrictive policy is ANDed with the permissive ones, so it can only narrow what the BU policies allow.
- The expression is recorded in `iam.bu_owned_tables.restriction`; `authz.apply_bu_rls` keeps the policy when it re-applies a table's BU policies.
- It applies to the application role. Definer roles keep the access their own policies give (amendment 3), since their functions check the caller themselves.

**Consequences.**
- The RLS harness checks `bu_restrict` against the registry: restrictive, SELECT, `app_rw` alone, with an expression; every other policy must be permissive.
- Used for `analysis.aggregate` and `analysis.aggregate_member` in v1: every member run in the reader's read scope, checked by the definer function `analysis.members_visible` (two tables' policies referring to each other would recurse).

## Amendment 5: definer insert (2026-11-14)
Status: Accepted (Robert Former, 2026-11-14; F-007 T-05)

**Context.** F-007's register makes F-005 aggregates of the results a risk pins: a risk's exposure (purpose `exposure`) and business unit roll-ups (purpose `rollup`, T-07). F-007's design (§5.2) has them requested by the register's definer functions, which check `register.edit` or `register.view` instead of `analysis.run`: Risk Owners hold `analysis.view`, not `analysis.run`. An aggregate's rows are inserted under the BU policies, so the insert needs the caller's `analysis` write scope, and `authz.apply_bu_rls` refuses any other policy. Amendment 3 gave a definer reads and updates of every row, never inserts.

**Decision.**
- `authz.allow_definer_insert(table, role)` gives one named definer role inserts into a registered BU-owned table: policy `bu_definer_insert` (`FOR INSERT TO <role> WITH CHECK (true)`). The migration grants the role `INSERT` on the columns it needs and nothing else on the table.
- The role must be `NOLOGIN`, `NOBYPASSRLS`, named `*_definer`, granted to no login role, and not `rollup_definer` or `bu_guard_definer`. It is recorded in `iam.bu_owned_tables.inserter`; one per table. `authz.apply_bu_rls` keeps the policy when it re-applies a table's BU policies.
- The role's functions are the only callers. They take the caller from the signed context and check the caller themselves (for F-007: `register.edit` at the risk's BU for an exposure). Every check on the inserted rows' own triggers still runs; for aggregates, each member must be in the caller's own `analysis` read scope, so only results the caller sees are aggregated.
- A table's definer (amendment 3) may also hold `INSERT` and `DELETE`. Without a definer insert, they stay within the caller's write scope (`bu_insert`, `bu_delete`). F-007's links table needs this: its rows are written by its version trigger under the caller's scope and read and updated by the definer everywhere.

**Consequences.**
- The RLS harness checks `bu_definer_insert` against the registry: the recorded role alone, `INSERT`, `WITH CHECK (true)`, and no privileges on the table beyond `INSERT`. A definer may hold `SELECT`, `UPDATE`, `INSERT` and `DELETE`.
- Application roles are unaffected: their access remains the BU policies.
- Used for `register_definer` on `analysis.aggregate` and `analysis.aggregate_member` in v1.
