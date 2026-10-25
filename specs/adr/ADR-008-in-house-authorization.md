# ADR-008 In-house authorization (closure table + RLS) rather than an external policy engine
Status: Accepted (Robert Former, 2026-10-24)
Date: 2026-10-24

## Context
The authorization model is roles composed of permissions, assigned at nodes in a BU tree, with inheritance that stops at restricted nodes. Data-layer enforcement through RLS is required regardless of which engine makes access decisions (A6, ADR-007).

## Decision
Build authorization in-house:
- a BU closure table with a `blocked` flag for restricted boundaries;
- a materialized per-user scope, recomputed by a worker within 60 s of any change;
- an embedded Go `authz` library for action checks;
- RLS for row visibility.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| In-house (chosen) | No additional bundled dependency; a single source of truth shared with RLS; simple to air-gap; fast in-process checks | We own correctness, so it needs thorough tests |
| OPA / Rego | Mature, policy-as-code | Second source of truth alongside RLS; policy data sync; another component to bundle and harden |
| OpenFGA / SpiceDB (ReBAC) | Strong for relationship-based sharing | Additional stateful service in every deployment; still has to be mirrored into RLS |

## Consequences
- An exhaustive authorization test suite is mandatory: property-based tests over random trees, assignments, and restrictions.
- Revisit this decision if per-record sharing or relationship-based rules are introduced.
