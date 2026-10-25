# ADR-001 Single-tenant deployment with business-unit hierarchy
Status: Accepted
Date: 2026-10-24

## Context
The target is enterprise risk teams, including federal and defense-industrial customers who are subject to FedRAMP and CMMC. Those customers expect strong data isolation and clear authorization boundaries.

## Decision
- Each customer gets a dedicated deployment: its own namespace or cluster, database, object store, and encryption keys.
- Within an instance, business units form a hierarchy (Enterprise → BU → sub-BU). Risks, analyses, and acceptances belong to a BU.
- Portfolio views roll up the hierarchy.

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Single-tenant (chosen) | Clean authorization boundary, per-customer keys, easy data residency, simpler audits | More instances to operate; needs strong IaC and GitOps |
| Multi-tenant shared schema | Cheapest to run | Harder FedRAMP/CMMC story; noisy-neighbor and isolation risk |

## Consequences
- Fully automated provisioning (IaC + Helm + GitOps) becomes a core requirement (F-012).
- BU-scoped RBAC is enforced with PostgreSQL row-level security.
- Upgrades must be safe to roll across a fleet of instances.
