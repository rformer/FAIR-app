# Spec-Driven Workflow — FAIR Risk Platform

Specs are the source of truth. Code, tests, and infrastructure are derived from them. If behavior needs to change, the spec changes first.

## Document hierarchy
| Layer | File | Purpose | Changes |
|---|---|---|---|
| 1. Constitution | `specs/01-constitution.md` | Non-negotiable principles (architecture, security, FAIR fidelity, quality bars) | Rarely; deliberate decision |
| 2. Product vision | `specs/02-product-vision.md` | Problem, users, scope, success measures | Per major release |
| 3. Roadmap / feature index | `specs/03-feature-index.md` | Ordered list of feature specs and their status | Continuously |
| 4. Feature specs | `specs/features/F-NNN-<slug>/` | `requirements.md` → `design.md` → `tasks.md` per feature | Per feature |
| 5. Decisions | `specs/adr/ADR-NNN-<slug>.md` | Architecture Decision Records for choices with real trade-offs | As decisions are made |

Templates live in `specs/templates/`.

## Lifecycle of a feature
1. **Requirements** (`requirements.md`) — user stories + acceptance criteria in EARS form ("WHEN <trigger> THE SYSTEM SHALL <response>"). Says *what*, never *how*. Gate: Robert approves.
2. **Design** (`design.md`) — components, data model, APIs, sequence flows, security controls, how each requirement is satisfied (traceability table). Gate: Robert approves.
3. **Tasks** (`tasks.md`) — small, ordered, independently verifiable tasks, each tied to requirement IDs. Gate: Robert approves.
4. **Implement** — one task at a time; each task references its requirement IDs in commits/PRs.
5. **Verify** — every acceptance criterion maps to a test; feature is "Done" only when all criteria pass.

Status values: `Draft` → `In Review` → `Approved` → `In Progress` → `Done` (or `Superseded`).

## Rules for working with Claude in this project
- No implementation work on a feature without an `Approved` requirements + design.
- Every requirement has a stable ID (`F-NNN-R-NN`); every acceptance criterion has an ID (`F-NNN-AC-NN`).
- Ambiguities are recorded as **Open Questions** in the spec, not silently assumed.
- Anything conflicting with the constitution is flagged, not worked around.
- Spec changes after approval are noted in the doc's Change Log.
