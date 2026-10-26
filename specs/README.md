# Specs

These are the approved specs for the FAIR Risk Platform. They are mirrored from the claude.ai Project **"FAIR Risk Assessment And Management Platform Development"**. The copy here is what Claude Code works from.

| Path | Contents |
|---|---|
| `00-workflow.md` | Spec-driven workflow and approval gates |
| `01-constitution.md` | Non-negotiable principles (approved baseline) |
| `02-product-vision.md` | Problem, users, scope |
| `03-feature-index.md` | Features, dependencies, status, build order, **current position** |
| `adr/ADR-001…008` | Architecture decisions |
| `features/F-001-identity-bu-rbac/` | Requirements, design, tasks, permission catalog v1 (all approved; Phase 0 done) |
| `features/F-015-security-posture-profiles/` | Requirements, design, tasks (all approved) |
| `templates/` | Templates for new requirements, designs, tasks and ADRs |

## Where we are
- **Done:** F-001 Phase 0 (T-00a, T-00b, T-00c, T-01, T-02). See `features/F-001-identity-bu-rbac/tasks.md`.
- **Next:** F-001 Phase 1, the authorization core (T-03 → T-12). It ends with the T-11 benchmark gate.
- **Then:** F-015, followed by the rest of F-001.

## Rules for contributors (human or AI)
- No implementation without approved requirements and an approved design for the feature.
- Every commit and PR references task IDs (e.g. `F-001 T-02`) and acceptance criteria (e.g. `F-001-AC-27`).
- If behavior needs to change, change the spec first and note it in the Change Log.
- When a task is finished, mark it Done in the feature's `tasks.md`.
