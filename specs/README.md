# Specs

The authoritative specs live in the claude.ai Project **"FAIR Risk Assessment And Management Platform Development"** under `specs/`:

| Path | Contents |
|---|---|
| `00-workflow.md` | Spec-driven workflow and approval gates |
| `01-constitution.md` | Non-negotiable principles (approved baseline) |
| `02-product-vision.md` | Problem, users, scope |
| `03-feature-index.md` | Features, dependencies, status, build order |
| `adr/ADR-001…008` | Architecture decisions |
| `features/F-001-identity-bu-rbac/` | Requirements, design, tasks (all approved) |
| `features/F-015-security-posture-profiles/` | Requirements, design, tasks (all approved) |

They will be mirrored into this directory when the repository is first pushed to GitHub, so every Claude Code session working on the repo sees them.

## Rules for contributors (human or AI)
- No implementation without an approved requirements + design for the feature.
- Every commit and PR references task IDs (e.g. `F-001 T-02`) and acceptance criteria (e.g. `F-001-AC-27`).
- If behavior needs to change, change the spec first.
