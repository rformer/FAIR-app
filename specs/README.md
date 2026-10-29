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
- **Done:** F-001 Phase 1, the authorization core (T-02b, T-03 to T-12; benchmark gate passed).
- **In progress:** F-015. Phase A done (T-01 to T-07; T-04 signed off 2026-10-27). Phase B done (T-08 to T-16); F-001 T-26 (dual approval) done, pulled forward. Phase C done (T-17 to T-21). Phase D: T-22 (BU overrides), T-23 (Restricted BU overlay) and T-24 (step-up check; split, T-24b waits for F-001 sessions and IdP flows) done. Phase E: T-25 (app drift engine), T-26 (finding lifecycle, event schema), T-27 (`posture-scanner`) T-28 (deployment check catalog, signed release manifest), T-29 (`fips-probe`) and T-30 (Kubernetes-access consent) done, which completes Phase E. Phase F: T-31 (Posture API; F-001 T-14 internal JWT pulled forward) T-32 (Posture page UI, the first web UI) T-33 (OSCAL Assessment Results export), T-34 (OSCAL POA&M export) T-35 (signed, recorded, reproducible exports) T-36 (STRIDE suite) and T-37 (deployment-mode matrix; air-gapped mode) and T-38 (control implementation statements, signed off) done: F-015 is complete apart from T-24b. F-001 Phase 2 has begun: T-13 (gateway sessions) and T-15 (SAML SP; ADR-009) and T-16 (OIDC RP) and T-17 (home-realm discovery, IdP administration API) and T-18 (MFA evidence rules) done. **Next:** F-001 T-19 (system-use banner); F-015 T-24b is now unblocked.
- **Then:** the rest of F-001.

## Rules for contributors (human or AI)
- No implementation without approved requirements and an approved design for the feature.
- Every commit and PR references task IDs (e.g. `F-001 T-02`) and acceptance criteria (e.g. `F-001-AC-27`).
- If behavior needs to change, change the spec first and note it in the Change Log.
- When a task is finished, mark it Done in the feature's `tasks.md`.
