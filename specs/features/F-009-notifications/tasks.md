# F-009 Notifications — Tasks
Status: In Review | Design: In Review 2026-11-16

Sizing: S ≤ 1 day · M = 2–3 days · L = up to 1 week (split when picked up).
Prerequisites, all done:
- F-001: users, email addresses, permissions and `iam.permission_holders`, the banner, keys, the gateway.
- F-002: the audit trail. F-015: settings, findings, the deployment mode.
- The outboxes of F-001, F-004, F-008 and F-015; F-007's register and F-008's `register.exposures`.

Rules for every task:
- A task that adds a migration follows the immutability rule.
- A new event type gets its catalog entry with the task that first emits it.
- Every new route is linted by `scripts/openapi-lint.sh`.
- Every UI task runs `scripts/ui-e2e.sh`, with axe on every page it touches.
- No test sends to the internet: SMTP and webhook tests use in-process test servers.

## Phase A — Foundations
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-01 | Permission catalog version 4 (`notification.view`: Platform Admin, Auditor); F-015 direction `EmptyIsStricter` (Go and SQL comparators); `settings.F009Defs()` (four settings, bindings, packages 1.8.0) | AC-06, AC-10, AC-14, AC-17; §4, §10 | Upgrade test of the catalog; comparator parity; `TestNotifySettings` | M | Not started |
| T-02 | Bootstrap roles `app_notify`, `notify_definer`; schema `notify` (§5) with `notify.kind` synced by `iam migrate`; grants on the outboxes; PF028 | AC-01, AC-13; §5 | DB tests: access by role, append and state checks, the sync | M | Not started |
| T-03 | `cmd/notify` scaffold (image target `notify`, `deploy/k8s/notify.yaml` with its NetworkPolicy), keys `notify/jwt` and `notify/secrets` (`iam keys upgrade`, rotate), `notify.CheckInstall` per mode, the leader, gateway segment `notifications` | §2, §11 | Unit tests; `TestDeploymentModeMatrix` rows; the keys tests | M | Not started |

## Phase B — Notices in the app
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-04 | `notify.collect()` for every source (§3.1), envelopes with titles by setting and never for restricted units (§3.3); `posture.finding_outbox` and its trigger (§3.6) | AC-01, AC-05, AC-06; §3.1, §3.3, §3.6 | DB tests per source: once only, marked delivered in the same transaction, restricted envelopes minimal | M | Not started |
| T-05 | Fan-out: recipients (users, permission holders, approvers who may decide; the 50 cap), re-checks with reasons, in-app rows, email and webhook deliveries (§3.2) | AC-01, AC-03, AC-04; §3.1, §3.2 | DB tests: every reason, inherited holders, restricted units, the cap | M | Not started |
| T-06 | The notifications API for users (`/notifications`, `/count`, `/read`, `/preferences`, `/kinds`), contract `api/openapi/notify.yaml`; preferences and digest options (§3.8) | AC-02, AC-18, AC-19; §3.8, §6 | DB tests through the API; `TestOpenAPIMatchesRoutes`; mandatory kinds refused | M | Not started |

## Phase C — Email and webhooks
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-07 | Templates per kind (HTML and text, subjects, the banner, links from the base URL); the webhook format `fair.notification.v1` and its document | AC-05 to AC-07; §3.3 | Unit tests: escaping, header injection refused, minimal content, golden files | M | Not started |
| T-08 | The destination guard (allowed hosts, address checks, air-gapped private ranges, pinned dialling, no redirects or proxies, timeouts, capped reads) | AC-10; §3.4 | Unit tests over a resolver fake and local listeners: every refused range, redirects, DNS rebinding | M | Not started |
| T-09 | The SMTP sender (implicit TLS and required STARTTLS, TLS 1.2+, trust anchors, PLAIN in TLS, password files) and the webhook sender (Standard Webhooks signatures, the previous secret for 24 hours) | AC-08, AC-09, AC-13; §3.4 | Tests against in-process SMTP and HTTPS servers: STARTTLS stripping refused, signatures verified, ids stable | M | Not started |
| T-10 | Delivery workers: claims with tokens, uncertain claims, back-off, permanent refusals, channel state, digests, retention; the `notification_undelivered` finding (§3.5, §3.8, §3.9) | AC-13 to AC-16, AC-19; §3.5, §3.8, §3.9 | DB tests with time travel: once only, retries, restarts, the finding opens and resolves | L | Not started |
| T-11 | The channel API (SMTP relay, webhooks, disable, enable, remove, rotate, test, status, deliveries); secrets as ciphertext, shown once; events | AC-08 to AC-12, AC-17, AC-21; §3.4, §6, §8 | DB tests through the API; audit event tests; secrets never returned | M | Not started |

## Phase D — The register's notices and the pages
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-12 | `register.notice_outbox`, `register.notice_state` and `register.notice_sweep()` on the risk service's leader (stale and overdue, once per transition, batched) | AC-20; §3.7 | DB tests with time travel: once per transition, again after clearing | M | Not started |
| T-13 | Pages `web/src/notify`: the header's unread count, `/notifications`, `/notifications/preferences`, the channels and deliveries pages; the UI harness runs the notify service with a test SMTP server | AC-02, AC-11, AC-17 to AC-19 | `web/e2e/notifications.spec.ts`; axe on every page | L | Not started |

## Phase E — Assurance
| # | Task | Traces to | Verification | Size | Status |
|---|---|---|---|---|---|
| T-14 | Benchmark gate `TestBenchmarkGateNotifications`: 10,000 users; 10,000 notices an hour in the app within 1 minute and handed to channels within 2; the list ≤ 1 s p95 | Requirements NFR; §9 | Bench gate passes | M | Not started |
| T-15 | STRIDE suite for design §7 (`db/tests/stride_f009_test.go` and unit tests, rows in `TestSTRIDECatalog`) | §7 | `make test-stride` covers every §7 row | M | Not started |
| T-16 | Control implementation statements `compliance/statements/F-009.yaml`, built into the component definition; the control mapping added to the requirements; Robert Former signs off | — | `internal/compliance` checks pass; sign-off recorded | S | Not started |

## Definition of Done
- All linked acceptance criteria have passing automated tests.
- Audit events are emitted per design §8, each in the catalog.
- The API contract is updated and linted.
- axe passes on every F-009 page.
- Security review notes are recorded (STRIDE rows and tests).

## Change Log
- 2026-11-16: Initial draft, In Review.
