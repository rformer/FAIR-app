# F-009 Notifications — Requirements
Status: Approved | Owner: Robert Former | Last updated: 2026-11-16

## Summary
F-009 delivers the notices the other features already queue, and the few they leave to it, to the people and systems that must act on them. Examples: an estimate request for an estimator (F-004), an acceptance about to expire (F-008), a posture exception expiring or a revert that failed (F-015), a break-glass login (F-001), an audit integrity alert (F-002), and stale analyses or overdue treatment actions (F-007). Every notice appears in the recipient's in-app notification list, which works in every deployment mode. Each notice can also go by email (the customer's SMTP relay) and to webhooks (HTTPS endpoints such as a chat tool or a ticketing system). Delivery is reliable: a notice is delivered once, retried while a channel is down, and reported when it cannot be delivered. Delivery is also safe: a notice says little more than what happened and links back to the platform, where the reader's permissions apply. Channels are configured by administrators within security settings, and in air-gapped mode only to destinations inside the enclave.

## Users & roles affected
- **Every user:** receives notices in the app, by email if one is configured, and chooses which optional notices to receive.
- **Estimators, risk owners, approvers, analysts:** act on the notices F-004, F-007 and F-008 produce.
- **Platform administrator** (`notification.manage`, new, privileged): configures the SMTP relay and webhooks, and sends test messages.
- **Security officer, auditor** (`notification.view`, new): see delivery status and failures.
- **Vendor SecOps (SaaS):** unchanged; F-015's signed SecOps webhook stays as it is (out of scope).

## User stories
### F-009-R-01 Notices reach the people they are for
**As a** user, **I want** the notices meant for me in one place in the app, and by email, **so that** I act on requests, expiries and alerts in time.

**Acceptance criteria (EARS):**
- F-009-AC-01: WHEN a feature queues a notice (F-001, F-002, F-004, F-007, F-008, F-015 outboxes), THE SYSTEM SHALL resolve its recipients, whether named users or the holders of a permission at a business unit, and add the notice to each recipient's in-app notification list within 1 minute.
- F-009-AC-02: THE SYSTEM SHALL show each user their notifications, newest first, with read and unread state, a link to the item each concerns, and a count of unread ones in the app's header; marking one read, or all, SHALL be possible.
- F-009-AC-03: WHERE an SMTP relay is configured and the recipient has an email address (from the IdP or SCIM), THE SYSTEM SHALL also send the notice by email, unless the recipient muted that kind of notice by email.
- F-009-AC-04: IF a recipient is inactive, or no longer holds the permission that made them a recipient, or no longer sees the item the notice concerns, at delivery time, THEN THE SYSTEM SHALL not deliver it to them, and SHALL record why.

### F-009-R-02 Notices say little and link back
**As a** security officer, **I want** notices outside the app to carry as little as possible, **so that** email and chat tools do not become a copy of our risk data.

**Acceptance criteria (EARS):**
- F-009-AC-05: THE SYSTEM SHALL compose email and webhook notices from fixed templates per notice kind. By default these give the kind, the time, the business unit's name and a link into the platform, and no risk, scenario, estimate or analysis content.
- F-009-AC-06: WHERE the setting `notification.detail` allows titles, THE SYSTEM SHALL add the item's title, except for items in restricted business units, which SHALL always be minimal.
- F-009-AC-07: THE SYSTEM SHALL neutralize every value placed in a template (HTML and header escaping, no markup from data) and SHALL show the system-use banner text's short form, if set, in every email.

### F-009-R-03 Channels the administrator controls
**As a** platform administrator, **I want** to configure the SMTP relay and webhooks within secure bounds, **so that** notices reach our tools without opening new risks.

**Acceptance criteria (EARS):**
- F-009-AC-08: WHEN an administrator with `notification.manage` configures the SMTP relay, THE SYSTEM SHALL require TLS 1.2 or later (implicit TLS or STARTTLS, never plaintext), verify the server's certificate against the configured trust anchors, and read credentials from files, never from the API or environment literals.
- F-009-AC-09: WHEN an administrator adds a webhook, THE SYSTEM SHALL require an HTTPS URL (TLS 1.2 or later, certificate verified), the notice kinds and business units it receives, and SHALL generate a signing secret shown once. Every delivery SHALL be signed with it (HMAC-SHA-256 over the body, a timestamp and a delivery id) so the receiver can verify it and refuse replays.
- F-009-AC-10: IF a destination's host is not allowed by the setting `notification.allowed_hosts`, or, in air-gapped mode, resolves outside the enclave's internal networks, THEN THE SYSTEM SHALL refuse the configuration and refuse delivery.
- F-009-AC-11: WHEN an administrator sends a test message to a channel, THE SYSTEM SHALL deliver a fixed test notice and report the result, including the TLS version and any refusal, without delivering real notices.
- F-009-AC-12: WHEN a channel is added, changed, disabled or removed, or its secret rotated, THE SYSTEM SHALL record the change with the actor and a reason, and SHALL never return a secret or credential again.

### F-009-R-04 Reliable delivery
**As a** security officer, **I want** every notice delivered once, or reported when it cannot be, **so that** an alert is never lost silently.

**Acceptance criteria (EARS):**
- F-009-AC-13: THE SYSTEM SHALL deliver each notice to each recipient and channel at most once. A retry after an uncertain failure SHALL carry the same delivery id, so a receiver can drop duplicates.
- F-009-AC-14: WHILE a channel is unavailable, THE SYSTEM SHALL retry with increasing delays for up to `notification.retry_hours`. Other channels and the in-app list SHALL be unaffected.
- F-009-AC-15: IF a delivery is still failing at the end of its retries, THEN THE SYSTEM SHALL mark it failed and emit an event. IF a security notice (break-glass, revert failed, audit integrity) cannot be delivered by any channel but the app, THEN THE SYSTEM SHALL also raise a high finding on the Security Posture page.
- F-009-AC-16: THE SYSTEM SHALL survive restarts without losing or repeating notices, and SHALL catch up after an outage.
- F-009-AC-17: THE SYSTEM SHALL show users with `notification.view` each channel's state (last success, failures, backlog) and the deliveries of the last `notification.log_retention_days`, with each one's outcome and reason. It SHALL not show the notices' content beyond their kind and links.

### F-009-R-05 Each person's choices
**As a** user, **I want** to mute notices I do not need, **so that** the ones that matter stand out.

**Acceptance criteria (EARS):**
- F-009-AC-18: THE SYSTEM SHALL let each user mute optional notice kinds by email. Security notices and those that ask the user to act (an estimate request, an acceptance decision, an expiring acceptance they own) SHALL be mandatory, and SHALL always be delivered in the app.
- F-009-AC-19: WHERE a user prefers it, THE SYSTEM SHALL gather their optional email notices into one daily digest instead of one email each.

### F-009-R-06 Notices nobody queues yet
**As a** risk owner, **I want** to hear when my risks' analyses go stale and their treatment actions are overdue, **so that** the register stays current (F-007).

**Acceptance criteria (EARS):**
- F-009-AC-20: THE SYSTEM SHALL notify a risk's owner once when its exposure becomes stale, and once when one of its treatment actions becomes overdue. It SHALL notify the owner again only after the condition has cleared and returned.

### F-009-R-07 Evidence
**As an** auditor, **I want** the notification configuration and failures in the audit trail, **so that** I can show alerts were configured and delivered.

**Acceptance criteria (EARS):**
- F-009-AC-21: THE SYSTEM SHALL record channel changes, test messages, failed deliveries, refused destinations and preference changes in the audit trail (F-002), in the transaction that makes them. Successful deliveries SHALL be kept in the delivery log, not the trail.

## Non-functional requirements
- Performance: a queued notice is in the recipient's in-app list within 1 minute and handed to email and webhooks within 2 minutes at 10,000 users. The notification list opens within 1 s p95. Delivery keeps up with 10,000 notices an hour.
- Security / privacy: TLS 1.2 is the floor for SMTP and webhooks; FIPS 140 cryptography for signing (HMAC-SHA-256). Secrets are stored as files or HMAC'd, never shown again. Notices carry minimal content (R-02). Recipients are re-checked at delivery (AC-04). Webhook and SMTP destinations are allow-listed. No redirects are followed, and no request is made to an address the allow-list does not name (SSRF). `notification.manage` is privileged.
- Audit: as AC-21; events in the catalog.
- Availability: delivery is a job that survives restarts and catches up; a failing channel never blocks the others or the in-app list.
- Accessibility: the notification list and preferences meet WCAG 2.1 AA; emails have a plain-text part.
- Secure defaults: no channel is configured on install; the in-app list always works; `notification.detail` is minimal; `notification.allowed_hosts` is empty (nothing allowed until set).

## Deployment modes
| Concern | SaaS | Self-hosted | Air-gapped |
|---|---|---|---|
| In-app notifications | Yes | Yes | Yes |
| Email | Vendor relay or customer SMTP | Customer SMTP | SMTP relay inside the enclave |
| Webhooks | Customer HTTPS endpoints | Customer HTTPS endpoints | Endpoints inside the enclave only |
| Vendor SecOps alerts | F-015's channel (unchanged) | None | None |

## Control mapping (NIST SP 800-53r5)
To be proposed with the tasks.

## Out of scope
- F-015's vendor SecOps webhook (unchanged; F-009 may carry it later).
- Chat-tool-specific formats (Slack, Teams blocks) and SMS or push notifications; webhooks send one documented JSON format.
- Customer-edited templates and localization (English only).
- Escalation chains and on-call schedules (the customer's incident tooling).
- Notice kinds beyond those listed in AC-01 and AC-20; later features queue their own.

## Dependencies
- F-001: users, email addresses (IdP, SCIM), permissions and permission holders, the banner; a permission catalog version adding `notification.manage` and `notification.view`.
- F-002: audit trail; F-015: settings, the Security Posture page's findings, the deployment mode.
- The outboxes of F-001, F-002, F-004, F-007, F-008 and F-015 (their rows and kinds are theirs; F-009 reads them).

## Open Questions
- OQ1 (resolved 2026-11-16: as proposed). Webhook signing (AC-09). Proposed: HMAC-SHA-256 with a per-webhook secret generated by the platform and shown once (as F-001's SCIM tokens), in the Standard Webhooks header format (`webhook-id`, `webhook-timestamp`, `webhook-signature`); rotation keeps the old secret valid for 24 hours.
- OQ2 (resolved 2026-11-16: as proposed). Detail (AC-05, AC-06). Proposed: `notification.detail` with values `minimal` (default) and `titles`; restricted business units always minimal.
- OQ3 (resolved 2026-11-16: as proposed). Retries (AC-14). Proposed: `notification.retry_hours` default 24 (bounds 1 to 72), exponential back-off from 30 seconds capped at 30 minutes.
- OQ4 (resolved 2026-11-16: as proposed). Delivery log retention (AC-17). Proposed: `notification.log_retention_days` default 90 (bounds 30 to 365); in-app notifications are kept 180 days.
- OQ5 (resolved 2026-11-16: as proposed). Mandatory kinds (AC-18). Proposed: security notices (break-glass, revert failed, audit integrity, exception expiring) and requests to act (estimate assigned and reminders, acceptance decision needed, acceptance expiring for its owner and requester) cannot be muted; the rest (decided, finished, stale, overdue) can be.
- OQ6 (resolved 2026-11-16: as proposed). Who receives permission-holder notices (AC-01): F-015 addresses some to holders of a permission and F-008's `decision_needed` to nobody in particular. Proposed: holders of the permission at the item's business unit (inherited), and for `decision_needed` the approvers at the acceptance's tier BU who may decide it (as the inbox), capped at 50 recipients with the cap recorded.
- OQ7 (resolved 2026-11-16: as proposed). Allowed hosts (AC-10). Proposed: `notification.allowed_hosts`, a list of host names or suffixes (`*.example.com`), empty by default; addresses resolving to loopback, link-local or the cluster's own service ranges are always refused, and in air-gapped mode only private ranges are allowed.
- OQ8 (resolved 2026-11-16: as proposed). Webhook scope (AC-09): a webhook receives only notices about business units its configuration names. Proposed: a webhook is configured for a business unit subtree, and never receives notices about restricted business units unless configured on that restricted unit itself.

## Change Log
- 2026-11-16: Initial draft, In Review.
- 2026-11-16: Approved by Robert Former; OQ1 to OQ8 resolved as proposed.
