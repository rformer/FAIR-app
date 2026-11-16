# fair.notification.v1: webhook notices

F-009 T-07 (F-009-AC-05, AC-06, AC-09; design §3.3, §3.4). The notify service sends each notice a webhook takes as one HTTPS `POST` with a JSON body in this format. The body says what happened and links back into the platform, where the reader's permissions apply. It never carries risk, scenario, estimate or analysis content.

## The body

```json
{
  "format": "fair.notification.v1",
  "delivery": "5b0e…",
  "notice": "0b6c…",
  "kind": "acceptance.decision_needed",
  "at": "2026-11-16T09:30:00Z",
  "bu": { "id": "4d3c…", "name": "Claims" },
  "item": { "type": "acceptance", "id": "8f0c…", "link": "https://fair.example.com/acceptances/8f0c…" },
  "title": "Claims ransomware"
}
```

- **`delivery`** identifies this delivery. It is the same on every retry of the same delivery, so a receiver drops any delivery id it has already handled.
- **`notice`** identifies the notice. Several webhooks receive the same notice under different delivery ids.
- **`kind`** is one of the notice kinds the release lists (`internal/notify` `Kinds`), for example:
  - `estimate.assigned` and `estimate.reminder`;
  - `acceptance.expiring` and `acceptance.decision_needed`;
  - `setting.revert_failed`, `breakglass.login` and `finding.opened`;
  - `risk.stale`.

  New kinds may appear in later releases, so ignore kinds you do not know.
- **`at`** is when the notice was queued, in UTC.
- **`bu`** is the business unit the notice concerns. Security notices (posture, break-glass, findings) name the top business unit.
- **`item`** gives the item's type (`acceptance`, `estimate_request`, `posture`, `breakglass`, `finding`, `risk`), its id where it has one, and an absolute link built from the platform's base URL.
- **`title`** appears only where the installation's `notification.detail` setting is `titles`, and never for an item inside a restricted business unit.

Receivers should ignore fields they do not know.

## Verifying a delivery

Every delivery is signed in the [Standard Webhooks](https://www.standardwebhooks.com/) form with the webhook's secret. The secret is shown once, as `whsec_<base64>`, when the webhook is created or its secret rotated. The headers:

| Header | Value |
|---|---|
| `webhook-id` | the delivery id (as `delivery` above) |
| `webhook-timestamp` | seconds since the Unix epoch, when this attempt was sent |
| `webhook-signature` | `v1,<base64 of HMAC-SHA-256(secret, "<webhook-id>.<webhook-timestamp>.<body>")>`; during the 24 hours after a rotation, also a second signature by the previous secret, space-separated |

To verify a delivery:

1. Take the bytes after `whsec_` and base64-decode them to get the secret.
2. Compute the HMAC over the id, the timestamp and the raw body, joined by `.`.
3. Compare it in constant time with each `v1,` signature.

Refuse a delivery whose timestamp is more than five minutes from your clock, or whose id you have already accepted. Answer `2xx` to accept. The service retries `408`, `429`, `5xx` and connection failures with growing delays for up to `notification.retry_hours`. It gives up at once on other `4xx` answers, and never follows redirects.
