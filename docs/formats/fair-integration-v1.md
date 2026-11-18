# fair.integration.v1: records for an integration

F-011 (integrations and automation inputs). A batch of records sent to an integration's batch endpoint, `POST /api/v1/imports/{integration}/batches`. Customer automation sends batches as a service account holding `integration.push`, administrators upload them, and the platform's connectors submit them. The JSON Schema is [`fair-integration-v1.schema.json`](fair-integration-v1.schema.json). The platform's typed validation (`internal/integration`) is the authority, and the schema is tested against it.

Nothing in a batch changes an analysis by itself. Valid records become proposed changes that a person accepts (F-011 R-03), except loss events, which are stored as data.

## The batch
```json
{
  "format": "fair.integration.v1",
  "complete": true,
  "records": [
    {"kind": "asset", "external_id": "CMDB-1001", "bu": "CLAIMS", "name": "Claims platform", "asset_type": "application",
     "value": {"min": "250000", "ml": "1500000", "max": "4000000", "confidence": "0.9", "basis": "Replacement cost"}}
  ]
}
```
| Member | Meaning |
|---|---|
| `format` | Always `fair.integration.v1`. |
| `complete` | Optional; `true` when the batch holds every record of the source. Linked records it does not hold are then proposed for archiving (assets, groups) or archived (loss events). |
| `records` | At most 10,000 records. The body is at most 20 MiB. |

A batch is refused whole only when it is not this format (not JSON, an unknown member, the wrong `format`, too many records). Otherwise each record is checked on its own, and a refused record is reported with:
- its position `n` (1-based);
- its `external_id`;
- the JSON `pointer` of the problem and a message.

The valid records go on. A record's `external_id` may appear once in a batch; later ones are refused.

An integration takes records of its input kind only:

| Integration kind | Record kinds |
|---|---|
| `assets` | `asset`, `asset_group` |
| `loss_events` | `loss_event` |
| `risks` | `risk` |
| `control_status` | `control_status` |

## Records
Every record has `kind` and `external_id`: the source's stable identifier, at most 256 characters. A record is matched to a platform record by its integration and external ID only, never by name. `bu` names a business unit inside the integration's subtree by its code or id. Unknown members are refused, so a rating or score column cannot slip in. Text is trimmed and must not hold control characters. Single-line fields hold no line breaks, and text that looks like a secret is refused. Decimals may be strings or JSON numbers and are stored canonical (F-003's `canon.Decimal`).

| Kind | Members |
|---|---|
| `asset` | `bu`, `name`, `asset_type`, optional `description` and `value` (a range: `min`, `ml`, `max`, optional `confidence` above 0 and below 1, optional `basis`) |
| `asset_group` | `bu`, `name`, `members` (external IDs of assets of the same integration, 1 to 1,000, each once), optional `description`, `value` |
| `loss_event` | `bu`, `occurred_on` (a date), `event_type` (the customer's category, at most 100 characters), optional `description` (at most 2,000) and `amounts` by FAIR form of loss (`productivity`, `response`, `replacement`, `fines_judgments`, `competitive_advantage`, `reputation`) in the installation currency, at least 0, at most 18 digits before the point and 6 after |
| `risk` | `bu`, `title`, optional `description`, `owner` (an email address), `category` (a category's name). No exposure, likelihood, impact or rating: imported risks are unquantified until analysed (P1) |
| `control_status` | `status` (`in_place`, `partial`, `planned`, `not_in_place`), `assessed_on` (a date), optional `note`, and `control` (the platform control's id) the first time the external ID is sent |

Each valid record is stored in its normalized form with the SHA-256 digest of its canonical JSON. A record whose digest matches what the platform already has, or what a reviewer last rejected, proposes nothing.

## CSV
An integration's mapping lets it take CSV (UTF-8, optionally with a byte-order mark, a header row). Every row is a record of the integration's first record kind (`asset` for an asset integration). The mapping is declarative:
```json
{
  "columns": {"Event ID": "external_id", "Unit": "bu", "Date": "occurred_on", "Category": "event_type", "Response cost": "amounts/response"},
  "values": {"event_type": {"PHISH": "Phishing", "FRAUD": "Payment fraud"}},
  "defaults": {"bu": "CLAIMS"},
  "separator": ";"
}
```
- **`columns`** maps a header to a field. Nested fields are paths: `value/min`, `amounts/response`. `members` is split on `separator` (default `;`). Every mapped column must be in the header; other columns are ignored.
- **`values`** translates a field's source values. A value it does not list is kept as it is.
- **`defaults`** fills fields a row leaves empty. `external_id` is never defaulted.
- **Refusals:** blank rows are skipped. A refused row is reported with its data row number, the field's pointer and the column it came from.
- **No expressions:** a cell is never evaluated, so `=1+1` is text, and as an amount it is refused.
