# fair.risk.v1: risk data export and import

F-003 T-11 (F-003-AC-24, AC-25; design §6.5). A `fair.risk.v1` file carries scenarios, library entries (assets, asset groups, threat communities, loss profiles, and reference classes since F-004 T-03) and controls between FAIR instances, or out of one for safekeeping. Its JSON Schema is [`fair-risk-v1.schema.json`](fair-risk-v1.schema.json).

## Getting one

`GET /api/v1/risk/export` with any of:

- `scenarios`, `library`, `controls`: ids, comma-separated, at most 1,000 of each;
- `bu`: everything you can see in that BU's subtree (`archived=true` also includes archived items).

The file holds only what you can see. It is returned in canonical form (below), and the `X-Fair-Digest` header carries its SHA-256. Every export is recorded in the audit trail (`risk.exported`, with the counts and the digest).

## Contents

```json
{
  "format": "fair.risk.v1",
  "currency": "USD",
  "exported_at": "2026-11-09T10:00:00Z",
  "scenarios": [ { "id": "…", "kind": "scenario", "versions": [ { "version": 1, "digest": "…", "change_note": "…", "document": { … } } ] } ],
  "library":   [ { "id": "…", "kind": "asset", "versions": [ … ] } ],
  "controls":  [ { "id": "…", "kind": "control", "versions": [ … ] } ],
  "pinned":    [ { "kind": "threat_community", "id": "…", "version": 2, "digest": "…", "document": { … } } ]
}
```

- **Items** have every version, from 1, in order. Each `document` is a scenario, library or control document (JSON Schemas `urn:fair:risk:scenario:1` and `urn:fair:risk:library:1`, in `internal/risk/model/schema`), and `digest` is the SHA-256 of its canonical form.
- **`pinned`** holds the versions the items pin that are not otherwise in the file, copied from the scenarios' and asset groups' pin rows. They include versions you can read only through a scenario, and an asset group's members. With them the file is self-contained.
- **`currency`** is the exporting installation's currency of every amount, or `null` if none was set.

## Canonical form

Canonical form is the subset of RFC 8785 (JCS) the platform uses:

- members are sorted by their names' UTF-16 code units;
- there is no insignificant whitespace;
- strings are escaped as JCS requires;
- numbers appear only as integers.

Fractions are canonical decimal strings, such as `"0.25"` or `"1500"`. A file's digest and each document's digest are SHA-256 over this form, written in lowercase hex.

## Importing one

`POST /api/v1/risk/imports` with `{"bu_id": "…", "file": { … }}` imports everything into one BU; add `?dry_run=true` to try it without keeping anything.

- **Permissions:** you need the edit permission at the BU for every kind the file holds.
- **Currency:** when the file holds amounts, its currency must be the installation's.
- **Checks before anything is written:** every document is validated, and must match its digest. Every pin must resolve to a version in the file or to a version you can already see. Every problem is listed (422) and nothing is written.
- **Items:** each item becomes a new entry with its versions replayed in order. Version numbers and change notes are kept, pins are re-pointed to the new entries, and you are each version's author.
- **Pinned versions:** a pinned version you already have, with the same id, version and digest, is used as it is. Otherwise it becomes a new entry at version 1.
- **All or nothing:** the import runs in one transaction, and if anything fails nothing is kept. It is recorded as `risk.imported` (with the source file's digest) and as each created item's event.
- **Size:** a file is at most 4 MiB, less 64 KiB for the request around it.

## Accepted estimates (F-004)

An estimate accepted from an estimate request carries an `elicitation` member: the request, the method (`single`, `equal`, `calibration` or `own`), the confidence, and each answer used with its estimator (id and name at the time), revision, weight, values and calibration at the time. One of its sources has type `elicitation` and names the request. The provenance is part of the document and its digest, so it travels with the file and is imported as it is; the request and the calibration records it refers to stay in the installation they came from.
