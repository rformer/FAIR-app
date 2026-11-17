# fair.report.v1: reports as JSON and CSV

F-010 (reporting and export) produces each report as PDF, CSV and JSON from one document (design §1, §3.5). This page defines the JSON form and the CSV archive, for the BI tools and integrations that read them (F-010-AC-13, AC-22). The JSON Schema is [`fair-report-v1.schema.json`](fair-report-v1.schema.json).

## JSON
A report file is one JSON object:

```json
{
  "format": "fair.report.v1",
  "metadata": { ... },
  "sections": [ { "heading": "Risks", "level": 1, "blocks": [ ... ] } ]
}
```

- **Canonical.** Object members are sorted, there is no insignificant whitespace, and there are no floating-point numbers: every number in a table cell is a canonical decimal string (plain notation, no trailing zeros, `"0"` for zero), as in F-003's documents. Two equal reports are byte-for-byte equal, and the SHA-256 of the file is recorded in the audit trail (`report.generated`) and shown in the report's listing (F-010-AC-14).
- **`metadata`** states what the report is (F-010-AC-10, AC-11):
  - `run_id`, `kind` (`register`, `portfolio`, `acceptances`, `treatment`, `risk`), `title`.
  - `bu` (`id`, `name`): the business unit whose subtree the report covers; `filters`: the filters applied, by name.
  - `generated_at`, `generated_by` (the requester's display name), `data_as_of` (the moment of the consistent read), all UTC to the second.
  - `currency` (ISO 4217): every `amount` is in it.
  - `marking`: the installation's marking (`report.marking`).
  - `runs`: each analysis run a figure comes from, with its scenario, engine version, seed and input digest (F-005), so any figure can be reproduced.
  - `left_out`: how many risks the report leaves out, by reason (`not_visible`, `restricted`, `unquantified`, ...).
  - `notes`: statements about the report as a whole.
- **`sections`**: a heading (`level` 1 to 3) and its blocks. A block's `kind` is one of:
  - `paragraph` (`text`), `list` (`items`), `pairs` (`label`, `value`);
  - `table`: `id` (unique in the report), `caption`, `columns` (`key`, `title`, `type`) and `rows` (arrays of strings, one per column);
  - `chart`: `kind` (`exceedance`, `histogram`, `bars`), `title`, `alt` (the text alternative), `log` (a logarithmic amount axis), `data` (a table: the values the chart draws), `x` (the column on the x axis, or the bars' labels) and `series` (`id`: a column; `name`: its label).
- **Column types:** `text`; `amount` (a decimal, in `currency`); `number`; `percent` (a fraction: `0.25` is 25%); `date` (`YYYY-MM-DD`); `time` (RFC 3339). An empty cell means no value.
- **What a report contains** is what its requester could see when it was generated, under the platform's row-level security; restricted business units contribute only as their roll-up mode allows. A report never contains calibration records. Exposure is always a distribution (mean and percentiles), never a score.

## CSV
The CSV form is a ZIP archive:

| Entry | Contents |
|---|---|
| `NNN-<table id>.csv` | One per table, in document order, charts' data tables included |
| `manifest.json` | `{ "format": "fair.report.v1", "metadata": { ... } }`, canonical |

Each CSV file is UTF-8 with a byte-order mark. Its first line is the marking, its second the column titles, then one line per row. A text cell that a spreadsheet would run as a formula (starting with `=`, `+`, `-`, `@`, a tab or a carriage return) is prefixed with an apostrophe; the marking and titles are treated the same way. Cells of the other types are not altered.

## Versioning
A change that a reader could not ignore (a removed or renamed member, a changed meaning) is a new format, `fair.report.v2`. New optional members may be added within v1, so readers should ignore members they do not know.
