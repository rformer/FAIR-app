# fair.crosswalk.v1 — relationships between two frameworks

F-013 relates the requirements of one framework version to another's, so that coverage of one shows what it means for the other. A crosswalk names its source and target versions (both imported first) and lists relationships, each one of the NIST IR 8278 set relationships:

| Relationship | Meaning | In coverage |
|---|---|---|
| `equal` | the source requirement and the target are the same | a control mapped to the source covers the target, shown as through this crosswalk |
| `superset_of` | the source requirement includes all of the target | as `equal` |
| `subset_of` | the source requirement is part of the target | partial only |
| `intersects` | they overlap | partial only |

Coverage reached through a crosswalk is always shown apart from direct mappings, with the crosswalk and the relationship; it is never counted as a direct, full mapping.

Upload it with `POST /api/v1/frameworks/imports` (kind `crosswalk`; holders of `framework.manage` at the top business unit), first as a dry run. Every source and target requirement must exist in its version; a file is imported whole or refused whole.

## JSON
```json
{
  "format": "fair.crosswalk.v1",
  "title": "NIST SP 800-171r3 to SP 800-53r5",
  "publisher": "NIST",
  "label": "2024-05",
  "source": { "family": "nist-800-171", "version": "3.0.0" },
  "target": { "family": "nist-800-53", "version": "5.1.1" },
  "relationships": [
    { "source": "03.01.01", "target": "ac-2", "relationship": "subset_of" }
  ]
}
```
Unknown members are refused; a source and target pair appears once. Limits: 50 MiB a file, 200,000 relationships in the installation.

The schema is `fair-crosswalk-v1.schema.json`; `internal/framework` is the authority and the schema is checked against it. OSCAL mapping collections are also accepted (F-013 T-07).

## CSV
A header row `source,target,relationship` (any order); the title, label and the source and target versions are given with the upload.
