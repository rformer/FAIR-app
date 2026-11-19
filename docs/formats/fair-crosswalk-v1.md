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

## OSCAL mapping collections
An OSCAL 1.2.3 `mapping-collection` (JSON) is validated against the pinned schema and read as a crosswalk. Its resources are named by `href`, so the upload names the versions it relates (`source_family`, `source_version`, `target_family`, `target_version`); `title` and `label` default to the collection's metadata title and version. Each map relates every source to every target: `equal-to` and `equivalent-to` are `equal`, `subset-of` is `subset_of`, `superset-of` is `superset_of`, `intersects-with` is `intersects`; `no-relationship` maps are left out. Maps of statements, and other relationships, are refused by pointer. Nothing a collection links to is fetched.

## How relationships derive coverage
A relationship reads "source *relationship* target". A requirement R is reached from R' (in the other version) as "R' *relationship* R", inverting `subset_of` and `superset_of` when R is the crosswalk's source. Satisfying R' reaches R fully only when R' `equal` R or R' `superset_of` R; `subset_of` and `intersects` reach it partly. Coverage reports what a crosswalk reaches apart from direct mappings, and never as in place (F-013-AC-11).

## Checks at import
Both versions must be imported and every relationship must name a requirement of its version; otherwise the whole file is refused, each problem by pointer (`/relationships/<i>/source` or `/target`; at most 100 listed). A crosswalk between the same versions with the same label is refused as a repeat. A retired crosswalk stays readable and no longer derives coverage.
