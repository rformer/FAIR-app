# fair.framework.v1 — a control framework without an OSCAL publication

F-013 (control framework library) imports frameworks as data. Where a framework is published in NIST OSCAL, import the OSCAL catalog. Use this format for the others, for example frameworks whose text your organization licenses (ISO/IEC 27001, the SOC 2 trust services criteria, CIS Controls): the platform ships none of that text.

Upload it with `POST /api/v1/frameworks/imports` (kind `simple`; holders of `framework.manage` at the top business unit), first as a dry run. A file is imported whole or refused whole, with every problem named by JSON pointer (JSON) or row and column (CSV).

## JSON
```json
{
  "format": "fair.framework.v1",
  "family": { "key": "iso-27001", "title": "ISO/IEC 27001", "publisher": "ISO/IEC" },
  "version": { "label": "2022", "title": "ISO/IEC 27001:2022", "published": "2022-10-25" },
  "requirements": [
    { "identifier": "A.5", "title": "Organizational controls" },
    { "identifier": "A.5.1", "label": "5.1", "title": "Policies for information security", "parent": "A.5" }
  ]
}
```
- `family.key` is the framework's stable key: every version of the framework uses the same key, so the platform can compare versions and move mappings between them. Lower-case letters, digits and hyphens, at most 63.
- `version.label` is unique within the family.
- Each requirement has an `identifier`, unique within the version (letters, digits and `. _ : ( ) -`, at most 100 characters, starting with a letter or digit), and a `title`. `label` is how people cite it; `statement` is its text and may be left out where the text is not licensed to the platform. `parent` names another requirement of the same version; parents form a tree.
- Unknown members are refused. Withdrawn requirements are OSCAL's to describe: a simple file lists the current requirements, and the platform compares it with the previous version of the family to find what was added, changed or withdrawn.
- Limits: 50 MiB a file, 20,000 requirements a version.

The schema is `fair-framework-v1.schema.json`; `internal/framework` is the authority and the schema is checked against it.

## CSV
A header row naming the columns, in any order: `identifier` and `title` (required), `label`, `statement`, `parent`. The family and version (key, title, label, published) are given with the upload, not in the file. UTF-8, a byte-order mark allowed.

```csv
identifier,title,parent
CC6,Logical and Physical Access Controls,
CC6.1,Logical access security software,CC6
```
