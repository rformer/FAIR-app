# fair.preflight-report.v1

The report of a preflight run (F-014 T-13; AC-15, AC-18, AC-21; design §3.7). `fairctl preflight` prints it (text, or `-output json`: `fairctl-preflight.schema.json`), and `fairctl install` and `upgrade` record it in `install.preflight` once the database exists. Schema: `fair-preflight-report-v1.schema.json`. Produced by `internal/preflight`.

## Fields
| Field | Meaning |
|---|---|
| `format` | `fair.preflight-report.v1` |
| `release` | The release checked (the verified release manifest's) |
| `purpose` | `check` (`fairctl preflight` alone), `install` or `upgrade` |
| `mode` | `saas`, `self-hosted` or `air-gapped` |
| `profile` | The posture profile of the decisions (the FIPS hard floor follows its family) |
| `started`, `finished` | RFC 3339, UTC |
| `result` | `passed` (no failure), `passed_with_overrides` (every failed finding overridden), `refused` (a failed finding not overridden, or a check that could not run) |
| `checks[]` | Every check of the registry, in its order: the drift checks (`source: drift`, F-015's catalog, also run by the drift scanner) then the preflight-only checks (`source: preflight`) |
| `checks[].result` | `passed`, `failed`, `overridden` (every finding overridden), `error` (could not run; never passed; `error` says why) or `not_applicable` (not in this mode) |
| `checks[].findings[]` | `subject` (the object, as the scanner names it), `severity`, `controls` (800-53r5), `detail` (what was found, a JSON object; any value that looks secret is `[redacted]`), `remediation`, `hard_floor` (no override in any mode, AC-19), `overridden` |
| `checks[].observations[]` | How a passing subject was assessed: `verified` or `attested` ("attested, not verified") |
| `overrides[]` | Each override given (check, subject, reason), whether it `applied`, and otherwise its `refusal`: `matches no failed finding`, `SaaS allows no override`, `on the hard floor: no override` |

## Rules
- A drift check's findings are exactly what the drift scanner reports for the same objects: the same code (`checks.Catalog`) reads the cluster with the release's rendered objects applied over it (`objreader.Overlay`). `TestPreflightMatchesDrift` holds them equal.
- Hard floor by finding (design §3.7): `tls_endpoints` with plaintext, no TLS 1.2+ handshake, or TLS 1.0/1.1 accepted; `node_fips` under a FedRAMP- or CMMC-derived (or unknown) profile; `plaintext_secrets` with key material in plain values or arguments. The preflight-only checks (T-14, T-15) add theirs.
- An override applies to its check's failed findings of its subject that are not on the hard floor, never in SaaS. Overrides become deployment exceptions when install records them (T-16).

## Stored form and digest
The stored form is the report's compact JSON encoding (fields in the order above, detail keys sorted). The digest is the SHA-256 of the stored form, in hex, kept beside it with the run identifier (a version 4 UUID), release, purpose, times and result (`install.record_preflight`). A report any of whose strings looks secret (`installer.LooksSecret`) is refused before it is printed or stored.
