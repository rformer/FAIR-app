# Verifying the audit trail offline: `fair-audit-verify`

`fair-audit-verify` checks audit trail evidence without access to the platform and without a network connection (F-002 AC-11). Auditors, assessors and the customer's own security staff can run it on any machine.

## Getting the tool
- **From the release:** download the binary for your platform (`fair-audit-verify-<release>-<os>-<arch>`) and `SHA256SUMS`, then check the binary: `sha256sum -c --ignore-missing SHA256SUMS`.
- **From the audit image** (air-gapped installs):
  ```
  docker run --rm --entrypoint /fair-audit-verify -v "$PWD:/e:ro" <audit image> verify-export /e/bundle.zip
  ```

`fair-audit-verify version` prints the release, the formats it reads and whether the FIPS 140 module is on.

## Getting an export
An export bundle holds the records matching a search, each with its Merkle proof, the signed checkpoints that cover them, the public keys and a signed manifest (F-002 AC-32 to AC-34). To make one:
- **In the web UI:** open **Audit trail**, apply the filters, then use **Export** on the same page: choose JSON lines or CSV, give a reason, and download the ZIP when it is ready. The page shows the bundle's SHA-256.
- **Through the API:** `POST /api/v1/audit/exports` with `{"filter": {...}, "format": "jsonl", "reason": "..."}` and an `Idempotency-Key`; follow `GET /api/v1/audit/exports/{id}` until `status` is `ready`; download `GET /api/v1/audit/exports/{id}/bundle` (its `Content-Digest` is the SHA-256).

Exports need `audit.export`. They include only what the requester could see and export when they asked (the manifest's `bu_scope`), up to a checkpoint closed for the export, and the manifest states the filter in words and as data. Each export is recorded in the trail (`audit.exported`, high), and so is each download (`audit.export_fetched`). Archived records are added to exports by F-002 T-18.

## Trusted keys
Checkpoints and export manifests are signed with the platform's checkpoint key (ECDSA P-256). A key is named by its key id, the SHA-256 of its public key.

Get the public keys **separately from the evidence you are checking**. Good sources are:
- the platform administrator;
- the write-once storage operator;
- a copy you kept from an earlier review.

Pass them with `-keys keys.pem`. An export bundle carries its own `keys.pem`, but that only vouches for itself. Without `-keys`, `verify-export` uses it, prints the signing key ids and warns that the result is **not pinned**. In that case, compare the printed key ids with ones you trust.

Rotated keys stay valid for the checkpoints they signed, so include every key that signed the range you are checking.

## Commands

| Command | Checks |
|---|---|
| `verify-export [-keys keys.pem] bundle.zip` | The manifest signature, every file's digest (and no unlisted files), the checkpoint chain, and each record's Merkle proof to its checkpoint. |
| `verify-archive -checkpoints checkpoints.jsonl -keys keys.pem <n>.jsonl.gz…` | Each archived segment against the checkpoints: its checkpoint is the trusted one, its name matches its content, and its records replay the chain and the Merkle root. |
| `compare -platform checkpoints.jsonl -external <siem.jsonl or directory> [-from N] [-to N]` | Whether two copies of the checkpoints agree. Use it for the platform's checkpoints against the SIEM's `audit.checkpoint` events, or against the write-once copies downloaded from `checkpoints/<instance>/`. |

### Exit codes
- **0:** the evidence is intact.
- **1:** it is not. The output names the first failing record (`FAILED at record N`) or segment (`FAILED at segment N`), or the first segment where two copies differ (`DIFFERENT at segment N`).
- **2:** usage error, an unreadable file, or input that cannot decide the question. For example, a segment whose previous checkpoint is not in the checkpoints file.

## What a result means
- **An intact export** proves the following:
  - every record in it is exactly as the platform recorded it, at the stated position;
  - every record is covered by a checkpoint signed by a trusted key;
  - the manifest's filter, BU scope, requester and reason are as signed.

  It does not prove that the filter selected every matching record. That rests on the platform, and the manifest states the filter so you can judge what is and is not included.
- **A checkpoint run that starts after segment 1** is trusted on its first statement's signature. The tool notes this. To link the run all the way back to the trail's start, include the checkpoints from segment 1.
- **`compare` reporting a difference** means one copy was changed, or is missing checkpoints. Report it to the platform's security contact with the segment number.
