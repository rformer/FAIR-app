# ADR-011 Audit trail integrity: a hash chain with signed Merkle segment checkpoints
Status: Accepted (Robert Former, 2026-11-04; F-002 design D1, T-01)
Date: 2026-11-04

## Context
Constitution S4 requires a tamper-evident, hash-chained audit trail. F-002 also requires two further things:
- **Signed checkpoints copied outside the platform** (F-002-AC-07, AC-09, AC-10). This catches rewrites and truncation by someone who controls the database.
- **Evidence exports of any filtered set of records** that an auditor can verify offline (AC-11, AC-32). An example is one user's records for a year.

A plain hash chain detects any change to a contiguous range. But it can prove a *filtered* record against a checkpoint only if the export also ships the leaf hash of every record in between, which is about 32 bytes per record of the whole range. That is gigabytes for a year's export of a busy instance.

A full transparency log would also work: one RFC 9162 tree over all records, with consistency proofs between tree heads. But it needs consistency proofs and tree-head bookkeeping that F-002 does not need while checkpoints are chained and copied outside the platform.

## Decision
Records are hash-chained, and every 15 minutes the chain is cut into a **segment** that a signed checkpoint covers with a Merkle root. The primitives live in `internal/audit/integrity`. They use only the standard library, with SHA-256 and ECDSA P-256 from the FIPS 140 module, so `fair-audit-verify` can use them without network access or other dependencies.

- **Body.** A record's body is its event serialized once: JSON with object keys sorted, no insignificant whitespace, no HTML escaping, and numbers kept exactly as given. The trail stores and exports these bytes. Verifiers hash them as they are and never re-serialize.
- **Leaf.** `leaf = SHA-256(0x00 ‖ body)`. This is the RFC 9162 leaf hash.
- **Chain.** `chain(seq) = SHA-256(0x01 ‖ chain(seq−1) ‖ seq as 8 bytes, big-endian ‖ leaf)`, with `chain(0) = SHA-256("fair-audit-v1" ‖ instance id)`.
  - A chain input is always 73 bytes. A Merkle interior-node input (`0x01 ‖ left ‖ right`) is always 65 bytes. So the shared prefix byte cannot make one be taken for the other.
- **Segment root.** The RFC 9162 Merkle tree hash over the segment's leaves. For an empty segment this is `SHA-256("")`.
- **Checkpoint statement.**
  - Its fields are `{v, instance, segment, seq_from, seq_to, merkle_root, chain_hash, prev_checkpoint_hash, issued_at, key_id}`, serialized as bodies are. Hashes are lowercase hex, and `issued_at` is RFC 3339 UTC.
  - An empty segment has `seq_to = seq_from − 1`.
  - Segments are numbered from 1, and each `seq_from` is the previous `seq_to + 1`.
  - `prev_checkpoint_hash` is `SHA-256` of the previous statement's bytes, or `chain(0)` for segment 1.
- **Signature.** ECDSA P-256 over `SHA-256(statement)`, ASN.1 encoded. `key_id` is the hex SHA-256 of the key's PKIX encoding, the same form as posture exports.
- **Proofs.**
  - A record in an export is proven by its body, its RFC 9162 inclusion path within its segment, and the signed checkpoint chain.
  - A contiguous range is proven by replaying the chain between two checkpoints.

## Consequences
- Proofs for filtered exports grow with log₂(segment size) per record, plus one statement per 15 minutes covered (about 35,000 a year).
- The checkpoint chain alone does not prove consistency between two *divergent* copies. The external copies (the SIEM stream, plus write-once storage in SaaS) do that: `fair-audit-verify compare` reports the first segment where they differ.
- Moving to a full transparency log later needs no change to bodies or leaves, because the leaves are already RFC 9162 leaf hashes.
- The format is versioned (`v: 1`, `fair-audit-v1`). A change of algorithm means a new version with a new genesis. Records already written keep their version.
