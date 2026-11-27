# ADR-020 Bundled object store: versitygw, rebuilt from source with the FIPS module
Status: Accepted (Robert Former, 2026-11-26; F-014 T-03, with the F-014 design approved 2026-11-26)
Date: 2026-11-26

## Context
The audit trail and the reports keep objects in S3-compatible storage through `internal/objstore` (ADR-012): archived segments, write-once checkpoint copies and evidence exports in the audit store and the WORM copy, report files in the report store. Every mode needs a store; self-hosted and air-gapped installations may bring their own or use one the chart bundles (ADR-005's dependency table). ADR-012 chose versitygw as the test server and left the bundled store to F-014.

`internal/objstore` requires, and refuses at startup otherwise:
- for the audit store and the WORM copy, a bucket with versioning and Object Lock (`CheckBucket`, `ErrNotWORM`); writes locked in compliance mode only, with a governance lock reported as no retention (`RetainedUntil`); legal holds (`SetLegalHold`, `LegalHold`); reads, digests and deletes of a named version; listings of every version;
- for the report store, a versioned bucket (`CheckVersioned`);
- TLS 1.2 or later, credentials from files, `Content-MD5` on writes (ADR-012).

The bucket is created by the installer (F-014 design §3.6; `objstore` gains `CreateBucket(lock bool)`), today by the contract tests themselves.

The selection criteria were fixed by F-014 OQ3: compliance-mode Object Lock, legal holds, versioning, TLS 1.2 or later with FIPS-capable cryptography, a licence that allows redistribution (no AGPL), maintained, and images we can rebuild and sign.

## Facts rechecked at the pinned version (2026-11-26)
- **Pinned version:** `scripts/s3-test-server.sh` pins `versity/versitygw:v1.9.0` by digest (`sha256:eb7f786f…fd3fdc7`; released 2026-10-13, ADR-012). CI's test job starts it and runs the `internal/objstore` contract tests against it (`.github/workflows/ci.yml`, `FAIR_TEST_S3=1`).
- **Licence:** Apache License 2.0. The `LICENSE` file at the `v1.9.0` tag of `github.com/versity/versitygw` was read on 2026-11-26 (web check); T-07 re-checks it at the commit pinned in `deploy/bundled/sources.json`.
- **Language and toolchain:** the module `github.com/versity/versitygw` at `v1.9.0` declares `go 1.26.0`, our toolchain (its `go.mod`, web check 2026-11-26), so it can be rebuilt with `GOFIPS140=v1.0.0`. Whether every cryptographic path (TLS, SigV4 verification) then runs in the FIPS module, and whether the build needs cgo, are not established from `go.mod`; T-07 confirms both with the image's FIPS report.
- **Capabilities against `internal/objstore`:** started as the test server runs it (the POSIX backend with `--versioning-dir`, TLS by `--cert`/`--key`), v1.9.0 passes `TestContractWORM` (`CheckBucket`, compliance retention, a governance lock reported as not compliance, legal holds blocking deletes until released, version deletes after retention, delete markers not listed as objects), `TestContractRefusesAPlainBucket` (`ErrNotWORM`) and `TestContractVersionedBucket` (`CheckVersioned`). Its upstream README does not describe Object Lock; the evidence for it is these tests, which is why every release's bundled image must pass them (Consequences).
- **Accounts:** the tests run as the gateway's root account. The upstream README describes its flat-file accounts (`--iam-dir`) as being "for testing". Per-service accounts limited to their bucket (audit store, WORM copy, report store) are therefore not yet established; T-07 must confirm an account backend fit for production, or this ADR is amended before the bundled store ships.
- **Scaling:** the upstream README describes the gateway as stateless, with several instances able to serve one backend behind a load balancer. The bundled configuration does not rely on this (one replica, below).

## Options considered
| Option | Licence | Assessment |
|---|---|---|
| versitygw (chosen) | Apache-2.0 | Written in Go, so rebuilt with the FIPS module its TLS and request signing can run in it; a single binary; its POSIX backend already passes the `internal/objstore` contract tests (ADR-012) |
| SeaweedFS | Apache-2.0 | Viable; passed ADR-012's probe (compliance retention, no governance bypass, legal holds, version deletes); more components to run and harden. The fallback if versitygw falls short |
| MinIO | AGPL-3.0 | Licence fails the redistribution criterion; no published images any more (ADR-012) |
| Garage | AGPL-3.0 | Licence fails; no Object Lock |
| Ceph RGW through Rook | Not recorded (not needed to reject it) | Privileged OSDs fail restricted pod security; heavy for a bundled dependency |
| RustFS | Apache-2.0 | Passed ADR-012's probe, but written in Rust, with no path to the FIPS module |

The licences of the rejected candidates are as the design records them (F-014 design §3.3) and were not re-checked here.

## Decision
- **The bundled object store is versitygw**, rebuilt from upstream source pinned by commit and checksum in `deploy/bundled/sources.json` (checked by `pincheck`), built with `GOFIPS140=v1.0.0` through the image matrix (`.github/actions/image`): its own target, SBOM, SLSA provenance, and both the keyless and the release-key signatures (design §3.3, D-OQ3). The upstream image is not shipped.
- **Configuration:** the POSIX backend with versioning and Object Lock, on an encrypted persistent volume (the storage-class encryption attestation of F-015's checks), one replica, TLS 1.2 or later with a certificate from the installation CA (or the customer's issuer), hardened like every platform workload (non-root, read-only root filesystem, capabilities dropped, default-deny network policy, restricted pod security).
- **Buckets and credentials:** `fairctl` creates the audit store and WORM copy with Object Lock and the report store with versioning, and generates one account per service, limited to its bucket, delivered only to the mode's key store (design §3.6). The root credential is not given to any service.
- **Gate:** the bundled image must pass the `internal/objstore` contract tests in the release pipeline (T-07), so a version that stops enforcing compliance retention, legal holds or versioned deletes cannot ship.
- **Brought stores** remain supported: AWS S3 or any store that passes `CheckBucket` / `CheckVersioned` and the preflight's `audit_store`, `report_store` and `worm_copy` checks.

## Limits (D-OQ12; accepted for v1)
- **Software WORM only.** The lock is enforced by the gateway; someone with access to the volume or the node can alter or delete the files beneath it. The audit trail's integrity does not rest on the store alone: checkpoints are signed and their copies verified (ADR-011), so such tampering is detected, not prevented.
- **Single replica.** The bundled store is not highly available; it is made durable by backups that keep retention and holds (ADR-022).
- Customers needing hardware-enforced WORM or high availability bring their own store. These limits are stated in the sizing and hardening guides and the responsibility matrix (design §3.3, §3.13).

## Consequences
- versitygw updates are reviewed like minio-go's (ADR-012): changelog and advisories, a new pinned source, the contract tests against the rebuilt image.
- If T-07 finds that versitygw cannot carry production accounts limited to a bucket, or that its cryptography cannot run in the FIPS module, the decision is reopened with SeaweedFS as the fallback, by amendment.
- Upstream FIPS rebuilds may lag upstream releases (design §14 risks); security fixes are rebuilt from the patched source, never by shipping the upstream image.
