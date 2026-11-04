# ADR-012 Object storage client: minio-go, tested against versitygw
Status: Accepted (Robert Former, 2026-11-04; F-002 T-08)
Date: 2026-11-04

## Context
The audit trail keeps three kinds of object in S3-compatible storage (F-002 design §6.3, §6.6, §6.7, D4):
- archived segments;
- write-once copies of checkpoints, required in SaaS;
- evidence export bundles.

It needs:
- writes under Object Lock in compliance mode;
- legal holds (AC-29);
- reads, read-back digests, and deletes of a specific version;
- listings of every version.

Every deployment mode uses a different store: the vendor's cloud store in SaaS, and the customer's own or a bundled store when self-hosted or air-gapped. So the client must work with S3-compatible stores in general, not only AWS. Connections use TLS 1.2 or later, credentials come from files, and hashing and signing run in the FIPS 140 module.

Three clients were weighed:
- **minio-go**: a mature S3-compatible client;
- **an own minimal SigV4 client**: standard library only, as SCIM and the PDF writer are;
- **the AWS SDK for Go v2**: complete, but the largest dependency tree, and less proven against other S3 stores.

Facts as of 2026-11-04 (module proxy and the module's go.mod):
- **Version:** `github.com/minio/minio-go/v7` v7.4.1, released 2026-10-12, declares `go 1.26.0`, our toolchain.
- **Direct dependencies:** `cespare/xxhash`, `dustin/go-humanize`, `google/uuid`, `klauspost/compress`, `klauspost/crc32`, `minio/crc64nvme`, `minio/md5-simd`, `rs/xid`, `tinylib/msgp`, `zeebo/xxh3`, `go.yaml.in/yaml/v3`, `golang.org/x/crypto`, `golang.org/x/net` and `gopkg.in/ini.v1`.
- **Existing dependencies raised by minimum version selection:** `santhosh-tekuri/jsonschema/v6` (v6.0.2 → v6.0.3), `klauspost/compress` (v1.18.7 → v1.19.2) and `google.golang.org/protobuf` (v1.36.11 → v1.36.12).
- **Signing:** SigV4 signatures use Go's `crypto/hmac` and `crypto/sha256`, so in our binaries they run in the FIPS module. `golang.org/x/crypto` is linked for minio-go's server-side-encryption key derivation (argon2), which F-002 does not use.

## Decision
Use **minio-go v7.4.1**, wrapped in `internal/objstore`, so it can be replaced.

`internal/objstore` constrains it:
- **TLS:** TLS 1.2 is the minimum, with an optional CA file. Plaintext is allowed only when `FAIR_ENV=development`.
- **Credentials:** read from files (`<PREFIX>_ACCESS_KEY_FILE`, `<PREFIX>_SECRET_KEY_FILE`), never from the environment.
- **Bucket check:** `CheckBucket` refuses a bucket without versioning and Object Lock (`ErrNotWORM`), so a store that cannot keep records write-once is found at startup.
- **Locking:** objects are locked only in compliance mode (no governance bypass). Every read, delete and hold names a version, so a delete never just hides an object behind a delete marker.
- **Write checksum:** writes send `Content-MD5`. S3 requires a body checksum for Object Lock writes, and MD5 is the one every S3-compatible store accepts; minio-go sends `x-amz-checksum-*` only for multipart or trailer uploads, and trailers are unevenly supported. MD5 here guards transport only, which Go's FIPS mode (`fips140=on`) permits. The trail's integrity rests on SHA-256 (ADR-011), and archives are read back and digested with SHA-256 after they are written (`Digest`).

**Test server: versitygw.** MinIO no longer publishes container images: quay.io refuses anonymous pulls, and Docker Hub's `minio/minio` is gone. LocalStack's S3 now requires a licence, and Zenko CloudServer needs extra configuration. A probe with minio-go found that RustFS, SeaweedFS and versitygw all enforce compliance retention, refuse a governance bypass, honour legal holds and version deletes. versitygw was chosen:
- it is Apache-2.0;
- it is a single binary built for S3 API compatibility;
- it has a POSIX backend with versioning and Object Lock;
- it takes TLS through `--cert`/`--key`.

It is pinned as `versity/versitygw:v1.9.0` by digest (released 2026-10-13), and `scripts/s3-test-server.sh` starts it with a throwaway CA. It is test infrastructure only, not shipped. The store bundled for self-hosted and air-gapped installs is F-014's decision.

## Consequences
- **Updates:** minio-go updates are reviewed like the SAML and WebAuthn libraries' (ADR-009, ADR-010): changelog and advisories, then the contract tests. The SBOM covers the new modules.
- **CI:** the contract tests (`internal/objstore`, `FAIR_TEST_S3=1`) run in CI's test job against versitygw. A store adopted later (the bundled one, or a customer's) should pass the same tests.
