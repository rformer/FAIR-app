# Verifying a FAIR release

Every FAIR release is signed with two kinds of signature (F-012 design §3.3):
- **Keyless Sigstore signatures**, made by the release workflow in this repository. These verify against the workflow's identity and the public transparency log.
- **Release-key signatures**, made with the FAIR release key, an ECDSA P-256 key held in AWS KMS (ADR-018). Its public half ships with every release as `cosign.pub`. These signatures verify with that file alone, so they also work air-gapped.

`scripts/verify-release.sh` checks a release with both. Run it before you install or upgrade. The air-gapped bundle (F-014) carries the script and its tools.

## What you need
- `cosign` 2.5 or later.
- `releasegen`: `go run ./cmd/releasegen` from a checkout of the release tag, or the binary from the release. Set `RELEASEGEN` to the command.
- The release directory, as published or as the bundle carries it:

| File | What it is |
|---|---|
| `release-manifest.json`, `.sig` | Every image by registry digest, the RBAC hashes and the engine's validation record, signed with the release key |
| `cosign.pub` | The release public key (PEM) |
| `SHA256SUMS`, `.sig` | The digest of every file of the release, signed with the release key |
| `images/<component>/` | Air-gapped bundles only: each image with its signatures and attestations, as written by `cosign save` |

Check `cosign.pub` before you trust it. Its SHA-256 fingerprint is printed in the release notes and on the vendor's support site, and must match:

```sh
openssl pkey -pubin -in cosign.pub -outform DER | sha256sum
```

## Online
```sh
RELEASEGEN="go run ./cmd/releasegen" scripts/verify-release.sh RELEASE_DIR
```

## Offline (air-gapped)
```sh
RELEASEGEN=./releasegen scripts/verify-release.sh -offline RELEASE_DIR
```

Offline, the script reads only `RELEASE_DIR` and never contacts a registry or the transparency log (`--offline --insecure-ignore-tlog`). The release key's signature takes the place of the log.

## With fairctl (air-gap packages)
`fairctl verify` (F-014 T-11) does what `verify-release.sh -offline` does, in Go with the standard library, so it needs neither `cosign` nor `releasegen` and makes no network call:

```sh
fairctl verify -key release.pub PACKAGE_DIR
```

`-key` is the release key you obtained and checked apart from the package (its fingerprint, as above); the package's own `cosign.pub` must be that key. On top of the script's checks, `fairctl verify` requires `package-manifest.json` (`fair.airgap-package.v1`) and its signature, every file and image it lists, nothing in the directory it does not list, each image's content against its digest, and each image's SLSA provenance naming the SLSA generator's container workflow and this repository's release workflow at a `v*` tag (the same rule as F-012's admission policy). It prints the script's `ok - …` and `FAIL - …` lines, or one JSON document with `-output json` (`docs/formats/fairctl-verify.schema.json`); exit code 0 verified, 1 refused, 2 usage.

## What each step checks
1. **Release manifest:** `release-manifest.json.sig` verifies with `cosign.pub` (`releasegen verify`). This proves the list of images, digests and RBAC objects is the one the vendor released.
2. **`SHA256SUMS`:** its signature verifies, and every file it lists has the listed digest (`sha256sum -c`).
3. **For each image the manifest names:**
   - the release key's signature verifies, on the digest the manifest names and no other;
   - an SPDX SBOM attestation verifies with the release key (`--type spdxjson`);
   - a SLSA provenance attestation verifies with the release key (`--type slsaprovenance`). This provenance is the predicate of the SLSA Build Level 3 provenance made by the SLSA generator, attested again with the release key so it verifies offline.
   - Online only: a keyless signature from this repository's release workflow on a `v*` tag. Set `FAIR_RELEASE_IDENTITY`, a regular expression, to check another identity.

The script prints `ok - …` for each check. It stops at the first failure with `FAIL - …` and exit code 1.

## How it is tested
`scripts/verify-release-test.sh` (CI job `release-verify`) builds a fixture release signed with a throwaway key (`scripts/release-fixture.sh`). It then checks that `-offline` verification passes the fixture and refuses each of these tampered copies:
- `cosign.pub` replaced by another key;
- an edited manifest;
- an image signed by another key;
- a missing manifest signature.

`TestVerifyMatchesVerifyRelease` (`internal/releaseverify`, in the same CI job) runs the script and `fairctl`'s verifier over the fixture release, further tampered copies of it and synthetic releases, and requires the same verdict and the same messages from both.

## Verifying provenance with slsa-verifier (optional)
Online, the SLSA generator's keyless provenance can also be checked with `slsa-verifier`:

```sh
slsa-verifier verify-image IMAGE@DIGEST --source-uri github.com/rformer/FAIR-app --source-tag vX.Y.Z
```
