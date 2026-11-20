# Releasing FAIR

A release is a signed `vX.Y.Z` tag. `.github/workflows/release.yml` builds and checks everything from the tag and publishes only when every check has passed (F-012 design §3.4).

## Cutting a release
1. On `main`, with CI green, tag the commit: `git tag -s vX.Y.Z -m "FAIR vX.Y.Z"`, then `git push origin vX.Y.Z`. Use a pre-release suffix (`vX.Y.Z-rc.1`) for a candidate; GitHub marks those as pre-releases.
2. Watch the release run. Nothing is published until the `publish` job; a failure in an earlier job leaves only staged images, which are never pulled by customers.
3. When `verify` has passed, check the release notes on the GitHub release and announce the release key's fingerprint with them (`openssl pkey -pubin -in cosign.pub -outform DER | sha256sum`).

## What the pipeline does
| Job | What it checks or makes |
|---|---|
| `plan` | The tag is a semantic version. It picks the repositories (`ghcr.io/<owner>/staging/` while checking, `ghcr.io/<owner>/` on publish) and the signing key. A real release without the KMS release key fails here. |
| `reproducible` | Every image is built twice on two runners, and the digests must be equal (AC-10). |
| `build` | Each image goes through every image gate (`.github/actions/image`: hardening, SBOM completeness, vulnerability scan with the accepted findings). It is pushed by digest to staging, signed keylessly, and its SBOM is attested. |
| `provenance` | SLSA Build Level 3 provenance for every staged image, from the SLSA generator. |
| `manifest` | `release-manifest.json` (images by digest under the release repository, RBAC hashes, the engine's validation record), `component-definition.json` (OSCAL), the OpenAPI bundle, `fair-audit-verify` for every platform, the SBOMs. |
| `release-checklist` | `profilegen release-check -online`: pins, profile packages rebuilt byte for byte, the CMMC rule re-confirmed against the eCFR, no open external pen-test findings, the engine's validation passed. |
| `bench` | The benchmark gate (`bench.yml`, as on `main`). |
| `notes` | `releasegen notes` since the previous release: migrations, profile packages, setting definitions, the permission catalog, security events added, ADRs, and pull requests labelled `security`. |
| `sign` | `release-sign.yml` verifies each staged image's keyless signature, SBOM and provenance. It then signs and attests them again with the release key, signs the profile packages, the manifest and `SHA256SUMS`, and writes `cosign.pub`. |
| `publish` | Copies the images with their signatures and attestations from staging to the release repository (`cosign copy`), then creates the GitHub release with every file. |
| `verify` | `scripts/verify-release.sh` on what was published, online, and offline as an air-gapped bundle carries it. |

The upgrade test (F-012 T-08) joins the gates before `sign`.

## The release key
The release key is an ECDSA P-256 key in AWS KMS in the shared-services account (ADR-018). It is set up by F-012 T-12, with the repository variables `FAIR_RELEASE_KMS_KEY`, `FAIR_RELEASE_ROLE_ARN` and `FAIR_RELEASE_REGION`. The role it is used through can only `kms:Sign` with that key, and only for this repository's release workflow on a `v*` tag. GitHub holds no credential for it.

## The dry run
The tag `v0.0.0-test` runs every job and publishes a test release:
- images under `ghcr.io/<owner>/test/`;
- the GitHub release as a draft, visible to collaborators only.

While the KMS key does not exist, the dry run signs with a throwaway key made in the `sign` job. That key is discarded with the job and never written to the public transparency log. No other tag may use a test key.

To run it again, delete the draft release and the tag, then push the tag again:

```sh
gh release delete v0.0.0-test --yes
git push origin :refs/tags/v0.0.0-test
git tag -f v0.0.0-test && git push origin v0.0.0-test
```

## Retention
Published releases and their images are kept for at least 24 months (AC-12, OQ9). Do not delete releases or the packages under `ghcr.io/<owner>/fair-*`.
