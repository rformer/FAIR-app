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
| `build` | Every image the chart can run: the platform's services, `fairctl` (the chart's hooks) and the bundled dependencies (`postgres`, `nats`, `openbao`, `versitygw`, `keycloak`; F-014 T-07). Each image goes through every image gate (`.github/actions/image`: hardening, SBOM completeness, vulnerability scan with the accepted findings). It is pushed by digest to staging, signed keylessly, and its SBOM is attested. |
| `provenance` | SLSA Build Level 3 provenance for every staged image, from the SLSA generator. |
| `manifest` | `release-manifest.json` (images by digest under the release repository, RBAC hashes, the engine's validation record, and the `mirrors` section: each mirrored third-party copy with its source and the publisher identity it was verified against, F-014 T-10), `component-definition.json` (OSCAL), the OpenAPI bundle, `fair-audit-verify` for every platform, the SBOMs. The third-party images (`deploy/third-party-images.json`) are verified against their publishers' exact identities and copied by digest to staging's `mirror/<name>` (`mirror.json`). The fleet's manifests (`releasegen fleet`, [fleet.md](fleet.md)), which name those copies, are pushed to staging as the OCI artifact `fair-manifests:<version>` and signed keylessly; `fleet.json` names it. |
| `chart` | `releasegen chart`: the `fair-platform` chart rendered from the reference manifests (F-014 T-06), every image by digest under the release repository (`-registry`). `releasegen push-chart` pushes it with the Helm SDK to staging's `charts/fair-platform:<version>`, and the chart is signed keylessly. `chart.json` names it in staging and in the release repository. |
| `release-checklist` | `profilegen release-check -online -chart`: pins, profile packages rebuilt byte for byte, the CMMC rule re-confirmed against the eCFR, no open external pen-test findings, the engine's validation passed. Every combination of the chart's switches renders and passes F-015's checks, and names only the manifest's images, mirrors and RBAC (F-014 T-09). |
| `bench` | The benchmark gate (`bench.yml`, as on `main`). |
| `upgrade` | The upgrade test (`upgrade.yml`, `TestUpgradeFromPreviousReleases`). Each earlier release (the newest patch of the two newest minor releases; before `v0.1.0`, the baseline commit in `db/upgrade/baseline`) seeds its data through its own services. This release migrates a copy of that data and checks it. Then both releases' services must start and answer on the upgraded schema (AC-13, AC-21). |
| `notes` | `releasegen notes` since the previous release: migrations, profile packages, setting definitions, the permission catalog, security events added, ADRs, and pull requests labelled `security`. `scripts/release-window.sh` works out the upgrade window (`upgrade_from`, the minor line's first release date) and fetches the window's published notes for the air-gap package. |
| `sign` | `release-sign.yml` verifies each staged image's keyless signature, SBOM and provenance. It then signs and attests them again with the release key, signs the fleet artifact (after checking its keyless signature) and the mirrored third-party images with the release key, signs the chart (after checking its keyless signature), signs the profile packages, the manifest and `SHA256SUMS`, and writes `cosign.pub`. It then builds the air-gap package (`scripts/airgap-package.sh`, [the format](../formats/fair-airgap-package-v1.md)). Zarf (v1.0.1, pinned by digest) pulls every image of the manifest and its mirrors, with their signatures and the release's attestations, from staging into its OCI layout. `zarf package sign` signs that with the release key. `releasegen package build` assembles the package directory. `releasegen sign -any` signs `package-manifest.json` and `SHA256SUMS`. `fairctl verify` checks the result. `cosign sign-blob --key` signs the tarball. The package is built in this job because only this workflow can reach the release key, and the dry run's throwaway key exists only in this job. |
| `package` | Signs the air-gap tarball keylessly (`.sigstore.json` bundle). It then runs `profilegen release-check -package`: the package verifies offline with the release key (`internal/releaseverify`, images read from the Zarf package), and its chart passes every combination against the package's own manifest and images. |
| `publish` | Copies the images with their signatures and attestations, the mirrored third-party images, the fleet artifact and the chart (`charts/fair-platform:<version>`) with their signatures, from staging to the release repository (`cosign copy`). It then creates the GitHub release with every file, including `fair-<version>-airgap.tar` with its `.sig` and `.sigstore.json`. |
| `verify` | `scripts/verify-release.sh` on what was published, online, and offline as an air-gapped bundle carries it (the mirrors included); the fleet artifact's and the chart's release-key and keyless signatures; each mirrored image's release-key signature; the published air-gap tarball's two signatures, then `fairctl verify` on the extracted package. |

## The release key
The release key is an ECDSA P-256 key in AWS KMS in the shared-services account (ADR-018). It is set up by F-012 T-12, with the repository variables `FAIR_RELEASE_KMS_KEY`, `FAIR_RELEASE_ROLE_ARN` and `FAIR_RELEASE_REGION`. The role it is used through can only `kms:Sign` with that key, and only for this repository's release workflow on a `v*` tag. GitHub holds no credential for it.

## The dry run
The tag `v0.0.0-test` runs every job and publishes a test release:
- images under `ghcr.io/<owner>/test/`;
- the GitHub release as a draft, visible to collaborators only.

While the KMS key does not exist, the dry run signs with a throwaway key made in the `sign` job. That key is discarded with the job and never written to the public transparency log. No other tag may use a test key.

From F-014 T-10, the dry run also builds, signs, gates and publishes the chart (`ghcr.io/<owner>/test/charts/fair-platform:0.0.0-test`) and the air-gap package. It is the verification of both F-012 T-07 and F-014 T-10.

To run it again, delete the draft release and the tag, then push the tag again:

```sh
gh release delete v0.0.0-test --yes
git push origin :refs/tags/v0.0.0-test
git tag -f v0.0.0-test && git push origin v0.0.0-test
```

## Retention
Published releases and their images are kept for at least 24 months (AC-12, OQ9). Do not delete releases or the packages under `ghcr.io/<owner>/fair-*`.
