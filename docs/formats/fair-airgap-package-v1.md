# The air-gap package (`fair.airgap-package.v1`)

F-014 T-10 (AC-01, AC-02, AC-04; design §3.1, D-OQ4). Each release ships one air-gap package, `fair-<version>-airgap.tar`: a tarball of one directory, `fair-<version>-airgap/`. `releasegen package` builds it (`internal/airgap`). `fairctl verify` reads it (`internal/releaseverify`) and so does the release gate (`profilegen release-check -package`, `internal/chartgate`).

## Layout

| Path | What it is |
|---|---|
| `zarf-package-fair-platform-<arch>-<version>.tar.zst` | The Zarf package (Zarf v1.0.1, `zarf.dev/v1beta1`). It holds the chart and every image any chart option can run: the release manifest's images and its mirrored third-party copies. Each image appears once, in Zarf's OCI image layout (`images/`), with its cosign signatures and, for the release's own images, its SPDX and SLSA attestations, stored under cosign's `sha256-<hex>.sig` and `.att` tags. Zarf's own signature (`zarf package sign`, the release key) is inside it. |
| `release-manifest.json`, `.sig` | The signed release manifest: images by digest, RBAC hashes, the engine's validation record and the `mirrors` section (below) |
| `cosign.pub` | The release public key. Check its fingerprint against one you got separately from the package. |
| `SHA256SUMS`, `.sig` | The SHA-256 of every file, as `sha256sum -c` reads it, signed with the release key |
| `package-manifest.json`, `.sig` | This format, signed with the release key |
| `chart/fair-platform-<v>.tgz` | The chart the Zarf package holds, as a plain file (also published as `oci://ghcr.io/rformer/charts/fair-platform:<v>`) |
| `tools/` | `fairctl`, `fair-audit-verify` and `releasegen`, each as `<tool>-<version>-<os>-<arch>[.exe]` for Linux, macOS and Windows on amd64 and arm64 |
| `content/` | What the images embed, so an assessor can read it: `profiles/` (the signed profile packages and their manifest), `frameworks/shipped.json.gz`, `starter-library/starter.json`, `question-bank/questions.json` |
| `compliance/` | `component-definition.json` (OSCAL). The responsibility matrix will join it with design §3.13's task. |
| `docs/` | `security/verify.md` (how to verify), the install guides, the package and decisions formats, fairctl's JSON schemas. The offline documentation site will join them with design §3.15's task. |
| `notes/` | `<version>.md` for this release and for every release it upgrades from |
| `platforms.json` | `fair.platforms.v1`: the supported Kubernetes versions (`kubernetes.minimum`, `tested`) and distributions, each verified by the install matrix in CI (`ci`) or by recorded runs (`recorded`) |

The package contains no URL it needs at install time. You can read it without Zarf: the verification kit, the chart and the tools are plain files, and `fairctl verify` reads the images directly from the Zarf package. Before it extracts anything, it checks the Zarf package's SHA-256 against the signed package manifest.

## `package-manifest.json`

```json
{
  "format": "fair.airgap-package.v1",
  "release": "v1.2.3",
  "source_date": "2026-11-20T10:00:00Z",
  "minor_first_released": "2026-11-01",
  "upgrade_from": ["v1.0.0", "v1.1.0"],
  "files": [{"path": "chart/fair-platform-1.2.3.tgz", "sha256": "…"}],
  "images": [{"component": "iam", "image": "ghcr.io/rformer/fair-iam@sha256:…"}]
}
```

- `files` lists every file of the directory except this manifest, `SHA256SUMS` and their signatures. Paths are relative and use slashes. A file the list does not name makes verification fail.
- `images` lists every image in the Zarf package by component: every image of the release manifest, with the same reference, and every mirror, by its `component` and `image`.
- `source_date` is the release commit's time. `minor_first_released` is the day the minor line's `.0` was released, and entitlements use it (design §3.9). `upgrade_from` lists the releases of the previous two minor lines that this one upgrades from (design §3.10).

The format is defined by `releaseverify.PackageManifest`, which decodes it strictly.

## The release manifest's `mirrors`

```json
"mirrors": [{
  "component": "cloudnative-pg",
  "image": "ghcr.io/rformer/mirror/cloudnative-pg@sha256:…",
  "source": "ghcr.io/cloudnative-pg/cloudnative-pg:1.30.2@sha256:…",
  "certificate_identity": "https://github.com/cloudnative-pg/cloudnative-pg/.github/workflows/release-publish.yml@refs/tags/v1.30.2",
  "certificate_oidc_issuer": "https://token.actions.githubusercontent.com"
}]
```

Each third-party image the release runs (`deploy/third-party-images.json`) appears here once the release has done two things: verified it against the publisher's exact identity, and copied it by digest to `<release repository>/mirror/<component>`. The copy has the source's digest. Mirrors are signed with the release key but carry none of the release's attestations, so verifiers check them by that signature alone (`releaseverify`, `scripts/verify-release.sh`). The scanner's `image_digests` check and the release gate accept them as the release's images. A mirror's component never names a release image.

## Signatures

| What | How |
|---|---|
| `release-manifest.json`, `SHA256SUMS`, `package-manifest.json` | Detached release-key signatures, `<file>.sig` (`releasegen sign -any`) |
| The Zarf package | `zarf package sign` with the release key (`zarf.bundle.sig` inside it). Check with `zarf package verify --key cosign.pub`. |
| `fair-<version>-airgap.tar` | `fair-<version>-airgap.tar.sig`, a release-key signature (`cosign sign-blob --key`; check with `cosign verify-blob --key cosign.pub --signature …`), and `fair-<version>-airgap.tar.sigstore.json`, a keyless Sigstore bundle from the release workflow |
