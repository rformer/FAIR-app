# ADR-019 Self-hosted distribution and installer: a chart generated from the fleet render, a Zarf package, and `fairctl`
Status: Accepted (Robert Former, 2026-11-26; F-014 T-03, with the F-014 design approved 2026-11-26)
Date: 2026-11-26

## Context
ADR-005 commits to one artifact set for every deployment mode (constitution M3): a Helm chart, the images with their SBOMs, signatures and attestations, an air-gap package, and an installer that refuses insecure installs (ADR-006, constitution S0). F-012 already renders `deploy/k8s` into the signed per-release artifact that Flux reconciles in SaaS (F-012 T-15, `internal/fleet`). F-014 must turn the same release into something a customer installs inside their own boundary (F-014 R-01, R-02):
- the hardening must not have a second source that can drift from the reference manifests (AC-03);
- the release must be verifiable offline with the release key alone (AC-02, AC-07; ADR-018);
- nothing may need an outbound connection (AC-05, constitution A7);
- the installer generates every credential and refuses insecure clusters (ADR-006), with cryptography in the FIPS 140 module (constitution S2).

The requirements resolved the package formats (OQ1: a signed OCI chart for connected installs, a Zarf package for air-gapped ones, with the verification files readable outside Zarf) and the installer's form (OQ2: a command-line installer in Go built with the FIPS module; the chart's hooks re-run the in-cluster preflight; no web installer in v1). The design resolved how it installs (D-OQ1: the Helm SDK) and how images are carried (D-OQ4: once, in Zarf's OCI layout).

## Options considered
| Option | Pros | Cons |
|---|---|---|
| Chart generated from the fleet render (chosen) | One source of the hardening; equality with the fleet artifact is testable | Templates are machine-written; only instance values and dependency switches are configurable |
| Hand-written Helm chart | Familiar to customers; any value can be exposed | Two sources of the hardening to keep equal; values can reach security fields |
| Kubernetes operator | Continuous reconciliation | Holds standing cluster rights; out of scope for v1 (OQ2) |
| Web installer | Guided experience | A second, network-facing surface to secure and assess; out of scope for v1 (OQ2) |
| `fairctl` shelling out to `helm` and `cosign` | Less code | Neither binary is built with the FIPS module; verification would rest on tools the customer must trust separately |
| `zarf package deploy` as the installer | Ready-made air-gap flow | Zarf would own the install, with no decisions, key generation or hard floor; verification would depend on the Zarf binary |
| Images twice in the package (OCI layout and Zarf) | Each reader has its own copy | Doubles the package; two copies to verify (D-OQ4) |

## Decision
- **The chart is a second output of the fleet render.** `fleet.RenderChart` (`releasegen chart`) shares `fleet.Render`'s loading, image substitution and key-mount patching and writes the `fair-platform` chart's `templates/` from the rendered objects. Only `fleet.Variables` placeholders, the registry prefix, the key-store kind and the bundled-dependency switches become values. `values.schema.json` is closed (`additionalProperties: false`) and no value reaches a security context, a capability, an image tag or a network policy rule. Images are named by digest from the release manifest. `TestChartMatchesFleet` holds the chart equal to the fleet artifact (design §3.2).
- **Hooks.** `pre-install` and `pre-upgrade` run the in-cluster preflight (`fairctl preflight -in-cluster`, read-only RBAC created and deleted with the hook) and then the existing `iam-migrate` Job, so a bare `helm install` also refuses an insecure cluster. Keys, database roles and decisions are provisioned only by `fairctl`; without them the services refuse to start (their `CheckInstall`s), which `NOTES.txt` says.
- **Publication.** The chart is pushed as `oci://ghcr.io/rformer/charts/fair-platform:<version>` and signed keylessly and with the release key on its OCI digest, like the images (F-012 design §3.3).
- **The air-gap package** is one directory: a Zarf package (the chart and every image any option can run, each with its cosign signature and attestations as OCI referrers, once, in Zarf's OCI image layout), and beside it the verification kit (`release-manifest.json`, `SHA256SUMS`, the signed `package-manifest.json` (`fair.airgap-package.v1`), their signatures and `cosign.pub`), the tools, content, compliance documents, the offline documentation, release notes and `platforms.json` (design §3.1). The package manifest is signed with the release key (`releasegen sign -kms`); the tarball is signed keylessly and with the release key, and the Zarf package with `zarf package sign`.
- **Zarf is transport only.** Images reach the private registry by `zarf package mirror-resources` or by `fairctl registry load`. `fairctl` reads Zarf's layout (tar and zstd) itself, so verification never depends on the Zarf binary.
- **`fairctl` is the installer**: one Go command (`cmd/fairctl` over `internal/installer`) built with `GOFIPS140=v1.0.0` and `-trimpath`, reproducible like the images, for Linux, macOS and Windows on amd64 and arm64, and an image target `fairctl` (distroless, UID 65532) for the chart's hooks and the backup jobs. It verifies, runs preflight, reads the decisions, generates every credential into the mode's key store, provisions what the services refuse to create, installs through the chart, and upgrades, rolls back, backs up, restores, installs licences, uninstalls and decommissions (design §3.4, §6.2). Every step is idempotent and recorded, so an interrupted install resumes.
- **Dependencies of `fairctl`.**
  - **Helm SDK** (`helm.sh/helm`): installs, upgrades and rollbacks, rendering in the release gate, and its OCI client for registry loads. It is linked only into `cmd/fairctl` and the release tools (`releasegen`, `profilegen`), never into a service (`TestSDKLinkedOnlyIntoTools` extended). The version is the newest release at least two weeks old when T-06 starts; T-06 records it here with its dependency facts, as ADR-012 and ADR-018 do.
  - Otherwise only the clients already in the module (the read-only kube client, pgx, `internal/objstore`, the NATS client) and the standard library.
  - No `helm`, `cosign` or `zarf` binary is required to install.
- **Release verification uses the standard library only.** `internal/releaseverify` (`fairctl verify`) checks the manifest's and `SHA256SUMS`' signatures, every file's digest, each image's cosign signature and its SPDX and SLSA attestations (DSSE) with `cosign.pub`, offline, with the same verdicts as `scripts/verify-release.sh -offline` (`TestVerifyMatchesVerifyRelease`). Online installs may also check keyless signatures through `cosign` when it is present, never instead.
- **The documentation renderer is build-only.** `releasegen docs` turns `docs/` into the offline site with a Markdown renderer linked only into `releasegen`; the site needs no scripts. The renderer is chosen, pinned and recorded here by T-31.

## Consequences
- The hardening has one source, `deploy/k8s`; a missing reference manifest (gateway, posture, design §10 item 4) is added there and reaches both the fleet artifact and the chart.
- Customers cannot tune security through chart values; a need for a new value is a schema change reviewed like any other, and the release gate renders every option combination and runs F-015's checks over each (design §3.17).
- The Helm SDK and the docs renderer enlarge the tools' dependency trees and SBOMs, not the services'. Their updates are reviewed like minio-go's (ADR-012): changelog and advisories, then the chart and gate tests.
- A web installer or an operator, if ever wanted, is a new ADR.

## Dependency record (F-014 T-06, 2026-11-26)
- **Helm SDK:** `helm.sh/helm/v4` v4.3.1, released 2026-10-15, declares `go 1.26.0`, our toolchain. v4.3.2 (2026-11-13) was 13 days old when T-06 started, short of the two weeks; the next update reviews it. Helm v4 is the current major line (v3.22.1 is the newest v3).
- **Used packages:** `pkg/chart/v2/loader` and `pkg/chart/v2/util` (load, validate, package) in `releasegen chart`; `pkg/engine` and `pkg/chart/common/util` (render with schema validation) in `internal/fleet`'s tests, with `sigs.k8s.io/kustomize/api` v0.21.1 (krusty) building the fleet artifact as Flux does.
- **New modules** (minimum version selection raised no existing dependency): the Kubernetes libraries `k8s.io/api`, `apimachinery`, `client-go`, `apiextensions-apiserver` v0.37.1, `klog/v2`, `kube-openapi`, `utils`, `sigs.k8s.io/json`, `kustomize/api`, `kustomize/kyaml`, `randfill`, `structured-merge-diff/v6`, `yaml` (Apache-2.0); Sprig and its helpers (`Masterminds/sprig/v3`, `semver/v3`, `goutils`, `huandu/xstrings`, `shopspring/decimal`, `spf13/cast`, `mitchellh/copystructure`, `reflectwalk`, `dario.cat/mergo`), `BurntSushi/toml`, `gobwas/glob`, `go-openapi/*`, `json-iterator/go`, `modern-go/*`, `emicklei/go-restful/v3`, `google/gnostic-models`, `xlab/treeprint`, `monochromegane/go-gitignore`, `munnerz/goautoneg`, `go-errors/errors`, `blang/semver/v4`, `davecgh/go-spew`, `gopkg.in/inf.v0`, `gopkg.in/evanphx/json-patch.v4`, `go.yaml.in/yaml/v2`, `golang.org/x/term`, `golang.org/x/time`: Apache-2.0, MIT, BSD-3-Clause or ISC. `cyphar/filepath-securejoin` v0.7.0 (BSD-3-Clause, its `pathrs-lite` MPL-2.0) is in the module graph but linked into no binary.
- **Advisories:** `govulncheck` v1.9.0 reports none for the new modules.
- **Linkage:** releasegen only (fairctl and profilegen are allowed); `TestSDKLinkedOnlyIntoTools` refuses `helm.sh/helm`, `k8s.io/*` and `sigs.k8s.io/*` in any other command.
