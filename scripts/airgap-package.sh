#!/usr/bin/env bash
# F-014 T-10 (F-014-AC-01, AC-02, AC-04; design §3.1, D-OQ4): build and sign
# the air-gap package fair-<version>-airgap.tar. release-sign.yml runs it
# after it has signed every image with the release key, since the release key
# can only be reached from that workflow (F-012 T-12) and the dry run's
# throwaway key only lives in that job.
#
#   scripts/airgap-package.sh RELEASE_DIR WINDOW_DIR OUT_DIR
#
# RELEASE_DIR  the signed release (release-manifest.json and .sig, cosign.pub,
#              the chart fair-platform-<v>.tgz, profile packages, fairctl-*,
#              fair-audit-verify-*, component-definition.json, release-notes.md)
# WINDOW_DIR   scripts/release-window.sh's output (package-meta.env, notes/)
# OUT_DIR      receives fair-<version>-airgap.tar and its release-key
#              signature fair-<version>-airgap.tar.sig
#
# Environment: VERSION; RELEASE and STAGING (the release and staging
# repositories: the package names images in RELEASE and pulls them from
# STAGING); RELEASE_SIGNING_KEY (a cosign key reference: awskms:///… or a
# cosign key file with COSIGN_PASSWORD), RELEASE_TLOG (cosign's
# --tlog-upload=…), RELEASEGEN_KEY (releasegen sign's -kms … -region … or
# -key FILE); for KMS the AWS_* variables of the job. Docker must be logged
# in to the registry (Zarf reads Docker's credentials).
#
# Steps: releasegen for every platform (tools/); zarf.yaml (releasegen
# package zarf); zarf package create (Zarf pulls each image by digest, its
# signatures and the release's attestations, once, into its OCI layout;
# no SBOM of its own, the images carry theirs); zarf package sign with the
# release key; releasegen package build; package-manifest.json and
# SHA256SUMS signed with the release key; fairctl verify on the result; the
# tarball (reproducible: sorted, the commit's time, no owners) and its
# release-key signature (cosign sign-blob).
set -euo pipefail

REL=${1:?usage: airgap-package.sh RELEASE_DIR WINDOW_DIR OUT_DIR}
WIN=${2:?usage: airgap-package.sh RELEASE_DIR WINDOW_DIR OUT_DIR}
OUT=${3:?usage: airgap-package.sh RELEASE_DIR WINDOW_DIR OUT_DIR}
: "${VERSION:?}" "${RELEASE:?}" "${STAGING:?}" "${RELEASE_SIGNING_KEY:?}" "${RELEASEGEN_KEY:?}"
# Zarf v1.0.1 (Apache-2.0; package format zarf.dev/v1beta1), the CLI in its
# agent image (internal/airgap.ZarfVersion; third_party/zarf).
ZARF_IMAGE=${ZARF_IMAGE:-ghcr.io/zarf-dev/zarf/agent:v1.0.1@sha256:81b6e798133e7ac055b2755baed93b45dfb8a38dfc075ca5a88d0501c3d701e0}
REPO="$(cd "$(dirname "$0")/.." && pwd)"
REL="$(cd "$REL" && pwd)"; WIN="$(cd "$WIN" && pwd)"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/airgap.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
chart="$(ls "$REL"/fair-platform-*.tgz)"
pkg="fair-$VERSION-airgap"
epoch="$(cd "$REPO" && git log -1 --format=%ct)"
# shellcheck disable=SC1091
. "$WIN/package-meta.env"
releasegen() { (cd "$REPO" && go run ./cmd/releasegen "$@"); }

# tools/: releasegen for every platform (verify-release.sh needs it).
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}" arch="${target#*/}"
  ext=""; [ "$os" = windows ] && ext=".exe"
  (cd "$REPO" && CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS="$os" GOARCH="$arch" GOFLAGS=-buildvcs=false \
    go build -trimpath -ldflags "-s -w" -o "$WORK/tools/releasegen-$VERSION-$os-$arch$ext" ./cmd/releasegen)
done

# The Zarf package.
releasegen package zarf -manifest "$REL/release-manifest.json" -chart "$chart" -out "$WORK/zarf"
zarf() {
  docker run --rm --user "$(id -u):$(id -g)" -e HOME="$WORK/home" -e DOCKER_CONFIG=/docker -v "${DOCKER_CONFIG:-$HOME/.docker}:/docker:ro" \
    -e COSIGN_PASSWORD -e AWS_REGION -e AWS_ROLE_ARN -e AWS_WEB_IDENTITY_TOKEN_FILE -e AWS_USE_FIPS_ENDPOINT \
    -v "$WORK:$WORK" -v "${RUNNER_TEMP:-/tmp}:${RUNNER_TEMP:-/tmp}:ro" -w "$WORK" --entrypoint /zarf "$ZARF_IMAGE" "$@" --no-color
}
mkdir -p "$WORK/home" "$WORK/cache" "$WORK/tmp" "$WORK/created" "$WORK/signed"
zarf package create "$WORK/zarf" --confirm --skip-sbom --registry-override "$RELEASE=$STAGING" \
  -o "$WORK/created" --cache "$WORK/cache" --tmpdir "$WORK/tmp"
zpkg="$(ls "$WORK"/created/zarf-package-*.tar.zst)"
rm -rf "$WORK/cache" "$WORK/tmp" && mkdir -p "$WORK/tmp" # disk: keep one copy of the images at a time
signing=(--signing-key "$RELEASE_SIGNING_KEY")
case "$RELEASE_SIGNING_KEY" in awskms://*) ;; *) signing+=(--signing-key-pass "${COSIGN_PASSWORD:-}") ;; esac
zarf package sign "$zpkg" "${signing[@]}" "$RELEASE_TLOG" -o "$WORK/signed" --confirm --tmpdir "$WORK/tmp"
zsigned="$WORK/signed/$(basename "$zpkg")"
rm -f "$zpkg"
cp "$REL/cosign.pub" "$WORK/zarf.pub"
zarf package verify "$zsigned" --key "$WORK/zarf.pub" --tmpdir "$WORK/tmp"

# The package directory, its manifest and SHA256SUMS, signed.
mkdir -p "$WORK/notes"
cp "$WIN"/notes/*.md "$WORK/notes/" 2>/dev/null || true
cp "$REL/release-notes.md" "$WORK/notes/$VERSION.md"
releasegen package build -release "$VERSION" -release-dir "$REL" -tools "$WORK/tools" -chart "$chart" -zarf "$zsigned" \
  -notes "$WORK/notes" -root "$REPO" -source-date "$epoch" -minor-first-released "$MINOR_FIRST_RELEASED" \
  -upgrade-from "$UPGRADE_FROM" -out "$WORK/pkg/$pkg"
for f in package-manifest.json SHA256SUMS; do
  # shellcheck disable=SC2086 # RELEASEGEN_KEY is two or four flags
  releasegen sign -any $RELEASEGEN_KEY -in "$WORK/pkg/$pkg/$f"
done
rm -f "$zsigned"
(cd "$REPO" && go run ./cmd/fairctl verify -key "$REL/cosign.pub" "$WORK/pkg/$pkg")

# The tarball and its release-key signature.
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C "$WORK/pkg" -cf "$OUT/$pkg.tar" "$pkg"
rm -rf "${WORK:?}/pkg"
cosign sign-blob --yes --key "$RELEASE_SIGNING_KEY" "$RELEASE_TLOG" --output-signature "$OUT/$pkg.tar.sig" "$OUT/$pkg.tar"
echo "airgap-package: $OUT/$pkg.tar ($(du -h "$OUT/$pkg.tar" | cut -f1))"
