#!/usr/bin/env bash
# F-014 T-12 (design §3.4, ADR-019): build fairctl, the installer, for each
# platform an administrator installs from (Linux, macOS, Windows; amd64 and
# arm64), with the FIPS 140 module (GOFIPS140=v1.0.0, on by default through
# go.mod's godebug), statically (no cgo), -trimpath and -buildvcs=false, so
# the bytes depend only on the source, the toolchain and the release; and
# write SHA256SUMS for the binaries. The image target `fairctl` carries the
# Linux build for the chart's hooks.
#
#   scripts/fairctl-dist.sh [-check] RELEASE OUTDIR    e.g. v1.4.0 fairctl-dist
#
# -check also builds everything a second time in another directory and
# requires the same bytes (reproducible, like the images: F-012 T-05), and
# that each binary records the FIPS 140 module and no cgo (go version -m).
set -euo pipefail
check=0
if [ "${1:-}" = -check ]; then check=1; shift; fi
release="${1:?release, e.g. v1.4.0}"
out="${2:?output directory}"
case "$release" in
  *[!A-Za-z0-9._+-]*) echo "fairctl-dist: release '$release' has characters a version does not" >&2; exit 1 ;;
esac
REPO="$(cd "$(dirname "$0")/.." && pwd)"
TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"

build() { # build DIR
  mkdir -p "$1"
  for target in $TARGETS; do
    os="${target%/*}" arch="${target#*/}"
    ext=""; [ "$os" = windows ] && ext=".exe"
    (cd "$REPO" && CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS="$os" GOARCH="$arch" GOFLAGS=-buildvcs=false \
      go build -trimpath -ldflags "-s -w -X main.version=${release}" -o "$1/fairctl-${release}-${os}-${arch}${ext}" ./cmd/fairctl)
  done
  (cd "$1" && sha256sum -- fairctl-* > SHA256SUMS) # verify: sha256sum -c --ignore-missing SHA256SUMS
}

mkdir -p "$out"
out="$(cd "$out" && pwd)"
build "$out"
if [ "$check" = 1 ]; then
  for f in "$out"/fairctl-*; do
    info="$(go version -m "$f")"
    grep -qE '^\s+build\s+GOFIPS140=v1\.0\.0' <<<"$info" || { echo "FAIL - $(basename "$f"): not built with the FIPS 140 module" >&2; exit 1; }
    grep -qE '^\s+build\s+DefaultGODEBUG=.*fips140=on' <<<"$info" || { echo "FAIL - $(basename "$f"): the FIPS 140 module is not on by default" >&2; exit 1; }
    grep -qE '^\s+build\s+CGO_ENABLED=0' <<<"$info" || { echo "FAIL - $(basename "$f"): built with cgo" >&2; exit 1; }
    grep -qE '^\s+build\s+-trimpath=true' <<<"$info" || { echo "FAIL - $(basename "$f"): not built with -trimpath" >&2; exit 1; }
  done
  echo "ok - FIPS 140 module on by default, static, -trimpath: every build"
  again="$(mktemp -d)"
  trap 'rm -rf "$again"' EXIT
  GOCACHE="$again/cache" build "$again/bin" # a cold cache: nothing reused from the first build
  if ! diff "$out/SHA256SUMS" "$again/bin/SHA256SUMS" >&2; then
    echo "FAIL - fairctl: two builds differ" >&2
    exit 1
  fi
  echo "ok - two builds have the same bytes"
fi
echo "fairctl-dist: $(ls "$out"/fairctl-* | wc -l | tr -d ' ') binaries for $release in $out"
