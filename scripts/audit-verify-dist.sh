#!/usr/bin/env bash
# F-002 T-10 (design §11): build fair-audit-verify for the release, for each
# platform an auditor may use, with the FIPS 140 module, statically, and
# write SHA256SUMS for the binaries. The tool needs no network and no
# platform access, so it is published on its own as well as in the audit
# image (/fair-audit-verify, so air-gapped bundles carry it).
#
#   scripts/audit-verify-dist.sh RELEASE OUTDIR      e.g. v1.4.0 audit-verify-dist
set -euo pipefail
release="${1:?release, e.g. v1.4.0}"
out="${2:?output directory}"
case "$release" in
  *[!A-Za-z0-9._+-]*) echo "audit-verify-dist: release '$release' has characters a version does not" >&2; exit 1 ;;
esac
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}" arch="${target#*/}"
  ext=""; [ "$os" = windows ] && ext=".exe"
  name="fair-audit-verify-${release}-${os}-${arch}${ext}"
  (cd "$REPO" && CGO_ENABLED=0 GOFIPS140=v1.0.0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=${release}" -o "$out/$name" ./cmd/audit-verify)
done
(cd "$out" && sha256sum -- fair-audit-verify-* > SHA256SUMS) # verify: sha256sum -c --ignore-missing SHA256SUMS
echo "audit-verify-dist: $(ls "$out"/fair-audit-verify-* | wc -l) binaries for $release in $out"
