#!/usr/bin/env bash
# F-001 T-42 (design §6: "OpenAPI published with the release"): copy the
# OpenAPI documents into OUTDIR, each stamped with the release it describes
# (x-fair-release under info; info.version stays the API's major version),
# and write SHA256SUMS for them. Lint first: scripts/openapi-lint.sh.
#
#   scripts/openapi-bundle.sh RELEASE OUTDIR      e.g. v1.4.0 openapi-dist
set -euo pipefail
release="${1:?release, e.g. v1.4.0}"
out="${2:?output directory}"
case "$release" in
  *[!A-Za-z0-9._+-]*) echo "openapi-bundle: release '$release' has characters a version does not" >&2; exit 1 ;;
esac
REPO="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$out"
for f in "$REPO"/api/openapi/*.yaml; do
  name="$(basename "$f")"
  # The stamp goes right after the info block's version line, once.
  awk -v rel="$release" '
    /^info:/ { in_info = 1 }
    /^[^ ]/ && !/^info:/ { in_info = 0 }
    { print }
    in_info && /^  version:/ && !done { print "  x-fair-release: \"" rel "\""; done = 1 }
    END { if (!done) exit 1 }
  ' "$f" > "$out/$name" || { echo "openapi-bundle: $name has no info.version" >&2; exit 1; }
done
(cd "$out" && sha256sum -- *.yaml > SHA256SUMS) # verify: sha256sum -c SHA256SUMS
echo "openapi-bundle: $(ls "$out"/*.yaml | wc -l) documents for $release in $out"
