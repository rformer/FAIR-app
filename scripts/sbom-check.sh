#!/usr/bin/env bash
# F-012 T-04 (F-012-AC-08; design §3.3): an image's SPDX SBOM lists every
# module or package the image contains.
#
#   scripts/sbom-check.sh SBOM.spdx.json IMAGE COMPONENT
#
# Go images: the main module, every module linked into the binary (its build
# information, "go version -m") and the standard library are in the SBOM, by
# module path. The engine: every package
# of engine/requirements.lock is in the SBOM, by name. Needs docker and
# python3.
set -euo pipefail
export MSYS_NO_PATHCONV=1

SBOM=${1:?sbom}
IMAGE=${2:?image}
COMPONENT=${3:?component}
GO_IMAGE=golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0
W="$(mktemp -d)"
trap 'rm -rf "$W"; docker rm -f "fair-sbom-$$" >/dev/null 2>&1 || true' EXIT
host() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }

python3 - "$(host "$SBOM")" > "$W/names" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
for p in d.get("packages", []):
    print(p.get("name", "").lower())
PY
tr -d '\r' < "$W/names" > "$W/names.lf" && mv "$W/names.lf" "$W/names" # Python on Windows writes CRLF

if [ "$COMPONENT" = engine ]; then
  grep -oE '^[A-Za-z0-9_.-]+==' engine/requirements.lock | tr -d '=' | tr 'A-Z_' 'a-z-' > "$W/want"
  tr '_' '-' < "$W/names" > "$W/have"
else
  docker create --name "fair-sbom-$$" "$IMAGE" >/dev/null
  entry="$(docker inspect -f '{{index .Config.Entrypoint 0}}' "$IMAGE")"
  docker cp "fair-sbom-$$:$entry" "$(host "$W")/bin" >/dev/null
  docker run --rm -v "$(host "$W"):/w:ro" "$GO_IMAGE" go version -m /w/bin | awk '$1 == "mod" || $1 == "dep" { print tolower($2) }' > "$W/want"
  echo stdlib >> "$W/want" # the Go standard library, which a stdlib-only binary (fips-probe) has alone
  cp "$W/names" "$W/have"
fi

[ -s "$W/want" ] || { echo "FAIL - $COMPONENT: nothing to look for in the image" >&2; exit 1; }
missing="$(sort -u "$W/want" | comm -23 - <(sort -u "$W/have"))"
if [ -n "$missing" ]; then
  echo "FAIL - $COMPONENT: missing from the SBOM:" >&2
  echo "$missing" >&2
  exit 1
fi
echo "ok - $COMPONENT: the SBOM lists all $(sort -u "$W/want" | wc -l | tr -d ' ') modules or packages"
