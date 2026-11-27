#!/usr/bin/env bash
# F-012 T-04 (F-012-AC-08; design §3.3): an image's SPDX SBOM lists every
# module or package the image contains.
#
#   scripts/sbom-check.sh SBOM.spdx.json IMAGE COMPONENT
#
# Go images: the main module, every module linked into the binary (its build
# information, "go version -m") and the standard library are in the SBOM, by
# module path. The engine: every package
# of engine/requirements.lock is in the SBOM, by name.
# F-014 T-07, the bundled dependency images: the Go ones (nats, openbao,
# versitygw) as above; postgres: every source pinned for it in
# deploy/bundled/sources.json (PostgreSQL, OpenSSL, the FIPS provider, which
# the image's own SPDX document names) and every Debian package it carries;
# keycloak: every jar in the image (but Quarkus's generated ones) by the
# path the SBOM found it at, and every BC-FIPS artifact pinned for it.
# Needs docker and python3.
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

pinned() { # names deploy/bundled/sources.json pins for the component, by kind
  python3 - "$(host deploy/bundled/sources.json)" "$1" "$2" <<'PY' | tr -d '\r'
import json, sys
for e in json.load(open(sys.argv[1], encoding="utf-8"))["sources"]:
    if e["component"] == sys.argv[2] and e["kind"] in sys.argv[3].split(","):
        print(e["name"].lower())
PY
}

if [ "$COMPONENT" = engine ]; then
  grep -oE '^[A-Za-z0-9_.-]+==' engine/requirements.lock | tr -d '=' | tr 'A-Z_' 'a-z-' > "$W/want"
  tr '_' '-' < "$W/names" > "$W/have"
elif [ "$COMPONENT" = postgres ]; then
  pinned postgres source > "$W/want"
  docker create --name "fair-sbom-$$" "$IMAGE" >/dev/null
  docker export "fair-sbom-$$" | tar -t | sed -n 's#^var/lib/dpkg/status.d/\([^/]*\)$#\1#p' | sed 's/\.md5sums$//' | sort -u >> "$W/want"
  cp "$W/names" "$W/have"
elif [ "$COMPONENT" = keycloak ]; then
  pinned keycloak artifact > "$W/want"
  docker create --name "fair-sbom-$$" "$IMAGE" >/dev/null
  docker export "fair-sbom-$$" | tar -t | grep -E '\.jar$' | grep -v '^opt/keycloak/lib/quarkus/' | sed 's#^#jar:/#' >> "$W/want"
  python3 - "$(host "$SBOM")" <<'PY' | tr -d '\r' > "$W/paths"
import json, re, sys
for p in json.load(open(sys.argv[1], encoding="utf-8")).get("packages", []):
    for m in re.findall(r"(/\S+\.jar)", p.get("sourceInfo", "")):
        print("jar:" + m)
PY
  cat "$W/names" "$W/paths" > "$W/have"
else
  docker create --name "fair-sbom-$$" "$IMAGE" >/dev/null
  entry="$(docker inspect -f '{{index .Config.Entrypoint 0}}' "$IMAGE")"
  docker cp "fair-sbom-$$:$entry" "$(host "$W")/bin" >/dev/null
  docker run --rm -v "$(host "$W"):/w:ro" "$GO_IMAGE" go version -m /w/bin | awk '$1 == "mod" || $1 == "dep" { print tolower($2) }' > "$W/want"
  echo stdlib >> "$W/want" # the Go standard library, which a stdlib-only binary (fips-probe) has alone
  cp "$W/names" "$W/have"
fi

sed -i '/^$/d' "$W/want"
[ -s "$W/want" ] || { echo "FAIL - $COMPONENT: nothing to look for in the image" >&2; exit 1; }
missing="$(sort -u "$W/want" | comm -23 - <(sort -u "$W/have"))"
if [ -n "$missing" ]; then
  echo "FAIL - $COMPONENT: missing from the SBOM:" >&2
  echo "$missing" >&2
  exit 1
fi
echo "ok - $COMPONENT: the SBOM lists all $(sort -u "$W/want" | wc -l | tr -d ' ') modules or packages"
