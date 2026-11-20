#!/usr/bin/env bash
# F-012 T-03 (F-012-AC-05, AC-06; design §3.2): one hardening check for every
# image the Dockerfile builds.
#
#   scripts/image-check.sh IMAGE COMPONENT
#
# Checks, for every component:
#   - it runs as 65532:65532 (non-root);
#   - its filesystem holds no shell, package manager or busybox;
#   - started with a read-only root, every capability dropped and
#     no-new-privileges, without configuration, it refuses to run (exit code
#     not 0): no TLS, no keys, no deployment mode (fips-probe: "check" fails
#     without the FIPS flag file);
# for the Go services, that the binary was built with the FIPS 140 module
# (GOFIPS140=v1.0.0) and runs it by default (DefaultGODEBUG fips140=on);
# for the engine, the F-005 checks: no TLS library, NumPy's CPU dispatch
# pinned, the validation suite's passed record in the image.
# Needs docker. Exits non-zero naming the first failed check.
set -euo pipefail
export MSYS_NO_PATHCONV=1

IMAGE=${1:?image}
COMPONENT=${2:?component}
GO_IMAGE=golang:1.26.11-bookworm@sha256:dc40a13b61304647ed7e5d581d246b86413dfc29d63c6d018310feb93cd98fc0
W="$(mktemp -d)"
trap 'rm -rf "$W"; docker rm -f "fair-check-$$" >/dev/null 2>&1 || true' EXIT
host() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
ok() { echo "ok - $COMPONENT: $*"; }
fail() { echo "FAIL - $COMPONENT: $*" >&2; exit 1; }

user="$(docker inspect -f '{{.Config.User}}' "$IMAGE")"
[ "$user" = "65532:65532" ] || fail "runs as '$user', not 65532:65532"
ok "non-root (65532:65532)"

docker create --name "fair-check-$$" "$IMAGE" >/dev/null
docker export "fair-check-$$" | tar -t > "$W/files"
for f in bin/sh bin/bash bin/dash bin/busybox usr/bin/apt usr/bin/apt-get usr/bin/dpkg usr/bin/pip usr/local/bin/pip usr/bin/apk; do
  if grep -qx "$f" "$W/files"; then fail "has $f"; fi
done
ok "no shell, busybox or package manager"

hardened=(--rm --read-only --cap-drop ALL --security-opt no-new-privileges)
case "$COMPONENT" in
  engine)
    docker run "${hardened[@]}" "$IMAGE" > "$W/info.json" || fail "the engine's self-description failed"
    python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["cpu_dispatch"] and not any(d["cpu_dispatch"].values()) else 1)' "$(host "$W/info.json")" ||
      fail "NumPy's CPU dispatch is not pinned"
    if docker run "${hardened[@]}" --entrypoint /usr/local/bin/python3.12 "$IMAGE" -c "import ssl" 2>/dev/null; then fail "the engine carries a TLS library"; fi
    docker run "${hardened[@]}" --entrypoint /usr/local/bin/python3.12 "$IMAGE" \
      -c 'import json,sys; r=json.load(open("/engine/validation.json")); sys.exit(0 if r["passed"] else 1)' || fail "no passed validation record"
    ok "no TLS library, CPU dispatch pinned, validation passed"
    exit 0
    ;;
  fips-probe) smoke=(check) ;;
  *) smoke=() ;;
esac

if docker run "${hardened[@]}" "$IMAGE" "${smoke[@]}" >"$W/run.log" 2>&1; then
  cat "$W/run.log" >&2
  fail "started unconfigured (it must refuse without TLS, keys or its mode)"
fi
ok "refuses to start unconfigured (read-only root, no capabilities)"

entry="$(docker inspect -f '{{index .Config.Entrypoint 0}}' "$IMAGE")"
docker cp "fair-check-$$:$entry" "$(host "$W")/bin" >/dev/null
docker run --rm -v "$(host "$W"):/w:ro" "$GO_IMAGE" go version -m /w/bin > "$W/buildinfo"
grep -qE '^\s+build\s+GOFIPS140=v1\.0\.0' "$W/buildinfo" || fail "not built with the FIPS 140 module (GOFIPS140=v1.0.0)"
grep -qE '^\s+build\s+DefaultGODEBUG=.*fips140=on' "$W/buildinfo" || fail "does not run the FIPS 140 module by default"
grep -qE '^\s+build\s+CGO_ENABLED=0' "$W/buildinfo" || fail "built with cgo"
ok "FIPS 140 module built in and on by default; static (no cgo)"
