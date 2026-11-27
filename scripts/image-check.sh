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
#
# F-014 T-07 (F-014-AC-01, AC-17; design §3.3, D-OQ3), the bundled
# dependency images, with the same checks and their own FIPS report:
#   - nats, openbao, versitygw (Go, rebuilt from pinned source): the Go
#     checks above plus -trimpath, the refusal naming the missing
#     configuration (versitygw: its TLS certificate), and a start that runs
#     the FIPS module's self-test (version, read-only, no capabilities);
#   - postgres: /bin/sh (dash) is the one shell allowed, since initdb,
#     pg_ctl and archive_command run through it; the OpenSSL FIPS provider
#     3.1.2 loaded and active, MD5 refused by OpenSSL and by pgcrypto,
#     SHA-256 and random bytes from pgcrypto, and a TLS 1.2+ session to a
#     server it started;
#   - keycloak: the upstream UBI image's bash is allowed (its kc.sh
#     launcher) but no package manager; Keycloak's crypto provider reported
#     as BC-FIPS in approved mode at start.
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

# The shells a bundled image may keep because its upstream software runs
# through them; never busybox or a package manager.
case "$COMPONENT" in
  postgres) allowed="bin/sh" ;;
  keycloak) allowed="bin/sh bin/bash usr/bin/sh usr/bin/bash" ;;
  *) allowed="" ;;
esac
docker create --name "fair-check-$$" "$IMAGE" >/dev/null
docker export "fair-check-$$" | tar -t > "$W/files"
for f in bin/sh bin/bash bin/dash usr/bin/sh usr/bin/bash usr/bin/dash bin/busybox usr/bin/busybox \
         usr/bin/apt usr/bin/apt-get usr/bin/dpkg usr/bin/pip usr/local/bin/pip usr/bin/apk \
         usr/bin/rpm usr/bin/dnf usr/bin/microdnf usr/bin/yum; do
  case " $allowed " in *" $f "*) continue ;; esac
  if grep -qx "$f" "$W/files"; then fail "has $f"; fi
done
if [ -n "$allowed" ]; then
  ok "no busybox or package manager; shell only as its upstream requires ($allowed)"
else
  ok "no shell, busybox or package manager"
fi

hardened=(--rm --read-only --cap-drop ALL --security-opt no-new-privileges)
refusal="" # what the refusal must name, for the bundled images
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
  nats) smoke=(); refusal="/etc/nats/nats.conf" ;;
  openbao) smoke=(); refusal="/openbao/config" ;;
  versitygw)
    # Writable data directories, so the refusal is the missing certificate.
    hardened+=(--tmpfs "/var/lib/versitygw/data:uid=65532,gid=65532" --tmpfs "/var/lib/versitygw/versions:uid=65532,gid=65532" -e ROOT_ACCESS_KEY=check -e ROOT_SECRET_KEY=check-only)
    smoke=(); refusal="/etc/versitygw/tls/tls.crt" ;;
  postgres) smoke=(); refusal="configuration file" ;;
  keycloak) hardened+=(--tmpfs /opt/keycloak/data:uid=65532 --tmpfs /tmp:uid=65532); smoke=(); refusal="HTTPS" ;;
  *) smoke=() ;;
esac

if docker run "${hardened[@]}" "$IMAGE" "${smoke[@]}" >"$W/run.log" 2>&1; then
  cat "$W/run.log" >&2
  fail "started unconfigured (it must refuse without TLS, keys or its mode)"
fi
if [ -n "$refusal" ] && ! grep -qF "$refusal" "$W/run.log"; then
  cat "$W/run.log" >&2
  fail "refused, but not for its missing configuration ($refusal)"
fi
ok "refuses to start unconfigured (read-only root, no capabilities)"
hardened=(--rm --read-only --cap-drop ALL --security-opt no-new-privileges)

case "$COMPONENT" in
  postgres)
    docker run "${hardened[@]}" --entrypoint /usr/local/ssl/bin/openssl "$IMAGE" list -providers > "$W/providers" || fail "openssl list -providers failed"
    python3 - "$(host "$W/providers")" <<'PY' || fail "the OpenSSL FIPS provider 3.1.2 is not the active provider"
import re, sys
t = open(sys.argv[1]).read()
m = re.search(r"^  fips\n((?:    .*\n?)+)", t, re.M)
sys.exit(0 if m and "version: 3.1.2" in m.group(1) and "status: active" in m.group(1) and "default" not in t else 1)
PY
    if echo x | docker run -i "${hardened[@]}" --entrypoint /usr/local/ssl/bin/openssl "$IMAGE" dgst -md5 >/dev/null 2>&1; then
      fail "OpenSSL computes MD5: not in FIPS mode"
    fi
    ok "OpenSSL FIPS provider 3.1.2 active (fips=yes for every fetch), MD5 refused"
    printf '%s\n' "CREATE EXTENSION pgcrypto;" \
      "SELECT encode(digest('x', 'sha256'), 'hex') AS sha256;" \
      "SELECT length(gen_random_bytes(32)) AS random;" \
      "SELECT encode(digest('x', 'md5'), 'hex') AS md5;" |
      docker run -i "${hardened[@]}" --tmpfs /tmp:uid=65532,gid=65532 --entrypoint /bin/sh "$IMAGE" \
        -c 'initdb -D /tmp/pg -A trust >/dev/null 2>&1 && exec postgres --single -D /tmp/pg postgres' > "$W/single.log" 2>&1 || true
    grep -q 'sha256 = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"' "$W/single.log" || { cat "$W/single.log" >&2; fail "pgcrypto SHA-256 failed"; }
    grep -q 'random = "32"' "$W/single.log" || { cat "$W/single.log" >&2; fail "pgcrypto random bytes failed"; }
    grep -q 'Cannot use "md5"' "$W/single.log" || { cat "$W/single.log" >&2; fail "pgcrypto computes MD5: not in FIPS mode"; }
    ok "pgcrypto: SHA-256 and random bytes through the provider, MD5 refused"
    docker run "${hardened[@]}" --tmpfs /tmp:uid=65532,gid=65532 --entrypoint /bin/sh "$IMAGE" -c '
      set -e
      initdb -D /tmp/pg -A trust >/dev/null 2>&1
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost \
        -keyout /tmp/pg/server.key -out /tmp/pg/server.crt >/dev/null 2>&1
      pg_ctl -D /tmp/pg -w -s -l /tmp/pg.log -o "-c ssl=on -c ssl_min_protocol_version=TLSv1.2 -c listen_addresses=127.0.0.1 -c unix_socket_directories=/tmp" start
      psql "host=127.0.0.1 dbname=postgres sslmode=require" -Atc "SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()"' > "$W/tls" 2>&1 || { cat "$W/tls" >&2; fail "TLS to PostgreSQL failed"; }
    grep -qxE 'TLSv1\.[23]' "$W/tls" || { cat "$W/tls" >&2; fail "PostgreSQL TLS session is not TLS 1.2 or later"; }
    ok "TLS $(tr -d '\r' < "$W/tls") session through the FIPS provider"
    exit 0
    ;;
  keycloak)
    docker run "${hardened[@]}" --tmpfs /opt/keycloak/data:uid=65532 --tmpfs /tmp:uid=65532 "$IMAGE" \
      --http-enabled=true --hostname-strict=false --db-url=jdbc:postgresql://127.0.0.1:1/none > "$W/kc.log" 2>&1 || true
    grep -qE 'FIPS1402Provider created: KC\(BCFIPS version [0-9.]+ Approved Mode' "$W/kc.log" ||
      { tail -20 "$W/kc.log" >&2; fail "Keycloak's crypto provider is not BC-FIPS in approved mode"; }
    ok "$(grep -oE 'KC\(BCFIPS[^)]*\)' "$W/kc.log" | head -1) (FIPS-JVM is enabled only on a FIPS node)"
    exit 0
    ;;
esac

entry="$(docker inspect -f '{{index .Config.Entrypoint 0}}' "$IMAGE")"
docker cp "fair-check-$$:$entry" "$(host "$W")/bin" >/dev/null
docker run --rm -v "$(host "$W"):/w:ro" "$GO_IMAGE" go version -m /w/bin > "$W/buildinfo"
grep -qE '^\s+build\s+GOFIPS140=v1\.0\.0' "$W/buildinfo" || fail "not built with the FIPS 140 module (GOFIPS140=v1.0.0)"
grep -qE '^\s+build\s+DefaultGODEBUG=.*fips140=on' "$W/buildinfo" || fail "does not run the FIPS 140 module by default"
grep -qE '^\s+build\s+CGO_ENABLED=0' "$W/buildinfo" || fail "built with cgo"
ok "FIPS 140 module built in and on by default; static (no cgo)"

case "$COMPONENT" in
  nats | openbao | versitygw)
    grep -qE '^\s+build\s+-trimpath=true' "$W/buildinfo" || fail "not built with -trimpath"
    case "$COMPONENT" in
      nats) version=(--version) ;;
      openbao) version=(version) ;;
      versitygw) version=(--version) ;;
    esac
    # With fips140=on the module checks its integrity at start; a binary
    # that runs at all has passed it.
    docker run "${hardened[@]}" --entrypoint "$entry" "$IMAGE" "${version[@]}" > "$W/version" 2>&1 ||
      { cat "$W/version" >&2; fail "does not start with the FIPS module on"; }
    ok "-trimpath; starts with the FIPS module's self-test passed: $(head -1 "$W/version" | tr -d '\r')"
    ;;
esac
