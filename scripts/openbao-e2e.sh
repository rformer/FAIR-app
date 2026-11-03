#!/usr/bin/env bash
# F-001 T-41 (design §10, self-hosted): the key delivery through OpenBao, live.
#
# Starts an OpenBao server (dev mode, on its own Docker network), creates the
# installation's keys with `iam keys init`, loads them into OpenBao as
# docs/install/keys.md describes, with the policies in deploy/k8s/keys/openbao,
# and renders them with OpenBao Agent using the templates the sidecars use
# (deploy/k8s/keys/openbao/*.ctmpl). Kubernetes auth is replaced by AppRole;
# everything else is as deployed. Then checks:
#   - the rendered directories pass `iam keys check` (complete, consistent,
#     not open to others) and hold exactly the files iam keys init wrote;
#   - each service's role reads only its own keys;
#   - after `iam keys rotate -kind jwt` and a reload, a new render holds the
#     new signing key and still passes.
# Every step runs in containers as uid 65532 (the services' user), so it runs
# the same on Linux and on Docker Desktop. Needs docker and go.
set -euo pipefail

IMAGE="${OPENBAO_IMAGE:-quay.io/openbao/openbao:2.2.0@sha256:19612d67a4a95d05a7b77c6ebc6c2ac5dac67a8712d8df2e4c31ad28bee7edaa}"
NET=fair-openbao-e2e
SERVER=fair-openbao-e2e
ROOT_TOKEN=e2e-root-token # dev server only; it exists for this run
REPO="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"
export MSYS_NO_PATHCONV=1

host() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }
cleanup() {
  docker rm -f "$SERVER" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  # Files rendered as 65532: remove them from a container.
  docker run --rm -v "$(host "$W"):/w" --entrypoint sh "$IMAGE" -c 'rm -rf /w/*' >/dev/null 2>&1 || true
  rm -rf "$W"
}
trap cleanup EXIT
passed=0
ok() { passed=$((passed + 1)); echo "ok $passed - $*"; }
fail() { echo "FAIL - $*" >&2; exit 1; }

# run as the services' user with the work directory at /w and the OpenBao
# configuration at /etc/openbao.
as65532() {
  docker run --rm --network "$NET" --user 65532:65532 -e BAO_ADDR="http://$SERVER:8200" -e BAO_TOKEN="$ROOT_TOKEN" \
    -v "$(host "$W"):/w" -v "$(host "$REPO/deploy/k8s/keys/openbao"):/etc/openbao:ro" --entrypoint sh "$IMAGE" -c "$1"
}

echo "# building iam (linux, FIPS module)"
mkdir -p "$W/bin"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFIPS140=v1.0.0 go build -o "$(host "$W/bin/iam")" ./cmd/iam)
chmod 0777 "$W"

docker network create "$NET" >/dev/null
docker run -d --name "$SERVER" --network "$NET" -e BAO_DEV_ROOT_TOKEN_ID="$ROOT_TOKEN" "$IMAGE" \
  server -dev -dev-listen-address=0.0.0.0:8200 >/dev/null
for _ in $(seq 1 30); do
  as65532 'bao status >/dev/null 2>&1' && break
  sleep 1
done
as65532 'bao status >/dev/null' || fail "OpenBao did not start"
ok "OpenBao server up"

# The installer's steps (docs/install/keys.md).
as65532 '/w/bin/iam keys init -dir /w/src' >/dev/null
ok "iam keys init"

load() { # load <service/dir>...: one KV entry per directory, a field per file
  for e in "$@"; do
    as65532 "set -e; args=''; for f in /w/src/$e/*; do args=\"\$args \$(basename \$f)=@\$f\"; done; bao kv put secret/fair/$e \$args >/dev/null"
  done
}
ENTRIES="gateway/jwt gateway/login-ticket gateway/secrets iam/jwt iam/login-ticket iam/secrets posture/jwt"
# shellcheck disable=SC2086
load $ENTRIES
as65532 'set -e; bao auth enable approle >/dev/null
  for s in gateway iam posture; do
    bao policy write fair-$s /etc/openbao/policy-$s.hcl >/dev/null
    bao write auth/approle/role/fair-$s token_policies=fair-$s token_ttl=10m >/dev/null
    bao read -field=role_id auth/approle/role/fair-$s/role-id > /w/role-$s
    bao write -f -field=secret_id auth/approle/role/fair-$s/secret-id > /w/secret-$s
  done'
ok "keys loaded, policies and roles written"

render() { # render <output dir>: each service's agent, once
  for s in gateway iam posture; do
    mkdir -p "$W/$1/$s"
    chmod 0777 "$W/$1/$s"
    cat > "$W/agent-$s.hcl" <<EOF
vault { address = "http://$SERVER:8200" }
auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/w/role-$s"
      secret_id_file_path                 = "/w/secret-$s"
      remove_secret_id_file_after_reading = false
    }
  }
}
template_config { exit_on_retry_failure = true }
template {
  source      = "/etc/openbao/$s.ctmpl"
  destination = "/keys/.rendered"
  perms       = "0640"
}
exit_after_auth = true
EOF
    docker run --rm --network "$NET" --user 65532:65532 -v "$(host "$W"):/w" -v "$(host "$W/$1/$s"):/keys" \
      -v "$(host "$REPO/deploy/k8s/keys/openbao"):/etc/openbao:ro" "$IMAGE" bao agent -config="/w/agent-$s.hcl" >"$W/agent-$s.log" 2>&1 ||
      { cat "$W/agent-$s.log" >&2; fail "OpenBao Agent for $s"; }
    as65532 "grep -qx rendered /w/$1/$s/.rendered" || { cat "$W/agent-$s.log" >&2; as65532 "ls -laR /w/$1/$s" >&2; fail "$s: no readiness marker"; }
  done
}
render rendered
ok "OpenBao Agent rendered each service's keys"

as65532 '/w/bin/iam keys check -dir /w/rendered' >/dev/null || { as65532 '/w/bin/iam keys check -dir /w/rendered'; fail "rendered keys"; }
ok "rendered keys pass iam keys check (complete, consistent, private)"

sums='cd /w/$0 && find . -type f ! -name .rendered | sort | xargs sha256sum'
[ "$(as65532 "sh -c '$sums' src")" = "$(as65532 "sh -c '$sums' rendered")" ] || fail "rendered files differ from iam keys init's"
ok "rendered files are exactly iam keys init's"

modes="$(as65532 'find /w/rendered -type f ! -name .rendered -exec stat -c %a {} \; | sort -u')"
[ "$modes" = "640" ] || fail "rendered modes: $modes"
ok "every key file is 0640 (owner rewrites, group reads, others nothing)"

# Least privilege: the gateway's role cannot read iam's signing key, nor
# posture's anything but its own.
denied() { # denied <service> <path>
  as65532 "tok=\$(bao write -field=token auth/approle/login role_id=\$(cat /w/role-$1) secret_id=\$(cat /w/secret-$1)); BAO_TOKEN=\$tok bao kv get $2 >/dev/null 2>&1" && fail "$1 reads $2"
  return 0
}
denied gateway secret/fair/iam/login-ticket
denied posture secret/fair/gateway/secrets
denied iam secret/fair/gateway/jwt
ok "each service's role reads only its own keys"

# Rotation: a new JWT signing key, reloaded and rendered.
new="$(as65532 '/w/bin/iam keys rotate -dir /w/src -kind jwt' | sed -n 's/^added jwt key \([^;]*\);.*/\1/p')"
[ -n "$new" ] || fail "rotate printed no key id"
load gateway/jwt iam/jwt posture/jwt
render rendered # in place: the refresh a running sidecar does
as65532 '/w/bin/iam keys check -dir /w/rendered' >/dev/null || fail "rotated keys"
as65532 "grep -q 'PRIVATE KEY' /w/rendered/gateway/jwt/$new.pem && test -f /w/rendered/iam/jwt/$new.pem && test -f /w/rendered/posture/jwt/$new.pem" ||
  fail "the new key $new was not delivered"
ok "rotation: the new signing key $new is delivered and the set is consistent"

echo "openbao-e2e: all $passed checks passed"
