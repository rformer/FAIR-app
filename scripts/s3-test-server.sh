#!/usr/bin/env bash
# F-002 T-08: an S3-compatible test server with Object Lock, over TLS, for
# the object storage contract tests (internal/objstore). versitygw (ADR-012:
# MinIO no longer publishes images) is test infrastructure only.
#
#   eval "$(scripts/s3-test-server.sh start)"   # exports FAIR_TEST_S3*
#   go test ./internal/objstore/
#   scripts/s3-test-server.sh stop
#
# NETWORK (optional) runs it on a docker network instead of publishing a
# port; ENDPOINT_HOST then names it (default fair-s3).
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep -subj and container paths as written

IMAGE=versity/versitygw:v1.9.0@sha256:eb7f786fcd91e72194e48fcf1ac16302d686bf8e3a71434bdbc067a6efd3fdc7
NAME=${NAME:-fair-s3}
PORT=${PORT:-7070}
DIR=${DIR:-${TMPDIR:-/tmp}/fair-s3-test}

case "${1:-}" in
start)
  mkdir -p "$DIR"
  chmod 700 "$DIR"
  host=${ENDPOINT_HOST:-localhost}
  [ -n "${NETWORK:-}" ] && host=${ENDPOINT_HOST:-$NAME}
  # A throwaway CA and server certificate for the test server only.
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj "/CN=fair-s3-test-ca" \
    -keyout "$DIR/ca.key" -out "$DIR/ca.pem" >/dev/null 2>&1
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$host" \
    -keyout "$DIR/key.pem" -out "$DIR/cert.csr" >/dev/null 2>&1
  printf 'subjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1\n' "$host" > "$DIR/san.ext"
  openssl x509 -req -in "$DIR/cert.csr" -CA "$DIR/ca.pem" -CAkey "$DIR/ca.key" -CAcreateserial -days 1 \
    -extfile "$DIR/san.ext" -out "$DIR/cert.pem" >/dev/null 2>&1
  chmod 644 "$DIR/cert.pem" "$DIR/key.pem" "$DIR/ca.pem"
  access=fairtest$(openssl rand -hex 4)
  secret=$(openssl rand -hex 16)
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  net=(-p "127.0.0.1:$PORT:7070")
  [ -n "${NETWORK:-}" ] && net=(--network "$NETWORK")
  MSYS_NO_PATHCONV=1 docker run -d --name "$NAME" "${net[@]}" -e ROOT_ACCESS_KEY="$access" -e ROOT_SECRET_KEY="$secret" \
    -v "$DIR:/certs:ro" --entrypoint sh "$IMAGE" \
    -c 'mkdir -p /tmp/gw /tmp/ver && exec versitygw --port :7070 --cert /certs/cert.pem --key /certs/key.pem posix --versioning-dir /tmp/ver /tmp/gw' >/dev/null
  for _ in $(seq 1 30); do
    if docker logs "$NAME" 2>&1 | grep -qi "listening\|started\|7070"; then break; fi
    sleep 1
  done
  echo "export FAIR_TEST_S3=1 FAIR_TEST_S3_ENDPOINT=$host:$PORT FAIR_TEST_S3_ACCESS_KEY=$access FAIR_TEST_S3_SECRET_KEY=$secret FAIR_TEST_S3_CA_FILE=$DIR/ca.pem"
  ;;
stop)
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$DIR"
  ;;
*)
  echo "usage: $0 start|stop" >&2
  exit 2
  ;;
esac
