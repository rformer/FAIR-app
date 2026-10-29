#!/usr/bin/env bash
# F-001 T-15/T-16 (AC-01): live SSO interop with Keycloak, the IdP bundled for
# self-hosted installs. Starts Keycloak on the DB test network, then runs
# db/tests TestSAMLKeycloakInterop and TestOIDCKeycloakInterop, which
# configure realms, a SAML client, an OIDC client (PKCE S256) and users
# through Keycloak's admin API and sign in through the gateway and the iam
# service (SAML SP- and IdP-initiated; OIDC authorization code).
#
# Needs the DB test containers (README: fairpg on the docker network
# fairtest) and the fair-dbtest image. Run from the repository root:
#   scripts/sso-e2e-keycloak.sh
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: do not rewrite container paths
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.0.7}
NET=${NET:-fairtest}
NAME=fair-keycloak-e2e
PW=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')
SRC=$(pwd)
if command -v cygpath >/dev/null; then SRC=$(cygpath -m "$SRC"); fi
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

cleanup
docker run -d --name "$NAME" --network "$NET" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$PW" \
  -e KC_HOSTNAME="http://$NAME:8080" -e KC_HTTP_ENABLED=true \
  "$KEYCLOAK_IMAGE" start-dev >/dev/null
echo "== Keycloak $KEYCLOAK_IMAGE starting"

docker run --rm --network "$NET" -v "$SRC:/src" -v fair-gocache:/root/.cache -v fair-gomod:/go/pkg/mod -w /src \
  -e PGHOST=fairpg -e PGUSER=postgres -e PGPASSWORD="${PGPASSWORD:-pgtest}" -e FAIR_TEST_PG=1 -e GOFLAGS=-buildvcs=false \
  -e GOFIPS140=v1.0.0 -e FAIR_TEST_KEYCLOAK="http://$NAME:8080" -e FAIR_TEST_KEYCLOAK_ADMIN_PASSWORD="$PW" \
  fair-dbtest go test -count=1 -v -run 'TestSAMLKeycloakInterop|TestOIDCKeycloakInterop' ./db/tests/
