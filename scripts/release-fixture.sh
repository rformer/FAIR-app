#!/usr/bin/env bash
# F-012 T-06: a fixture release for testing scripts/verify-release.sh. It is
# laid out as a real release, but signed with a throwaway test key, and its
# one image is a pinned public base image copied into a local registry.
#
#   scripts/release-fixture.sh OUT_DIR
#
# OUT_DIR gets release-manifest.json and .sig, cosign.pub, SHA256SUMS and
# .sig, and images/fixture/ ("cosign save": the image, its signature, an SPDX
# and an SLSA provenance attestation, all made with the test key and no
# transparency log). The key never leaves a temporary directory. Needs
# docker, cosign, openssl and releasegen (RELEASEGEN).
set -euo pipefail

OUT=${1:?out dir}
RELEASEGEN=${RELEASEGEN:-releasegen}
COSIGN=${COSIGN:-cosign}
REGISTRY_IMAGE=registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
BASE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
PORT=${FAIR_FIXTURE_REGISTRY_PORT:-5055}
K="$(mktemp -d)"
trap 'rm -rf "$K"; docker rm -f fair-fixture-registry >/dev/null 2>&1 || true' EXIT

mkdir -p "$OUT/images"
docker run -d --rm --name fair-fixture-registry -p "127.0.0.1:$PORT:5000" "$REGISTRY_IMAGE" >/dev/null
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PORT/v2/" >/dev/null && break; sleep 1; done

docker pull -q "$BASE" >/dev/null
docker tag "$BASE" "localhost:$PORT/fair-fixture:test"
docker push -q "localhost:$PORT/fair-fixture:test" >/dev/null
ref="$(docker inspect --format='{{index .RepoDigests 0}}' "localhost:$PORT/fair-fixture:test" | grep "localhost:$PORT" || true)"
[ -n "$ref" ] || ref="localhost:$PORT/fair-fixture@$(docker buildx imagetools inspect "localhost:$PORT/fair-fixture:test" | awk '/^Digest:/{print $2; exit}')"
digest="${ref#*@}"
ref="localhost:$PORT/fair-fixture@$digest"

# One test key, as PEM for releasegen and imported for cosign, as the KMS
# release key serves both.
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out "$K/release.pem"
openssl ec -in "$K/release.pem" -pubout -out "$OUT/cosign.pub" 2>/dev/null
(cd "$K" && COSIGN_PASSWORD="" $COSIGN import-key-pair --key release.pem --output-key-prefix release >/dev/null 2>&1)

export COSIGN_PASSWORD=""
$COSIGN sign --yes --key "$K/release.key" --tlog-upload=false --allow-insecure-registry "$ref" >/dev/null 2>&1
cat > "$K/spdx.json" <<EOF
{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "fair-fixture", "documentNamespace": "https://example.invalid/fair-fixture", "creationInfo": {"created": "2026-01-01T00:00:00Z", "creators": ["Tool: release-fixture"]}, "packages": []}
EOF
cat > "$K/slsa.json" <<EOF
{"buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1", "builder": {"id": "https://example.invalid/fixture"}, "invocation": {}, "materials": []}
EOF
$COSIGN attest --yes --key "$K/release.key" --tlog-upload=false --allow-insecure-registry --type spdxjson --predicate "$K/spdx.json" "$ref" >/dev/null 2>&1
$COSIGN attest --yes --key "$K/release.key" --tlog-upload=false --allow-insecure-registry --type slsaprovenance --predicate "$K/slsa.json" "$ref" >/dev/null 2>&1
$COSIGN save --allow-insecure-registry --dir "$OUT/images/fixture" "$ref" >/dev/null 2>&1

printf '{"fixture": "%s"}\n' "$ref" > "$K/images.json"
$RELEASEGEN manifest -release v0.0.0-fixture -images "$K/images.json" -out "$OUT/release-manifest.json"
$RELEASEGEN sign -key "$K/release.pem" -in "$OUT/release-manifest.json"
(cd "$OUT" && sha256sum release-manifest.json cosign.pub > SHA256SUMS)
$RELEASEGEN sign -any -key "$K/release.pem" -in "$OUT/SHA256SUMS"
echo "fixture release in $OUT ($ref)"
