#!/usr/bin/env bash
# F-012 T-06 (F-012-AC-08, AC-09; design §3.3): verify a FAIR release.
#
#   scripts/verify-release.sh [-offline] RELEASE_DIR
#
# RELEASE_DIR holds the release as published (and as the air-gapped bundle
# carries it, F-014): release-manifest.json and .sig, cosign.pub (the
# release key), optionally SHA256SUMS and .sig, and for -offline the images
# with their signatures and attestations as cosign directories
# (images/<component>/, from "cosign save").
#
# Every run checks, with the release key alone:
#   - the release manifest's signature (releasegen verify);
#   - SHA256SUMS's signature and every file it lists;
#   - for each image the manifest names: its signature, its SPDX SBOM
#     attestation and its SLSA provenance attestation, and that what was
#     verified is the digest the manifest names.
# -offline reads only RELEASE_DIR: images from images/<component>/, no
# transparency log, no network. Online, images come from their registry, and
# the keyless signature is also checked against the release workflow's
# identity (FAIR_RELEASE_IDENTITY, a regular expression; default this
# repository's release workflow on a v* tag).
#
# Needs cosign (2.5 or later) and releasegen (RELEASEGEN, default
# "releasegen"; "go run ./cmd/releasegen" from a checkout). Exit 0 when all
# pass, 1 on the first failure. docs/security/verify.md explains each step.
set -euo pipefail

OFFLINE=0
if [ "${1:-}" = "-offline" ]; then OFFLINE=1; shift; fi
DIR=${1:?usage: verify-release.sh [-offline] RELEASE_DIR}
RELEASEGEN=${RELEASEGEN:-releasegen}
COSIGN=${COSIGN:-cosign}
IDENTITY=${FAIR_RELEASE_IDENTITY:-'^https://github\.com/rformer/FAIR-app/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'}
ISSUER=https://token.actions.githubusercontent.com
PUB="$DIR/cosign.pub"

fail() { echo "FAIL - $*" >&2; exit 1; }
ok() { echo "ok - $*"; }

[ -f "$PUB" ] || fail "no cosign.pub in $DIR"
[ -f "$DIR/release-manifest.json.sig" ] || fail "no release-manifest.json.sig in $DIR"

images="$($RELEASEGEN verify -pub "$PUB" -in "$DIR/release-manifest.json" -list 2>/dev/null)" \
  || fail "release-manifest.json: the signature does not verify with cosign.pub"
images="$(printf '%s\n' "$images" | tr -d '\r')"
[ -n "$images" ] || fail "release-manifest.json names no images"
ok "release manifest signed by the release key"

if [ -f "$DIR/SHA256SUMS" ]; then
  $RELEASEGEN verify -any -pub "$PUB" -in "$DIR/SHA256SUMS" 2>/dev/null || fail "SHA256SUMS: the signature does not verify"
  (cd "$DIR" && sha256sum --quiet --strict -c SHA256SUMS) || fail "SHA256SUMS: a file does not match"
  ok "SHA256SUMS signed, and every file it lists matches"
fi

# The digest cosign verified, from its JSON output.
verified_digest() {
  sed -n 's/.*"docker-manifest-digest":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' | head -1
}

while read -r component ref; do
  [ -n "$component" ] || continue
  want="${ref#*@}"
  if [ "$OFFLINE" = 1 ]; then
    local_dir="$DIR/images/$component"
    [ -d "$local_dir" ] || fail "$component: no images/$component in the release"
    target=(--local-image "$local_dir")
    flags=(--key "$PUB" --offline --insecure-ignore-tlog)
  else
    target=("$ref")
    flags=(--key "$PUB")
  fi
  got="$($COSIGN verify "${flags[@]}" "${target[@]}" -o json 2>/dev/null | verified_digest)" \
    || fail "$component: the release key's signature does not verify"
  [ "$got" = "$want" ] || fail "$component: verified ${got:-nothing}, the manifest names $want"
  for type in spdxjson slsaprovenance; do
    $COSIGN verify-attestation "${flags[@]}" --type "$type" "${target[@]}" >/dev/null 2>&1 \
      || fail "$component: no $type attestation verifies with the release key"
  done
  if [ "$OFFLINE" = 0 ]; then
    $COSIGN verify --certificate-identity-regexp "$IDENTITY" --certificate-oidc-issuer "$ISSUER" "$ref" >/dev/null 2>&1 \
      || fail "$component: no keyless signature from the release workflow"
  fi
  ok "$component $want: signed, SBOM and provenance attested"
done <<< "$images"

echo "release verified$([ "$OFFLINE" = 1 ] && echo ' (offline)')"
