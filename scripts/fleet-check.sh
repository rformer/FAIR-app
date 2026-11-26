#!/usr/bin/env bash
# F-012 T-15 (F-012-AC-18; design §3.6): offline checks of the fleet's
# templates (CI job fleet). Renders deploy/k8s as a release artifact
# (releasegen fleet, placeholder digests), builds every directory of it and
# every kustomization of deploy/fleet, and validates the objects with
# kubeconform (strict: unknown fields fail) against the Kubernetes schemas
# and the CRD schemas of Flux, the policy-controller, External Secrets,
# cert-manager, the AWS Private CA issuer and the load balancer controller
# (datreeio/CRDs-catalog, pinned by commit). internal/fleet's tests check
# the rest offline (order, verification, pins, variables); the live checks
# are scripts/admission-e2e.sh's.
# Needs docker, kubectl, go. Run from the repository root.
set -euo pipefail
export MSYS_NO_PATHCONV=1
KUBECONFORM_IMAGE=ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e
CRDS_CATALOG=https://raw.githubusercontent.com/datreeio/CRDs-catalog/49729e49e8f062933e3716a26540d41b0cd0856c
TMP=$(mktemp -d)
if command -v cygpath >/dev/null; then TMP=$(cygpath -m "$TMP"); fi
trap 'rm -rf "$TMP"' EXIT

zero=$(printf '%064d' 0)
first=1
{
  printf '{'
  for c in iam gateway posture posture-scanner fips-probe audit risk notify integrate engine-gate engine; do
    [ $first = 1 ] || printf ', '
    first=0
    printf '"%s": "ghcr.io/rformer/fair-%s@sha256:%s"' "$c" "$c" "$zero"
  done
  printf '}\n'
} > "$TMP/images.json"
GOFIPS140=v1.0.0 go run ./cmd/releasegen fleet -release v0.0.0-check -images "$TMP/images.json" -out "$TMP/release"

mkdir -p "$TMP/built"
for d in namespaces secrets migrate platform observability; do
  kubectl kustomize "$TMP/release/$d" > "$TMP/built/release-$d.yaml"
done
for d in flux release-key addons addons-config policy instances/example; do
  kubectl kustomize "deploy/fleet/$d" > "$TMP/built/fleet-${d//\//-}.yaml"
done
docker run --rm -v "$TMP/built:/built:ro" "$KUBECONFORM_IMAGE" -strict -summary -output text \
  -schema-location default \
  -schema-location "$CRDS_CATALOG/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
  /built
echo "fleet check: PASS"
