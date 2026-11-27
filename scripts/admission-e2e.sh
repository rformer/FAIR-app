#!/usr/bin/env bash
# F-012 T-15 verification (F-012-AC-18, AC-19; design §3.6, STRIDE "a
# forged or swapped image runs in SaaS"): the fleet's templates on a kind
# cluster, with a stand-in release built here.
#
#   * a local registry (on kind's network) holds a fixture "release": one
#     image signed with a throwaway release key and attested with SLSA
#     provenance from this repository's release workflow, and copies of it
#     that are unsigned, signed by another key, attested from another
#     source, without provenance, or in another repository; the Collector
#     (deploy/third-party-images.json) verified against its publisher's
#     exact identity, mirrored and re-signed with the release key, beside an
#     unsigned and an other-key copy; the release's
#     manifests rendered by releasegen fleet (internal/fleet/testdata/e2e)
#     and pushed as a signed OCI artifact, plus an unsigned and an
#     other-key copy;
#   * Flux (pinned by digest) and the instance's Flux objects from
#     deploy/fleet (flux/, release-key/, policy/, the policy-controller's
#     HelmRelease from addons/), with an e2e instance overlay; the fleet
#     repository itself is stood in for by an OCI artifact;
#   * asserts: every step reconciles in order (policy before namespaces,
#     the migration Job complete before the services), the release
#     artifact's signature verified, instance values substituted; the
#     signed image and the re-signed mirrored Collector admitted, every
#     other one (the publisher's original included) refused; an unsigned or
#     other-key artifact refused by Flux, and the instance keeps its release
#     when its pin moves to one;
#   * the real deploy/k8s rendered as a release and built by
#     `flux build kustomization --strict-substitute` with the example
#     instance's values: every placeholder filled.
# Needs docker, kind, kubectl, go. Run from the repository root:
#   scripts/admission-e2e.sh            (KEEP=1 keeps the cluster)
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: do not rewrite container paths
CLUSTER=${CLUSTER:-fair-admission-e2e}
NODE_IMAGE=${NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
REGISTRY_IMAGE=registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e
CRANE_IMAGE=gcr.io/go-containerregistry/crane:v0.22.1@sha256:1f968817b95790bed063f71175aa6b8ff879fa17064020415f3e18bb6e6a36e1
COSIGN_IMAGE=ghcr.io/sigstore/cosign/cosign:v2.5.2@sha256:23d07b53d59a1233e1ab5e7d082cf4182fc90067d2f86a662ba3003215cb0c95
# Reads publishers' Sigstore bundle signatures (2.5 does not), as release.yml.
COSIGN26_IMAGE=ghcr.io/sigstore/cosign/cosign:v2.6.4@sha256:278d0b6c728608731d8fa2123c00c8b8dd6207aa53f079b195dea906b29ab0b2
FLUX_IMAGE=ghcr.io/fluxcd/flux-cli:v2.10.0@sha256:1a5178b1770052d6e88ab1c7c8434c5ac9bca8a8ab984dcaf6b9df31814ce9f2
# The controllers `flux install` of that CLI names, by digest.
SOURCE_CONTROLLER_IMAGE=ghcr.io/fluxcd/source-controller:v1.10.1@sha256:611b6bca3eae95bcff471414d1fb14a4ab83d7f14e609cccef2bd389c121f37e
KUSTOMIZE_CONTROLLER_IMAGE=ghcr.io/fluxcd/kustomize-controller:v1.10.1@sha256:37db29b25dae35b881a5e064acedb0cc954442da453a39eaa0eab7a90dbecc4e
NOTIFICATION_CONTROLLER_IMAGE=ghcr.io/fluxcd/notification-controller:v1.10.0@sha256:9f58b9532ec9d3ccf539cd3ccdf283477a5dcb7777b922db5477d8bbd4d3767c
HELM_CONTROLLER_IMAGE=ghcr.io/fluxcd/helm-controller:v1.7.1@sha256:54526cc6ed1202d71d44c310676448065664f3255ad671d9a69ac26f904e617a
# The fixture image (one manifest of it, linux/amd64).
FIXTURE_IMAGE=busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
# The third-party image and its publisher, as the release mirrors them.
third() { sed -n "s/.*\"$1\": \"\([^\"]*\)\".*/\1/p" deploy/third-party-images.json | head -1; }
COLLECTOR_IMAGE=$(third image)
COLLECTOR_NAME=$(third name)
PUBLISHER_ID=$(third certificate_identity)
PUBLISHER_ISSUER=$(third certificate_oidc_issuer)
REG_NAME=$CLUSTER-registry
K="kubectl --context kind-$CLUSTER"
TMP=$(mktemp -d)
if command -v cygpath >/dev/null; then TMP=$(cygpath -m "$TMP"); fi # Windows tools need a native path
fail=0
pass() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fail=1; }
cleanup() {
  if [ "${KEEP:-}" != 1 ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
    docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
# Tools run pinned, in containers on kind's network, with $TMP as /work, as
# this user (the images run as non-root users that cannot read mktemp's
# private directory) with /work as their home.
run() { docker run --rm --network kind --user "$(id -u):$(id -g)" -e HOME=/work -v "$TMP:/work" -w /work "$@"; }
cosign() { run -e COSIGN_PASSWORD= -e COSIGN_YES=true --entrypoint cosign "$COSIGN_IMAGE" "$@"; }
cosign26() { run --entrypoint cosign "$COSIGN26_IMAGE" "$@"; }
crane() { run --entrypoint crane "$CRANE_IMAGE" "$@"; }
flux() { run -e KUBECONFIG=/work/kubeconfig --entrypoint flux "$FLUX_IMAGE" "$@"; }
wait_ready() { # kind name timeout
  $K -n flux-system wait "$1/$2" --for=condition=Ready --timeout="$3"
}

echo "== cluster and registry"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
cat > "$TMP/kind.yaml" <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --config "$TMP/kind.yaml" --wait 180s
kind get kubeconfig --internal --name "$CLUSTER" > "$TMP/kubeconfig"
docker run -d --name "$REG_NAME" --network kind --restart=no "$REGISTRY_IMAGE" >/dev/null
REG_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$REG_NAME")
# By its private address: the policy-controller and cosign then use plain
# HTTP (go-containerregistry does for RFC 1918 hosts), and so do the nodes.
REG=$REG_IP:5000
for n in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$n" sh -c "mkdir -p /etc/containerd/certs.d/$REG && printf '[host.\"http://$REG\"]\n  capabilities = [\"pull\", \"resolve\"]\n' > /etc/containerd/certs.d/$REG/hosts.toml"
done
echo "registry $REG"

echo "== the fixture release: images, keys, signatures, provenance"
for repo in fair/fair-iam fair/fair-unsigned fair/fair-otherkey fair/fair-wrongsource fair/fair-noprovenance other/fair-iam; do
  crane copy --platform linux/amd64 "$FIXTURE_IMAGE" "$REG/$repo:e2e" >/dev/null
done
DIGEST=$(crane digest "$REG/fair/fair-iam:e2e" | tr -d '\r')
img() { echo "$REG/$1@$DIGEST"; }
(cd "$TMP" && cosign generate-key-pair --output-key-prefix release >/dev/null && cosign generate-key-pair --output-key-prefix other >/dev/null)
provenance() { # source-uri file
  cat > "$TMP/$2" <<EOF
{
  "builder": {"id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0"},
  "buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1",
  "invocation": {"configSource": {"uri": "$1", "digest": {"sha1": "0000000000000000000000000000000000000000"}, "entryPoint": ".github/workflows/release.yml"}}
}
EOF
}
provenance "git+https://github.com/rformer/FAIR-app@refs/tags/v0.0.1-e2e" slsa.json
provenance "git+https://github.com/someone-else/FAIR-app@refs/tags/v0.0.1-e2e" slsa-wrong.json
sign() { # key image [provenance]
  cosign sign --key "$1.key" --tlog-upload=false "$2" >/dev/null 2>&1
  if [ -n "${3:-}" ]; then
    cosign attest --key "$1.key" --tlog-upload=false --type slsaprovenance --predicate "$3" "$2" >/dev/null 2>&1
  fi
}
sign release "$(img fair/fair-iam)" slsa.json
sign other "$(img fair/fair-otherkey)" slsa.json
sign release "$(img fair/fair-wrongsource)" slsa-wrong.json
sign release "$(img fair/fair-noprovenance)"
sign release "$(img other/fair-iam)" slsa.json
cosign verify --key release.pub --insecure-ignore-tlog "$(img fair/fair-iam)" >/dev/null 2>&1 && echo "signed $(img fair/fair-iam)"

echo "== the third-party image: publisher verified, mirrored by digest, re-signed (as release.yml)"
src="${COLLECTOR_IMAGE%@*}"; src="${src%:*}@${COLLECTOR_IMAGE#*@}"
if cosign26 verify --certificate-identity "$PUBLISHER_ID" --certificate-oidc-issuer "$PUBLISHER_ISSUER" "$src" >/dev/null 2>&1; then
  pass "$COLLECTOR_IMAGE verified against its publisher ($PUBLISHER_ID)"
else bad "$COLLECTOR_IMAGE does not verify against $PUBLISHER_ID"; fi
if cosign26 verify --certificate-identity "${PUBLISHER_ID/v0./v9.}" --certificate-oidc-issuer "$PUBLISHER_ISSUER" "$src" >/dev/null 2>&1; then
  bad "the publisher check accepts another identity"
else pass "control: the publisher check refuses another identity"; fi
# One platform here (the release copies the whole index by digest).
for repo in "mirror/$COLLECTOR_NAME" mirror/otel-unsigned mirror/otel-otherkey; do
  crane copy --platform linux/amd64 "$src" "$REG/$repo:e2e" >/dev/null
done
MIRROR_DIGEST=$(crane digest "$REG/mirror/$COLLECTOR_NAME:e2e" | tr -d '\r')
mirrored() { echo "$REG/$1@$MIRROR_DIGEST"; }
sign release "$(mirrored "mirror/$COLLECTOR_NAME")"
sign other "$(mirrored mirror/otel-otherkey)"

echo "== the release's manifests: rendered, pushed, signed"
printf '{"iam": "%s"}\n' "$(img fair/fair-iam)" > "$TMP/images.json"
GOFIPS140=v1.0.0 go run ./cmd/releasegen fleet -release v0.0.1-e2e -images "$TMP/images.json" \
  -deploy internal/fleet/testdata/e2e/k8s -keys internal/fleet/testdata/e2e/keys \
  -observability internal/fleet/testdata/e2e/observability -third-party "" -out "$TMP/artifact"
push() { # dir tag revision -> digest
  flux push artifact "oci://$REG/fair/fair-manifests:$2" --path="/work/$1" --source=https://github.com/rformer/FAIR-app \
    --revision="$3" --reproducible --insecure-registry 2>&1 | sed -n 's/.*@\(sha256:[0-9a-f]*\).*/\1/p' | tail -1
}
REL=$(push artifact v0.0.1-e2e "v0.0.1-e2e@sha1:0000000000000000000000000000000000000001")
cosign sign --key release.key --tlog-upload=false "$REG/fair/fair-manifests@$REL" >/dev/null 2>&1
# The same files as another revision: a different digest, never signed;
# and one signed by another key.
push artifact unsigned "v0.0.1-e2e@sha1:0000000000000000000000000000000000000002" >/dev/null
OTHER=$(push artifact otherkey "v0.0.1-e2e@sha1:0000000000000000000000000000000000000003")
cosign sign --key other.key --tlog-upload=false "$REG/fair/fair-manifests@$OTHER" >/dev/null 2>&1
echo "release artifact $REG/fair/fair-manifests:v0.0.1-e2e@$REL"

echo "== the fleet repository's stand-in (deploy/fleet as an OCI artifact)"
cp -r deploy/fleet "$TMP/fleet"
cp "$TMP/release.pub" "$TMP/fleet/release-key/cosign.pub"
# The add-ons a kind cluster can run: the policy-controller (its real
# HelmRelease); the AWS-bound ones are not installed here.
cat > "$TMP/fleet/addons/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [repositories.yaml, policy-controller.yaml]
EOF
cat > "$TMP/fleet/addons-config/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [stand-in.yaml]
EOF
cat > "$TMP/fleet/addons-config/stand-in.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata: { name: e2e-addons-config, namespace: fair-platform }
data: { region: "${FAIR_REGION}" }
EOF
flux push artifact "oci://$REG/fair-e2e/fleet:e2e" --path=/work/fleet --source=https://example.invalid/fleet \
  --revision="main@sha1:0000000000000000000000000000000000000004" --reproducible --insecure-registry >/dev/null 2>&1
mkdir -p "$TMP/fleet/instances/e2e"
sed -e "s#^FAIR_INSTANCE=.*#FAIR_INSTANCE=e2e#" -e "s#^FAIR_DB_HOST=.*#FAIR_DB_HOST=db.e2e.invalid#" \
    -e "s#^FAIR_RELEASE_IMAGES=.*#FAIR_RELEASE_IMAGES=$REG/fair/fair-*#" \
    -e "s#^FAIR_MIRROR_IMAGES=.*#FAIR_MIRROR_IMAGES=$REG/mirror/*#" \
    deploy/fleet/instances/example/instance.env > "$TMP/fleet/instances/e2e/instance.env"
cat > "$TMP/fleet/instances/e2e/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: [../../release-key, ../../flux, fleet-source.yaml]
generatorOptions: { disableNameSuffixHash: true }
configMapGenerator:
  - { name: fair-instance, namespace: flux-system, envs: [instance.env] }
secretGenerator:
  - { name: fair-ops-events, namespace: flux-system, literals: [token=e2e-only] }
patches:
  - target: { kind: OCIRepository, name: fair-release }
    patch: |
      - { op: replace, path: /spec/url, value: "oci://$REG/fair/fair-manifests" }
      - { op: replace, path: /spec/ref/tag, value: v0.0.1-e2e }
      - { op: add, path: /spec/insecure, value: true }
      - { op: replace, path: /spec/interval, value: 1m }
  # The fleet repository: an OCI artifact here, the instance's Git source in SaaS.
  - target: { kind: Kustomization, name: "fair-addons|fair-policy|fair-addons-config" }
    patch: |
      - { op: replace, path: /spec/sourceRef, value: { kind: OCIRepository, name: flux-system } }
  - target: { kind: Kustomization }
    patch: |
      - { op: replace, path: /spec/interval, value: 1m }
  - target: { kind: Provider, name: fair-ops }
    patch: |
      - { op: replace, path: /spec/address, value: "https://events.e2e.invalid/flux/events" }
EOF
cat > "$TMP/fleet/instances/e2e/fleet-source.yaml" <<EOF
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata: { name: flux-system, namespace: flux-system }
spec:
  interval: 1m
  url: oci://$REG/fair-e2e/fleet
  ref: { tag: e2e }
  insecure: true
EOF

echo "== Flux (strict post-build substitution, as in SaaS)"
flux install --export --components=source-controller,kustomize-controller,notification-controller,helm-controller > "$TMP/flux.yaml"
sed -i -e "s#ghcr.io/fluxcd/source-controller:v[0-9.]*#$SOURCE_CONTROLLER_IMAGE#" \
       -e "s#ghcr.io/fluxcd/kustomize-controller:v[0-9.]*#$KUSTOMIZE_CONTROLLER_IMAGE#" \
       -e "s#ghcr.io/fluxcd/notification-controller:v[0-9.]*#$NOTIFICATION_CONTROLLER_IMAGE#" \
       -e "s#ghcr.io/fluxcd/helm-controller:v[0-9.]*#$HELM_CONTROLLER_IMAGE#" "$TMP/flux.yaml"
if grep -E 'image: ghcr.io/fluxcd/[a-z-]+:' "$TMP/flux.yaml" | grep -v '@sha256:'; then echo "a Flux image is not pinned by digest" >&2; exit 2; fi
$K apply --server-side -f "$TMP/flux.yaml" >/dev/null
$K -n flux-system patch deployment kustomize-controller --type=json \
  -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--feature-gates=StrictPostBuildSubstitutions=true"}]' >/dev/null
for d in source-controller kustomize-controller notification-controller helm-controller; do
  $K -n flux-system rollout status "deployment/$d" --timeout=180s >/dev/null
done

echo "== the instance (deploy/fleet/flux, release-key, policy, addons)"
$K kustomize "$TMP/fleet/instances/e2e" > "$TMP/instance.yaml"
$K apply -f "$TMP/instance.yaml" >/dev/null
for k in fair-addons fair-policy fair-namespaces fair-addons-config fair-secrets fair-migrate fair-platform fair-observability; do
  if wait_ready kustomization "$k" 600s >/dev/null 2>&1; then pass "Flux reconciled $k"; else
    bad "Flux did not reconcile $k"
    $K -n flux-system get kustomization "$k" -o jsonpath='{.status.conditions}'; echo
  fi
done

echo "== 1. Flux: the release's signature, order, substitution"
cond() { $K -n flux-system get "$1" -o jsonpath="{.status.conditions[?(@.type==\"$2\")].$3}"; }
if [ "$(cond ocirepository/fair-release SourceVerified status)" = True ]; then
  pass "release artifact verified with the release key ($(cond ocirepository/fair-release SourceVerified message))"
else bad "release artifact not verified"; fi
rev=$($K -n flux-system get kustomization fair-platform -o jsonpath='{.status.lastAppliedRevision}')
case "$rev" in *"$REL"*) pass "fair-platform applied $rev" ;; *) bad "fair-platform revision $rev, want $REL" ;; esac
done_at=$($K -n fair-platform get job iam-migrate -o jsonpath='{.status.completionTime}')
created=$($K -n fair-platform get deployment iam -o jsonpath='{.metadata.creationTimestamp}')
if [ -n "$done_at" ] && [[ ! "$created" < "$done_at" ]]; then pass "migration complete ($done_at) before the services ($created)"; else bad "migration $done_at, services $created"; fi
if [ -z "$($K -n fair-platform get job iam-migrate -o jsonpath='{.spec.ttlSecondsAfterFinished}')" ]; then pass "the migration Job has no TTL (Flux owns it)"; else bad "the migration Job keeps a TTL"; fi
ns_t=$($K get namespace fair-platform -o jsonpath='{.metadata.creationTimestamp}')
pol_t=$($K get clusterimagepolicy fair-release -o jsonpath='{.metadata.creationTimestamp}')
if [[ ! "$ns_t" < "$pol_t" ]]; then pass "admission policy ($pol_t) before the platform namespace ($ns_t)"; else bad "namespace $ns_t before policy $pol_t"; fi
[ "$($K get namespace fair-platform -o jsonpath='{.metadata.labels.policy\.sigstore\.dev/include}')" = true ] \
  && pass "fair-platform enforced by the policy-controller" || bad "fair-platform not labelled for admission"
env_of() { $K -n fair-platform get deployment iam -o jsonpath="{.spec.template.spec.containers[0].env[?(@.name==\"$1\")].value}"; }
[ "$(env_of PGHOST)" = db.e2e.invalid ] && pass "instance value substituted (PGHOST)" || bad "PGHOST $(env_of PGHOST)"
[ "$(env_of FAIR_DEPLOYMENT_MODE)" = saas ] && pass "deployment mode saas" || bad "mode $(env_of FAIR_DEPLOYMENT_MODE)"
[ "$($K -n fair-platform get deployment iam -o jsonpath='{.spec.template.spec.containers[0].image}')" = "$(img fair/fair-iam)" ] \
  && pass "the service runs the release's image by digest" || bad "the service's image"
case "$($K -n fair-platform get configmap otelcol-saas -o jsonpath='{.data.config\.yaml}')" in
  *'${env:FAIR_INSTANCE}'*) pass "Collector configuration left to the Collector (no Flux substitution)" ;;
  *) bad "Collector configuration substituted" ;;
esac
$K -n fair-platform rollout status deployment/iam --timeout=120s >/dev/null && pass "the service is running" || bad "the service is not running"

echo "== 2. admission (policy-controller, deploy/fleet/policy)"
pod() { # namespace image -> server dry-run output
  cat > "$TMP/pod.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata: { name: probe, namespace: $1 }
spec:
  automountServiceAccountToken: false
  securityContext: { runAsNonRoot: true, runAsUser: 65532, seccompProfile: { type: RuntimeDefault } }
  containers:
    - name: probe
      image: $2
      command: ["sleep", "60"]
      securityContext: { allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] } }
EOF
  $K apply --dry-run=server -f "$TMP/pod.yaml" 2>&1
}
admitted() { # what namespace image
  if out=$(pod "$2" "$3"); then pass "admitted: $1"; else bad "refused: $1: $out"; fi
}
refused() { # what namespace image
  if out=$(pod "$2" "$3"); then bad "ADMITTED: $1"; else pass "refused: $1 ($(echo "$out" | tr '\n' ' ' | cut -c1-160))"; fi
}
admitted "the signed release image with its provenance" fair-platform "$(img fair/fair-iam)"
refused "an unsigned image of the release repository" fair-platform "$(img fair/fair-unsigned)"
refused "an image signed by another key" fair-platform "$(img fair/fair-otherkey)"
refused "provenance from another source" fair-platform "$(img fair/fair-wrongsource)"
refused "a signed image without provenance" fair-platform "$(img fair/fair-noprovenance)"
refused "a signed, attested image from another repository" fair-platform "$(img other/fair-iam)"
refused "an image by tag from a public registry" fair-platform "$FIXTURE_IMAGE"
# Third-party images run only as mirrored, release-key-signed copies
# (deploy/fleet/policy/mirror.yaml).
admitted "the mirrored Collector, re-signed with the release key" fair-platform "$(mirrored "mirror/$COLLECTOR_NAME")"
admitted "the mirrored Collector in the log agent's namespace" fair-observability "$(mirrored "mirror/$COLLECTOR_NAME")"
refused "the publisher's original Collector (not re-signed)" fair-platform "$COLLECTOR_IMAGE"
refused "a mirrored copy left unsigned" fair-platform "$(mirrored mirror/otel-unsigned)"
refused "a mirrored copy signed by another key" fair-platform "$(mirrored mirror/otel-otherkey)"
refused "another third-party image in the Collector's namespace" fair-observability "$FIXTURE_IMAGE"
$K create namespace fair-e2e-unenforced >/dev/null
admitted "control: an unsigned image outside the platform's namespaces" fair-e2e-unenforced "$(img fair/fair-unsigned)"
webhook_fp=$($K get validatingwebhookconfiguration policy.sigstore.dev -o jsonpath='{.webhooks[*].failurePolicy}')
case "$webhook_fp" in *Ignore*) bad "a webhook fails open ($webhook_fp)" ;; *) pass "webhooks fail closed ($webhook_fp)" ;; esac

echo "== 3. Flux refuses an unsigned or other-key release artifact"
for tag in unsigned otherkey; do
  cat <<EOF | $K apply -f - >/dev/null
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata: { name: e2e-$tag, namespace: flux-system }
spec:
  interval: 1m
  url: oci://$REG/fair/fair-manifests
  ref: { tag: $tag }
  insecure: true
  verify: { provider: cosign, secretRef: { name: fair-release-key } }
EOF
done
for tag in unsigned otherkey; do
  r=""
  for _ in $(seq 1 30); do
    r=$(cond "ocirepository/e2e-$tag" Ready reason)
    [ -n "$r" ] && [ "$r" != Progressing ] && break
    sleep 2
  done
  art=$($K -n flux-system get "ocirepository/e2e-$tag" -o jsonpath='{.status.artifact.digest}')
  st=$(cond "ocirepository/e2e-$tag" Ready status)
  # Refused: no artifact stored, and Ready false or a verification error
  # (the reason can be set before the status turns False).
  if [ -z "$art" ] && { [ "$st" = False ] || [ "$r" = VerificationError ]; }; then
    pass "Flux refused the $tag artifact ($r: $(cond "ocirepository/e2e-$tag" Ready message | cut -c1-120))"
  else bad "Flux accepted the $tag artifact (Ready $st, $r, artifact ${art:-none})"; fi
done
# The instance's pin moved to the unsigned artifact: nothing changes.
$K -n flux-system patch ocirepository fair-release --type=merge -p '{"spec":{"ref":{"tag":"unsigned"}}}' >/dev/null
$K -n flux-system annotate ocirepository fair-release reconcile.fluxcd.io/requestedAt="$(date +%s)" --overwrite >/dev/null
for _ in $(seq 1 30); do
  [ "$(cond ocirepository/fair-release Ready status)" = False ] && break
  sleep 2
done
if [ "$(cond ocirepository/fair-release Ready status)" = False ]; then pass "pin to an unsigned artifact: the source refuses it"; else bad "the source took the unsigned pin"; fi
rev=$($K -n flux-system get kustomization fair-platform -o jsonpath='{.status.lastAppliedRevision}')
case "$rev" in *"$REL"*) pass "the instance keeps the signed release ($rev)" ;; *) bad "fair-platform moved to $rev" ;; esac

echo "== 4. the real release: deploy/k8s rendered and built with the example instance"
real_images=$(printf '"%s": "ghcr.io/rformer/fair-%s@sha256:%064d"' iam iam 0)
for c in gateway posture posture-scanner fips-probe audit risk notify integrate engine-gate engine; do
  real_images="$real_images, $(printf '"%s": "ghcr.io/rformer/fair-%s@sha256:%064d"' "$c" "$c" 0)"
done
echo "{$real_images}" > "$TMP/real-images.json"
GOFIPS140=v1.0.0 go run ./cmd/releasegen fleet -release v0.0.0-e2e -images "$TMP/real-images.json" -mirror-prefix ghcr.io/rformer/mirror -out "$TMP/real"
$K create namespace fair-e2e-build >/dev/null
$K -n fair-e2e-build create configmap fair-instance --from-env-file=deploy/fleet/instances/example/instance.env >/dev/null
$K kustomize deploy/fleet/flux > "$TMP/flux-objects.yaml"
build_ok=1
for k in fair-namespaces fair-secrets fair-migrate fair-platform fair-observability; do
  awk -v k="$k" 'BEGIN{RS="---\n"} $0 ~ "kind: Kustomization" && $0 ~ "\n  name: " k "\n" {print}' "$TMP/flux-objects.yaml" \
    | sed -e 's/namespace: flux-system/namespace: fair-e2e-build/' -e 's/^spec:$/spec:\n  suspend: true/' > "$TMP/ks-$k.yaml"
  $K apply -f "$TMP/ks-$k.yaml" >/dev/null # suspended: flux build reads the object
  dir=$(sed -n 's#^  path: \./##p' "$TMP/ks-$k.yaml")
  if ! flux build kustomization "$k" -n fair-e2e-build --path "/work/real/$dir" --kustomization-file "/work/ks-$k.yaml" \
      --strict-substitute > "$TMP/built-$k.yaml" 2> "$TMP/built-$k.err"; then
    bad "flux build $k: $(head -c 400 "$TMP/built-$k.err")"; build_ok=0; continue
  fi
  left=$(grep -v '^\s*#' "$TMP/built-$k.yaml" | grep -o 'REPLACE_WITH_[A-Z_]*' | sort -u | tr '\n' ' ' || true)
  vars=$(grep -v 'substitute: disabled' "$TMP/built-$k.yaml" | grep -o '\${[A-Za-z_][A-Za-z0-9_]*}' | sort -u | tr '\n' ' ' || true)
  if [ -n "$left$vars" ]; then bad "$k: unfilled $left$vars"; build_ok=0; fi
done
[ $build_ok = 1 ] && pass "every step of the real release builds with every placeholder filled"
grep -q 'FAIR_AUDIT_STORE_CREDENTIALS' "$TMP/built-fair-platform.yaml" && ! grep -q 'FAIR_AUDIT_STORE_ACCESS_KEY_FILE' "$TMP/built-fair-platform.yaml" \
  && pass "SaaS stores: web-identity credentials, no key files" || bad "SaaS store patches"
grep -q "image: ghcr.io/rformer/mirror/$COLLECTOR_NAME@${COLLECTOR_IMAGE#*@}" "$TMP/built-fair-observability.yaml" \
  && ! grep -q "image: ${COLLECTOR_IMAGE%%:*}" "$TMP/built-fair-observability.yaml" \
  && pass "the release runs the Collector's mirrored copy" || bad "the Collector's image in the real release"
grep -q 'eks.amazonaws.com/role-arn: arn:aws-us-gov:iam::111122223333:role/fair-example-audit' "$TMP/built-fair-platform.yaml" \
  && pass "IRSA annotations from the instance" || bad "IRSA annotations"

echo
if [ $fail = 0 ]; then echo "admission e2e: PASS"; else echo "admission e2e: FAIL"; exit 1; fi
