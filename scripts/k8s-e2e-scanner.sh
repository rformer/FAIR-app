#!/usr/bin/env bash
# F-015 T-27 verification on a live cluster (kind, whose default CNI enforces
# NetworkPolicy): posture-scanner deployed from deploy/k8s/posture-scanner.yaml
#   * reports to a posture stand-in over mTLS gRPC, with no refused reads;
#   * RBAC audit: its ServiceAccount can only get/list/watch what the
#     manifest grants, never Secrets, nothing outside the platform namespace;
#   * egress test: from the scanner pod's own network namespace, only the API
#     server, posture's scanner channel and DNS are reachable; a control
#     allow-rule proves the denials come from the NetworkPolicy.
# Needs docker, kind, kubectl, openssl. Run from the repository root:
#   scripts/k8s-e2e-scanner.sh            (KEEP=1 keeps the cluster)
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: do not rewrite container paths
CLUSTER=${CLUSTER:-fair-scanner-e2e}
NODE_IMAGE=${NODE_IMAGE:-kindest/node:v1.36.1}
NS=fair-platform
SA=system:serviceaccount:$NS:posture-scanner
TMP=$(mktemp -d)
if command -v cygpath >/dev/null; then TMP=$(cygpath -m "$TMP"); fi # Windows tools need a native path
K="kubectl --context kind-$CLUSTER"
fail=0
pass() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fail=1; }
cleanup() {
  rm -rf "$TMP"
  if [ "${KEEP:-}" != 1 ]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "== cluster and images"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 180s
docker build -q --target posture-scanner -t fair-posture-scanner:e2e . >/dev/null
docker build -q -f scripts/e2e/Dockerfile.sink -t fair-scanner-sink:e2e . >/dev/null
docker image inspect busybox:1.36 >/dev/null 2>&1 || docker pull -q busybox:1.36 >/dev/null
# Single-platform archives: kind's direct load imports every platform of a
# multi-platform image, which fails when only one is present locally.
for img in fair-posture-scanner:e2e fair-scanner-sink:e2e busybox:1.36; do
  docker save --platform linux/amd64 -o "$TMP/image.tar" "$img"
  kind load image-archive --name "$CLUSTER" "$TMP/image.tar"
done

echo "== PKI (ECDSA P-256)"
issue() { # name subjectAltName extendedKeyUsage
  openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/$1.key"
  openssl req -new -key "$TMP/$1.key" -subj "/CN=$1" -out "$TMP/$1.csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=%s\nkeyUsage=digitalSignature\n' "$2" "$3" > "$TMP/$1.ext"
  openssl x509 -req -in "$TMP/$1.csr" -CA "$TMP/ca.crt" -CAkey "$TMP/ca.key" -CAcreateserial -days 90 -sha256 \
    -extfile "$TMP/$1.ext" -out "$TMP/$1.crt" 2>/dev/null
}
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/ca.key"
openssl req -x509 -new -key "$TMP/ca.key" -sha256 -days 90 -subj "/CN=fair-e2e-ca" -out "$TMP/ca.crt" 2>/dev/null
issue posture "DNS:posture.$NS,DNS:posture.$NS.svc" serverAuth
issue posture-scanner "URI:spiffe://fair-platform/posture-scanner" clientAuth

echo "== signed release manifest (T-28)"
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/release.key"
openssl ec -in "$TMP/release.key" -pubout -out "$TMP/release-signing.pub" 2>/dev/null
D1=sha256:$(printf '1%.0s' $(seq 64))
D2=sha256:$(printf '2%.0s' $(seq 64))
printf '{"iam": "ghcr.io/rformer/fair-iam@%s", "posture-scanner": "ghcr.io/rformer/fair-posture-scanner@%s"}\n' "$D1" "$D2" > "$TMP/images.json"
GOFIPS140=v1.0.0 go run ./cmd/releasegen manifest -release e2e -images "$TMP/images.json" -deploy deploy/k8s -out "$TMP/release-manifest.json"
GOFIPS140=v1.0.0 go run ./cmd/releasegen sign -key "$TMP/release.key" -in "$TMP/release-manifest.json"

echo "== platform namespace, posture stand-in, decoy"
sed "s/__NS__/$NS/g" scripts/e2e/scanner-e2e-fixtures.yaml | $K apply -f -
$K -n $NS create secret generic posture-scanner-tls --from-file=tls.crt="$TMP/posture-scanner.crt" \
  --from-file=tls.key="$TMP/posture-scanner.key" --from-file=ca.crt="$TMP/ca.crt"
$K -n $NS create secret generic posture-tls --from-file=tls.crt="$TMP/posture.crt" \
  --from-file=tls.key="$TMP/posture.key" --from-file=ca.crt="$TMP/ca.crt"
$K -n $NS create configmap fair-release-manifest --from-file="$TMP/release-manifest.json" \
  --from-file="$TMP/release-manifest.json.sig" --from-file="$TMP/release-signing.pub"
$K -n $NS rollout status deploy/e2e-bad --timeout=180s

echo "== posture-scanner from deploy/k8s/posture-scanner.yaml"
APISERVER_IP=$($K get endpoints kubernetes -n default -o jsonpath='{.subsets[0].addresses[0].ip}')
APISERVER_PORT=$($K get endpoints kubernetes -n default -o jsonpath='{.subsets[0].ports[0].port}')
sed -e "s#ghcr.io/rformer/fair-posture-scanner:REPLACE_WITH_DIGEST#fair-posture-scanner:e2e#" \
    -e "s#REPLACE_WITH_APISERVER_CIDR#$APISERVER_IP/32#" -e 's#"REPLACE_WITH_INGRESS_HOST:443"#""#' \
    -e "s#REPLACE_WITH_INGRESS_CIDR#192.0.2.1/32#" deploy/k8s/posture-scanner.yaml | $K apply -f -
$K -n $NS rollout status deploy/posture --timeout=180s
$K -n $NS rollout status deploy/posture-scanner --timeout=180s
$K -n $NS wait --for=condition=Ready pod/decoy --timeout=120s
POD=$($K -n $NS get pod -l app.kubernetes.io/name=posture-scanner -o jsonpath='{.items[0].metadata.name}')
DECOY_IP=$($K -n $NS get pod decoy -o jsonpath='{.status.podIP}')
POSTURE_IP=$($K -n $NS get pod -l app.kubernetes.io/name=posture -o jsonpath='{.items[0].status.podIP}')

echo "== 1. the scanner reports over mTLS gRPC, with no refused reads"
report=""
for _ in $(seq 1 60); do
  report=$($K -n $NS logs deploy/posture | grep '"report"' | head -1 || true)
  [ -n "$report" ] && break
  sleep 2
done
echo "      $report"
if [ -z "$report" ]; then
  bad "no report reached posture"
  $K -n $NS logs "$POD" | tail -20
else
  pass "report received from $POD"
fi
case "$report" in
  *'"check_errors":null'* | *'"check_errors":[]'*) pass "no check errors: every granted read works, the release manifest verifies" ;;
  *) bad "check errors reported" ;;
esac

echo "== 1b. the check catalog on a live cluster (T-28)"
NODE=$($K get nodes -o jsonpath='{.items[0].metadata.name}')
for c in pod_security_admission network_policy tls_endpoints node_fips image_digests signature_admission pod_hardening \
         storage_encryption plaintext_secrets platform_rbac; do
  case "$report" in *"\"$c\""*) ;; *) bad "check $c did not run" ;; esac
done
finds() { case "$report" in *"$1"*) pass "finding: $1" ;; *) bad "missing finding: $1" ;; esac; }
none() { case "$report" in *"\"$1 "*) bad "unexpected $1 finding" ;; *) pass "passes: $1" ;; esac; }
none pod_security_admission # the namespace enforces restricted
none network_policy         # default deny plus a policy for every workload
none platform_rbac          # RBAC as applied from deploy/k8s, matching the signed manifest
finds "tls_endpoints endpoint/e2e-bad.$NS.svc:8443 high"
finds "node_fips node/$NODE high"
finds "signature_admission cluster/admission high"
finds "storage_encryption storageclass/standard high"
finds "pod_hardening workload/$NS/Deployment/e2e-bad high"
finds "plaintext_secrets workload/$NS/Deployment/e2e-bad high"
finds "image_digests workload/$NS/Deployment/posture-scanner high"
case "$report" in
  *"tls_endpoints endpoint/posture.$NS.svc:9443"*) bad "posture's mTLS endpoint flagged" ;;
  *) pass "posture's mTLS endpoint passes the TLS check" ;;
esac

echo "== 2. RBAC audit ($SA)"
can() { $K auth can-i "$@" --as="$SA" 2>/dev/null || true; }
yes_() { if [ "$(can "$@")" = yes ]; then pass "can $*"; else bad "cannot $*"; fi; }
no_() { if [ "$(can "$@")" = no ]; then pass "cannot $*"; else bad "CAN $*"; fi; }
yes_ list pods -n $NS
yes_ watch networkpolicies.networking.k8s.io -n $NS
yes_ list deployments.apps -n $NS
yes_ list roles.rbac.authorization.k8s.io -n $NS
yes_ list nodes
yes_ get namespaces
yes_ list clusterroles.rbac.authorization.k8s.io
yes_ list storageclasses.storage.k8s.io
yes_ list validatingadmissionpolicies.admissionregistration.k8s.io
no_ get secrets -n $NS
no_ list secrets -A
no_ watch secrets -n $NS
no_ get configmaps -n $NS
no_ create pods -n $NS
no_ update deployments.apps -n $NS
no_ patch networkpolicies.networking.k8s.io -n $NS
no_ delete pods -n $NS
no_ deletecollection pods -n $NS
no_ create pods --subresource=exec -n $NS
no_ get pods --subresource=log -n $NS
no_ create serviceaccounts --subresource=token -n $NS
no_ impersonate serviceaccounts
no_ escalate roles.rbac.authorization.k8s.io -n $NS
no_ bind clusterroles.rbac.authorization.k8s.io
no_ list pods -n kube-system
no_ list '*' -n $NS
no_ '*' '*'
# Every rule the scanner holds, apart from what all authenticated users hold
# (self-reviews and discovery URLs), has only get, list and watch.
extra=$($K auth can-i --list -n $NS --as="$SA" | tail -n +2 \
  | grep -v -E '^(selfsubject[a-z]+\.authorization\.k8s\.io|selfsubjectreviews\.authentication\.k8s\.io) ' \
  | grep -v -E '^ +\[/' | sed -E 's/.*\[([^]]*)\] *$/\1/' | tr ' ' '\n' | grep -v -E '^(get|list|watch)?$' || true)
if [ -z "$extra" ]; then pass "can-i --list: only get, list, watch"; else bad "can-i --list shows other verbs: $extra"; fi

echo "== 3. egress from the scanner pod's network namespace"
printf '%s\n' '{"securityContext": {"runAsNonRoot": true, "runAsUser": 65532, "allowPrivilegeEscalation": false,' \
  '"capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}' > "$TMP/probe.json"
$K -n $NS debug "$POD" --image=busybox:1.36 --container=probe --profile=restricted --custom="$TMP/probe.json" -- sleep 900 >/dev/null
for _ in $(seq 1 60); do
  running=$($K -n $NS get pod "$POD" -o jsonpath='{.status.ephemeralContainerStatuses[?(@.name=="probe")].state.running}')
  [ -n "$running" ] && break
  sleep 2
done
reach() { $K -n $NS exec "$POD" -c probe -- nc -z -w 3 "$1" "$2" >/dev/null 2>&1; }
if reach "$APISERVER_IP" "$APISERVER_PORT"; then pass "allowed: API server $APISERVER_IP:$APISERVER_PORT"; else bad "API server unreachable"; fi
if reach "posture.$NS.svc.cluster.local" 9443; then pass "allowed: posture:9443 (with DNS)"; else bad "posture:9443 unreachable"; fi
if reach "e2e-bad.$NS.svc.cluster.local" 8443; then pass "allowed: a platform workload's TLS port (8443)"; else bad "platform TLS port unreachable"; fi
if reach "$DECOY_IP" 8080; then bad "REACHED decoy $DECOY_IP:8080"; else pass "denied: a pod outside the platform ($DECOY_IP:8080)"; fi
if reach "$POSTURE_IP" 8443; then bad "REACHED posture on 8443"; else pass "denied: posture on a port other than 9443"; fi
if reach "$APISERVER_IP" 10250; then bad "REACHED the kubelet ($APISERVER_IP:10250)"; else pass "denied: kubelet on the API server's node (10250)"; fi
if reach 1.1.1.1 443; then bad "REACHED the internet (1.1.1.1:443)"; else pass "denied: internet (1.1.1.1:443)"; fi
# Control: allow the decoy explicitly; it must then be reachable.
sed "s/__NS__/$NS/g" scripts/e2e/scanner-e2e-control.yaml | $K apply -f - >/dev/null
ok=0
for _ in $(seq 1 15); do
  if reach "$DECOY_IP" 8080; then ok=1; break; fi
  sleep 2
done
if [ $ok = 1 ]; then pass "control: decoy reachable once allowed (the CNI enforces policy)"; else bad "control: decoy unreachable even when allowed"; fi
$K -n $NS delete networkpolicy e2e-control-allow-decoy >/dev/null

echo
if [ $fail = 0 ]; then echo "posture-scanner e2e: PASS"; else echo "posture-scanner e2e: FAIL"; exit 1; fi
