#!/usr/bin/env bash
# F-015 T-27/T-28/T-29 verification on a live cluster (kind, whose default CNI enforces
# NetworkPolicy): posture-scanner deployed from deploy/k8s/posture-scanner.yaml
#   * reports to a posture stand-in over mTLS gRPC, with no refused reads;
#   * RBAC audit: its ServiceAccount can only get/list/watch what the
#     manifest grants, never Secrets, nothing outside the platform namespace;
#   * egress test: from the scanner pod's own network namespace, only the API
#     server, posture's scanner channel and DNS are reachable; a control
#     allow-rule proves the denials come from the NetworkPolicy.
# Needs docker, kind, kubectl, openssl. Run from the repository root:
#   scripts/k8s-e2e-scanner.sh            (KEEP=1 keeps the cluster)
#   CONTEXT=docker-desktop scripts/k8s-e2e-scanner.sh
#                                         an existing cluster instead of a new
#                                         kind one (F-015 T-37): images are
#                                         loaded and node files written through
#                                         scripts/e2e/node-access.yaml, and
#                                         everything the run created is removed
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: do not rewrite container paths
CLUSTER=${CLUSTER:-fair-scanner-e2e}
NODE_IMAGE=${NODE_IMAGE:-kindest/node:v1.36.1}
NS=fair-platform
SA=system:serviceaccount:$NS:posture-scanner
TMP=$(mktemp -d)
if command -v cygpath >/dev/null; then TMP=$(cygpath -m "$TMP"); fi # Windows tools need a native path
CONTEXT=${CONTEXT:-}
if [ -n "$CONTEXT" ]; then K="kubectl --context $CONTEXT"; else K="kubectl --context kind-$CLUSTER"; fi
fail=0
pass() { echo "PASS  $*"; }
bad() { echo "FAIL  $*"; fail=1; }
# On an existing cluster, nodes are reached through the node-access pods.
access_pod() { $K -n fair-e2e-node-access get pod -l app=node-access --field-selector "spec.nodeName=$1" -o jsonpath='{.items[0].metadata.name}'; }
node_exec() { # node command
  if [ -n "$CONTEXT" ]; then
    $K -n fair-e2e-node-access exec "$(access_pod "$1")" -- nsenter -t 1 -m -- sh -c "$2"
  else
    docker exec "$1" sh -c "$2"
  fi
}
cleanup() {
  if [ -n "$CONTEXT" ]; then
    # Undo everything this run created on a cluster it does not own.
    for n in $($K get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
      node_exec "$n" 'rm -rf /var/lib/fair-e2e /var/lib/fair-e2e-images' >/dev/null 2>&1 || true
      $K label node "$n" fair-platform.io/fips- >/dev/null 2>&1 || true
    done
    for f in "$TMP"/applied-*.yaml; do [ -f "$f" ] && $K delete -f "$f" --ignore-not-found --wait=false >/dev/null 2>&1; done
    $K delete namespace "$NS" fair-fips-probe fair-e2e-node-access --ignore-not-found --wait=false >/dev/null 2>&1 || true
  elif [ "${KEEP:-}" != 1 ]; then
    kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "== cluster and images"
if [ -n "$CONTEXT" ]; then
  $K get nodes
  if $K get namespace "$NS" fair-fips-probe >/dev/null 2>&1; then
    echo "namespace $NS or fair-fips-probe already exists on $CONTEXT; refusing to touch it" >&2
    exit 2
  fi
  $K apply -f scripts/e2e/node-access.yaml >/dev/null
  $K -n fair-e2e-node-access rollout status daemonset/node-access --timeout=180s
else
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 180s
fi
docker build -q --target posture-scanner -t fair-posture-scanner:e2e . >/dev/null
docker build -q -f scripts/e2e/Dockerfile.sink -t fair-scanner-sink:e2e . >/dev/null
docker build -q --target fips-probe -t fair-fips-probe:e2e . >/dev/null
docker image inspect busybox:1.36 >/dev/null 2>&1 || docker pull -q busybox:1.36 >/dev/null
# Single-platform archives: kind's direct load imports every platform of a
# multi-platform image, which fails when only one is present locally.
for img in fair-posture-scanner:e2e fair-scanner-sink:e2e fair-fips-probe:e2e busybox:1.36; do
  docker save --platform linux/amd64 -o "$TMP/image.tar" "$img"
  if [ -n "$CONTEXT" ]; then
    for n in $($K get nodes -o jsonpath='{.items[*].metadata.name}'); do
      # kubectl cp with a relative path: a Windows path's drive colon would read as pod:path.
      (cd "$TMP" && $K cp image.tar "fair-e2e-node-access/$(access_pod "$n"):/images/image.tar")
      want=$(wc -c < "$TMP/image.tar" | tr -d ' ')
      got=$($K -n fair-e2e-node-access exec "$(access_pod "$n")" -- sh -c 'wc -c < /images/image.tar' | tr -d ' 
')
      if [ "$want" != "$got" ]; then echo "copy of $img to $n truncated ($got of $want bytes)" >&2; exit 2; fi
      node_exec "$n" 'ctr -n k8s.io images import --platform linux/amd64 /var/lib/fair-e2e-images/image.tar >/dev/null'
    done
  else
    kind load image-archive --name "$CLUSTER" "$TMP/image.tar"
  fi
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
sed "s/__NS__/$NS/g" scripts/e2e/scanner-e2e-fixtures.yaml > "$TMP/applied-fixtures.yaml"
$K apply -f "$TMP/applied-fixtures.yaml"
$K -n $NS create secret generic posture-scanner-tls --from-file=tls.crt="$TMP/posture-scanner.crt" \
  --from-file=tls.key="$TMP/posture-scanner.key" --from-file=ca.crt="$TMP/ca.crt"
$K -n $NS create secret generic posture-tls --from-file=tls.crt="$TMP/posture.crt" \
  --from-file=tls.key="$TMP/posture.key" --from-file=ca.crt="$TMP/ca.crt"
$K -n $NS create configmap fair-release-manifest --from-file="$TMP/release-manifest.json" \
  --from-file="$TMP/release-manifest.json.sig" --from-file="$TMP/release-signing.pub"
$K -n $NS rollout status deploy/e2e-bad --timeout=180s

echo "== fips-probe from deploy/k8s/fips-probe.yaml (T-29)"
sed -e "s#ghcr.io/rformer/fair-fips-probe:REPLACE_WITH_DIGEST#fair-fips-probe:e2e#" deploy/k8s/fips-probe.yaml > "$TMP/applied-fips-probe.yaml"
$K apply -f "$TMP/applied-fips-probe.yaml"

echo "== posture-scanner from deploy/k8s/posture-scanner.yaml"
APISERVER_IP=$($K get endpoints kubernetes -n default -o jsonpath='{.subsets[0].addresses[0].ip}')
APISERVER_PORT=$($K get endpoints kubernetes -n default -o jsonpath='{.subsets[0].ports[0].port}')
sed -e "s#ghcr.io/rformer/fair-posture-scanner:REPLACE_WITH_DIGEST#fair-posture-scanner:e2e#" \
    -e "s#REPLACE_WITH_APISERVER_CIDR#$APISERVER_IP/32#" -e 's#"REPLACE_WITH_INGRESS_HOST:443"#""#' \
    -e "s#REPLACE_WITH_INGRESS_CIDR#192.0.2.1/32#" deploy/k8s/posture-scanner.yaml > "$TMP/applied-posture-scanner.yaml"
$K apply -f "$TMP/applied-posture-scanner.yaml"
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
yes_ list pods -n fair-fips-probe
no_ list secrets -n fair-fips-probe
no_ get configmaps -n fair-fips-probe
no_ delete pods -n fair-fips-probe
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

echo "== 4. node FIPS evidence: fips-probe readiness and attestation (T-29)"
# A new scan: restart the scanner and wait for a report after the restart.
rescan() {
  local before
  before=$($K -n $NS logs deploy/posture | grep -c '"report"' || true)
  $K -n $NS rollout restart deploy/posture-scanner >/dev/null
  $K -n $NS rollout status deploy/posture-scanner --timeout=180s >/dev/null
  report=""
  for _ in $(seq 1 60); do
    if [ "$($K -n $NS logs deploy/posture | grep -c '"report"' || true)" -gt "$before" ]; then
      report=$($K -n $NS logs deploy/posture | grep '"report"' | tail -1)
      return
    fi
    sleep 2
  done
  bad "no report after the scanner restart"
}
# (a) This kernel has no FIPS flag file: the probe cannot become Ready.
probe_ready() { $K -n fair-fips-probe get pod -l app.kubernetes.io/name=fips-probe --field-selector "spec.nodeName=$NODE"   -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}'; }
PROBE=$($K -n fair-fips-probe get pod -l app.kubernetes.io/name=fips-probe --field-selector "spec.nodeName=$NODE" -o jsonpath='{.items[0].metadata.name}')
ready=$($K -n fair-fips-probe get pod "$PROBE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
if [ "$ready" != True ]; then pass "probe not Ready on a kernel without the FIPS flag ($PROBE)"; else bad "probe Ready without a FIPS flag"; fi
finds "node_fips node/$NODE high"
# (b) Attested at install: an observation, not a finding.
$K label node "$NODE" fair-platform.io/fips=attested --overwrite >/dev/null
rescan
case "$report" in *"node_fips node/$NODE high"*) bad "attested node still a finding" ;; *) pass "attested node: no finding" ;; esac
finds "node_fips node/$NODE attested"
# (c) Verified: simulate a FIPS kernel by pointing the probe's single-file
# hostPath at a node-local file reading 1 (the real path is the kernel's
# /proc/sys/crypto/fips_enabled); the label is removed, so only the probe
# can make the node pass.
# Every node reads 1: the patched hostPath must exist everywhere, and the
# DaemonSet's rolling update waits for each node's probe to become Ready.
for n in $($K get nodes -o jsonpath='{.items[*].metadata.name}'); do
  node_exec "$n" 'mkdir -p /var/lib/fair-e2e && echo 1 > /var/lib/fair-e2e/fips_enabled'
done
$K label node "$NODE" fair-platform.io/fips- >/dev/null
$K -n fair-fips-probe patch daemonset fips-probe --type=json \
  -p '[{"op":"replace","path":"/spec/template/spec/volumes/0/hostPath/path","value":"/var/lib/fair-e2e/fips_enabled"}]' >/dev/null
$K -n fair-fips-probe rollout status daemonset/fips-probe --timeout=180s >/dev/null
ok=0
for _ in $(seq 1 30); do
  [ "$(probe_ready)" = True ] && { ok=1; break; }
  sleep 2
done
if [ $ok = 1 ]; then pass "probe Ready where the flag reads 1"; else bad "probe not Ready with the flag at 1"; fi
rescan
finds "node_fips node/$NODE verified"
case "$report" in *"node_fips node/$NODE high"*) bad "verified node still a finding" ;; *) pass "verified node: no finding" ;; esac
# The flag back at 0: the probe drops out of Ready at its next check.
node_exec "$NODE" 'echo 0 > /var/lib/fair-e2e/fips_enabled'
ok=0
for _ in $(seq 1 45); do
  [ "$(probe_ready)" = False ] && { ok=1; break; }
  sleep 2
done
if [ $ok = 1 ]; then pass "probe leaves Ready when the flag reads 0"; else bad "probe stayed Ready with the flag at 0"; fi
rescan
finds "node_fips node/$NODE high"

echo
if [ $fail = 0 ]; then echo "posture-scanner e2e: PASS"; else echo "posture-scanner e2e: FAIL"; exit 1; fi
