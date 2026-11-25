#!/usr/bin/env bash
# F-012 T-11 (F-012-AC-24, AC-25; design §3.7): check deploy/observability.
#   - promtool check rules over the alert rules, and promtool test rules over
#     deploy/observability/tests (the alerts fire on the series the services
#     emit);
#   - every PromQL expression of the dashboards parses (as recording rules);
#   - otelcol-contrib validate over each Collector configuration (the
#     self-hosted one also with its forwarding overlay).
# Needs docker and python3 (or python). The images are pinned by digest.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep the container paths

PROMETHEUS_IMAGE=prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06
OTELCOL_IMAGE=otel/opentelemetry-collector-contrib:0.165.0@sha256:e40d61f10c9a617cca1ffd1be4d7e2b3a4b0f0001798ff07e58cabe82e618cea
OBS="$REPO/deploy/observability"
PY="$(command -v python3 || command -v python)"

tmp="$(mktemp -d deploy/observability/.check.XXXXXX)" # relative: python may be a Windows one
chmod 755 "$tmp" # the containers run as non-root users
trap 'rm -rf "$tmp"' EXIT

promtool() {
  docker run --rm --entrypoint /bin/promtool -v "$OBS:/obs:ro" -w /obs "$PROMETHEUS_IMAGE" "$@"
}

echo "== promtool check rules"
(cd "$OBS" && promtool check rules alerts/*.yaml)

echo "== promtool test rules"
(cd "$OBS/tests" && docker run --rm --entrypoint /bin/promtool -v "$OBS:/obs:ro" -w /obs/tests "$PROMETHEUS_IMAGE" test rules ./*.test.yaml)

echo "== dashboard queries parse"
"$PY" - deploy/observability/dashboards "$tmp/dashboards.rules.yaml" <<'PYEOF'
import glob, json, os, sys
src, out = sys.argv[1], sys.argv[2]
rules = []
def walk(panels):
    for p in panels:
        for t in p.get("targets", []):
            if t.get("expr"):
                rules.append(t["expr"])
        walk(p.get("panels", []))
files = sorted(glob.glob(os.path.join(src, "*.json")))
if not files:
    sys.exit("no dashboards")
for f in files:
    with open(f, encoding="utf-8") as fh:
        walk(json.load(fh)["panels"])
with open(out, "w", encoding="utf-8", newline="\n") as fh:
    fh.write("groups:\n  - name: dashboards\n    rules:\n")
    for i, e in enumerate(rules):
        e = e.replace("$instance", ".*").replace("$service", ".*")
        fh.write("      - record: dashboard:query%d\n        expr: %s\n" % (i, json.dumps(e)))
print("%d queries from %d dashboards" % (len(rules), len(files)))
PYEOF
chmod 644 "$tmp/dashboards.rules.yaml"
promtool check rules "/obs/$(basename "$tmp")/dashboards.rules.yaml"

echo "== otelcol-contrib validate"
otelcol() {
  docker run --rm -v "$OBS:/cfg:ro" \
    -e FAIR_INSTANCE=i-check -e FAIR_OPS_PROMETHEUS_URL=https://prometheus.ops.invalid/api/v1/write \
    -e FAIR_OPS_LOKI_URL=https://loki.ops.invalid/otlp -e FAIR_OPS_TEMPO_ENDPOINT=tempo.ops.invalid:4317 \
    -e FAIR_KSM_TARGET=kube-state-metrics.invalid:8080 -e FAIR_CERT_MANAGER_TARGET=cert-manager.invalid:9402 \
    -e FAIR_COLLECTOR_ENDPOINT=otel-collector.invalid:4317 -e FAIR_OTEL_FORWARD_ENDPOINT=collector.customer.invalid:4317 \
    "$OTELCOL_IMAGE" validate "$@"
}
for c in collector-saas.yaml collector-saas-agent.yaml collector-selfhosted.yaml; do
  echo "$c"
  otelcol --config "/cfg/$c"
done
echo "collector-selfhosted.yaml + collector-selfhosted-forward.yaml"
otelcol --config /cfg/collector-selfhosted.yaml --config /cfg/collector-selfhosted-forward.yaml
echo "observability checks passed"
