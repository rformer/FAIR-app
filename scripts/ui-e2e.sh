#!/usr/bin/env bash
# F-015 T-32: end-to-end tests of the Posture page against the real posture
# service and database.
#   1. builds the web UI (web/dist);
#   2. runs the UI harness (db/tests TestPostureUIHarness) in the DB test
#      container: it seeds a posture scenario and serves the UI and the real
#      Posture API on :8099 behind a test-only dev gateway;
#   3. runs Playwright (with axe WCAG 2.1 AA scans) on the host against it.
# F-005 T-13: the simulation engine runs too: its image (built here, so its
# validation suite runs), with no network, its socket in a volume shared with
# the harness (FAIR_UI_ENGINE_SOCKET).
# Needs docker with the fairpg/fairnats containers on network fairtest and the
# fair-dbtest image (see README), node and npm. Run from the repository root.
set -euo pipefail
export MSYS_NO_PATHCONV=1
ROOT=$(pwd)
HOSTPATH=$ROOT
if command -v cygpath >/dev/null; then HOSTPATH=$(cygpath -m "$ROOT"); fi

(cd web && npm ci --no-audit --no-fund >/dev/null && npm run build >/dev/null)
rm -f web/.harness-stop
docker start fairpg fairnats >/dev/null
docker rm -f fair-ui-harness fair-ui-engine >/dev/null 2>&1 || true
docker build -q --target engine -t fair-engine:ui . >/dev/null
docker volume rm fair-ui-engine >/dev/null 2>&1 || true
docker volume create fair-ui-engine >/dev/null
docker run --rm -v fair-ui-engine:/v --entrypoint /bin/chown fair-dbtest 65532:65532 /v
docker run -d --name fair-ui-engine --network none --read-only --cap-drop ALL -v fair-ui-engine:/run/engine \
  fair-engine:ui serve --socket /run/engine/engine.sock --workers 2 >/dev/null
docker run -d --name fair-ui-harness --network fairtest -p 8099:8099 \
  -v "$HOSTPATH:/src" -v fair-gocache:/root/.cache -v fair-gomod:/go/pkg/mod -v fair-ui-engine:/run/engine -w /src \
  -e PGHOST=fairpg -e PGUSER=postgres -e PGPASSWORD=pgtest -e FAIR_TEST_PG=1 -e FAIR_UI_HARNESS=1 -e GOFLAGS=-buildvcs=false \
  -e FAIR_UI_ENGINE_SOCKET=/run/engine/engine.sock \
  fair-dbtest go test -count=1 -timeout 30m -v -run '^TestPostureUIHarness$' ./db/tests/ >/dev/null
cleanup() {
  touch "$ROOT/web/.harness-stop"
  docker wait fair-ui-harness >/dev/null 2>&1 || true
  docker logs fair-ui-harness 2>&1 | grep -E "FAIL|panic|scenario seeded|run seeded|ui_harness_test" || true
  docker rm -f fair-ui-harness fair-ui-engine >/dev/null 2>&1 || true
  docker volume rm fair-ui-engine >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 150); do
  if curl -fsS http://localhost:8099/dev/ready >/dev/null 2>&1; then break; fi
  if [ "$(docker inspect -f '{{.State.Running}}' fair-ui-harness 2>/dev/null)" != true ]; then
    docker logs fair-ui-harness 2>&1 | tail -30
    echo "the UI harness stopped"; exit 1
  fi
  sleep 2
done
curl -fsS http://localhost:8099/dev/ready >/dev/null

cd web
npx playwright install chromium >/dev/null
npx playwright test
