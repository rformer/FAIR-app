#!/usr/bin/env bash
# F-001 T-42 (design §6): lint the published OpenAPI documents with Spectral
# (pinned in tools/spectral; ruleset .spectral.yaml), failing on any warning,
# and check that the convention rules still catch what they are for
# (tools/spectral/selftest.mjs). Needs node and npm.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
if [ ! -x tools/spectral/node_modules/.bin/spectral ]; then
  npm ci --prefix tools/spectral --no-audit --no-fund --ignore-scripts >/dev/null
fi
tools/spectral/node_modules/.bin/spectral lint api/openapi/*.yaml --ruleset .spectral.yaml --fail-severity=warn
node tools/spectral/selftest.mjs
