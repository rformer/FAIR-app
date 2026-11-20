#!/usr/bin/env bash
# F-012 T-06 (F-012-AC-09): scripts/verify-release.sh -offline passes a
# release signed with its key and fails a tampered one. Run in CI (job
# release-verify) and by hand; needs what scripts/release-fixture.sh needs.
#
#   scripts/verify-release-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

bash scripts/release-fixture.sh "$W/a" >/dev/null
FAIR_FIXTURE_REGISTRY_PORT=5056 bash scripts/release-fixture.sh "$W/b" >/dev/null

pass() { bash scripts/verify-release.sh -offline "$1" >/dev/null 2>&1 || { echo "FAIL - $2: refused"; bash scripts/verify-release.sh -offline "$1"; exit 1; }; echo "ok - $2: verified"; }
refuse() { if bash scripts/verify-release.sh -offline "$1" >/dev/null 2>&1; then echo "FAIL - $2: verified"; exit 1; fi; echo "ok - $2: refused"; }
copy() { rm -rf "$W/t"; cp -r "$W/a" "$W/t"; }

pass "$W/a" "the release as signed"

copy; cp "$W/b/cosign.pub" "$W/t/cosign.pub"
refuse "$W/t" "another key as cosign.pub"

copy; sed -i 's/v0.0.0-fixture/v9.9.9/' "$W/t/release-manifest.json"
refuse "$W/t" "an edited release manifest"

copy; rm -rf "$W/t/images/fixture"; cp -r "$W/b/images/fixture" "$W/t/images/fixture"
refuse "$W/t" "an image signed by another key"

copy; rm "$W/t/release-manifest.json.sig"
refuse "$W/t" "no manifest signature"

echo "verify-release: all cases as expected"
