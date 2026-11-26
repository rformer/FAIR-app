#!/usr/bin/env bash
# F-012 T-14 (F-012-AC-16; design §3.5, §6 "T: infrastructure drifts from
# code"): the daily drift job's decision. Every instance's two roots are
# planned read-only with tofu plan -detailed-exitcode (scripts/infra-instance.sh
# plan, in .github/workflows/infra-instances.yml); this decides from those
# plans whether any instance drifted (or could not be checked) and writes
# the issue the job opens.
#
#   scripts/infra-drift.sh -plans DIR [-issue FILE] [-run URL]
#       DIR/<instance>/<root>.{exitcode,json}; exit 0: no drift; 2: drift
#       or an instance not checked (FILE holds the issue body); 1: failure
#   scripts/infra-drift.sh -dry-run
#       the same decision over the recorded runs in
#       internal/infraplan/testdata/drift (no AWS): clean, drifted (an
#       instance's security group rule changed outside OpenTofu), a failed
#       plan, a missing plan, changes outside OpenTofu the code does not
#       manage, and a plan that would delete a retained store. Each must
#       reach its recorded verdict and issue text; the CI job infra-drift
#       runs it on every pull request.
# Needs Go.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
export GOFIPS140="${GOFIPS140:-v1.0.0}"

# Built, not go run: go run reports every failure as exit 1, and exit 2
# (drift) must reach the job.
BIN="$(mktemp -d)"
trap 'rm -rf "$BIN"' EXIT
go build -o "$BIN/infraplan" ./cmd/infraplan

if [ "${1:-}" = -dry-run ]; then
  [ $# -eq 1 ] || { echo "usage: $0 -dry-run" >&2; exit 1; }
  "$BIN/infraplan" drift -dry-run internal/infraplan/testdata/drift
  exit 0
fi
code=0
"$BIN/infraplan" drift "$@" || code=$?
exit "$code"
