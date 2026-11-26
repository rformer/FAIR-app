#!/usr/bin/env bash
# F-012 T-02, T-12 (F-012-AC-01, AC-14, AC-15; design §3.5): check the
# infrastructure code without reaching a cloud:
#   - tofu fmt -check over infra/;
#   - for every root and module (each directory under infra/ holding *.tf):
#     tofu init -backend=false against the committed lock file, validate,
#     and test (mock providers: no AWS or GitHub call);
#   - Checkov over infra/ with every Terraform check (the FedRAMP Moderate
#     selection is a Prisma Cloud filter; without it the whole set runs,
#     which contains it). Findings fail; suppressions are inline with
#     a reason.
# Usage: scripts/infra-check.sh [dir ...]  (default: every directory)
#        INFRA_LOCK=1 scripts/infra-check.sh [dir ...]  writes the lock files
#        first (after a provider version change), then checks.
#        INFRA_SKIP_CHECKOV=1 skips Checkov (while iterating on one dir).
# Needs docker. Images are pinned by digest. Nothing is planned against or
# applied to a real account (design §10).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep the container paths

TOFU_IMAGE=ghcr.io/opentofu/opentofu:1.13.9@sha256:f5aef7f2632b490e3c289a239d7974497d0583f3df6bfa35e8eb31a367ee5ec0
CHECKOV_IMAGE=bridgecrew/checkov:3.4.3@sha256:bfe9d70bb7f044aba49bd99675813445f106dee6072da583f51008cb667f3a63

host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi; }
INFRA="$(host_path "$REPO/infra")"

# The plugin cache is shared between the directories (one download per
# provider version); the lock files pin the hashes.
CACHE="${TF_PLUGIN_CACHE_DIR_HOST:-$REPO/infra/.plugin-cache}"
mkdir -p "$CACHE"
CACHE_HOST="$(host_path "$CACHE")"

tofu() { # dir args...
  local d="$1"
  shift
  docker run --rm -v "$INFRA:/infra" -v "$CACHE_HOST:/cache" -e TF_PLUGIN_CACHE_DIR=/cache \
    -e TF_IN_AUTOMATION=1 -w "/infra/$d" "$TOFU_IMAGE" "$@"
}

if [ "$#" -gt 0 ]; then
  dirs=("$@")
else
  mapfile -t dirs < <(find infra -name '*.tf' -not -path '*/.terraform/*' -printf '%h\n' | sed 's#^infra/##' | sort -u)
fi

# Every AWS provider configuration uses FIPS endpoints (ADR-016; the SCPs
# cannot require them, design §3.5).
echo "== FIPS endpoints in every aws provider"
fips_ok=1
while IFS= read -r f; do
  providers="$(grep -c '^provider "aws"' "$f" || true)"
  fips="$(grep -c '^  use_fips_endpoint *= *true$' "$f" || true)"
  if [ "$providers" != "$fips" ]; then
    echo "$f: $providers aws provider block(s), $fips with use_fips_endpoint = true"
    fips_ok=0
  fi
done < <(grep -rl --include='*.tf' '^provider "aws"' infra | grep -v '/\.terraform/')
[ "$fips_ok" = 1 ] || exit 1

echo "== tofu fmt -check"
tofu . fmt -check -recursive -diff

for d in "${dirs[@]}"; do
  d="${d#infra/}"
  if [ "${INFRA_LOCK:-}" = 1 ]; then
    # Write the lock file (after a provider version change): the hashes of
    # every platform the repository's engineers and CI use.
    echo "== $d: lock"
    tofu "$d" init -input=false -backend=false -no-color >/dev/null
    tofu "$d" providers lock -no-color -platform=linux_amd64 -platform=linux_arm64 \
      -platform=darwin_amd64 -platform=darwin_arm64 -platform=windows_amd64 >/dev/null
  fi
  echo "== $d: init, validate, test"
  tofu "$d" init -input=false -backend=false -lockfile=readonly -no-color >/dev/null
  tofu "$d" validate -no-color
  if [ -d "infra/$d/tests" ]; then
    tofu "$d" test -no-color
  fi
done

if [ "${INFRA_SKIP_CHECKOV:-}" = 1 ]; then
  echo "infra: OK (Checkov skipped)"
  exit 0
fi

echo "== checkov (every Terraform check)"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
status=0
docker run --rm -v "$INFRA:/infra:ro" -w /infra "$CHECKOV_IMAGE" \
  --directory /infra --framework terraform --compact --quiet \
  --skip-path '\.terraform' --skip-path '\.plugin-cache' --skip-path '\.tftest\.hcl$' \
  --download-external-modules false >"$out" 2>&1 || status=$?
cat "$out"
grep -q '^Passed checks: [1-9][0-9]*, Failed checks: 0, ' "$out" \
  || { echo "infra: Checkov reported failed checks (or checked nothing)"; exit 1; }
if grep -q 'Parsing errors: [1-9]' "$out"; then
  echo "infra: Checkov could not parse every file"
  exit 1
fi
[ "$status" -eq 0 ] || { echo "infra: Checkov exited $status"; exit 1; }

echo "infra: OK"
