#!/usr/bin/env bash
# Fetches the pinned OSCAL schemas and NIST OSCAL content (F-015 T-01) and
# writes MANIFEST.json with each file's source URL and SHA-256. Re-run only
# to change a pin; commit the files and the manifest together.
# Pins: OSCAL v1.2.3 (schemas), usnistgov/oscal-content v1.6.0 (content).
set -euo pipefail
cd "$(dirname "$0")"

OSCAL=v1.2.3
CONTENT=v1.6.0
schema="https://github.com/usnistgov/OSCAL/releases/download/$OSCAL"
content="https://raw.githubusercontent.com/usnistgov/oscal-content/$CONTENT"

files=(
  "schemas/oscal_complete_schema.json|$schema/oscal_complete_schema.json"
  "nist/sp800-53r5/NIST_SP-800-53_rev5_catalog.json|$content/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
  "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json|$content/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json"
  "nist/sp800-53r5/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json|$content/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json"
  "examples/catalog/basic-catalog.json|$content/examples/catalog/json/basic-catalog.json"
  "examples/profile/basic-profile.json|$content/examples/profile/json/basic-profile.json"
  "examples/component-definition/example-component-definition.json|$content/examples/component-definition/json/example-component-definition.json"
  "examples/assessment-results/ifa_assessment-results-example.json|$content/examples/ar/json/ifa_assessment-results-example.json"
  "examples/poam/ifa_plan-of-action-and-milestones.json|$content/examples/poam/json/ifa_plan-of-action-and-milestones.json"
)

{
  echo '{'
  echo "  \"oscal_version\": \"${OSCAL#v}\","
  echo "  \"oscal_content_release\": \"$CONTENT\","
  echo '  "files": ['
  for i in "${!files[@]}"; do
    IFS='|' read -r path url <<<"${files[$i]}"
    mkdir -p "$(dirname "$path")"
    curl -fsSL -o "$path" "$url"
    sum="$(sha256sum "$path" | cut -d' ' -f1)"
    sep=,; [[ $i -eq $((${#files[@]} - 1)) ]] && sep=
    echo "    {\"path\": \"$path\", \"source\": \"$url\", \"sha256\": \"$sum\"}$sep"
  done
  echo '  ]'
  echo '}'
} > MANIFEST.json
echo "fetched ${#files[@]} files"
