#!/usr/bin/env bash
# Fetches the pinned OSCAL schemas and NIST OSCAL content (F-015 T-01) and
# writes MANIFEST.json with each file's source URL and SHA-256. Re-run only
# to change a pin; commit the files and the manifest together.
# Pins: OSCAL v1.2.3 (schemas), usnistgov/oscal-content v1.6.0 (content),
# oscal-content v1.3.0 (the catalog FedRAMP resolves against), and
# OSCAL-Foundation/fedramp-resources at a fixed commit. That repository
# declares no license; its provenance is recorded here and in MANIFEST.json.
set -euo pipefail
cd "$(dirname "$0")"

OSCAL=v1.2.3
CONTENT=v1.6.0
# FedRAMP's rev5 baselines resolve against this NIST content release (F-015 D-OQ4).
FEDRAMP_NIST_CONTENT=v1.3.0
# OSCAL-Foundation/fedramp-resources has no releases or tags: pinned by commit.
FEDRAMP_COMMIT=383977291aad960b0811faf6ebf5a893b0811f7f
schema="https://github.com/usnistgov/OSCAL/releases/download/$OSCAL"
content="https://raw.githubusercontent.com/usnistgov/oscal-content/$CONTENT"
# The exact URL form FedRAMP's tailoring profile imports (refs/tags/...).
oldcontent="https://raw.githubusercontent.com/usnistgov/oscal-content/refs/tags/$FEDRAMP_NIST_CONTENT"
fedramp="https://raw.githubusercontent.com/OSCAL-Foundation/fedramp-resources/$FEDRAMP_COMMIT/baselines/rev5/json"

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
  # T-02 profile resolution: NIST examples (profile + expected resolved catalog)
  "examples/catalog/basic_catalog.json|$content/examples/catalog/json/basic_catalog.json"
  "examples/profile/basic_profile.json|$content/examples/profile/json/basic_profile.json"
  "examples/profile/basic-resolved-profile_catalog.json|$content/examples/profile/json/basic-resolved-profile_catalog.json"
  "examples/profile/basic_select_with_id_profile.json|$content/examples/profile/json/basic_select_with_id_profile.json"
  "examples/profile/basic_select_with_id-resolved-profile_catalog.json|$content/examples/profile/json/basic_select_with_id-resolved-profile_catalog.json"
  "examples/profile/basic_select_with_match_profile.json|$content/examples/profile/json/basic_select_with_match_profile.json"
  "examples/profile/basic_select_with_match-resolved-profile_catalog.json|$content/examples/profile/json/basic_select_with_match-resolved-profile_catalog.json"
  # T-02: FedRAMP rev5 Moderate and the NIST catalog it resolves against
  "nist/sp800-53r5-oscal-content-v1.3.0/NIST_SP-800-53_rev5_catalog.json|$oldcontent/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
  "fedramp/rev5/FedRAMP_rev5_catalog_tailoring_profile.json|$fedramp/FedRAMP_rev5_catalog_tailoring_profile.json"
  "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline_profile.json|$fedramp/FedRAMP_rev5_MODERATE-baseline_profile.json"
  "fedramp/rev5/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json|$fedramp/FedRAMP_rev5_MODERATE-baseline-resolved-profile_catalog.json"
)

{
  echo '{'
  echo "  \"oscal_version\": \"${OSCAL#v}\","
  echo "  \"oscal_content_release\": \"$CONTENT\","
  echo "  \"fedramp_nist_content_release\": \"$FEDRAMP_NIST_CONTENT\","
  echo "  \"fedramp_resources_commit\": \"$FEDRAMP_COMMIT\","
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
