#!/usr/bin/env bash
# F-012 T-05 (F-012-AC-10; design §3.3): build every image reproducibly and
# print "component digest" for each, so two builds on separate runners can be
# compared (.github/workflows/reproducible.yml).
#
#   scripts/repro-build.sh OUT_DIR [COMPONENT...]
#
# The inputs that would otherwise differ are fixed: SOURCE_DATE_EPOCH is the
# commit time, VERSION the tag when HEAD is tagged (else the short commit),
# the Go build is -trimpath -buildvcs=false (Dockerfile), and BuildKit
# rewrites every file timestamp to the source date. Nothing is cached, so
# each build starts from the pinned bases. Images are written as OCI
# archives to OUT_DIR; OUT_DIR/digests lists the manifest digests.
set -euo pipefail
export MSYS_NO_PATHCONV=1

OUT=${1:?out dir}
shift
COMPONENTS=("$@")
if [ ${#COMPONENTS[@]} -eq 0 ]; then
  COMPONENTS=(iam gateway posture posture-scanner fips-probe audit risk notify integrate engine-gate engine)
fi
BUILDKIT=moby/buildkit:v0.34.2@sha256:c5f8862f52499773af85bc07695b2379ef08e8002352b0df2c4864c91d78dabe
BUILDER=${FAIR_REPRO_BUILDER:-fair-repro}

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
VERSION="$(git describe --tags --exact-match 2>/dev/null || git rev-parse --short=12 HEAD)"
export SOURCE_DATE_EPOCH

# OCI export with rewritten timestamps needs a BuildKit container builder.
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
  docker buildx create --name "$BUILDER" --driver docker-container --driver-opt "image=$BUILDKIT" >/dev/null
fi

mkdir -p "$OUT"
: > "$OUT/digests"
for c in "${COMPONENTS[@]}"; do
  docker buildx build --builder "$BUILDER" --no-cache --progress plain \
    --target "$c" \
    --build-arg SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" --build-arg VERSION="$VERSION" \
    --output "type=oci,dest=$OUT/$c.tar,rewrite-timestamp=true" \
    --metadata-file "$OUT/$c.json" . > "$OUT/$c.log" 2>&1 || { tail -40 "$OUT/$c.log" >&2; echo "FAIL - $c: build" >&2; exit 1; }
  digest="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$OUT/$c.json" | tr -d '\r')"
  echo "$c $digest" | tee -a "$OUT/digests"
done
echo "source date $SOURCE_DATE_EPOCH, version $VERSION" >&2
