#!/usr/bin/env bash
# F-014 T-10 (design §3.1, §3.9, §3.10): the upgrade window of a release,
# for its air-gap package.
#
#   scripts/release-window.sh VERSION OUT_DIR
#
# Writes OUT_DIR/package-meta.env with
#   UPGRADE_FROM          the releases VERSION upgrades from, comma-separated:
#                         earlier patches of its own minor line and every
#                         release of the two minor lines before it (vX.Y.Z
#                         tags only; pre-releases and the dry-run tag never)
#   MINOR_FIRST_RELEASED  the day vX.Y.0 was tagged (YYYY-MM-DD), or today
#                         for the .0 release itself
# and OUT_DIR/notes/<release>.md, the published release notes of each
# release of the window (gh release download; a release without notes is
# reported and left out). The caller adds VERSION's own notes.
# Needs git (tags fetched) and gh (GH_TOKEN).
set -euo pipefail

VERSION=${1:?usage: release-window.sh VERSION OUT_DIR}
OUT=${2:?usage: release-window.sh VERSION OUT_DIR}
mkdir -p "$OUT/notes"

core="${VERSION#v}"; core="${core%%-*}"
IFS=. read -r major minor _patch <<< "$core"

window=()
while read -r tag; do
  [ -n "$tag" ] || continue
  [ "$tag" = "$VERSION" ] && continue
  t="${tag#v}"
  IFS=. read -r tmaj tmin _tpat <<< "$t"
  [ "$tmaj" = "$major" ] || continue
  # Earlier releases of the same minor line, and the two minor lines before.
  if [ "$tmin" -le "$minor" ] && [ "$tmin" -ge $((minor - 2)) ]; then
    # Only releases older than VERSION.
    if [ "$(printf '%s\n%s\n' "$tag" "$VERSION" | sort -V | head -1)" = "$tag" ]; then
      window+=("$tag")
    fi
  fi
done < <(git tag --list 'v*' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V)

first="$(git log -1 --format=%cs "v$major.$minor.0" 2>/dev/null || true)"
[ -n "$first" ] || first="$(date -u +%F)"

for tag in "${window[@]}"; do
  if ! gh release download "$tag" --pattern release-notes.md --output "$OUT/notes/$tag.md" --clobber 2>/dev/null; then
    echo "release-window: $tag has no published release-notes.md; left out" >&2
    rm -f "$OUT/notes/$tag.md"
  fi
done

{
  echo "UPGRADE_FROM=$(IFS=,; echo "${window[*]}")"
  echo "MINOR_FIRST_RELEASED=$first"
} > "$OUT/package-meta.env"
cat "$OUT/package-meta.env"
