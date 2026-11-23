#!/bin/bash
# Xcode build phase (after Copy Bundle Resources, before code signing) for the iOS shell.
# Writes the embedded PWA identity as a sidecar resource BeamioPWABuild.json next to SilentPassUI.zip
# (same-version repair design; sidecar chosen because Xcode sandboxing forbids editing Info.plist here):
#   ver         PWA version from the ZIP update.json
#   zipSha256   SHA-256 of the one SilentPassUI.zip that is packed into the product
#   treeDigest  tree digest of that ZIP unzipped (same algorithm as scripts/pwa-tree-digest.sh and the runtime)
# Fails the build when the ZIP is missing, when there is more than one, when BEAMIO_PWA_EXPECTED_ZIP_SHA256 differs from
# the product ZIP, or when a Release build does not set BEAMIO_PWA_EXPECTED_ZIP_SHA256. Debug without it: warning only.
set -euo pipefail

APP_RES="${TARGET_BUILD_DIR}/${UNLOCALIZED_RESOURCES_FOLDER_PATH}"
SIDECAR="${APP_RES}/BeamioPWABuild.json"

zips=()
while IFS= read -r z; do zips+=("$z"); done < <(find "$APP_RES" -name 'SilentPassUI.zip' -type f 2>/dev/null)
if [ "${#zips[@]}" -ne 1 ]; then
  echo "error: PWA embed: expected exactly one SilentPassUI.zip in the product, found ${#zips[@]}" >&2
  exit 1
fi
zip_path="${zips[0]}"

zip_sha="$(shasum -a 256 "$zip_path" | cut -d' ' -f1)"
# Release (archive) builds must name the frozen single-ZIP hash; Debug may omit it with a warning.
if [ "${CONFIGURATION:-}" = "Release" ] && [ -z "${BEAMIO_PWA_EXPECTED_ZIP_SHA256:-}" ]; then
  echo "error: PWA embed: BEAMIO_PWA_EXPECTED_ZIP_SHA256 must be set for Release/QA archive builds" >&2
  exit 1
fi
if [ -n "${BEAMIO_PWA_EXPECTED_ZIP_SHA256:-}" ]; then
  if [ "$zip_sha" != "$BEAMIO_PWA_EXPECTED_ZIP_SHA256" ]; then
    echo "error: PWA embed: ZIP SHA-256 $zip_sha differs from the frozen manifest $BEAMIO_PWA_EXPECTED_ZIP_SHA256" >&2
    exit 1
  fi
else
  echo "warning: PWA embed: BEAMIO_PWA_EXPECTED_ZIP_SHA256 not set; frozen manifest not checked" >&2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
unzip -q "$zip_path" -d "$tmp"
tree_digest="$("${SRCROOT}/scripts/pwa-tree-digest.sh" "$tmp")"
ver="$(sed -n 's/.*"ver" *: *"\([^"]*\)".*/\1/p' "$tmp/update.json" | head -1)"
if [ -z "$ver" ]; then
  echo "error: PWA embed: update.json in the ZIP has no ver" >&2
  exit 1
fi

printf '{"ver":"%s","zipSha256":"%s","treeDigest":"%s"}\n' "$ver" "$zip_sha" "$tree_digest" > "$SIDECAR"
echo "PWA embed: zip=$zip_sha tree=$tree_digest"
