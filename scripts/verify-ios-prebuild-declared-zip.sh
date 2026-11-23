#!/usr/bin/env bash
# Build-phase pre check, scheme B: checks ONLY the declared ZIP file itself.
# It does NOT enumerate any folder, so it runs under the Xcode script sandbox. It is NOT the full-folder
# stray-ZIP gate: that gate is verify-shell-pwa-version.sh ios-prebuild / ios-artifact, run outside the sandbox.
#
# Usage: verify-ios-prebuild-declared-zip.sh FILE
#   FILE must be a regular file named SilentPassUI.zip, a ZIP that lists index.html and update.json at its
#   root and no nested .zip entry. If BEAMIO_PWA_EXPECTED_ZIP_SHA256 is set, its SHA-256 must equal it.
#   In a Release configuration the expected hash is required (missing = fail, never skipped).
set -euo pipefail
FILE="${1:?usage: verify-ios-prebuild-declared-zip.sh FILE}"
fail() { echo "FAIL: declared-zip pre: $*" >&2; exit 1; }
[[ "$(basename "$FILE")" == "SilentPassUI.zip" ]] || fail "declared file must be SilentPassUI.zip, got $(basename "$FILE")"
[[ -f "$FILE" && ! -L "$FILE" ]] || fail "not a regular file: $FILE"
LISTING="$(unzip -Z1 "$FILE" 2>/dev/null)" || fail "not a readable ZIP: $FILE"
printf '%s\n' "$LISTING" | grep -qx 'index.html' || fail "index.html missing at the ZIP root"
printf '%s\n' "$LISTING" | grep -qx 'update.json' || fail "update.json missing at the ZIP root"
if printf '%s\n' "$LISTING" | grep -qi '\.zip$'; then fail "the ZIP contains a nested .zip entry"; fi
GOT="$(shasum -a 256 "$FILE" | awk '{print $1}')"
if [[ "${CONFIGURATION:-}" == "Release" && -z "${BEAMIO_PWA_EXPECTED_ZIP_SHA256:-}" ]]; then
  fail "Release build needs BEAMIO_PWA_EXPECTED_ZIP_SHA256 (not skipped)"
fi
if [[ -n "${BEAMIO_PWA_EXPECTED_ZIP_SHA256:-}" && "$GOT" != "$BEAMIO_PWA_EXPECTED_ZIP_SHA256" ]]; then
  fail "sha256 $GOT != expected $BEAMIO_PWA_EXPECTED_ZIP_SHA256"
fi
echo "PASS: declared-zip pre: $FILE sha256 $GOT"
