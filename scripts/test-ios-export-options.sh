#!/usr/bin/env bash
# Stub cases for check_export_plist in build-qa-adhoc.sh. Extracts the pins and the
# function from build-qa-adhoc.sh and runs each case in a subshell; temporary plists only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd -P)"; ROOT="$(cd "$HERE/.." && pwd -P)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
sed -n '/^PIN_EXPORT_STORE=/,/^}/p' "$ROOT/build-qa-adhoc.sh" > "$TMP/fn.sh"
STORE="${STORE_PLIST:?set STORE_PLIST to the reviewed app-store-connect ExportOptions plist}"
ADHOC="$ROOT/ExportOptions-ad-hoc.plist"
pass=0; total=0
run() {  # $1 name, $2 mode, $3 path, $4 expected exit
  total=$((total + 1))
  ( MODE="$2"; . "$TMP/fn.sh"; check_export_plist "$3" "case" ) >/dev/null 2>&1 && rc=0 || rc=$?
  if [[ "$rc" == "$4" ]]; then pass=$((pass + 1)); echo "ok   $1"; else echo "FAIL $1 (exit $rc, want $4)"; fi
}
cp "$STORE" "$TMP/upload.plist"; /usr/libexec/PlistBuddy -c 'Set :destination upload' "$TMP/upload.plist"
cp "$STORE" "$TMP/other-store.plist"; /usr/libexec/PlistBuddy -c 'Set :uploadSymbols false' "$TMP/other-store.plist"
cp "$ADHOC" "$TMP/dev.plist"; /usr/libexec/PlistBuddy -c 'Set :method debugging' "$TMP/dev.plist"
run "formal: reviewed store options pass" formal "$STORE" 0
run "formal: repository Ad Hoc options pass" formal "$ADHOC" 0
run "formal: store options with other bytes refused" formal "$TMP/other-store.plist" 1
run "formal: destination upload refused" formal "$TMP/upload.plist" 1
run "formal: other method refused" formal "$TMP/dev.plist" 1
run "formal: relative path refused" formal "ExportOptions-ad-hoc.plist" 1
run "formal: missing file refused" formal "$TMP/none.plist" 1
run "qa: store options with other bytes allowed" qa "$TMP/other-store.plist" 0
run "qa: relative path refused" qa "ExportOptions-ad-hoc.plist" 1
run "qa: destination upload refused" qa "$TMP/upload.plist" 1
# order: both option files are checked before the archive is built
total=$((total + 1))
first_check="$(grep -n 'check_export_plist "\$EXPORT_PLIST" "first"' "$ROOT/build-qa-adhoc.sh" | head -1 | cut -d: -f1)"
second_check="$(grep -n 'check_export_plist "\$EXPORT2_PLIST" "second"' "$ROOT/build-qa-adhoc.sh" | head -1 | cut -d: -f1)"
first_archive="$(grep -n 'archive -archivePath' "$ROOT/build-qa-adhoc.sh" | head -1 | cut -d: -f1)"
if [[ -n "$first_check" && -n "$second_check" && "$first_check" -lt "$first_archive" && "$second_check" -lt "$first_archive" ]]; then
  pass=$((pass + 1)); echo "ok   export options are checked before the archive"; else echo "FAIL export options are checked before the archive"; fi
echo "$pass/$total passed"; [[ "$pass" == "$total" ]]
