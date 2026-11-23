#!/bin/zsh
# iOS packaging for Beamio shells: QA mode (default) or formal mode (explicit switch).
#
# QA mode (BEAMIO_PACKAGE_MODE unset or "qa"): QA Ad Hoc build (Release configuration, production APNs) for device call
# debugging. Differences from a normal Ad Hoc build, all set on this command line only (the project file and Info.plist
# are not changed):
#   - Swift flag BEAMIO_QA: BeamioQALog writes the call path to Documents/qa-call.log and BeamioCallTiming writes
#     Documents/call-timing.log. Ids, stages and ok/fail only: no keys, mnemonics, session keys or message text.
#   - UIFileSharingEnabled + LSSupportsOpeningDocumentsInPlace, so the logs can be read without a debug-signed app.
# QA output is labelled QA-ONLY-NOT-FROZEN and is never a formal package. Never ship it: test devices only.
#
# Formal mode (BEAMIO_PACKAGE_MODE=formal): no --qa-manifest, no --unreleased-test, no manual pin. The expected ZIP sha256
# comes only from the repository root pwa-freeze-manifest.json (written by the authoritative sync flow). The gate must
# return exactly 0 at every step; 4 or any other code fails. Temporary paths and hand-written manifests are refused.
#
# usage: BEAMIO_PACKAGE_MODE=formal|qa ./build-qa-adhoc.sh <output-dir>
set -euo pipefail
cd "$(dirname "$0")"
OUT="${1:?usage: build-qa-adhoc.sh <output-dir>}"
MODE="${BEAMIO_PACKAGE_MODE:-qa}"
case "$MODE" in qa|formal) ;; *) echo "error: BEAMIO_PACKAGE_MODE must be qa or formal (got '$MODE')" >&2; exit 2 ;; esac

# M6 SC-04: the shell never logs the passcode. A source check, so it runs first, before any build step.
# A formal package is refused when it fails (like the Web Inspector check); a QA package records the result.
PNL_RESULT="$("$PWD/scripts/verify-ios-passcode-no-logging.sh" "$PWD" 2>&1)" && PNL_RC=0 || PNL_RC=$?
echo "$PNL_RESULT"
if [[ "$MODE" == formal && "$PNL_RC" != 0 ]]; then echo "FORMAL REFUSED: passcode logging check failed (SC-04)" >&2; exit 1; fi

is_temp_path() {  # $1 = path; true when its real location is a temporary area
  local real; real="$(cd "$(dirname "$1")" 2>/dev/null && pwd -P)/$(basename "$1")"
  case "$real" in /tmp/*|/private/tmp/*|/var/folders/*|/private/var/folders/*|*/claudeTemp/*) return 0 ;; *) return 1 ;; esac
}

if [[ "$MODE" == formal ]]; then
  [[ -z "${BEAMIO_QA_MANIFEST:-}" ]] || { echo "refused: formal mode does not take a QA manifest (BEAMIO_QA_MANIFEST)" >&2; exit 1; }
  [[ -z "${BEAMIO_PWA_FROZEN_MANIFEST:-}" ]] || { echo "refused: formal mode does not take a hand-written manifest (BEAMIO_PWA_FROZEN_MANIFEST)" >&2; exit 1; }
  is_temp_path "$OUT" && { echo "refused: formal output in a temporary path: $OUT" >&2; exit 1; }
  ROOT_MANIFEST="$PWD/pwa-freeze-manifest.json"
  [[ -f "$ROOT_MANIFEST" && ! -L "$ROOT_MANIFEST" ]] || { echo "refused: root pwa-freeze-manifest.json missing or a symlink" >&2; exit 1; }
  is_temp_path "$ROOT_MANIFEST" && { echo "refused: root manifest resolves to a temporary path" >&2; exit 1; }
  EXPECTED="$(/usr/bin/python3 -I -c 'import json,sys; m=json.load(open(sys.argv[1], encoding="utf-8")); print(m.get("zip_sha256",""))' "$ROOT_MANIFEST")"
  printf '%s' "$EXPECTED" | grep -Eq '^[0-9a-f]{64}$' || { echo "refused: root manifest zip_sha256 is not 64 lowercase hex" >&2; exit 1; }
  export BEAMIO_PWA_EXPECTED_ZIP_SHA256="$EXPECTED"
  QA_ARGS=()
  QA_MANIFEST_NOTE="none (formal)"
else
  FROZEN="${BEAMIO_PWA_FROZEN_MANIFEST:?set BEAMIO_PWA_FROZEN_MANIFEST to the frozen single-ZIP sha256 manifest (QA mode)}"
  export BEAMIO_PWA_EXPECTED_ZIP_SHA256="$(awk 'NR==1{print $1}' "$FROZEN")"
  if ! printf '%s' "$BEAMIO_PWA_EXPECTED_ZIP_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "error: frozen manifest $FROZEN does not start with a 64-hex SHA-256" >&2
    exit 1
  fi
  : "${BEAMIO_QA_MANIFEST:?set BEAMIO_QA_MANIFEST to the QA candidate manifest matching the embedded ZIP}"
  QA_ARGS=(--qa-manifest "$BEAMIO_QA_MANIFEST" --unreleased-test)
  QA_MANIFEST_NOTE="$BEAMIO_QA_MANIFEST sha256=$(shasum -a 256 "$BEAMIO_QA_MANIFEST" | awk '{print $1}')"
fi

mkdir -p "$OUT"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

QA_PLIST="$OUT/Info-QA.plist"
cp CashTrees_iOS/Info.plist "$QA_PLIST"
if [[ "$MODE" == qa ]]; then
  /usr/libexec/PlistBuddy -c "Add :UIFileSharingEnabled bool true" "$QA_PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Set :UIFileSharingEnabled true" "$QA_PLIST"
  /usr/libexec/PlistBuddy -c "Add :LSSupportsOpeningDocumentsInPlace bool true" "$QA_PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Set :LSSupportsOpeningDocumentsInPlace true" "$QA_PLIST"
fi

# Authoritative single-ZIP gate, run OUTSIDE the Xcode script sandbox.
: "${BEAMIO_SHELL_GATE:?set BEAMIO_SHELL_GATE to the authoritative verify-shell-pwa-version.sh}"
GATE_DIR="$(cd "$(dirname "$BEAMIO_SHELL_GATE")" && pwd)"
# Pinned SHA-256 of the reviewed gate files. Any mismatch stops the build.
PIN_GATE="407b6dd922f0fd265d936215457d1daed24f7e5ca8b2b9f21e86b05971100390"
PIN_FREEZE="26a43f7f19c3557bb673215815ffdf2a905aed70db2a2c560b4fe5e8c555b270"
PIN_SINGLE="990cb82bbc69949d5fb5606722e6c5e3f32d3d22015f011aad0606ed1bbb3a6a"
check_pin() { local f="$1" want="$2"; [[ -f "$f" ]] || { echo "error: gate file missing: $f" >&2; exit 1; }; local got; got="$(shasum -a 256 "$f" | awk '{print $1}')"; [[ "$got" == "$want" ]] || { echo "error: $f sha256 $got != pinned $want; build stopped" >&2; exit 1; }; }
check_pin "$BEAMIO_SHELL_GATE" "$PIN_GATE"
check_pin "$GATE_DIR/verify-delegated-freeze.py" "$PIN_FREEZE"
check_pin "$GATE_DIR/verify-ios-single-zip.sh" "$PIN_SINGLE"
echo "mode: $MODE"
echo "gate pins ok: verify-shell-pwa-version.sh ${PIN_GATE:0:16}, verify-delegated-freeze.py ${PIN_FREEZE:0:16}, verify-ios-single-zip.sh ${PIN_SINGLE:0:16}"

LAST_RC=0
. "$PWD/scripts/ios-gate-exit-map.sh"
run_gate() {  # $1 = label, rest = gate arguments. Output kept per stage; the exit decision comes from gate_exit_decision.
  local label="$1"; shift
  local log="$OUT/gate-$label.log"
  set +e; bash "$BEAMIO_SHELL_GATE" "$@" > "$log" 2>&1; LAST_RC=$?; set -e
  cat "$log"
  local verdict
  if verdict="$(gate_exit_decision "$MODE" "$LAST_RC")"; then
    if [[ "$MODE" == formal ]]; then echo "GATE $label: exit 0 (formal)"; else echo "GATE $label: exit 4 (QA ONLY - NOT FROZEN; not for acceptance)"; fi
  else
    echo "$verdict: $label" >&2; exit 1
  fi
}

run_gate ios-prebuild ios-prebuild --ios-root "$PWD" --resources "$PWD/CashTrees_iOS" ${QA_ARGS[@]+"${QA_ARGS[@]}"}
RC="$LAST_RC"
QA_LABEL=""; if [[ "$MODE" == qa && "$RC" == 4 ]]; then QA_LABEL="QA-ONLY-NOT-FROZEN-"; fi
if [[ "$MODE" == formal ]]; then
  . "$PWD/scripts/ios-formal-delegation-check.sh"
  ACTUAL_ZIP_SHA="$(shasum -a 256 "$PWD/CashTrees_iOS/SilentPassUI.zip" | awk '{print $1}')"
  DELEG_RESULT="$(formal_delegation_check "$OUT/gate-ios-prebuild.log" "$BEAMIO_PWA_EXPECTED_ZIP_SHA256" "$ACTUAL_ZIP_SHA")" \
    || { echo "FORMAL REFUSED: $DELEG_RESULT" >&2; exit 1; }
  echo "$DELEG_RESULT"
fi

# Export options: default the repository's Ad Hoc options (device tests); a store package passes
# BEAMIO_EXPORT_OPTIONS pointing at an app-store-connect ExportOptions plist. The method and the file hash go to the receipt.
# The path must be absolute; in formal mode destination must be "export"
# and the file is pinned by method (app-store-connect: the reviewed store options; release-testing: this repository's Ad Hoc
# options); any other method is refused in formal mode. destination must be "export" in every mode. Both option files are checked
# before the archive is built.
PIN_EXPORT_STORE="406c4ee17dc95fc327f1a7394e5db6d43c80ab5d596603baca90330439a73edd"
PIN_EXPORT_ADHOC="6bfc916c304f31dad01f0baf2daacfe66032d5bd56d3aa90970664eebcfbcf6a"
check_export_plist() {  # $1 = path, $2 = label; refuses (exit 1) on any failed rule
  local f="$1" label="$2" method dest sha
  [[ "$f" == /* ]] || { echo "error: $label export options must be an absolute path: $f" >&2; exit 1; }
  [[ -f "$f" ]] || { echo "error: $label export options not found: $f" >&2; exit 1; }
  method="$(/usr/libexec/PlistBuddy -c 'Print :method' "$f" 2>/dev/null || echo unknown)"
  dest="$(/usr/libexec/PlistBuddy -c 'Print :destination' "$f" 2>/dev/null || echo missing)"
  sha="$(shasum -a 256 "$f" | awk '{print $1}')"
  # every mode: nothing in this flow may send the package out before the gates
  [[ "$dest" == export ]] || { echo "REFUSED: $label export options destination is '$dest', not export" >&2; exit 1; }
  if [[ "$MODE" == formal ]]; then
    case "$method" in
      app-store-connect) [[ "$sha" == "$PIN_EXPORT_STORE" ]] || { echo "FORMAL REFUSED: $label app-store-connect options sha256 $sha != pinned $PIN_EXPORT_STORE" >&2; exit 1; } ;;
      release-testing) [[ "$sha" == "$PIN_EXPORT_ADHOC" ]] || { echo "FORMAL REFUSED: $label release-testing options sha256 $sha != pinned $PIN_EXPORT_ADHOC" >&2; exit 1; } ;;
      *) echo "FORMAL REFUSED: $label export method '$method' is not app-store-connect or release-testing" >&2; exit 1 ;;
    esac
  fi
}
EXPORT_PLIST="${BEAMIO_EXPORT_OPTIONS:-$PWD/ExportOptions-ad-hoc.plist}"
check_export_plist "$EXPORT_PLIST" "first"
EXPORT_METHOD="$(/usr/libexec/PlistBuddy -c 'Print :method' "$EXPORT_PLIST" 2>/dev/null || echo unknown)"
EXPORT_PLIST_SHA="$(shasum -a 256 "$EXPORT_PLIST" | awk '{print $1}')"
echo "export options: $EXPORT_PLIST method=$EXPORT_METHOD sha256=$EXPORT_PLIST_SHA"
EXPORT2_PLIST="${BEAMIO_SECOND_EXPORT_OPTIONS:-}"
if [[ -n "$EXPORT2_PLIST" ]]; then
  check_export_plist "$EXPORT2_PLIST" "second"
  EXPORT2_METHOD="$(/usr/libexec/PlistBuddy -c 'Print :method' "$EXPORT2_PLIST" 2>/dev/null || echo unknown)"
  EXPORT2_PLIST_SHA="$(shasum -a 256 "$EXPORT2_PLIST" | awk '{print $1}')"
  echo "second export options: $EXPORT2_PLIST method=$EXPORT2_METHOD sha256=$EXPORT2_PLIST_SHA"
fi

rm -rf "$OUT/qa.xcarchive" "$OUT/qa-adhoc" "$OUT/export-2"
# leftovers of an earlier run (second-export IPAs are named *CashTrees_iOS-<method>.ipa)
find "$OUT" -maxdepth 1 -type f -name '*CashTrees_iOS-*.ipa' -delete
# (find, not a glob: this script runs under zsh, where an unmatched glob is an error)
find "$OUT" -maxdepth 1 -type f \( -name 'macho-*.txt' -o -name 'entitlements-*.plist' -o -name 'entitlements-diff.txt' \) -delete
if [[ "$MODE" == formal ]]; then
  xcodebuild -project CashTrees_iOS.xcodeproj -scheme CashTrees_iOS -configuration Release \
    -destination 'generic/platform=iOS' -derivedDataPath DerivedData-Release \
    archive -archivePath "$OUT/qa.xcarchive" \
    'SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited)'
else
  xcodebuild -project CashTrees_iOS.xcodeproj -scheme CashTrees_iOS -configuration Release \
    -destination 'generic/platform=iOS' -derivedDataPath DerivedData-QARel \
    archive -archivePath "$OUT/qa.xcarchive" \
    'SWIFT_ACTIVE_COMPILATION_CONDITIONS=$(inherited) BEAMIO_QA BEAMIO_QA_BUILD' \
    INFOPLIST_FILE="$QA_PLIST"
fi
xcodebuild -exportArchive -archivePath "$OUT/qa.xcarchive" \
  -exportOptionsPlist "$EXPORT_PLIST" -exportPath "$OUT/qa-adhoc"

run_gate ios-artifact ios-artifact --ios-root "$PWD" ${QA_ARGS[@]+"${QA_ARGS[@]}"} "$OUT/qa.xcarchive"
RC="$LAST_RC"

IPA="$OUT/qa-adhoc/CashTrees_iOS.ipa"; [[ -f "$IPA" ]] || { echo "error: ipa not produced: $IPA" >&2; exit 1; }
IPA_SHA="$(shasum -a 256 "$IPA" | awk '{print $1}')"
UNPACK="$(mktemp -d "${TMPDIR:-/tmp}/beamio-ipa-unpack.XXXXXX")"; trap 'rm -rf "$UNPACK"' EXIT
unzip -q "$IPA" -d "$UNPACK"
APP_IN_IPA="$(ls -d "$UNPACK"/Payload/*.app | head -1)"; [[ -d "$APP_IN_IPA" ]] || { echo "error: no Payload/*.app in ipa" >&2; exit 1; }
run_gate ios-artifact-ipa ios-artifact --ios-root "$PWD" ${QA_ARGS[@]+"${QA_ARGS[@]}"} "$APP_IN_IPA"
RC2="$LAST_RC"
# Web Inspector: a formal package must not reference setInspectable:; a QA package is expected to (BEAMIO_QA).
WI_RESULT="$("$PWD/scripts/verify-ios-webinspector-off.sh" "$APP_IN_IPA" 2>&1)" && WI_RC=0 || WI_RC=$?
echo "$WI_RESULT"
if [[ "$MODE" == formal && "$WI_RC" != 0 ]]; then echo "FORMAL REFUSED: Web Inspector reference in the formal package" >&2; exit 1; fi
# Page console relay: a formal package must not contain it; a QA package is expected to (BEAMIO_QA).
CR_RESULT="$("$PWD/scripts/verify-ios-console-relay-off.sh" "$APP_IN_IPA" 2>&1)" && CR_RC=0 || CR_RC=$?
echo "$CR_RESULT"
if [[ "$MODE" == formal && "$CR_RC" != 0 ]]; then echo "FORMAL REFUSED: page console relay in the formal package" >&2; exit 1; fi
# QA marker: a formal package must not carry the chat SDK's QA-only marker; a QA package does (BEAMIO_QA_BUILD).
QM_RESULT="$("$PWD/scripts/verify-ios-qa-marker-off.sh" "$APP_IN_IPA" 2>&1)" && QM_RC=0 || QM_RC=$?
echo "$QM_RESULT"
if [[ "$MODE" == formal && "$QM_RC" != 0 ]]; then echo "FORMAL REFUSED: QA marker in the formal package" >&2; exit 1; fi

# Same-archive evidence: the archive's file-tree digest and main binary, and per IPA the embedded ZIP and the main
# binary with its signature removed, so a device-test IPA can be shown to carry the store IPA's code.
ARCHIVE_APP="$(ls -d "$OUT/qa.xcarchive/Products/Applications/"*.app | head -1)"
ARCHIVE_TREE_SHA="$(cd "$OUT/qa.xcarchive" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')"
# Same-source digest over every Mach-O file of an app (main executable, Frameworks, PlugIns/appex): each file is copied and its
# code signature removed; the evidence file lists "<relative path> <unsigned sha256> <unsign ok|FAILED>" sorted by path, and the
# function prints the sha256 of that list. A failed signature removal is recorded in the evidence file; formal mode refuses it
# below (decided from the evidence files, since the function runs in a command substitution).
macho_digest() {  # $1 = app, $2 = evidence file
  local app="$1" ev="$2" f rel tmp st
  : > "$ev"
  while IFS= read -r -d '' f; do
    [[ "$(file -b "$f")" == *Mach-O* ]] || continue
    rel="${f#"$app"/}"
    tmp="$(mktemp "${TMPDIR:-/tmp}/beamio-unsigned.XXXXXX")"; cp "$f" "$tmp"
    if codesign --remove-signature "$tmp" 2>/dev/null; then st=ok; else st=FAILED; fi
    printf '%s %s %s\n' "$rel" "$(shasum -a 256 "$tmp" | awk '{print $1}')" "$st" >> "$ev"
    rm -f "$tmp"
  done < <(find "$app" -type f -print0)
  LC_ALL=C sort -o "$ev" "$ev"
  awk '{print $1, $2}' "$ev" | shasum -a 256 | awk '{print $1}'
}
check_same_source_evidence() {  # $1 = main executable name, rest = evidence files; prints the reason and returns 1 on a failed rule
  local main="$1" ev n lines=""; shift
  for ev in "$@"; do
    [[ -f "$ev" ]] || { echo "same-source evidence missing: $ev"; return 1; }
    n="$(wc -l < "$ev" | tr -d ' ')"
    [[ "$n" -ge 1 ]] || { echo "same-source evidence is empty: $ev"; return 1; }
    awk -v m="$main" '$1 == m {f=1} END {exit !f}' "$ev" || { echo "same-source evidence does not list the main executable $main: $ev"; return 1; }
    [[ -z "$lines" || "$lines" == "$n" ]] || { echo "same-source evidence files differ in line count ($lines vs $n): $ev"; return 1; }
    lines="$n"
  done
  return 0
}
ARCHIVE_UNSIGNED_SHA="$(macho_digest "$ARCHIVE_APP" "$OUT/macho-archive.txt")"
IPA_ZIP_SHA="$(shasum -a 256 "$APP_IN_IPA/SilentPassUI.zip" | awk '{print $1}')"
IPA_UNSIGNED_SHA="$(macho_digest "$APP_IN_IPA" "$OUT/macho-ipa1.txt")"

# Optional second export of the SAME archive: e.g. Ad Hoc for the device test next to the app-store-connect store
# package. The second IPA's app runs the same artifact gate and binary checks; a formal run refuses if any fails.
if [[ -n "$EXPORT2_PLIST" ]]; then
  rm -rf "$OUT/export-2"
  xcodebuild -exportArchive -archivePath "$OUT/qa.xcarchive" -exportOptionsPlist "$EXPORT2_PLIST" -exportPath "$OUT/export-2"
  IPA2="$OUT/export-2/CashTrees_iOS.ipa"; [[ -f "$IPA2" ]] || { echo "error: second ipa not produced: $IPA2" >&2; exit 1; }
  IPA2_SHA="$(shasum -a 256 "$IPA2" | awk '{print $1}')"
  UNPACK2="$(mktemp -d "${TMPDIR:-/tmp}/beamio-ipa2-unpack.XXXXXX")"; trap 'rm -rf "$UNPACK" "$UNPACK2"' EXIT
  unzip -q "$IPA2" -d "$UNPACK2"
  APP2="$(ls -d "$UNPACK2"/Payload/*.app | head -1)"; [[ -d "$APP2" ]] || { echo "error: no Payload/*.app in second ipa" >&2; exit 1; }
  run_gate ios-artifact-ipa2 ios-artifact --ios-root "$PWD" ${QA_ARGS[@]+"${QA_ARGS[@]}"} "$APP2"
  RC3="$LAST_RC"
  for c in webinspector console-relay qa-marker; do
    R2="$("$PWD/scripts/verify-ios-$c-off.sh" "$APP2" 2>&1)" && C2=0 || C2=$?
    echo "second ipa: $R2"
    eval "EX2_${c//-/_}=$C2"
    if [[ "$MODE" == formal && "$C2" != 0 ]]; then echo "FORMAL REFUSED: $c check failed on the second ipa" >&2; exit 1; fi
  done
  IPA2_ZIP_SHA="$(shasum -a 256 "$APP2/SilentPassUI.zip" | awk '{print $1}')"
  IPA2_UNSIGNED_SHA="$(macho_digest "$APP2" "$OUT/macho-ipa2.txt")"
  if [[ "$MODE" == formal && ( "$IPA2_ZIP_SHA" != "$IPA_ZIP_SHA" || "$IPA_ZIP_SHA" != "$BEAMIO_PWA_EXPECTED_ZIP_SHA256" ) ]]; then
    echo "FORMAL REFUSED: embedded ZIP differs between the two ipas or from the expected sha256" >&2; exit 1
  fi
fi

# Same-source enforcement: in formal mode every signature removal must succeed and the archive and the IPAs
# must have the same unsigned Mach-O digest. Entitlements and embedded.mobileprovision of the two IPAs are compared and only recorded.
UNSIGN_FAILED="$(find "$OUT" -maxdepth 1 -type f -name 'macho-*.txt' -exec cat {} + | awk '$3 != "ok"' | wc -l | tr -d ' ')"
SAME_SOURCE="archive=$ARCHIVE_UNSIGNED_SHA ipa1=$IPA_UNSIGNED_SHA${EXPORT2_PLIST:+ ipa2=$IPA2_UNSIGNED_SHA}"
if [[ "$MODE" == formal ]]; then
  [[ "$UNSIGN_FAILED" == 0 ]] || { echo "FORMAL REFUSED: a code signature could not be removed (see $OUT/macho-*.txt)" >&2; exit 1; }
  # Evidence must not be empty (two empty lists would give the same empty-list digest): each file has at least one line, lists
  # the main executable, and all have the same number of lines.
  MAIN_EXE="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$ARCHIVE_APP/Info.plist")"
  EV_FILES=("$OUT/macho-archive.txt" "$OUT/macho-ipa1.txt")
  [[ -n "$EXPORT2_PLIST" ]] && EV_FILES+=("$OUT/macho-ipa2.txt")
  EV_RESULT="$(check_same_source_evidence "$MAIN_EXE" "${EV_FILES[@]}")" || { echo "FORMAL REFUSED: $EV_RESULT" >&2; exit 1; }
  [[ "$ARCHIVE_UNSIGNED_SHA" == "$IPA_UNSIGNED_SHA" ]] || { echo "FORMAL REFUSED: archive and first ipa differ after signature removal ($SAME_SOURCE)" >&2; exit 1; }
  if [[ -n "$EXPORT2_PLIST" && "$IPA2_UNSIGNED_SHA" != "$IPA_UNSIGNED_SHA" ]]; then
    echo "FORMAL REFUSED: the two ipas differ after signature removal ($SAME_SOURCE)" >&2; exit 1
  fi
fi
ent_sha() { codesign -d --entitlements :- "$1" 2>/dev/null | shasum -a 256 | awk '{print $1}'; }
prof_info() {  # sha256, UUID and name of embedded.mobileprovision
  local p="$1/embedded.mobileprovision" d; [[ -f "$p" ]] || { echo "none"; return; }
  d="$(security cms -D -i "$p" 2>/dev/null)"
  echo "sha256=$(shasum -a 256 "$p" | awk '{print $1}') uuid=$(/usr/libexec/PlistBuddy -c 'Print :UUID' /dev/stdin <<< "$d" 2>/dev/null) name=$(/usr/libexec/PlistBuddy -c 'Print :Name' /dev/stdin <<< "$d" 2>/dev/null)"
}
IPA_ENT_SHA="$(ent_sha "$APP_IN_IPA")"; IPA_PROF="$(prof_info "$APP_IN_IPA")"
codesign -d --entitlements :- "$APP_IN_IPA" > "$OUT/entitlements-ipa1.plist" 2>/dev/null || true
if [[ -n "$EXPORT2_PLIST" ]]; then
  IPA2_ENT_SHA="$(ent_sha "$APP2")"; IPA2_PROF="$(prof_info "$APP2")"
  codesign -d --entitlements :- "$APP2" > "$OUT/entitlements-ipa2.plist" 2>/dev/null || true
  diff "$OUT/entitlements-ipa1.plist" "$OUT/entitlements-ipa2.plist" > "$OUT/entitlements-diff.txt" 2>&1 || true
fi

echo "expected ZIP sha256 passed to the build (BEAMIO_PWA_EXPECTED_ZIP_SHA256): $BEAMIO_PWA_EXPECTED_ZIP_SHA256"
RECEIPT="$OUT/${QA_LABEL}RECEIPT.txt"
{
  echo "mode: $MODE"
  echo "product: ${QA_LABEL}CashTrees_iOS.ipa"
  echo "ipa_sha256: $IPA_SHA"
  echo "prebuild_exit: $RC"
  echo "ipa_app_exit: $RC2"
  echo "webinspector_off_exit: $WI_RC"
  echo "console_relay_off_exit: $CR_RC"
  echo "qa_marker_off_exit: $QM_RC"
  echo "passcode_no_logging_exit: $PNL_RC"
  echo "export_method: $EXPORT_METHOD"
  echo "export_options_sha256: $EXPORT_PLIST_SHA"
  echo "archive: $OUT/qa.xcarchive tree_sha256=$ARCHIVE_TREE_SHA"
  echo "same_source_unsigned_macho_digest: $SAME_SOURCE (per file: $OUT/macho-archive.txt macho-ipa1.txt${EXPORT2_PLIST:+ macho-ipa2.txt})"
  echo "signature_removal_failed: $UNSIGN_FAILED"
  echo "ipa_entitlements_sha256: $IPA_ENT_SHA"
  echo "ipa_provisioning_profile: $IPA_PROF"
  echo "ipa_embedded_zip_sha256: $IPA_ZIP_SHA"
  if [[ -n "$EXPORT2_PLIST" ]]; then
    echo "second_export_method: $EXPORT2_METHOD"
    echo "second_export_options_sha256: $EXPORT2_PLIST_SHA"
    echo "second_ipa_sha256: $IPA2_SHA"
    echo "second_ipa_app_exit: $RC3 webinspector=$EX2_webinspector console_relay=$EX2_console_relay qa_marker=$EX2_qa_marker"
    echo "second_ipa_embedded_zip_sha256: $IPA2_ZIP_SHA"
    echo "second_ipa_entitlements_sha256: $IPA2_ENT_SHA (diff: $OUT/entitlements-diff.txt, recorded only)"
    echo "second_ipa_provisioning_profile: $IPA2_PROF (recorded only)"
  fi
  echo "expected_zip_sha256: $BEAMIO_PWA_EXPECTED_ZIP_SHA256"
  echo "manifest: $( [[ "$MODE" == formal ]] && echo "repository root pwa-freeze-manifest.json sha256=$(shasum -a 256 "$PWD/pwa-freeze-manifest.json" | awk '{print $1}')" || echo "QA candidate (not frozen): $QA_MANIFEST_NOTE" )"
  if [[ "$MODE" == formal ]]; then
    echo "delegation (verbatim, gate $OUT/gate-ios-prebuild.log): $DELEG_RESULT"
    echo "actual ZIP sha256 (embedded SilentPassUI.zip): $ACTUAL_ZIP_SHA"
    echo "root manifest zip_sha256: $BEAMIO_PWA_EXPECTED_ZIP_SHA256"
    echo "gate logs: $OUT/gate-ios-prebuild.log $OUT/gate-ios-artifact.log $OUT/gate-ios-artifact-ipa.log"
  fi
} > "$RECEIPT"
if [[ -n "$EXPORT2_PLIST" ]]; then
  mv "$IPA2" "$OUT/${QA_LABEL}CashTrees_iOS-$EXPORT2_METHOD.ipa"; echo "second ipa ($EXPORT2_METHOD): $OUT/${QA_LABEL}CashTrees_iOS-$EXPORT2_METHOD.ipa"
fi
if [[ "$MODE" == formal ]]; then
  mv "$IPA" "$OUT/CashTrees_iOS.ipa"; echo "formal ipa ($EXPORT_METHOD): $OUT/CashTrees_iOS.ipa"
elif [[ -n "$QA_LABEL" ]]; then
  mv "$IPA" "$OUT/${QA_LABEL}CashTrees_iOS.ipa"; echo "QA ONLY - NOT FROZEN: not for acceptance or release: $OUT/${QA_LABEL}CashTrees_iOS.ipa"
else
  echo "QA run with a formal gate result: $IPA"
fi
echo "receipt: $RECEIPT"
