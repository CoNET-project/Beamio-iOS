#!/usr/bin/env bash
# Release / App Store check for the signed OTA code. A formal package must not carry:
#  - the QA-only OTA override (manifest URL / test key Info.plist keys, their symbol names, the loopback address,
#    the QA capability injection), which is compiled only with BEAMIO_QA_OTA;
#  - any test key id in the compiled key table (strings in the Mach-O files).
# Optional: --keys <ota-public-keys.json> checks that every compiled production key id is listed there.
# Usage: verify-ios-ota-release.sh <path/to/App.app> [--forbid-key <16 hex>]... [--keys <json>]
# exit 0 = PASS, 1 = FAIL, 2 = usage error
set -euo pipefail
APP="${1:-}"
[[ -n "$APP" && -d "$APP" ]] || { echo "usage: verify-ios-ota-release.sh <App.app> [--forbid-key ID]... [--keys JSON]" >&2; exit 2; }
shift
FORBID=(250cf19731885996 633f7e7faa3978cd)
KEYS_JSON=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --forbid-key) FORBID+=("${2:?--forbid-key needs an id}"); shift 2 ;;
    --keys) KEYS_JSON="${2:?--keys needs a file}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
PATTERNS=("BeamioQAOtaManifestURL" "BeamioQAOtaPublicKey" "CashTreesPWAOtaQA" "127.0.0.1" "pwa.embedded-ota.v1" "${FORBID[@]}")
hits=0; checked=0
while IFS= read -r -d '' f; do
  if file -b "$f" | grep -q 'Mach-O'; then
    checked=$((checked + 1))
    s="$(strings -a "$f")"
    for p in "${PATTERNS[@]}"; do
      n="$(printf '%s\n' "$s" | grep -cF -- "$p" || true)"
      if [[ "$n" != 0 ]]; then echo "FAIL: ota-release: '$p' x$n in ${f#"$APP"/}"; hits=$((hits + n)); fi
    done
  fi
done < <(find "$APP" -type f -print0)
[[ "$checked" -gt 0 ]] || { echo "FAIL: ota-release: no Mach-O file found in $APP" >&2; exit 1; }
for k in BeamioQAOtaManifestURL BeamioQAOtaPublicKey; do
  if /usr/libexec/PlistBuddy -c "Print :$k" "$APP/Info.plist" >/dev/null 2>&1; then echo "FAIL: ota-release: Info.plist has $k"; hits=$((hits + 1)); fi
done
if [[ -n "$KEYS_JSON" ]]; then
  [[ -f "$KEYS_JSON" ]] || { echo "FAIL: ota-release: key list not found: $KEYS_JSON"; exit 1; }
  for id in $(/usr/bin/python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); ks=d.get("keys",d) if isinstance(d,dict) else d; print(" ".join(k["keyId"] for k in ks))' "$KEYS_JSON"); do
    for f in "${FORBID[@]}"; do [[ "$id" != "$f" ]] || { echo "FAIL: ota-release: forbidden key id $id in $KEYS_JSON"; hits=$((hits + 1)); }; done
  done
fi
if [[ "$hits" -eq 0 ]]; then echo "PASS: ota-release: no QA OTA override, loopback address or test key in $checked Mach-O file(s)"; exit 0; fi
exit 1
