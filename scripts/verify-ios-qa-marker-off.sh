#!/usr/bin/env bash
# Release / App Store check: a formal package must not contain the chat SDK's QA-only marker. The SDK compiles
# its marker literal (beamio-sdk-qa-only-marker-...) only when BEAMIO_QA_BUILD is defined; no Mach-O file of the .app may carry the
# prefix `beamio-sdk-qa-only-marker`.
# Usage: verify-ios-qa-marker-off.sh <path/to/App.app>   exit 0 = PASS, 1 = FAIL, 2 = usage error
set -euo pipefail
APP="${1:-}"
[[ -n "$APP" && -d "$APP" ]] || { echo "usage: verify-ios-qa-marker-off.sh <App.app>" >&2; exit 2; }
PREFIX="beamio-sdk-qa-only-marker"
hits=0; checked=0
while IFS= read -r -d '' f; do
  if file -b "$f" | grep -q 'Mach-O'; then
    checked=$((checked + 1))
    n="$(strings -a "$f" | grep -c "$PREFIX" || true)"
    if [[ "$n" != 0 ]]; then echo "FAIL: qa-marker: $PREFIX x$n in ${f#"$APP"/}"; hits=$((hits + n)); fi
  fi
done < <(find "$APP" -type f -print0)
[[ "$checked" -gt 0 ]] || { echo "FAIL: qa-marker: no Mach-O file found in $APP" >&2; exit 1; }
if [[ "$hits" -eq 0 ]]; then echo "PASS: qa-marker: no QA marker in $checked Mach-O file(s)"; exit 0; fi
exit 1
