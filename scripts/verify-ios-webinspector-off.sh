#!/usr/bin/env bash
# Release / App Store check: the built app must not reference the WebKit selector setInspectable:.
# The shell sets isInspectable only under `#if DEBUG || BEAMIO_QA` (CashTreesWebInspection), so a Release build without
# BEAMIO_QA has no reference. Checks every Mach-O file in the .app (main binary, *.debug.dylib, Frameworks, PlugIns).
# Usage: verify-ios-webinspector-off.sh <path/to/App.app>   exit 0 = PASS (no reference), 1 = FAIL, 2 = usage error
set -euo pipefail
APP="${1:-}"
[[ -n "$APP" && -d "$APP" ]] || { echo "usage: verify-ios-webinspector-off.sh <App.app>" >&2; exit 2; }
hits=0; checked=0
while IFS= read -r -d '' f; do
  if file -b "$f" | grep -q 'Mach-O'; then
    checked=$((checked + 1))
    n="$(strings -a "$f" | grep -c 'setInspectable:' || true)"
    if [[ "$n" != 0 ]]; then echo "FAIL: webinspector: setInspectable: x$n in ${f#"$APP"/}"; hits=$((hits + n)); fi
  fi
done < <(find "$APP" -type f -print0)
[[ "$checked" -gt 0 ]] || { echo "FAIL: webinspector: no Mach-O file found in $APP" >&2; exit 1; }
if [[ "$hits" -eq 0 ]]; then echo "PASS: webinspector: no setInspectable: reference in $checked Mach-O file(s)"; exit 0; fi
exit 1
