#!/usr/bin/env bash
# Release / App Store check: the built app must not contain the page console relay. The relay script
# (CashTreesWebConsoleRelay.injectionScript) is compiled only under `#if DEBUG || BEAMIO_QA`; its marker __CT_CONSOLE_PROXY_V4__
# must not appear in any Mach-O file of the .app.
# Usage: verify-ios-console-relay-off.sh <path/to/App.app>   exit 0 = PASS, 1 = FAIL, 2 = usage error
set -euo pipefail
APP="${1:-}"
[[ -n "$APP" && -d "$APP" ]] || { echo "usage: verify-ios-console-relay-off.sh <App.app>" >&2; exit 2; }
MARKER="__CT_CONSOLE_PROXY_V4__"
hits=0; checked=0
while IFS= read -r -d '' f; do
  if file -b "$f" | grep -q 'Mach-O'; then
    checked=$((checked + 1))
    n="$(strings -a "$f" | grep -c "$MARKER" || true)"
    if [[ "$n" != 0 ]]; then echo "FAIL: console-relay: page console relay script x$n in ${f#"$APP"/}"; hits=$((hits + n)); fi
  fi
done < <(find "$APP" -type f -print0)
[[ "$checked" -gt 0 ]] || { echo "FAIL: console-relay: no Mach-O file found in $APP" >&2; exit 1; }
if [[ "$hits" -eq 0 ]]; then echo "PASS: console-relay: no page console relay in $checked Mach-O file(s)"; exit 0; fi
exit 1
