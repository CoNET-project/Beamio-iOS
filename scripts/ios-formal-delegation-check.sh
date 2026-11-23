#!/usr/bin/env bash
# Formal-mode check of the authoritative gate's delegation line.
# Sourced by build-qa-adhoc.sh and by scripts/test-ios-formal-delegation.sh. It only reads the gate's output; the gate
# itself is never replaced. Without a delegation the gate falls back to the owner/unreleased rules, so exit 0 alone
# does not prove a delegated freeze.
#
# formal_delegation_check LOG ROOT_ZIP_SHA ACTUAL_ZIP_SHA
#   LOG            the gate's ios-prebuild output (must contain one "==> delegated freeze check: " line with PASS JSON)
#   ROOT_ZIP_SHA   zip_sha256 of the repository root pwa-freeze-manifest.json
#   ACTUAL_ZIP_SHA sha256 of the ZIP the build embeds
# Prints the verbatim delegation line on success (ACCEPT), or REFUSE: reason. Returns 0 accept, 1 refuse.
formal_delegation_check() {
  local log="$1" root_sha="$2" actual_sha="$3" line json deleg_sha
  local n
  n="$(grep -c '^==> delegated freeze check: ' "$log" 2>/dev/null || true)"
  if [[ "${n:-0}" != 1 ]]; then echo "REFUSE: expected exactly one '==> delegated freeze check:' line, found ${n:-0}"; return 1; fi
  line="$(grep '^==> delegated freeze check: ' "$log")"
  case "$line" in *"NO DELEGATION"*|*"REFUSED"*) echo "REFUSE: delegation line reports no delegation or a refusal"; return 1 ;; esac
  json="${line#==> delegated freeze check: }"
  case "$json" in
    \{*) ;;
    *) echo "REFUSE: delegated freeze check is not a PASS JSON (no delegation: ${json:0:80})"; return 1 ;;
  esac
  if ! deleg_sha="$(printf '%s' "$json" | /usr/bin/python3 -I -c '
import json, sys, re
try:
    d = json.load(sys.stdin)
except Exception as e:
    print("BAD " + str(e)); sys.exit(0)
for k in ("version", "approval_txt_sha256", "zip_sha256", "approved_by"):
    if not isinstance(d.get(k), str) or not d.get(k):
        print("MISSING " + k); sys.exit(0)
if d.get("result") != "PASS":
    print("RESULT " + str(d.get("result"))); sys.exit(0)
if d.get("shell") != "ios":
    print("SHELL " + str(d.get("shell"))); sys.exit(0)
if d.get("scope") != "shared-zip-formal-freeze":
    print("SCOPE " + str(d.get("scope"))); sys.exit(0)
if not re.fullmatch(r"[0-9a-f]{64}", d["zip_sha256"]) or not re.fullmatch(r"[0-9a-f]{64}", d["approval_txt_sha256"]):
    print("BADHEX"); sys.exit(0)
print("OK " + d["zip_sha256"])
')"; then echo "REFUSE: delegation JSON unreadable"; return 1; fi
  case "$deleg_sha" in
    OK\ *) deleg_sha="${deleg_sha#OK }" ;;
    *) echo "REFUSE: delegation JSON invalid: $deleg_sha"; return 1 ;;
  esac
  if [[ "$actual_sha" != "$root_sha" || "$root_sha" != "$deleg_sha" ]]; then
    echo "REFUSE: ZIP sha256 mismatch: actual=$actual_sha root_manifest=$root_sha delegation=$deleg_sha"; return 1
  fi
  echo "ACCEPT: $line"
  return 0
}
