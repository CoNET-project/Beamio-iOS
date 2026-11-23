#!/usr/bin/env bash
# Stub tests for formal_delegation_check. No gate is run; logs are synthetic stubs.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/ios-formal-delegation-check.sh"
T="$(mktemp -d "${TMPDIR:-/tmp}/formal-deleg-test.XXXXXX")"; trap 'rm -rf "$T"' EXIT
Z=1111111111111111111111111111111111111111111111111111111111111111
Y=2222222222222222222222222222222222222222222222222222222222222222
A=3333333333333333333333333333333333333333333333333333333333333333
J_OK="{\"result\":\"PASS\",\"shell\":\"ios\",\"scope\":\"shared-zip-formal-freeze\",\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Z\",\"approved_by\":\"project-owner\"}"
J_NOAPP="{\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Z\"}"
J_BADZIP="{\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Y\",\"approved_by\":\"project-owner\"}"
printf '%s\n' "==> delegated freeze check: $J_OK" > "$T/ok.log"
printf '%s\n' "==> delegated freeze check: NO DELEGATION (manifest status is 'qa-candidate')" > "$T/nodeleg.log"
printf '%s\n' "==> delegated freeze check: $J_NOAPP" > "$T/noapp.log"
printf '%s\n' "==> delegated freeze check: $J_BADZIP" > "$T/badzip.log"
: > "$T/none.log"
fails=0
expect() {  # $1 name, $2 log, $3 root, $4 actual, $5 expected ACCEPT|REFUSE
  local out rc got
  out="$(formal_delegation_check "$2" "$3" "$4")"; rc=$?
  if [[ $rc -eq 0 ]]; then got=ACCEPT; else got=REFUSE; fi
  if [[ "$got" == "$5" ]]; then echo "ok   $1 -> $got"; else echo "FAIL $1 expected $5 got $got ($out)"; fails=$((fails+1)); fi
}
expect pass-all-equal "$T/ok.log" "$Z" "$Z" ACCEPT
expect no-delegation-line "$T/none.log" "$Z" "$Z" REFUSE
expect NO-DELEGATION-line "$T/nodeleg.log" "$Z" "$Z" REFUSE
expect json-missing-approved_by "$T/noapp.log" "$Z" "$Z" REFUSE
expect delegation-zip-differs "$T/badzip.log" "$Z" "$Z" REFUSE
expect actual-zip-differs "$T/ok.log" "$Z" "$Y" REFUSE
expect root-manifest-differs "$T/ok.log" "$Y" "$Z" REFUSE
printf '%s\n' "==> delegated freeze check: $J_OK" "==> delegated freeze check: $J_OK" > "$T/twolines.log"
expect two-delegation-lines "$T/twolines.log" "$Z" "$Z" REFUSE
printf '%s\n' "==> delegated freeze check: NO DELEGATION (manifest status is 'qa-candidate')" > "$T/exit0nodel.log"
expect exit0-no-delegation-json "$T/exit0nodel.log" "$Z" "$Z" REFUSE
J_RES="{\"result\":\"REFUSED\",\"shell\":\"ios\",\"scope\":\"shared-zip-formal-freeze\",\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Z\",\"approved_by\":\"project-owner\"}"
J_ANDROID="{\"result\":\"PASS\",\"shell\":\"android\",\"scope\":\"shared-zip-formal-freeze\",\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Z\",\"approved_by\":\"project-owner\"}"
J_SCOPE="{\"result\":\"PASS\",\"shell\":\"ios\",\"scope\":\"other\",\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Z\",\"approved_by\":\"project-owner\"}"
J_GOOD="{\"result\":\"PASS\",\"shell\":\"ios\",\"scope\":\"shared-zip-formal-freeze\",\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Z\",\"approved_by\":\"project-owner\"}"
printf '%s\n' "==> delegated freeze check: $J_RES" > "$T/res.log"
printf '%s\n' "==> delegated freeze check: $J_ANDROID" > "$T/android.log"
printf '%s\n' "==> delegated freeze check: $J_SCOPE" > "$T/scope.log"
printf '%s\n' "==> delegated freeze check: $J_GOOD" > "$T/good.log"
expect result-not-PASS "$T/res.log" "$Z" "$Z" REFUSE
expect shell-android "$T/android.log" "$Z" "$Z" REFUSE
expect scope-mismatch "$T/scope.log" "$Z" "$Z" REFUSE
expect pass-shell-ios-scope-ok "$T/good.log" "$Z" "$Z" ACCEPT
# result FAIL with no REFUSED / NO DELEGATION text anywhere on the line: only the result check can refuse it
J_FAIL="{\"result\":\"FAIL\",\"shell\":\"ios\",\"scope\":\"shared-zip-formal-freeze\",\"version\":\"0.53.43\",\"approval_txt_sha256\":\"$A\",\"zip_sha256\":\"$Z\",\"approved_by\":\"project-owner\"}"
printf '%s\n' "==> delegated freeze check: $J_FAIL" > "$T/fail.log"
case "$(grep '^==> delegated freeze check: ' "$T/fail.log")" in *REFUSED*|*"NO DELEGATION"*) echo "FAIL fixture contains REFUSED/NO DELEGATION"; fails=$((fails+1));; esac
expect result-FAIL-no-marker "$T/fail.log" "$Z" "$Z" REFUSE
# control: a temporary copy of the check with the result test removed must ACCEPT the same line
CTRL="$T/ctrl-check.sh"
sed 's/if d.get("result") != "PASS":/if False:/' "$HERE/ios-formal-delegation-check.sh" > "$CTRL"
grep -q 'if False:' "$CTRL" || { echo "FAIL control copy not altered"; fails=$((fails+1)); }
( . "$CTRL"; out="$(formal_delegation_check "$T/fail.log" "$Z" "$Z")"; rc=$?; if [[ $rc -eq 0 ]]; then echo "ok   control-without-result-check -> ACCEPT (shows the case tests the result check)"; else echo "FAIL control expected ACCEPT got REFUSE ($out)"; exit 1; fi ) || fails=$((fails+1))
echo "failures: $fails"
exit $fails
