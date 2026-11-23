#!/usr/bin/env bash
# Unit test of the exit-code decision with stub values. No gate is run and nothing is replaced.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/ios-gate-exit-map.sh"
fails=0
expect() {  # $1 mode, $2 rc, $3 expected ACCEPT|REJECT
  local out rc; out="$(gate_exit_decision "$1" "$2")"; rc=$?
  local got; if [[ $rc -eq 0 ]]; then got=ACCEPT; else got=REJECT; fi
  if [[ "$got" == "$3" ]]; then echo "ok   mode=$1 rc=$2 -> $got"; else echo "FAIL mode=$1 rc=$2 expected $3 got $got ($out)"; fails=$((fails+1)); fi
}
for rc in 0; do expect formal "$rc" ACCEPT; done
for rc in 4 1 2 255; do expect formal "$rc" REJECT; done
expect qa 4 ACCEPT
for rc in 0 1 2 255; do expect qa "$rc" REJECT; done
expect bogus 0 REJECT
echo "failures: $fails"
exit $fails
