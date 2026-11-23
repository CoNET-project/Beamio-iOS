#!/usr/bin/env bash
# Exit-code decision for the authoritative iOS gate (verify-shell-pwa-version.sh). Sourced by build-qa-adhoc.sh and by
# scripts/test-ios-gate-exit-map.sh. It decides only; it never runs the gate.
#   formal: exit 0 is accepted; 4, 1, 2 and anything else is rejected.
#   qa:     exit 4 is accepted; exit 0 is an anomaly and is rejected until explained; 1, 2 and anything else are rejected.
# Prints ACCEPT, or REJECT with the reason. Returns 0 for accept, 1 for reject.
gate_exit_decision() {
  local mode="$1" rc="$2"
  case "$mode" in
    formal)
      if [[ "$rc" == 0 ]]; then echo ACCEPT; return 0; fi
      echo "REJECT: formal requires exit 0, got $rc"; return 1 ;;
    qa)
      case "$rc" in
        4) echo ACCEPT; return 0 ;;
        0) echo "REJECT: exit 0 is an anomaly in QA (a QA candidate must return 4); explain before use"; return 1 ;;
        *) echo "REJECT: qa requires exit 4, got $rc"; return 1 ;;
      esac ;;
    *) echo "REJECT: unknown mode $mode"; return 1 ;;
  esac
}
