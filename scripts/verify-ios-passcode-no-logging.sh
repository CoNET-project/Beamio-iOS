#!/usr/bin/env bash
# M6 SC-04 source check (vectors v2/v3): the shell never logs the passcode field. Runs on the host (the simulator test host
# may not read the sources). Read-only.
#  1. The files the passcode passes through (PwaWalletSyncBridge.swift, PwaWalletSyncSdkEngine.swift) contain no logging call.
#  2. ContentView.swift (it receives the page message) has no log line that prints a whole message body or command dictionary.
#  3. SC-05 (patch v3.2): no logging call anywhere in the shell interpolates or passes a value whose name is a passcode, phrase,
#     mnemonic, private key, seed, secret, password or PIN (Swift interpolation \(...) or a format argument).
# Usage: verify-ios-passcode-no-logging.sh [IOS_ROOT]   exit 0 = PASS, 1 = FAIL
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "$0")/.." && pwd -P)}"
SRC="$ROOT/CashTrees_iOS"
fail=0
LOG_RE='\b(NSLog|print|debugPrint|dump|os_log|os_signpost)[[:space:]]*\(|Logger[[:space:]]*\(|\.(debug|info|notice|error|fault|log)[[:space:]]*\(|BeamioQALog\.|qaTrail[[:space:]]*\('
for f in PwaWalletSyncBridge.swift PwaWalletSyncSdkEngine.swift; do
  [[ -f "$SRC/$f" ]] || { echo "FAIL: passcode-no-logging: missing $f"; exit 1; }
  hits="$(grep -vE '^[[:space:]]*//' "$SRC/$f" | grep -nE "$LOG_RE" || true)"
  if [[ -n "$hits" ]]; then echo "FAIL: passcode-no-logging: logging call in $f:"; echo "$hits"; fail=1; fi
done
WHOLE_RE='(NSLog|print|qaTrail|BeamioQALog\.write)[[:space:]]*\(.*(\\\((body|command|message\.body)\)|,[[:space:]]*(body|command|message\.body)[[:space:]]*[,)])'
hits="$(grep -nE "$WHOLE_RE" "$SRC/ContentView.swift" || true)"
if [[ -n "$hits" ]]; then echo "FAIL: passcode-no-logging: ContentView logs a whole page message:"; echo "$hits"; fail=1; fi
hits="$(/usr/bin/python3 -I - "$SRC" <<'PY'
import os, re, sys
src = sys.argv[1]
call = re.compile(r'(\bos_log|\bLogger\(|\bNSLog|\bprint\(|\bdebugPrint|\bdump\(|BeamioQALog\.write|qaTrail\(|logNative\(|\.(debug|info|notice|error|fault|log)\()')
secret = re.compile(r'passcode|phrase|mnemonic|privatekey|privkey|seed|password|secret')
ident = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
def values(line):
    """The interpolated expressions and the format arguments of the first string literal on a log line."""
    out = re.findall(r'\\\(([^()]*(?:\([^()]*\)[^()]*)*)\)', line)
    m = re.search(r'"((?:[^"\\]|\\.)*)"\s*,(.*)$', line)
    if m and '%' in m.group(1):
        out.append(m.group(2))
    return out
for root, _, files in os.walk(src):
    for name in files:
        if not name.endswith('.swift'):
            continue
        path = os.path.join(root, name)
        lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
        for i, first in enumerate(lines):
            if first.lstrip().startswith('//') or not call.search(first):
                continue
            # Join a multi-line call until its parentheses balance (at most 15 lines).
            line, depth, j = first, first.count('(') - first.count(')'), i
            while depth > 0 and j + 1 < len(lines) and j - i < 15:
                j += 1
                line += ' ' + lines[j].strip()
                depth += lines[j].count('(') - lines[j].count(')')
            no = i + 1
            for expr in values(line):
                for tok in ident.findall(expr):
                    if tok[0].isupper():
                        continue  # a type name, not a value
                    low = tok.lower()
                    if secret.search(low) or low == 'pin':
                        print(f"{path}:{no}: {tok}: {line.strip()[:200]}")
                        break
PY
)"
if [[ -n "$hits" ]]; then echo "FAIL: passcode-no-logging: a log call passes a secret-named value (SC-05):"; echo "$hits"; fail=1; fi
[[ "$fail" == 0 ]] && echo "PASS: passcode-no-logging: no logging on the passcode path; ContentView logs no whole page message; no log call passes a secret-named value"
exit "$fail"
