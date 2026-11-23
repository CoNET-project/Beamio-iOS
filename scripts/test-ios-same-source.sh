#!/bin/zsh
# Stub cases for the same-source digest (macho_digest) of build-qa-adhoc.sh. The function is
# extracted from build-qa-adhoc.sh and run under zsh like the script. Fixtures are temporary copies of a system Mach-O.
set -euo pipefail
HERE="${0:A:h}"; ROOT="${HERE:h}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
sed -n '/^macho_digest() {/,/^}/p; /^check_same_source_evidence() {/,/^}/p' "$ROOT/build-qa-adhoc.sh" > "$TMP/fn.zsh"
source "$TMP/fn.zsh"
# Fixtures: thin arm64e copies of system binaries with the platform signature removed, then signed ad hoc per app (a different
# identifier per app stands for the two exports' different signatures of the same archive).
lipo -thin arm64e /usr/bin/true -output "$TMP/base"; codesign --remove-signature "$TMP/base"
lipo -thin arm64e /usr/bin/false -output "$TMP/other"; codesign --remove-signature "$TMP/other"
mkapp() {  # $1 = app dir, $2 = signing identifier: main executable, a framework binary, an appex binary, a non-Mach-O resource
  mkdir -p "$1/Frameworks/F.framework" "$1/PlugIns/E.appex"
  cp "$TMP/base" "$1/Main"; cp "$TMP/base" "$1/Frameworks/F.framework/F"; cp "$TMP/base" "$1/PlugIns/E.appex/E"; echo data > "$1/res.txt"
  local f; for f in "$1/Main" "$1/Frameworks/F.framework/F" "$1/PlugIns/E.appex/E"; do codesign -f -s - -i "$2" "$f" 2>/dev/null; done
}
pass=0; total=0
check() { total=$((total + 1)); if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); echo "ok   $1"; else echo "FAIL $1 (got $2, want $3)"; fi; }
mkapp "$TMP/a" com.example.store; mkapp "$TMP/b" com.example.store
da="$(macho_digest "$TMP/a" "$TMP/ev-a.txt")"; db="$(macho_digest "$TMP/b" "$TMP/ev-b.txt")"
check "identical apps give equal digests" "$([[ $da == $db ]] && echo eq || echo ne)" eq
check "every Mach-O is listed (main, framework, appex)" "$(wc -l < "$TMP/ev-a.txt" | tr -d ' ')" 3
check "non-Mach-O files are not listed" "$(grep -c res.txt "$TMP/ev-a.txt" || true)" 0
check "signature removal ok for every file" "$(awk '$3 != "ok"' "$TMP/ev-a.txt" | wc -l | tr -d ' ')" 0
# the same code signed differently (the two exports) keeps the digest
mkapp "$TMP/c" com.example.adhoc
dc="$(macho_digest "$TMP/c" "$TMP/ev-c.txt")"
check "a different signature alone keeps the digest" "$([[ $da == $dc ]] && echo eq || echo ne)" eq
# a different framework binary changes the digest
mkapp "$TMP/d" com.example.store; cp "$TMP/other" "$TMP/d/Frameworks/F.framework/F"; codesign -f -s - -i com.example.store "$TMP/d/Frameworks/F.framework/F" 2>/dev/null
dd="$(macho_digest "$TMP/d" "$TMP/ev-d.txt")"
check "a different framework binary changes the digest" "$([[ $da == $dd ]] && echo eq || echo ne)" ne
# an extra appex changes the digest
mkapp "$TMP/e" com.example.store; mkdir -p "$TMP/e/PlugIns/X.appex"; cp "$TMP/base" "$TMP/e/PlugIns/X.appex/X"
de="$(macho_digest "$TMP/e" "$TMP/ev-e.txt")"
check "an extra appex changes the digest" "$([[ $da == $de ]] && echo eq || echo ne)" ne
# a Mach-O whose signature cannot be removed is recorded FAILED (a truncated thin copy: file(1) still says Mach-O)
mkapp "$TMP/f" com.example.store; head -c 4096 "$TMP/base" > "$TMP/f/Frameworks/F.framework/F"
macho_digest "$TMP/f" "$TMP/ev-f.txt" > /dev/null
check "a failed signature removal is recorded FAILED" "$(awk '$3 == "FAILED"' "$TMP/ev-f.txt" | wc -l | tr -d ' ')" 1
# the formal decision reads the evidence files: one FAILED line makes the count non-zero
check "the failure count read from the evidence files is non-zero" "$(cat "$TMP/ev-f.txt" | awk '$3 != "ok"' | wc -l | tr -d ' ')" 1
# evidence rules: two apps without any Mach-O give the same empty-list digest, so the evidence itself
# must be non-empty, list the main executable and have equal line counts
mkdir -p "$TMP/g1" "$TMP/g2"; echo x > "$TMP/g1/res.txt"; echo y > "$TMP/g2/res.txt"
d1="$(macho_digest "$TMP/g1" "$TMP/ev-g1.txt")"; d2="$(macho_digest "$TMP/g2" "$TMP/ev-g2.txt")"
check "two apps without Mach-O give the same (empty-list) digest" "$([[ $d1 == $d2 ]] && echo eq || echo ne)" eq
check_same_source_evidence Main "$TMP/ev-g1.txt" "$TMP/ev-g2.txt" >/dev/null && rc=0 || rc=$?
check "empty evidence is refused" "$rc" 1
check_same_source_evidence Main "$TMP/ev-a.txt" "$TMP/ev-b.txt" "$TMP/ev-c.txt" >/dev/null && rc=0 || rc=$?
check "complete evidence passes" "$rc" 0
check_same_source_evidence OtherMain "$TMP/ev-a.txt" "$TMP/ev-b.txt" >/dev/null && rc=0 || rc=$?
check "evidence without the main executable is refused" "$rc" 1
check_same_source_evidence Main "$TMP/ev-a.txt" "$TMP/ev-e.txt" >/dev/null && rc=0 || rc=$?
check "evidence files with different line counts are refused" "$rc" 1
check_same_source_evidence Main "$TMP/ev-a.txt" "$TMP/missing.txt" >/dev/null && rc=0 || rc=$?
check "a missing evidence file is refused" "$rc" 1
# the Mach-O test has no pipe (no SIGPIPE under pipefail): a large Mach-O is still listed with pipefail on
setopt pipefail; mkapp "$TMP/h" com.example.store; cat "$TMP/base" "$TMP/base" "$TMP/base" "$TMP/base" > /dev/null
macho_digest "$TMP/h" "$TMP/ev-h.txt" > /dev/null
check "every Mach-O is listed with pipefail on" "$(wc -l < "$TMP/ev-h.txt" | tr -d ' ')" 3
echo "$pass/$total passed"; [[ "$pass" == "$total" ]]
