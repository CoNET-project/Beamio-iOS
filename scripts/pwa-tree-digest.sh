#!/bin/bash
# Independent implementation of CashTreesPWASameVersionRule.treeDigest (iOS shell, design r3 §5).
# Used at build time to record the embedded tree digest, and by the fixture test to prove both sides agree.
# Algorithm: regular files, excluding only .source.json, any-level __MACOSX/ and ._* names,
# sorted by UTF-8 byte order of the relative path; each contributes "path<NUL>sha256(content)<LF>";
# the digest is the SHA-256 (lower-case hex) of that byte stream. A symbolic link anywhere fails the script.
# usage: pwa-tree-digest.sh <dir>
set -euo pipefail
dir="${1:?usage: pwa-tree-digest.sh <dir>}"
cd "$dir"
if [ -n "$(find . -type l -print -quit)" ]; then
  echo "error: symbolic link in tree" >&2
  exit 1
fi
find . -type f | sed 's#^\./##' | LC_ALL=C sort | while IFS= read -r rel; do
  case "$rel" in
    __MACOSX/*|*/__MACOSX/*|.source.json|*/.source.json) continue ;;
    ._*|*/._*) continue ;;
  esac
  printf '%s\0%s\n' "$rel" "$(shasum -a 256 "$rel" | cut -d' ' -f1)"
done | shasum -a 256 | cut -d' ' -f1
