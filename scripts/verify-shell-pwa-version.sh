#!/usr/bin/env bash
# Pre-pack PWA version gate for the Beamio shells (owner rule 2026-11-11).
# A shell must embed the latest RELEASED PWA, or a strictly higher version
# that is either an explicitly approved release or a local unreleased test.
# Read-only: never changes the project, the ZIP, OTA or production.
#
# "Released" = the live OTA manifest (default https://beamio.ca/app/update.json):
#   its "ver", and the SHA-256 of the ZIP it names (streamed, not saved).
#
# Modes:
#   zip               FILE.zip              check one PWA ZIP before copying it in
#   android-prebuild  [--app-dir DIR]       check the Android shell assets, then run
#                                           verify-android-single-zip.sh prebuild
#   android-artifact  FILE.apk|FILE.aab ... check built artifacts, then run
#                                           verify-android-single-zip.sh artifact
#
# Options:
#   --released-url URL        manifest URL (default above)
#   --released-ver X --released-sha HEX --released-source TEXT
#                             offline override of the released version (all three)
#   --unreleased-test         allow a version above released, labelled
#                             "UNRELEASED TEST / 未发布测试" (local test shells only)
#   --approved-ver X --approved-sha HEX --approval TEXT
#                             allow a version above released when it is exactly this
#                             approved release (version and SHA-256 must both match)
#   --freeze-manifest FILE    freeze manifest JSON, checked against --approval-dir. Accepted only when every
#                             field the gate reads is present and exact: status "frozen"; not_frozen JSON false;
#                             freeze_kind "owner-freeze"; release_state "frozen-owner-approved"; approved_by
#                             "project-owner"; version X.Y.Z; zip_sha256 64 lowercase hex; void a list; and
#                             owner_freeze_approval a bare file name. not_an_official_freeze, not_for_release,
#                             not_for_store and not_for_ota must be absent or JSON false. Duplicate JSON keys
#                             are refused. Then its version+zip_sha256 pass as FROZEN (not yet released) without
#                             --unreleased-test; its "void" list joins the void ZIPs. Same version, other bytes -> FAIL.
#                             QA candidates (status "qa-candidate") never go here: check them with
#                             --unreleased-test and no --freeze-manifest.
#   --approval-dir DIR        the dedicated directory of owner approval records (required with --freeze-manifest).
#                             The record is a separate file here, never the manifest and never outside this
#                             directory; it must hold these whole lines once each: OWNER FREEZE APPROVAL,
#                             version: X, zip_sha256: Y, manifest_sha256: <sha256 of the manifest bytes>,
#                             approved_by: project-owner. Records are written only by the project's release
#                             coordinator, from the project owner's own statement. No other session may write or
#                             complete one. The record needs no signature and need not be submitted by the project
#                             owner in person, so the gate adds no signature check.
#                             Test fixtures are labelled "FIXTURE，非真实批准" and are never approval.
#   --qa-manifest FILE        QA candidate manifest (status "qa-candidate", not_frozen JSON true, not_for_release /
#                             not_for_store / not_for_ota JSON true, freeze_kind "qa-candidate-not-frozen", release_state
#                             saying NOT FROZEN). Needs --unreleased-test; cannot be combined with --freeze-manifest or
#                             --approved-*. It binds ONE ZIP: the ZIP's version and sha256 must equal the manifest's, else
#                             FAIL. The verdict is QA (hash and single-ZIP check only): never FROZEN, never a formal package.
#
# Void ZIPs (withdrawn 0.52.931 30f08316..., 0.52.932 005baca0...) always FAIL.
# The manifest filename must be exactly SilentPassUI-<ver>.zip; any read error FAILs.
# Rules: ver < released -> FAIL. ver == released -> SHA-256 must equal the
# released ZIP. ver > released -> FAIL unless --approved-* matches or
# --unreleased-test is given. Exit: 0 pass, 1 fail, 2 usage error.

set -euo pipefail
# Hardening: git environment overrides must not redirect the identity check to another repository.
unset GIT_DIR GIT_COMMON_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE GIT_PREFIX GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM GIT_CONFIG_PARAMETERS GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM
# every GIT_CONFIG_* variable (including GIT_CONFIG_COUNT, GIT_CONFIG_KEY_n and GIT_CONFIG_VALUE_n) is cleared as well
for __gv in $(env | sed -n 's/^\(GIT_CONFIG_[A-Za-z0-9_]*\)=.*/\1/p'); do unset "$__gv"; done
# bash 3.2 safe argument check: a missing or empty value is a usage error (exit 2), never a silent pass.
need_arg() { if [[ $# -lt 2 || -z "$2" ]]; then echo "error: $1 needs a value" >&2; exit 2; fi; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() { sed -n '2,57p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
[[ $# -ge 1 ]] || usage
MODE="$1"; shift
case "$MODE" in zip|android-prebuild|android-artifact|ios-prebuild|ios-artifact) ;; -h|--help) usage ;; *) echo "error: unknown mode $MODE" >&2; exit 2 ;; esac

# --- iOS modes. Released-version rules run through this script's own zip mode; the delegated
# check runs in verify-delegated-freeze.py; the iOS single-ZIP gate runs last. Other modes are unchanged below.
# iOS repository identity (read from the environment, no built-in default). An --ios-root is accepted only
# when ALL of these hold (see ios_identity_check): (1) its real path is the iOS repository or lies under one of the two allowed
# roots below, with the trailing separator; (2) no ancestor of the root, up to /, is a symbolic link; (3) its git common directory
# equals IOS_REPO_COMMON_DIR_PINNED (the iOS repository's .git, never a temporary worktree path); (4) its working tree is clean
# (git status --porcelain prints nothing, untracked files count); (5) its full HEAD hash is printed for the receipt.
# Any failure, or any inability to establish identity, refuses every iOS mode.
# Trust anchor: the environment variables named in this script (BEAMIO_GATE_IOS_REPO, BEAMIO_GATE_IOS_WORKTREES) may be set only by trusted
# private configuration of the machine running the gate. Scripts and shell repositories in the repository must never set them.
# The identity of the iOS repository is the public origin address below plus the git common directory; the variable only locates it.
IOS_ORIGIN_EXPECTED="https://github.com/CoNET-project/Beamio-iOS.git"
norm_git_url() {  # canonical lower-case https form without .git: accepts https, http, git@host:path and ssh://git@host/path
	local u="${1%/}"; u="${u%.git}"
	case "$u" in
		git@github.com:*) u="https://github.com/${u#git@github.com:}" ;;
		ssh://git@github.com/*) u="https://github.com/${u#ssh://git@github.com/}" ;;
		http://github.com/*) u="https://github.com/${u#http://github.com/}" ;;
	esac
	printf '%s' "$u" | tr 'A-Z' 'a-z'
}
# BEAMIO_GATE_IOS_REPO = absolute path of the iOS repository; BEAMIO_GATE_IOS_WORKTREES = optional absolute path of the folder holding its
# worktrees. Unset, relative or missing means every iOS mode is refused (there is no default allow).
IOS_ALLOWED_ROOT_A="${BEAMIO_GATE_IOS_REPO:-}"
IOS_ALLOWED_ROOT_B="${BEAMIO_GATE_IOS_WORKTREES:-}"
IOS_REPO_COMMON_DIR_PINNED="${BEAMIO_GATE_IOS_REPO:+$BEAMIO_GATE_IOS_REPO/.git}"
ios_identity_check() {  # $1 = --ios-root as given; returns 0 when identity is established, else prints FAIL and returns 1
	local given="$1" abs real common top head st
	[[ -n "$IOS_ALLOWED_ROOT_A" && "$IOS_ALLOWED_ROOT_A" == /* && -d "$IOS_ALLOWED_ROOT_A" ]] \
		|| { echo "FAIL: BEAMIO_GATE_IOS_REPO is not set to an existing absolute directory: iOS modes refused" >&2; return 1; }
	[[ -z "$IOS_ALLOWED_ROOT_B" || "$IOS_ALLOWED_ROOT_B" == /* ]] \
		|| { echo "FAIL: BEAMIO_GATE_IOS_WORKTREES is not an absolute path: iOS modes refused" >&2; return 1; }
	[[ -d "$given" ]] || { echo "FAIL: iOS root not found or not a directory: $given: refused" >&2; return 1; }
	abs="$(cd "$given" 2>/dev/null && pwd -L)" || { echo "FAIL: cannot resolve iOS root $given: refused" >&2; return 1; }
	real="$(cd "$given" 2>/dev/null && pwd -P)" || { echo "FAIL: cannot resolve real path of iOS root $given: refused" >&2; return 1; }
	# (2) no ancestor (including the root itself) is a symbolic link, and the logical path is already the real path
	local p="$abs"
	while [[ -n "$p" && "$p" != "/" ]]; do
		[[ ! -L "$p" ]] || { echo "FAIL: iOS root $given has a symbolic link in its path ($p): refused" >&2; return 1; }
		p="$(dirname "$p")"
	done
	[[ "$abs" == "$real" ]] || { echo "FAIL: iOS root $given realpath $real differs from its path: refused" >&2; return 1; }
	# (1) allowed prefixes, with the trailing separator (Beamio-iOS-evil is refused)
	if [[ "$real" == "$IOS_ALLOWED_ROOT_A" || "$real" == "$IOS_ALLOWED_ROOT_A/"* || ( -n "$IOS_ALLOWED_ROOT_B" && "$real" == "$IOS_ALLOWED_ROOT_B/"* ) ]]; then :; else
		echo "FAIL: iOS root $real is outside the allowed iOS roots: refused" >&2; return 1
	fi
	# the root must be the top of its own working tree, not a subdirectory of some repository
	top="$(git -C "$real" rev-parse --path-format=absolute --show-toplevel 2>/dev/null)" && [[ "$top" == "$real" ]] \
		|| { echo "FAIL: iOS root $real is not the top of a git working tree: refused" >&2; return 1; }
	# (3a) the origin remote must be the public iOS repository address (identity), not merely the located path
	local origin
	origin="$(git -C "$real" remote get-url origin 2>/dev/null)" && [[ -n "$origin" ]] \
		|| { echo "FAIL: iOS root $real has no origin remote: refused" >&2; return 1; }
	[[ "$(norm_git_url "$origin")" == "$(norm_git_url "$IOS_ORIGIN_EXPECTED")" ]] \
		|| { echo "FAIL: iOS root $real has origin $origin, not the iOS repository $IOS_ORIGIN_EXPECTED: refused" >&2; return 1; }
	# (3) git common directory must be the pinned iOS repository
	common="$(git -C "$real" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" && [[ -n "$common" ]] \
		|| { echo "FAIL: cannot read the git common directory of $real: refused" >&2; return 1; }
	[[ "$common" == "$IOS_REPO_COMMON_DIR_PINNED" ]] \
		|| { echo "FAIL: iOS root $real has git common dir $common, not the pinned $IOS_REPO_COMMON_DIR_PINNED: refused" >&2; return 1; }
	# (4) clean working tree (untracked files count)
	# Known limitation: git status --porcelain does not list gitignored files, so a gitignored build product (for example
	# Vendor/X19) does not make the root dirty. Untracked and modified tracked files do. The ZIP content is checked by the single-ZIP gate,
	# not here. The genuine-root pass on the real iOS checkout is checked in QA, not by this test.
	st="$(git -C "$real" status --porcelain 2>/dev/null)" || { echo "FAIL: cannot read git status of $real: refused" >&2; return 1; }
	[[ -z "$st" ]] || { echo "FAIL: iOS root $real has uncommitted or untracked changes: refused" >&2; return 1; }
	# (5) full HEAD hash for the receipt
	head="$(git -C "$real" rev-parse HEAD 2>/dev/null)" && [[ -n "$head" ]] || { echo "FAIL: cannot read HEAD of $real: refused" >&2; return 1; }
	echo "iOS repository identity: OK root=$real common-dir=$common HEAD=$head"
	return 0
}
ios_mode() {
	local IOS_ROOT="" RES="" SHA_IN="" VER_IN="" ZIP_PATH="" DELEG_JSON="" DRC=0 ZSHA="" DVER=""
	local PASS=() ART=() HAS_APPROVED=0 TMPD="" FILE_SHA=""
	local SELF="$SCRIPT_DIR/verify-shell-pwa-version.sh"
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--ios-root) need_arg "$1" "${2-}"; IOS_ROOT="$2"; shift 2 ;;
			--resources) need_arg "$1" "${2-}"; RES="$2"; shift 2 ;;
			--sha256) need_arg "$1" "${2-}"; SHA_IN="$2"; shift 2 ;;
			--ver) need_arg "$1" "${2-}"; VER_IN="$2"; shift 2 ;;
			--unreleased-test) PASS+=("$1"); shift ;;
			--approved-ver|--approved-sha|--approval) need_arg "$1" "${2-}"; HAS_APPROVED=1; PASS+=("$1" "$2"); shift 2 ;;
			--freeze-manifest|--approval-dir|--qa-manifest|--released-url|--released-ver|--released-sha|--released-source)
				need_arg "$1" "${2-}"; PASS+=("$1" "$2"); shift 2 ;;
			--*) echo "error: unknown option $1" >&2; exit 2 ;;
			*) ART+=("$1"); shift ;;
		esac
	done
	[[ -n "$IOS_ROOT" ]] || { echo "error: $MODE needs --ios-root DIR (the iOS repository root, pinned in the caller)" >&2; exit 2; }
	ios_identity_check "$IOS_ROOT" || exit 1
	# unreleased test builds above the released version need a freeze or QA manifest
	if [[ " ${PASS[*]+${PASS[*]}} " == *" --unreleased-test "* ]] && [[ " ${PASS[*]+${PASS[*]}} " != *" --freeze-manifest "* && " ${PASS[*]+${PASS[*]}} " != *" --qa-manifest "* ]]; then
		echo "FAIL: --unreleased-test needs --freeze-manifest or --qa-manifest in an iOS mode" >&2; exit 1
	fi
	[[ -d "$IOS_ROOT" ]] || { echo "FAIL: iOS root not found: $IOS_ROOT" >&2; exit 1; }
	# dependency self-check: the iOS single-ZIP gate must be the reviewed file (sha256 pinned)
	# the iOS repository copy is the authority for the iOS single-ZIP gate
	# the delegated check module is pinned too: its reviewed sha256
	local DMOD="$SCRIPT_DIR/verify-delegated-freeze.py"
	[[ "$(shasum -a 256 "$DMOD" 2>/dev/null | awk '{print $1}')" == "26a43f7f19c3557bb673215815ffdf2a905aed70db2a2c560b4fe5e8c555b270" ]] \
		|| { echo "FAIL: verify-delegated-freeze.py is not the pinned value (build refused)" >&2; exit 1; }
	local IOSZ="$IOS_ROOT/scripts/verify-ios-single-zip.sh"
	[[ -f "$IOSZ" ]] || { echo "FAIL: dependency missing: $IOSZ (build refused)" >&2; exit 1; }
	local IOSZ_SHA; IOSZ_SHA="$(shasum -a 256 "$IOSZ" | awk '{print $1}')"
	[[ "$IOSZ_SHA" == "990cb82bbc69949d5fb5606722e6c5e3f32d3d22015f011aad0606ed1bbb3a6a" ]] \
		|| { echo "FAIL: verify-ios-single-zip.sh sha256 $IOSZ_SHA is not the pinned value (build refused)" >&2; exit 1; }
	if [[ "$MODE" == ios-prebuild ]]; then
		[[ -n "$RES" && -d "$RES" ]] || { echo "error: ios-prebuild needs --resources DIR (existing folder)" >&2; exit 2; }
		ZIP_PATH="$RES/SilentPassUI.zip"
	else
		[[ ${#ART[@]} -ge 1 ]] || { echo "error: ios-artifact needs at least one .app or .xcarchive (.ipa is refused until post is hardened)" >&2; exit 2; }
		TMPD="$(mktemp -d "${TMPDIR:-/tmp}/verify-ios-art.XXXXXX")"
		trap 'rm -rf "$TMPD"' EXIT
		ZSHA=""
		for a in ${ART[@]+"${ART[@]}"}; do
			a="${a%/}"
			out="$TMPD/$(basename "$a").SilentPassUI.zip"
			got="$(python3 -I - "$a" "$out" <<'PYX'
import glob, hashlib, os, sys
art, out = sys.argv[1], sys.argv[2]
# Independent full-tree stray scan: the whole artifact is walked here, not left to the post step.
# Every regular file that is a ZIP (name or PK magic) must be the one fixed-path SilentPassUI.zip; symlinks are refused.
def tree_zip_scan(root, fixed):
    hits, links, errs = [], [], []
    for dp, dn, fn in os.walk(root, followlinks=False, onerror=lambda e: errs.append(str(e))):
        for n in dn + fn:
            full = os.path.join(dp, n)
            if os.path.islink(full):
                links.append(full)
        for n in fn:
            full = os.path.join(dp, n)
            if os.path.islink(full):
                continue
            with open(full, "rb") as fh:
                head = fh.read(4)
            if n.lower().endswith(".zip") or head in (b"PK\x03\x04", b"PK\x05\x06"):
                hits.append(full)
    if errs:
        return "cannot enumerate the artifact (unreadable folder): " + errs[0]
    if links:
        return "symlink inside the artifact refused: " + links[0]
    if [h for h in hits] != [fixed]:
        return "stray or missing ZIP in the artifact (expected only the fixed-path SilentPassUI.zip): " + ", ".join(sorted(hits))
    return None
if art.lower().endswith(".ipa"):
    print("REFUSE .ipa is refused until verify-ios-single-zip.sh post extracts only the required member"); sys.exit(0)
if art.lower().endswith(".app") and os.path.isdir(art):
    cands = [os.path.join(art, "SilentPassUI.zip")]
elif art.lower().endswith(".xcarchive") and os.path.isdir(art):
    apps = sorted(glob.glob(os.path.join(art, "Products", "Applications", "*.app")))
    if len(apps) != 1:
        print(f"REFUSE xcarchive must contain exactly one .app (found {len(apps)})"); sys.exit(0)
    cands = [os.path.join(apps[0], "SilentPassUI.zip")]
else:
    print("REFUSE artifact must be an existing .app or .xcarchive directory"); sys.exit(0)
c = [p for p in cands if os.path.isfile(p) and not os.path.islink(p)]
if len(c) != 1:
    print("REFUSE embedded SilentPassUI.zip missing or not a regular file at the fixed load path"); sys.exit(0)
root = art if os.path.isdir(art) else None
if art.lower().endswith(".xcarchive"):
    root = art
err = tree_zip_scan(root, c[0]) if root else "not a directory"
if err:
    print("REFUSE " + err); sys.exit(0)
data = open(c[0], "rb").read()
open(out, "wb").write(data)
print(hashlib.sha256(data).hexdigest())
PYX
)"
			case "$got" in
				REFUSE*) echo "FAIL: $a: ${got#REFUSE }" >&2; exit 1 ;;
			esac
			if [[ -z "$ZSHA" ]]; then ZSHA="$got"; elif [[ "$ZSHA" != "$got" ]]; then
				echo "FAIL: artifacts embed different ZIPs ($ZSHA vs $got): one release per call" >&2; exit 1
			fi
			ZIP_PATH="$out"
		done
	fi
	[[ -f "$ZIP_PATH" ]] || { echo "FAIL: ZIP not found: $ZIP_PATH" >&2; exit 1; }
	FILE_SHA="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
	# the ZIP's own version (its update.json). Always taken from the ZIP; --ver, when given, must equal it.
	ZVER="$(python3 -I - "$ZIP_PATH" <<'PYV'
import json, sys, zipfile
try:
    print(json.loads(zipfile.ZipFile(sys.argv[1]).read("update.json").decode("utf-8")).get("ver", ""))
except Exception:
    print("")
PYV
)"
	[[ "$ZVER" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "FAIL: the ZIP has no readable X.Y.Z version in update.json" >&2; exit 1; }
	[[ -z "$VER_IN" || "$VER_IN" == "$ZVER" ]] || { echo "FAIL: --ver $VER_IN does not match the ZIP version $ZVER" >&2; exit 1; }
	[[ -z "$SHA_IN" || "$SHA_IN" == "$FILE_SHA" ]] || { echo "FAIL: --sha256 does not match the ZIP bytes" >&2; exit 1; }
	# QA-only branch: a QA manifest given explicitly skips the DELEGATED judgement only.
	# The single-ZIP gate, the ZIP/QA-manifest hash binding and the ZIP's own version still run. The result is never a formal
	# pass: exit 4 with "QA ONLY - NOT FROZEN". A frozen root manifest is ignored here (no mixing of the two paths).
	if [[ " ${PASS[*]+${PASS[*]}} " == *" --qa-manifest "* ]]; then
		[[ " ${PASS[*]+${PASS[*]}} " != *" --freeze-manifest "* ]] || { echo "FAIL: --qa-manifest and --freeze-manifest cannot be combined" >&2; exit 1; }
		[[ $HAS_APPROVED -eq 0 ]] || { echo "FAIL: --qa-manifest cannot be combined with --approved-*" >&2; exit 1; }
		set +e
		"$SELF" zip "$ZIP_PATH" ${PASS[@]+"${PASS[@]}"} --unreleased-test
		QRC=$?
		set -e
		[[ $QRC -eq 4 ]] || { echo "RESULT: FAIL (QA manifest refused; not a QA pass)" >&2; exit 1; }
		set +e
		if [[ "$MODE" == ios-prebuild ]]; then
			"$IOSZ" pre --resources "$RES" --sha256 "$FILE_SHA" --ver "$ZVER"
		else
			"$IOSZ" post --sha256 "$FILE_SHA" --ver "$ZVER" ${ART[@]+"${ART[@]}"}
		fi
		IRC=$?
		set -e
		[[ $IRC -eq 0 ]] || { echo "RESULT: FAIL (iOS single-ZIP gate, QA path)" >&2; exit 1; }
		echo "RESULT: QA ONLY - NOT FROZEN (--qa-manifest; not_for_release; not a delegated freeze; never a formal pass)"
		exit 4
	fi
	# 1. delegated check (exit 0 PASS, 1 REFUSED, 3 NO DELEGATION)
	set +e
	DELEG_JSON="$(python3 -I "$SCRIPT_DIR/verify-delegated-freeze.py" --shell ios --shell-root "$IOS_ROOT" --zip "$ZIP_PATH")"
	DRC=$?
	set -e
	echo "==> delegated freeze check: $DELEG_JSON"
	if [[ $DRC -eq 1 ]]; then echo "RESULT: FAIL (delegated freeze refused)" >&2; exit 1; fi
	if [[ $DRC -eq 0 ]]; then
		[[ $HAS_APPROVED -eq 0 ]] || { echo "FAIL: a delegated freeze and --approved-* cannot be used together" >&2; exit 1; }
		DVER="$(printf '%s' "$DELEG_JSON" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
		DSHA="$(printf '%s' "$DELEG_JSON" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["approval_txt_sha256"])')"
		"$SELF" zip "$ZIP_PATH" --approved-ver "$DVER" --approved-sha "$FILE_SHA" --approval "PM DELEGATED FREEZE approval_txt_sha256=$DSHA" || { echo "RESULT: FAIL (released-version gate)" >&2; exit 1; }
	else
		# no delegation: the owner / unreleased rules, passed through to this script's zip mode
		"$SELF" zip "$ZIP_PATH" ${PASS[@]+"${PASS[@]}"} || { echo "RESULT: FAIL (released-version gate)" >&2; exit 1; }
		DVER="$ZVER"
	fi
	[[ -z "$VER_IN" || -z "$DVER" || "$VER_IN" == "$DVER" ]] || { echo "FAIL: --ver $VER_IN does not match the ZIP version $DVER" >&2; exit 1; }
	# 2. the iOS single-ZIP gate (pre on the resource folder, post on the artifacts)
	if [[ "$MODE" == ios-prebuild ]]; then
		exec "$IOSZ" pre --resources "$RES" --sha256 "$FILE_SHA" --ver "${DVER:-$VER_IN}"
	else
		exec "$IOSZ" post --sha256 "$FILE_SHA" --ver "${DVER:-$VER_IN}" ${ART[@]+"${ART[@]}"}
	fi
}
if [[ "$MODE" == ios-prebuild || "$MODE" == ios-artifact ]]; then
	ios_mode "$@"
fi

URL="https://beamio.ca/app/update.json"  # strict TLS
RVER="" RSHA="" RSRC="" TEST=0 AVER="" ASHA="" AREF="" FMAN="" APPR="" QMAN=""
APP_DIR="$REPO_ROOT/src/CaehTrees/app"
FILES=()
while [[ $# -gt 0 ]]; do
	case "$1" in
		--released-url) need_arg "$1" "${2-}"; URL="$2"; shift 2 ;;
		--released-ver) need_arg "$1" "${2-}"; RVER="$2"; shift 2 ;;
		--released-sha) need_arg "$1" "${2-}"; RSHA="$2"; shift 2 ;;
		--released-source) need_arg "$1" "${2-}"; RSRC="$2"; shift 2 ;;
		--unreleased-test) TEST=1; shift ;;
		--approved-ver) need_arg "$1" "${2-}"; AVER="$2"; shift 2 ;;
		--approved-sha) need_arg "$1" "${2-}"; ASHA="$2"; shift 2 ;;
		--approval) need_arg "$1" "${2-}"; AREF="$2"; shift 2 ;;
		--freeze-manifest) need_arg "$1" "${2-}"; FMAN="$2"; shift 2 ;;
		--approval-dir) need_arg "$1" "${2-}"; APPR="$2"; shift 2 ;;
		--qa-manifest) need_arg "$1" "${2-}"; QMAN="$2"; shift 2 ;;
		--app-dir) need_arg "$1" "${2-}"; APP_DIR="$2"; shift 2 ;;
		-h|--help) usage ;;
		--*) echo "error: unknown option $1" >&2; exit 2 ;;
		*) FILES+=("$1"); shift ;;
	esac
done
if [[ -n "$RVER$RSHA$RSRC" && ( -z "$RVER" || -z "$RSHA" || -z "$RSRC" ) ]]; then
	echo "error: --released-ver, --released-sha and --released-source go together" >&2; exit 2
fi
if [[ -n "$AVER$ASHA$AREF" && ( -z "$AVER" || -z "$ASHA" || -z "$AREF" ) ]]; then
	echo "error: --approved-ver, --approved-sha and --approval go together" >&2; exit 2
fi
if [[ -n "$QMAN" && "$TEST" != 1 ]]; then echo "FAIL: --qa-manifest needs --unreleased-test: a QA candidate is never a freeze or a formal package" >&2; exit 1; fi
if [[ -n "$QMAN" && -n "$FMAN" ]]; then echo "FAIL: --qa-manifest and --freeze-manifest cannot be combined" >&2; exit 1; fi
if [[ -n "$QMAN" && -n "$AVER$ASHA$AREF" ]]; then echo "FAIL: --qa-manifest cannot be combined with --approved-*" >&2; exit 1; fi
case "$MODE" in
	zip) [[ ${#FILES[@]} -eq 1 ]] || { echo "error: zip mode takes exactly one ZIP" >&2; exit 2; } ;;
	android-artifact) [[ ${#FILES[@]} -ge 1 ]] || { echo "error: give at least one .apk/.aab" >&2; exit 2; } ;;
	android-prebuild) FILES=("$APP_DIR/src/main/assets/SilentPassUI.zip") ;;
esac

# --- Android delegated check: the same authority as the iOS modes, before the released-version rules.
# The Gradle call site is unchanged; the shell root is the parent of the app folder (manifest at <root>/app/pwa-freeze-manifest.json).
# PASS sets the approved triple for the existing rules below; NO DELEGATION leaves the owner/unreleased path unchanged; REFUSED fails.
if [[ "$MODE" == android-prebuild || "$MODE" == android-artifact ]]; then
	DMOD="$SCRIPT_DIR/verify-delegated-freeze.py"
	[[ "$(shasum -a 256 "$DMOD" 2>/dev/null | awk '{print $1}')" == "26a43f7f19c3557bb673215815ffdf2a905aed70db2a2c560b4fe5e8c555b270" ]] \
		|| { echo "FAIL: verify-delegated-freeze.py is not the pinned value (build refused)" >&2; exit 1; }
	ANDROID_ROOT="$(cd "$APP_DIR/.." && pwd -P)"
	DZIP=""
	if [[ "$MODE" == android-prebuild ]]; then
		DZIP="${FILES[0]}"
	else
		DTMP="$(mktemp -d "${TMPDIR:-/tmp}/verify-android-deleg.XXXXXX")"
		DZIP="$DTMP/SilentPassUI.zip"
		python3 -I - "${FILES[0]}" "$DZIP" <<'PYA' || { rm -rf "$DTMP"; echo "FAIL: cannot read the embedded ZIP from ${FILES[0]} (refused)" >&2; exit 1; }
import sys, zipfile
p, out = sys.argv[1], sys.argv[2]
z = zipfile.ZipFile(p)
n = "base/assets/SilentPassUI.zip" if p.lower().endswith(".aab") else "assets/SilentPassUI.zip"
open(out, "wb").write(z.read(n))
PYA
	fi
	set +e
	DJSON="$(python3 -I "$DMOD" --shell android --shell-root "$ANDROID_ROOT" --zip "$DZIP")"
	DRC=$?
	set -e
	[[ "$MODE" == android-artifact ]] && rm -rf "${DTMP:-}"
	echo "==> delegated freeze check (android): $DJSON"
	if [[ $DRC -eq 1 ]]; then echo "RESULT: FAIL (delegated freeze refused)" >&2; exit 1; fi
	if [[ $DRC -eq 0 ]]; then
		[[ -z "$AVER$ASHA$AREF" ]] || { echo "FAIL: a delegated freeze and --approved-* cannot be used together" >&2; exit 1; }
		AVER="$(printf '%s' "$DJSON" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["version"])')"
		ASHA="$(printf '%s' "$DJSON" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["zip_sha256"])')"
		AREF="PM DELEGATED FREEZE approval_txt_sha256=$(printf '%s' "$DJSON" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["approval_txt_sha256"])')"
	fi
fi
set +e
export PWA_FREEZE_MANIFEST="$FMAN"
export PWA_FREEZE_APPROVAL_DIR="$APPR"
export PWA_QA_MANIFEST="$QMAN"
python3 -I - "$MODE" "$URL" "$RVER" "$RSHA" "$RSRC" "$TEST" "$AVER" "$ASHA" "$AREF" ${FILES[@]+"${FILES[@]}"} <<'PY'
import hashlib, io, json, os, re, sys, time, urllib.request, zipfile
mode, url, rver, rsha, rsrc, test, aver, asha, aref = sys.argv[1:10]
files = sys.argv[10:]
test = test == "1"
MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
# Withdrawn, never-released PWA ZIPs (PWA release line, 2026-11-11). Reject in any mode.
VOID = {
    "30f08316d43ea4e328ae72642f2cd5fabb44b222c2026b83c9ba14b363338450": "0.52.931 fb97c1f9, withdrawn",
    "005baca0d6992bf4779ff9bef0335a06fdd2ad978c5896c0f8f9db08c1568517": "0.52.932 non-clean build, withdrawn",
}
# Freeze manifest (pwa-version-ledger): the one frozen, not-yet-released build allowed above released.
# Accepted only when every check below passes; each refusal is printed with its reason .
#   - every field the gate reads must be present and exactly as written: status "frozen"; not_frozen JSON false;
#     freeze_kind "owner-freeze"; release_state "frozen-owner-approved"; approved_by "project-owner"; version X.Y.Z;
#     zip_sha256 64 lowercase hex; void a list of 64-hex strings; owner_freeze_approval a bare file name.
#   - not_an_official_freeze, not_for_release, not_for_store, not_for_ota: absent or JSON false.
#   - duplicate JSON keys are refused.
#   - the approval record is a separate file inside --approval-dir (resolved). It is never the manifest, never outside that
#     directory, and the directory is never the manifest's own directory. Its lines must contain each of these whole lines
#     (trailing blanks ignored) exactly once:
#       OWNER FREEZE APPROVAL
#       version: <manifest version>
#       zip_sha256: <manifest zip_sha256>
#       manifest_sha256: <sha256 of the manifest file bytes>
#       approved_by: project-owner
FREEZE_KIND = "owner-freeze"
RELEASE_STATE = "frozen-owner-approved"
APPROVED_BY = "project-owner"
FREEZE_FLAGS = ("not_an_official_freeze", "not_for_release", "not_for_store", "not_for_ota")
FROZEN = None
def _no_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out: raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out
def approval_record_refusals(raw, path, approval_dir, name, m, ver_ok, sha_ok):
    why = []
    manifest_real = os.path.realpath(path)
    adir = os.path.realpath(approval_dir)
    if adir == os.path.dirname(manifest_real):
        why.append("the approval record directory is the manifest's own directory; records must be kept apart")
        return why
    rp = os.path.realpath(os.path.join(adir, name))
    if rp == manifest_real:
        why.append("owner_freeze_approval names the manifest itself")
        return why
    if os.path.dirname(rp) != adir:
        why.append(f"approval record {name!r} resolves outside the approval directory")
        return why
    if not os.path.isfile(rp):
        why.append(f"approval record {name!r} is missing from the approval directory")
        return why
    try:
        with open(rp, encoding="utf-8") as rf: text = rf.read()
    except Exception as e:
        why.append(f"approval record {name!r} unreadable: {e}")
        return why
    if not (ver_ok and sha_ok): return why  # the version or sha is already refused
    lines = [ln.rstrip(" \t\r") for ln in text.splitlines()]
    manifest_sha = hashlib.sha256(raw).hexdigest()
    wanted = ["OWNER FREEZE APPROVAL", f"version: {m['version']}", f"zip_sha256: {m['zip_sha256']}",
              f"manifest_sha256: {manifest_sha}", f"approved_by: {APPROVED_BY}"]
    for want in wanted:
        n = sum(1 for ln in lines if ln == want)
        if n != 1: why.append(f"approval record {name!r} must contain the line {want!r} exactly once (found {n})")
    return why
def freeze_manifest_refusals(raw, path, approval_dir):
    """Returns (refusal reasons, parsed manifest). Never raises."""
    why = []
    try:
        m = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except Exception as e:
        return [f"not valid JSON: {e}"], None
    if not isinstance(m, dict):
        return ["not a JSON object"], None
    def need(k):
        if k in m: return True
        why.append(f"{k} is missing")
        return False
    if need("status") and m["status"] != "frozen":
        why.append(f"status is {m['status']!r}, not 'frozen'")
    if need("not_frozen") and m["not_frozen"] is not False:
        why.append(f"not_frozen is {m['not_frozen']!r}, not JSON false: this manifest is not a freeze")
    for k in FREEZE_FLAGS:
        if k in m and m[k] is not False:
            why.append(f"{k} is {m[k]!r}, not JSON false: this is not a freeze")
    if need("freeze_kind") and m["freeze_kind"] != FREEZE_KIND:
        why.append(f"freeze_kind is {m['freeze_kind']!r}, not {FREEZE_KIND!r}")
    if need("release_state") and m["release_state"] != RELEASE_STATE:
        why.append(f"release_state is {m['release_state']!r}, not {RELEASE_STATE!r}")
    if need("approved_by") and m["approved_by"] != APPROVED_BY:
        why.append(f"approved_by is {m['approved_by']!r}, not {APPROVED_BY!r}")
    ver_ok = sha_ok = False
    if need("version"):
        ver_ok = isinstance(m["version"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", m["version"]) is not None
        if not ver_ok: why.append(f"version {m['version']!r} is not X.Y.Z")
    if need("zip_sha256"):
        sha_ok = isinstance(m["zip_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", m["zip_sha256"]) is not None
        if not sha_ok: why.append("zip_sha256 is not 64 lowercase hex characters")
    if need("void"):
        if not isinstance(m["void"], list) or not all(isinstance(h, str) and re.fullmatch(r"[0-9a-f]{64}", h) for h in m["void"]):
            why.append("void must be a list of 64-hex sha256 strings")
    if need("owner_freeze_approval"):
        name = m["owner_freeze_approval"]
        if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name) is None:
            why.append("owner_freeze_approval must be a bare file name (no directory part)")
        elif not approval_dir:
            why.append("no approval record directory given (--approval-dir)")
        elif not os.path.isdir(approval_dir):
            why.append(f"approval record directory {approval_dir!r} does not exist")
        else:
            why += approval_record_refusals(raw, path, approval_dir, name, m, ver_ok, sha_ok)
    return why, m
_fm = os.environ.get("PWA_FREEZE_MANIFEST", "")
if _fm:
    try:
        with open(_fm, "rb") as _f: _raw = _f.read()
    except Exception as _e:
        print(f"FAIL: freeze manifest {_fm} unreadable: {_e}")
        print("RESULT: FAIL (freeze manifest refused)"); sys.exit(1)
    _why, _m = freeze_manifest_refusals(_raw, _fm, os.environ.get("PWA_FREEZE_APPROVAL_DIR", ""))
    if _why:
        for _w in _why: print(f"FAIL: freeze manifest {os.path.basename(_fm)} refused: {_w}")
        print(f"RESULT: FAIL (freeze manifest refused: {len(_why)} reason(s); not accepted as a freeze)"); sys.exit(1)
    FROZEN = (_m["version"], _m["zip_sha256"])
    for _h in _m["void"]: VOID[_h] = f"voided in {os.path.basename(_fm)}"
    print(f"freeze manifest: ver={FROZEN[0]} sha256={FROZEN[1]} ({os.path.basename(_fm)}) - all freeze conditions met")
# QA candidate manifest: with --unreleased-test only. It binds ONE ZIP by its version and sha256 and says
# nothing else: the verdict is QA, NOT FROZEN. It is never a freeze, never a formal package, and never read by --freeze-manifest.
QA = None
QA_FREEZE_KIND = "qa-candidate-not-frozen"
def qa_manifest_refusals(raw, path):
    """Returns (reasons, parsed manifest). Never raises."""
    why = []
    try:
        m = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except Exception as e:
        return [f"not valid JSON: {e}"], None
    if not isinstance(m, dict):
        return ["not a JSON object"], None
    def need(k):
        if k in m: return True
        why.append(f"{k} is missing")
        return False
    if need("status") and m["status"] != "qa-candidate":
        why.append(f"status is {m['status']!r}, not 'qa-candidate'")
    if need("not_frozen") and m["not_frozen"] is not True:
        why.append(f"not_frozen is {m['not_frozen']!r}, not JSON true: a QA manifest must say it is not a freeze")
    for k in ("not_for_release", "not_for_store", "not_for_ota"):
        if need(k) and m[k] is not True:
            why.append(f"{k} is {m[k]!r}, not JSON true")
    if need("freeze_kind") and m["freeze_kind"] != QA_FREEZE_KIND:
        why.append(f"freeze_kind is {m['freeze_kind']!r}, not {QA_FREEZE_KIND!r}")
    if need("release_state") and not (isinstance(m["release_state"], str) and "NOT FROZEN" in m["release_state"]):
        why.append("release_state must say NOT FROZEN")
    if need("version"):
        if not (isinstance(m["version"], str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", m["version"])):
            why.append(f"version {m['version']!r} is not X.Y.Z")
    if need("zip_sha256"):
        if not (isinstance(m["zip_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", m["zip_sha256"])):
            why.append("zip_sha256 is not 64 lowercase hex characters")
    return why, m
_qm = os.environ.get("PWA_QA_MANIFEST", "")
if _qm:
    try:
        with open(_qm, "rb") as _f: _qraw = _f.read()
    except Exception as _e:
        print(f"FAIL: qa manifest {_qm} unreadable: {_e}")
        print("RESULT: FAIL (qa manifest refused)"); sys.exit(1)
    _qwhy, _qobj = qa_manifest_refusals(_qraw, _qm)
    if _qwhy:
        for _w in _qwhy: print(f"FAIL: qa manifest {os.path.basename(_qm)} refused: {_w}")
        print(f"RESULT: FAIL (qa manifest refused: {len(_qwhy)} reason(s); a QA candidate is not a freeze)"); sys.exit(1)
    QA = (_qobj["version"], _qobj["zip_sha256"])
    print(f"qa manifest: ver={QA[0]} sha256={QA[1]} ({os.path.basename(_qm)}) - QA only: hash and single ZIP, NOT FROZEN")
errors = []
def fail(m): errors.append(m); print("FAIL: " + m)
def semver(v):
    try: return tuple(int(x) for x in v.strip().split("."))
    except ValueError: return None
now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
print(f"checked at {now}")

# 1. released version and its source
released_bytes = None
if rver:
    released_ver, released_sha = rver, rsha.lower()
    print(f"released: ver={released_ver} sha256={released_sha} source=override: {rsrc}")
else:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Cache-Control": "no-cache"}), timeout=20) as r:
            if r.status != 200: raise RuntimeError(f"HTTP {r.status}")
            man = json.loads(r.read()); mlm, metag = r.headers.get("Last-Modified"), r.headers.get("ETag")
        released_ver, fname = str(man["ver"]), str(man["filename"])
        if fname != f"SilentPassUI-{released_ver}.zip":
            raise RuntimeError(f"manifest filename {fname!r} is not SilentPassUI-{released_ver}.zip")
        zurl = url.rsplit("/", 1)[0] + "/" + fname
        with urllib.request.urlopen(urllib.request.Request(zurl, headers={"Cache-Control": "no-cache"}), timeout=120) as r:
            if r.status != 200: raise RuntimeError(f"ZIP HTTP {r.status}")
            zlm, zetag = r.headers.get("Last-Modified"), r.headers.get("ETag")
            released_bytes = r.read()  # kept in memory only, for the same-version diagnosis
        n = len(released_bytes)
        released_sha = hashlib.sha256(released_bytes).hexdigest()
        print(f"released: ver={released_ver} sha256={released_sha} size={n} source={url} -> {zurl}")
        print(f"  manifest Last-Modified={mlm} ETag={metag}; ZIP Last-Modified={zlm} ETag={zetag}")
    except Exception as e:
        print(f"FAIL: cannot read the released version from {url}: {e}")
        print("RESULT: FAIL (released version unknown; use --released-* only with a recorded source)")
        sys.exit(1)
if semver(released_ver) is None:
    print(f"FAIL: released ver {released_ver!r} is not X.Y.Z"); sys.exit(1)

# 2. find the embedded ZIP(s)
def zips_in(path):
    low = path.lower()
    if low.endswith(".zip"):
        return [(path, open(path, "rb").read())]
    z = zipfile.ZipFile(path); out = []
    for i in z.infolist():
        if i.is_dir(): continue
        with z.open(i) as f: head = f.read(4)
        if i.filename.lower().endswith(".zip") or head in MAGIC:
            out.append((i.filename, z.read(i)))
    return out

def same_ver_diff(data):
    """Short content diff against the released ZIP (only when its bytes were read)."""
    if released_bytes is None: return ""
    try:
        def files(b):
            z = zipfile.ZipFile(io.BytesIO(b))
            return {i.filename: hashlib.sha256(z.read(i)).hexdigest() for i in z.infolist() if not i.is_dir()}
        e, r = files(data), files(released_bytes)
        main = lambda m: ",".join(sorted(k.rsplit("/", 1)[1] for k in m if k.startswith("static/js/main.") and k.endswith(".js"))) or "?"
        only_e, only_r = len(set(e) - set(r)), len(set(r) - set(e))
        changed = sum(1 for k in set(e) & set(r) if e[k] != r[k])
        return (f"; main script: embedded {main(e)} vs released {main(r)}; "
                f"files only in embedded/released: {only_e}/{only_r}; same path, different content: {changed}")
    except Exception as ex:
        return f"; diff unavailable ({ex})"

def check_zip(label, data):
    sha = hashlib.sha256(data).hexdigest()
    try:
        zz = zipfile.ZipFile(io.BytesIO(data))
        ver = str(json.loads(zz.read("update.json")).get("ver", ""))
        has_index = "index.html" in zz.namelist()
    except Exception as e:
        fail(f"{label}: unreadable PWA ZIP ({e})"); return
    print(f"  embedded: {label} ver={ver} sha256={sha} index.html={'yes' if has_index else 'NO'}")
    if sha in VOID:
        fail(f"{label}: sha256 {sha} is a VOID PWA ZIP ({VOID[sha]}); never embed it"); return
    if not has_index: fail(f"{label}: no index.html at the ZIP root")
    if QA and (ver != QA[0] or sha != QA[1]):
        fail(f"{label}: ver {ver}/sha {sha} is not the qa manifest {QA[0]}/{QA[1]} (a QA manifest binds one ZIP)"); return
    sv, rv = semver(ver), semver(released_ver)
    if sv is None: fail(f"{label}: update.json ver {ver!r} is not X.Y.Z"); return
    if sv < rv:
        fail(f"{label}: ver {ver} is LOWER than released {released_ver} (stale PWA; embed {released_ver} or a newer version)")
    elif sv == rv:
        if sha != released_sha:
            fail(f"{label}: ver {ver} equals released but sha256 {sha} != released {released_sha} (not the released ZIP) "
                 f"— 同号不同包 / same version, different package{same_ver_diff(data)}")
        else:
            print(f"  verdict: OK, embeds the released PWA {ver}")
    else:
        if QA:
            print(f"  verdict: QA {ver} - qa-candidate manifest: hash and single ZIP checked only; NOT FROZEN (not a freeze, not a formal package; test shells only)")
        elif aver and ver == aver and sha == asha.lower():
            print(f"  verdict: OK, {ver} is above released {released_ver} and is the approved release (approval: {aref})")
        elif aver and (ver != aver or sha != asha.lower()):
            fail(f"{label}: ver {ver}/sha {sha} does not match approved {aver}/{asha.lower()}")
        elif FROZEN and ver == FROZEN[0] and sha == FROZEN[1]:
            print(f"  verdict: FROZEN {ver} — the frozen build in the ledger (not yet released; the frozen release candidate)")
        elif FROZEN and ver == FROZEN[0]:
            fail(f"{label}: ver {ver} is the frozen version but sha256 {sha} != frozen {FROZEN[1]} (同号不同包 / same version, different package)")
        elif test:
            print(f"  verdict: UNRELEASED TEST / 未发布测试 — {ver} > released {released_ver}; local test shell only, do not ship")
        else:
            fail(f"{label}: ver {ver} is above released {released_ver}; pass --approved-ver/--approved-sha/--approval for an approved release, or --unreleased-test for a local test shell")

for f in files:
    print(f"input: {f}")
    try:
        found = zips_in(f)
    except FileNotFoundError:
        fail(f"{f}: not found"); continue
    except zipfile.BadZipFile:
        fail(f"{f}: not a ZIP/APK/AAB"); continue
    if len(found) != 1:
        fail(f"{f}: {len(found)} ZIPs found ({', '.join(n for n, _ in found) or 'none'}); exactly one is required")
    for name, data in found:
        check_zip(name, data)

# A QA-only result is exit 4 with one label, in every mode. A formal pass stays exit 0.
if errors:
    print("RESULT: FAIL (%d problem(s))" % len(errors)); sys.exit(1)
if QA:
    # the single RESULT line for zip mode; the android chain prints its own final line (one QA conclusion per run)
    if mode == "zip":
        print("RESULT: QA ONLY - NOT FROZEN (exit 4; not_for_release; never a formal pass)")
    else:
        print("QA manifest checked: hash and single ZIP bound; the chain below decides the final result")
    sys.exit(4)
print("RESULT: PASS (version gate)"); sys.exit(0)
PY
rc=$?
set -e
# QA (exit 4) continues into the Android single-ZIP gate for android modes: the single-ZIP gate must run
# on a QA candidate too, and its own failure wins. A QA result is returned at the end as exit 4, never as a formal pass.
ANDROID_QA=0
if [[ $rc -eq 4 && "$MODE" != zip ]]; then
	ANDROID_QA=1
elif [[ $rc -ne 0 ]]; then
	exit $rc
fi

# 3. chain into the existing single-ZIP gate with the embedded ZIP's own hash
if [[ "$MODE" != zip ]]; then
	ZSHA="$(python3 -I - "${FILES[0]}" <<'PY'
import hashlib, sys, zipfile
p = sys.argv[1]
if p.lower().endswith(".zip"):
    print(hashlib.sha256(open(p, "rb").read()).hexdigest())
else:
    z = zipfile.ZipFile(p); n = "base/assets/SilentPassUI.zip" if p.lower().endswith(".aab") else "assets/SilentPassUI.zip"
    # Not at the load path: hand a dummy hash on, the single-ZIP gate reports the location.
    print(hashlib.sha256(z.read(n)).hexdigest() if n in z.namelist() else "0" * 64)
PY
)"
	echo "==> single-ZIP gate (verify-android-single-zip.sh) with embedded sha256 $ZSHA"
	if [[ ! -x "$SCRIPT_DIR/verify-android-single-zip.sh" ]]; then
		echo "FAIL: single-ZIP gate missing: $SCRIPT_DIR/verify-android-single-zip.sh (build refused)" >&2
		echo "RESULT: FAIL (gate script missing)" >&2
		exit 1
	fi
	ARC=0
	if [[ "$MODE" == android-prebuild ]]; then
		"$SCRIPT_DIR/verify-android-single-zip.sh" prebuild --app-dir "$APP_DIR" --sha256 "$ZSHA" || ARC=$?
	else
		"$SCRIPT_DIR/verify-android-single-zip.sh" artifact --sha256 "$ZSHA" ${FILES[@]+"${FILES[@]}"} || ARC=$?
	fi
	# the single-ZIP gate's failure always wins; a QA candidate that passes the single-ZIP gate is exit 4, a formal pass exit 0
	[[ $ARC -eq 0 ]] || exit $ARC
	if [[ $ANDROID_QA -eq 1 ]]; then
		echo "RESULT: QA ONLY - NOT FROZEN (exit 4; the Android single-ZIP gate passed; never a formal pass)"
		exit 4
	fi
	exit 0
fi
