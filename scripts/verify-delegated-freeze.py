#!/usr/bin/env python3
"""Delegated formal freeze verification for the shared Beamio consumer PWA ZIP .

Run with `python3 -I`. Exit codes: 0 = PASS (a verified delegated freeze of exactly one ZIP); 1 = REFUSED (a reason is printed);
3 = NO DELEGATION (no delegated manifest in the shell, or the placeholder {"status": "none"}). The shell gate treats 3 as "no
delegation" and falls back to the owner / unreleased rules; any 1 is a hard refusal.

The environment variables below may be set only by trusted private configuration of the machine running the gate; scripts and shell
repositories must never set them. The production roots come from three environment variables (never from arguments): BEAMIO_FREEZE_APPROVALS_DIR (the approval
records), BEAMIO_FREEZE_REVIEWS_DIR (the independent-review receipts) and BEAMIO_FREEZE_DELEGATION_FILE (the pinned delegation record). Each must be an
absolute path to an existing location; an unset, relative or missing value is REFUSED (nothing falls back to a default). The delegation
record must lie inside the approvals folder, and the reviews folder must lie under the same records root as the approvals folder. The delegation record is
still pinned by its sha256 and the record folders still need the owner and permission checks below. Tests call verify() with fixture roots;
a fixture is labelled FIXTURE and is never an approval.
"""
import datetime
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile

EXIT_PASS, EXIT_REFUSE, EXIT_NONE = 0, 1, 3

# --- constants (pinned in code) -------------------------------------------------
DELEGATION_SOURCE = None  # production: BEAMIO_FREEZE_DELEGATION_FILE (see production_delegation_source); tests may set it
DELEGATION_SOURCE_SHA256 = "d870a92000e4778c0906a53f5bd9f83a1ef909c8880946689536df78a4fb7fc7"
DELEGATED_IDENTITY = "conet-top-pm"
SCOPE = "shared-zip-formal-freeze"
EFFECTIVE_UTC = "2026-11-21T00:00:00Z"
FREEZE_KIND = "pm-delegated-freeze"
MANIFEST_NAME = "pwa-freeze-manifest.json"
APPROVAL_FILE = "approval.txt"
BINDING_FILE = "binding.json"
RECEIPT_FILE = "receipt.md"
ENV_APPROVALS = "BEAMIO_FREEZE_APPROVALS_DIR"
ENV_REVIEWS = "BEAMIO_FREEZE_REVIEWS_DIR"
ENV_DELEGATION = "BEAMIO_FREEZE_DELEGATION_FILE"


def _env_absolute(name):
    """An absolute, normalised path from the environment. Unset, empty or relative is REFUSED (fail closed, no default)."""
    value = os.environ.get(name, "")
    if not value:
        raise Refuse(f"{name} is not set: the record location is unknown (refused, nothing falls back to a default)")
    if not os.path.isabs(value):
        raise Refuse(f"{name} must be an absolute path (refused)")
    return os.path.normpath(value)


def _inside(root, path):
    rel = os.path.relpath(path, root)
    return rel != ".." and not rel.startswith(".." + os.sep) and not os.path.isabs(rel)


def production_roots():
    """The approval and review roots of this machine, from the environment. Both must lie under one records root (the parent of the approvals folder)."""
    roots = {"approvals_dir": _env_absolute(ENV_APPROVALS), "reviews_dir": _env_absolute(ENV_REVIEWS)}
    records_root = os.path.dirname(roots["approvals_dir"])
    if records_root == os.sep:
        raise Refuse(f"{ENV_APPROVALS} must not sit directly under the filesystem root (records root would be /) (refused)")
    if not _inside(records_root, roots["reviews_dir"]) or roots["reviews_dir"] == records_root:
        raise Refuse(f"{ENV_REVIEWS} must lie under the same records root as {ENV_APPROVALS} (refused)")
    if roots["reviews_dir"] == roots["approvals_dir"] or _inside(roots["approvals_dir"], roots["reviews_dir"]):
        raise Refuse(f"{ENV_REVIEWS} must not lie inside the approvals folder (refused)")
    return roots


def production_delegation_source():
    """The pinned delegation record; it must lie inside the approvals folder (checked on real paths)."""
    if DELEGATION_SOURCE:
        return DELEGATION_SOURCE
    path = _env_absolute(ENV_DELEGATION)
    approvals = _env_absolute(ENV_APPROVALS)
    if not _inside(os.path.realpath(approvals), os.path.realpath(path)):
        raise Refuse(f"{ENV_DELEGATION} must lie inside {ENV_APPROVALS} (refused)")
    return path
# Shell-relative manifest paths. Relative to each shell's repository root.
SHELL_MANIFEST_REL = {"android": os.path.join("app", MANIFEST_NAME), "ios": MANIFEST_NAME}

MANIFEST_KEYS = {"status", "not_frozen", "freeze_kind", "version", "zip_name", "zip_sha256", "commit", "main_bundle",
                 "file_count", "void"}
BINDING_REQUIRED = {"approval_txt_sha256", "version", "zip_sha256", "manifest_sha256", "commit", "approval_time_utc",
                    "receipt_path", "receipt_sha256", "delegation_sha256"}
BINDING_ALLOWED = BINDING_REQUIRED | {"scope"}
RE_VER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
RE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
RE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
RE_TIME = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
RE_BUNDLE = re.compile(r"^static/js/main\.[A-Za-z0-9]+\.js$")


class Refuse(Exception):
    pass


class NoDelegation(Exception):
    pass


def utc_now_str():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def probe(path):
    """lstat that distinguishes ENOENT (absent, returns None) from every other error (refused)."""
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        raise Refuse(f"cannot inspect {path}: errno {e.errno} ({os.strerror(e.errno)})")


def read_regular(path):
    """Reads a regular, non-symlink file's bytes. Any error refuses."""
    st = probe(path)
    if st is None:
        raise Refuse(f"missing: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise Refuse(f"not a regular file (or a symlink): {path}")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            return f.read()
    except OSError as e:
        raise Refuse(f"cannot read {path}: errno {e.errno}")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def no_dup_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Refuse(f"duplicate JSON key {k!r}")
        out[k] = v
    return out


def strict_json(data, label):
    if data.startswith(b"\xef\xbb\xbf"):
        raise Refuse(f"{label}: BOM is not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refuse(f"{label}: not UTF-8")
    try:
        obj = json.loads(text, object_pairs_hook=no_dup_pairs)
    except Refuse:
        raise
    except Exception as e:
        raise Refuse(f"{label}: not valid JSON ({e})")
    if not isinstance(obj, dict):
        raise Refuse(f"{label}: must be a JSON object")
    return obj


def zip_checks(zip_bytes, manifest):
    """ZIP content checks against the manifest. Reads entry names only; never extracts."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise Refuse("ZIP is not readable")
    names = zf.namelist()
    for n in names:
        if n.startswith("/") or ".." in n.split("/") or "\\" in n or "\x00" in n or re.match(r"^[A-Za-z]:", n):
            raise Refuse(f"ZIP entry name refused: {n!r}")
    if "index.html" not in names:
        raise Refuse("ZIP has no index.html at the root")
    if manifest["main_bundle"] not in names:
        raise Refuse(f"ZIP has no main_bundle entry {manifest['main_bundle']!r}")
    files = [n for n in names if not n.endswith("/")]
    if len(files) != manifest["file_count"]:
        raise Refuse(f"ZIP file count {len(files)} != manifest file_count {manifest['file_count']}")
    try:
        upd = json.loads(zf.read("update.json").decode("utf-8"))
    except Exception:
        raise Refuse("ZIP update.json missing or unreadable")
    if str(upd.get("ver", "")) != manifest["version"]:
        raise Refuse(f"ZIP update.json ver {upd.get('ver')!r} != manifest version {manifest['version']!r} (embedded ZIP differs)")


def check_revocation(roots):
    """lstat rules on the directory and then the marker. Any refusal is hard."""
    rdir = os.path.join(roots["approvals_dir"], "owner-freeze-delegation")
    st = probe(rdir)
    if st is None:
        return  # directory absent: not revoked
    if not stat.S_ISDIR(st.st_mode):
        raise Refuse("owner-freeze-delegation is not a real directory (file or symlink): refused")
    marker = os.path.join(rdir, "REVOKED")
    if probe(marker) is not None:
        raise Refuse("delegation is REVOKED (marker exists)")


def owner_ok(st):
    """Owner is the gate account or root, and the entry is not group- or world-writable."""
    return (st.st_uid in (os.getuid(), 0)) and not (st.st_mode & 0o022)


def chain_between(stop, target):
    """Every folder from `stop` (inclusive) down to `target` (inclusive). `target` must lie under `stop`."""
    rel = os.path.relpath(target, stop)
    if rel.startswith("..") or os.path.isabs(rel):
        raise Refuse(f"record path is not under the records root: {target}")
    out, cur = [stop], stop
    for part in ([] if rel == "." else rel.split(os.sep)):
        cur = os.path.join(cur, part)
        out.append(cur)
    return out


def check_dir_chain(dirs):
    """Each folder must exist, be a real directory, be owned by the gate account or root, and not be group- or world-writable.
    Residual risk: the records folder's own parents are not checked."""
    seen = set()
    for d in dirs:
        if d in seen:
            continue
        seen.add(d)
        st = probe(d)
        if st is None:
            raise Refuse(f"folder missing in the record chain: {d}")
        if not stat.S_ISDIR(st.st_mode):
            raise Refuse(f"record chain entry is not a real directory: {d}")
        if not owner_ok(st):
            raise Refuse(f"record chain folder is group/world-writable or not owned by the gate account or root: {d}")


def only_files(dirpath, allowed):
    """The directory must contain exactly the allowed regular files: nothing else (no subdirectories, symlinks, extras)."""
    st = probe(dirpath)
    if st is None:
        raise Refuse(f"record directory missing: {dirpath}")
    if not stat.S_ISDIR(st.st_mode):
        raise Refuse(f"record path is not a real directory: {dirpath}")
    # residual-risk guard: record folders must be owned by the account running the gate and must not be
    # group- or world-writable. This narrows who can plant a record; it is not a signature (see the review note).
    if not owner_ok(st):
        raise Refuse(f"record folder is group/world-writable or not owned by the gate account or root: {dirpath}")
    try:
        entries = sorted(os.listdir(dirpath))
    except OSError as e:
        raise Refuse(f"cannot list {dirpath}: errno {e.errno}")
    extra = [e for e in entries if e not in allowed]
    if extra:
        raise Refuse(f"extra entries in {dirpath}: {extra}")
    for name in allowed:
        if name not in entries:
            raise Refuse(f"missing {name} in {dirpath}")
        p = os.path.join(dirpath, name)
        s = probe(p)
        if not stat.S_ISREG(s.st_mode):
            raise Refuse(f"{name} in {dirpath} is not a regular file")
        if not owner_ok(s):
            raise Refuse(f"{name} in {dirpath} is group/world-writable or not owned by the gate account or root")


def parse_approval(raw, version_dir):
    if raw.startswith(b"\xef\xbb\xbf"):
        raise Refuse("approval.txt: BOM is not allowed")
    if b"\r" in raw:
        raise Refuse("approval.txt: CR is not allowed (LF only)")
    if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise Refuse("approval.txt: must end with exactly one LF")
    try:
        lines = raw.decode("utf-8").split("\n")[:-1]
    except UnicodeDecodeError:
        raise Refuse("approval.txt: not UTF-8")
    if len(lines) != 5:
        raise Refuse(f"approval.txt: must have exactly 5 lines (found {len(lines)})")
    if lines[0] != "PM DELEGATED FREEZE APPROVAL":
        raise Refuse("approval.txt: line 1 must be 'PM DELEGATED FREEZE APPROVAL'")
    m = {}
    for ln, key in ((lines[1], "version"), (lines[2], "zip_sha256"), (lines[3], "manifest_sha256"), (lines[4], "approved_by")):
        if ln != ln.strip():
            raise Refuse("approval.txt: leading or trailing whitespace on a line")
        prefix = key + ": "
        if not ln.startswith(prefix):
            raise Refuse(f"approval.txt: line must start with {prefix!r}")
        m[key] = ln[len(prefix):]
    if not RE_VER.match(m["version"]):
        raise Refuse("approval.txt: version is not X.Y.Z")
    if not RE_SHA256.match(m["zip_sha256"]) or not RE_SHA256.match(m["manifest_sha256"]):
        raise Refuse("approval.txt: hashes must be 64 lowercase hex")
    if m["approved_by"] != DELEGATED_IDENTITY:
        raise Refuse(f"approval.txt: approved_by must be {DELEGATED_IDENTITY!r} (got {m['approved_by']!r})")
    if m["version"] != version_dir:
        raise Refuse("approval.txt: version differs from the directory name")
    return m


def parse_manifest(raw):
    m = strict_json(raw, "manifest")
    if m.get("status") != "frozen":
        raise Refuse(f"manifest is not frozen, no valid delegation (manifest status is {m.get('status')!r}; a non-frozen manifest is refused)")
    if set(m.keys()) != MANIFEST_KEYS:
        raise Refuse(f"manifest fields must be exactly {sorted(MANIFEST_KEYS)} (missing {sorted(MANIFEST_KEYS - set(m))}, extra {sorted(set(m) - MANIFEST_KEYS)})")
    if m["status"] != "frozen":
        raise Refuse(f"manifest status is {m['status']!r}, not 'frozen'")
    if m["not_frozen"] is not False:
        raise Refuse("manifest not_frozen must be JSON false")
    if m["freeze_kind"] != FREEZE_KIND:
        raise Refuse(f"manifest freeze_kind must be {FREEZE_KIND!r}")
    if not isinstance(m["version"], str) or not RE_VER.match(m["version"]):
        raise Refuse("manifest version is not X.Y.Z")
    if m["zip_name"] != f"SilentPassUI-{m['version']}.zip":
        raise Refuse("manifest zip_name must be SilentPassUI-<version>.zip")
    if not isinstance(m["zip_sha256"], str) or not RE_SHA256.match(m["zip_sha256"]):
        raise Refuse("manifest zip_sha256 is not 64 lowercase hex")
    if not isinstance(m["commit"], str) or not RE_COMMIT.match(m["commit"]):
        raise Refuse("manifest commit is not 40 lowercase hex")
    if not isinstance(m["main_bundle"], str) or not RE_BUNDLE.match(m["main_bundle"]):
        raise Refuse("manifest main_bundle must match static/js/main.<hash>.js")
    fc = m["file_count"]
    if isinstance(fc, bool) or not isinstance(fc, int) or not (1 <= fc <= 10000):
        raise Refuse("manifest file_count must be an integer 1..10000")
    if not isinstance(m["void"], list) or not all(isinstance(h, str) and RE_SHA256.match(h) for h in m["void"]):
        raise Refuse("manifest void must be a list of 64 lowercase hex strings")
    return m


def parse_binding(raw):
    b = strict_json(raw, "binding.json")
    keys = set(b.keys())
    if keys - BINDING_ALLOWED:
        raise Refuse(f"binding.json has extra fields {sorted(keys - BINDING_ALLOWED)}")
    if BINDING_REQUIRED - keys:
        raise Refuse(f"binding.json is missing {sorted(BINDING_REQUIRED - keys)}")
    for k in BINDING_REQUIRED | ({"scope"} & keys):
        if not isinstance(b[k], str):
            raise Refuse(f"binding.json {k} must be a string")
    if not RE_SHA256.match(b["approval_txt_sha256"]) or not RE_SHA256.match(b["zip_sha256"]) or not RE_SHA256.match(b["manifest_sha256"]) or not RE_SHA256.match(b["receipt_sha256"]) or not RE_SHA256.match(b["delegation_sha256"]):
        raise Refuse("binding.json hash fields must be 64 lowercase hex")
    if not RE_COMMIT.match(b["commit"]):
        raise Refuse("binding.json commit must be 40 lowercase hex")
    if not RE_TIME.match(b["approval_time_utc"]):
        raise Refuse("binding.json approval_time_utc must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.datetime.strptime(b["approval_time_utc"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise Refuse("binding.json approval_time_utc is not a valid date/time")
    if "scope" in b and b["scope"] != SCOPE:
        raise Refuse(f"binding.json scope must be {SCOPE!r} when present")
    if not RE_VER.match(b["version"]):
        raise Refuse("binding.json version is not X.Y.Z")
    return b


def parse_receipt(raw):
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
        raise Refuse("receipt.md: BOM, CR, or missing single final LF")
    try:
        lines = raw.decode("utf-8").split("\n")[:-1]
    except UnicodeDecodeError:
        raise Refuse("receipt.md: not UTF-8")
    if len(lines) != 6:
        raise Refuse(f"receipt.md must have exactly 6 lines (found {len(lines)})")
    if lines[0] != "INDEPENDENT REVIEW RECEIPT":
        raise Refuse("receipt.md line 1 must be 'INDEPENDENT REVIEW RECEIPT'")
    keys = ["version", "commit", "zip_sha256", "manifest_sha256"]
    out = {}
    for ln, key in zip(lines[1:5], keys):
        if ln != ln.strip() or not ln.startswith(key + ": "):
            raise Refuse(f"receipt.md line must be '{key}: ...' with no extra whitespace")
        out[key] = ln[len(key) + 2:]
    if lines[5] != "verdict: PASS":
        raise Refuse("receipt.md line 6 must be 'verdict: PASS'")
    return out


def verify(shell, shell_root, zip_path, roots=None, delegation_source=None, now_utc=None):
    """Returns the PASS dict. Raises Refuse (hard) or NoDelegation (exit 3). Checks run in the fixed order below."""
    if shell not in SHELL_MANIFEST_REL:
        raise Refuse(f"unknown shell {shell!r}")
    try:
        roots = roots or production_roots()
        src = delegation_source or production_delegation_source()
    except Refuse:
        # The record location is unknown. A shell that claims no delegation (no manifest, or the placeholder) is still "no delegation";
        # a shell that carries a delegated manifest is REFUSED. Nothing is ever accepted without the records.
        pre = os.path.join(shell_root, SHELL_MANIFEST_REL[shell])
        if probe(pre) is None:
            raise NoDelegation(f"no delegated manifest at {pre}")
        try:
            pobj = strict_json(read_regular(pre), "manifest")
        except Refuse:
            raise
        if pobj.get("status") == "none" and set(pobj.keys()) == {"status"}:
            raise NoDelegation("manifest is the placeholder {\"status\": \"none\"}")
        raise
    # 1 + 2: the delegation source is the pinned file; its hash must match before anything else is trusted.
    if sha256_hex(read_regular(src)) != DELEGATION_SOURCE_SHA256:
        raise Refuse("delegation source hash does not match the pinned value (d870a920...)")
    # 3: revocation, after the delegation source check.
    check_revocation(roots)
    # Manifest location (shell-relative). Absent or the placeholder {"status": "none"} is "no delegation".
    mpath = os.path.join(shell_root, SHELL_MANIFEST_REL[shell])
    if probe(mpath) is None:
        raise NoDelegation(f"no delegated manifest at {mpath}")
    mraw = read_regular(mpath)
    mobj = strict_json(mraw, "manifest")
    if mobj.get("status") == "none" and set(mobj.keys()) == {"status"}:
        raise NoDelegation("manifest is the placeholder {\"status\": \"none\"}")
    manifest = parse_manifest(mraw)
    version = manifest["version"]
    vdir = os.path.join(roots["approvals_dir"], "pm-delegated-freeze", version)
    # 4: the record chain, then the exact file set in the approval record directory.
    ap = roots["approvals_dir"]
    notes = os.path.dirname(ap)
    check_dir_chain(chain_between(notes, vdir))
    only_files(vdir, [APPROVAL_FILE, BINDING_FILE])
    araw = read_regular(os.path.join(vdir, APPROVAL_FILE))
    braw = read_regular(os.path.join(vdir, BINDING_FILE))
    # 5: approval.txt (five lines); 6: binding.json (strict), bound to approval.txt bytes.
    approval = parse_approval(araw, version)
    binding = parse_binding(braw)
    if sha256_hex(araw) != binding["approval_txt_sha256"]:
        raise Refuse("binding.json approval_txt_sha256 does not match approval.txt bytes")
    if binding["version"] != version:
        raise Refuse("binding.json version differs from manifest/approval")
    if binding["delegation_sha256"] != DELEGATION_SOURCE_SHA256:
        raise Refuse("binding.json delegation_sha256 is not the pinned value")
    # 7: manifest bytes and ZIP bytes.
    zip_bytes = read_regular(zip_path)
    zsha = sha256_hex(zip_bytes)
    msha = sha256_hex(mraw)
    if zsha != manifest["zip_sha256"] or zsha != approval["zip_sha256"] or zsha != binding["zip_sha256"]:
        raise Refuse("ZIP SHA256 does not match manifest, approval.txt and binding.json")
    if msha != approval["manifest_sha256"] or msha != binding["manifest_sha256"]:
        raise Refuse("manifest SHA256 does not match approval.txt and binding.json")
    if manifest["commit"] != binding["commit"]:
        raise Refuse("commit differs between manifest and binding.json")
    # void: a voided ZIP hash is refused everywhere.
    voids = set(manifest["void"])
    if zsha in voids or approval["zip_sha256"] in voids or binding["zip_sha256"] in voids:
        raise Refuse("ZIP hash is listed in void: refused")
    zip_checks(zip_bytes, manifest)
    # 8: receipt in the independent-review directory (exact file set, bound by binding.json).
    rdir = os.path.join(roots["reviews_dir"], version)
    check_dir_chain(chain_between(notes, rdir))
    only_files(rdir, [RECEIPT_FILE])
    expected_receipt = os.path.join(rdir, RECEIPT_FILE)
    if binding["receipt_path"] != expected_receipt:
        raise Refuse("binding.json receipt_path is not the fixed receipt path")
    rraw = read_regular(expected_receipt)
    if sha256_hex(rraw) != binding["receipt_sha256"]:
        raise Refuse("receipt.md SHA256 does not match binding.json receipt_sha256")
    rc = parse_receipt(rraw)
    if rc["version"] != version or rc["commit"] != binding["commit"] or rc["zip_sha256"] != zsha or rc["manifest_sha256"] != msha:
        raise Refuse("receipt.md does not agree with the version, commit, ZIP SHA256 and manifest SHA256")
    # 10: time window: not earlier than the effective date, not later than this check.
    check_at = now_utc or utc_now_str()
    t = binding["approval_time_utc"]
    if t < EFFECTIVE_UTC:
        raise Refuse(f"approval_time_utc {t} is earlier than the delegation effective date {EFFECTIVE_UTC}")
    if t > check_at:
        raise Refuse(f"approval_time_utc {t} is later than the revocation check time {check_at}")
    return {"result": "PASS", "scope": SCOPE, "shell": shell, "version": version, "zip_sha256": zsha,
            "manifest_sha256": msha, "approval_txt_sha256": sha256_hex(araw), "commit": binding["commit"],
            "approved_by": approval["approved_by"], "approval_time_utc": t, "checked_at_utc": check_at}


def main(argv):
    import argparse
    p = argparse.ArgumentParser(description="delegated formal freeze check (exit 0 PASS, 1 REFUSED, 3 NO DELEGATION)")
    p.add_argument("--shell", required=True, choices=sorted(SHELL_MANIFEST_REL))
    p.add_argument("--shell-root", required=True)
    p.add_argument("--zip", required=True)
    a = p.parse_args(argv)
    try:
        out = verify(a.shell, a.shell_root, a.zip)
    except NoDelegation as e:
        print(f"NO DELEGATION: {e}")
        return EXIT_NONE
    except Refuse as e:
        print(f"REFUSED: {e}")
        return EXIT_REFUSE
    print(json.dumps(out, sort_keys=True))
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
