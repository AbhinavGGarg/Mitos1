"""Trustworthy downstream repair via a real three-way merge — closed around ONE exact pinned repair.

Take the real Git parent->child patch and three-way merge it onto the vendored copy
(base=parent, other=child, current=copy). Acceptance rests on a hard GOLDEN gate: the merged file
and fix.diff must hash to the recipe's independently-reviewed expected constants (never learned from
the run). A positional per-hunk cross-check runs alongside — it rejects the covered regression cases
but is EXPERIMENTAL, not a general mislocation proof. The copy is then built with its own build
system before and after and its own binary is probed. VERIFIED only when every gate passes and every
reachable loader is exercised; VERIFIED_SCOPED when the golden/merge/build checks pass but only a
subset of the reachable loaders were behaviourally exercised; anything worse is NEEDS_REVIEW.

Constrained host execution
--------------------------
Builds and probes run the downstream project's own commands and binary on this host.
There is no network/PID/memory namespace isolation here, so only an internal allowlisted,
pinned recipe may run. Git runs from a from-scratch whitelisted environment with an
isolated HOME, replacement objects/hooks/attributes disabled, into a fresh Mitos-owned
0700 clone that is validated (origin, no grafts/replace-refs/filters/insteadOf). Build and
probe processes run with a scrubbed no-credentials env, CPU/file-size/core resource limits,
wall timeouts, their own process group (killed as a group on timeout), and bounded captured
output. A real no-network sandbox is required before running an arbitrary repository.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import signal
import stat as statmod
import struct
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

from .applyfix import enclosing_functions

CPU_LIMIT_SEC = 180
FSIZE_LIMIT = 1 << 30              # 1 GiB max single file from a build/probe
OUTPUT_CAP = 256 * 1024           # bytes captured per stream from a constrained process
BUILD_TIMEOUT = 300
PROBE_TIMEOUT = 60


class SecurityError(Exception):
    """A path escape, symlink, origin/graft/filter mismatch, or disallowed recipe."""


def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: str) -> str:
    return sha256_bytes(_read_nofollow(path))


# ---------------------------------------------------------------------------
# file I/O that refuses to follow symlinks
# ---------------------------------------------------------------------------
def _excl_write(path: str, data: bytes):
    """Create a NEW file exclusively, never following a symlink."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _nofollow_write(path: str, data: bytes):
    """Truncate+write an EXISTING regular file, refusing a symlink."""
    st = os.lstat(path)
    if not statmod.S_ISREG(st.st_mode):
        raise SecurityError(f"refusing to write non-regular file: {path}")
    fd = os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _read_nofollow(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        out = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return out
            out += chunk
    finally:
        os.close(fd)


def safe_subpath(root: str, rel: str) -> str:
    """Join rel under root, rejecting symlinks and any path that escapes root."""
    root_r = os.path.realpath(root)
    joined = os.path.join(root, rel)
    parts = Path(rel).parts
    probe = root
    for p in parts:                      # reject a symlink at any component
        probe = os.path.join(probe, p)
        if os.path.islink(probe):
            raise SecurityError(f"refusing to follow symlink: {rel}")
    real = os.path.realpath(joined)
    if os.path.commonpath([root_r, real]) != root_r:
        raise SecurityError(f"path escapes {root_r}: {rel}")
    return joined


def _dir_walk(root: str, rel: str):
    """Open the PARENT directory of root/rel via dirfd-relative O_DIRECTORY|O_NOFOLLOW steps, so a
    directory symlink at ANY intermediate component is refused *atomically* (no check-then-use gap
    — a `make clean` that swaps a component for a symlink cannot redirect Mitos's write). Returns
    (parent_dirfd, last_component); the caller must os.close(parent_dirfd)."""
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        raise SecurityError(f"unsafe relative path: {rel!r}")
    dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for comp in parts[:-1]:
            nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dirfd)
            os.close(dirfd); dirfd = nfd
    except OSError as e:
        os.close(dirfd)
        raise SecurityError(f"intermediate component of {rel!r} is not a real directory: {e}")
    return dirfd, parts[-1]


def _write_at(root: str, rel: str, data: bytes, exclusive: bool = False):
    dirfd, last = _dir_walk(root, rel)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
        with os.fdopen(os.open(last, flags, 0o600, dir_fd=dirfd), "wb") as f:
            f.write(data)
    finally:
        os.close(dirfd)


def _read_at(root: str, rel: str) -> bytes:
    dirfd, last = _dir_walk(root, rel)
    try:
        fd = os.open(last, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dirfd)
        try:
            out = b""
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    return out
                out += chunk
        finally:
            os.close(fd)
    finally:
        os.close(dirfd)


def _lstat_at(root: str, rel: str):
    dirfd, last = _dir_walk(root, rel)
    try:
        return os.lstat(last, dir_fd=dirfd)
    finally:
        os.close(dirfd)


def _unlink_at(root: str, rel: str):
    dirfd, last = _dir_walk(root, rel)
    try:
        os.unlink(last, dir_fd=dirfd)
    finally:
        os.close(dirfd)


# ---------------------------------------------------------------------------
# command logging (full logs retained)
# ---------------------------------------------------------------------------
@dataclass
class Cmd:
    argv: list
    cwd: str
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool
    label: str = ""
    stdout_total: int = 0       # total bytes produced (may exceed the captured, capped output)
    stderr_total: int = 0
    truncated: bool = False


@dataclass
class Res:
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool


class Log:
    def __init__(self, verbose: Optional[Callable[[str], None]] = None):
        self.cmds: list[Cmd] = []
        self._v = verbose or (lambda m: None)

    def run(self, argv, cwd=None, timeout=600, check=False, env=None, label="") -> Res:
        argv = [str(a) for a in argv]
        self._v("$ " + " ".join(argv) + (f"   ({cwd})" if cwd else ""))
        try:
            r = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env)
            rc, out, err, timed = r.returncode, r.stdout or "", r.stderr or "", False
        except subprocess.TimeoutExpired as e:
            out = (e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")) or ""
            err = (e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")) or ""
            rc, timed = None, True
        self.cmds.append(Cmd(argv, str(cwd or ""), rc, out, err, timed, label, len(out), len(err), False))
        if check and (timed or rc != 0):
            raise RuntimeError(f"command failed ({'timeout' if timed else rc}): {' '.join(argv)}\n{err}")
        return Res(rc, out, err, timed)


# ---------------------------------------------------------------------------
# hardened git — a from-scratch whitelisted environment
# ---------------------------------------------------------------------------
_GIT_HARDEN = ["--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.symlinks=false", "-c", "core.fsmonitor=false",
               "-c", "core.attributesFile=/dev/null", "-c", "protocol.allow=user"]


def git_env(home: str) -> dict:
    """Built from scratch: no inherited GIT_* (defeats GIT_CONFIG_COUNT/url.insteadOf
    injection), isolated HOME, global/system config neutralised, replacement/attrs off."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        "HOME": home,
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_ALLOW_PROTOCOL": "file:https",
        "LANG": "C", "LC_ALL": "C",
    }


class Git:
    """git callable bound to a log + isolated HOME; every call is hardened + scrubbed."""

    def __init__(self, log: Log, home: str):
        self.log, self.home = log, home

    def __call__(self, *args, cwd=None, check=False, timeout=600, label="git") -> Res:
        return self.log.run(["git", *_GIT_HARDEN, *args], cwd=cwd, check=check,
                            timeout=timeout, env=git_env(self.home), label=label)


# ---------------------------------------------------------------------------
# constrained host execution for build/probe (NOT "sandbox" — no namespaces)
# ---------------------------------------------------------------------------
_CRED_VARS = ("GITHUB_TOKEN", "GH_TOKEN", "GIT_ASKPASS", "SSH_ASKPASS", "SSH_AUTH_SOCK",
              "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "NPM_TOKEN",
              "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "HF_TOKEN")


def constrained_env(home: str) -> dict:
    keep = {"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            "HOME": home, "TMPDIR": home, "LANG": "C", "LC_ALL": "C"}
    for k in ("SDKROOT", "DEVELOPER_DIR", "TERM"):   # macOS toolchain hints (not secrets)
        if k in os.environ and k not in _CRED_VARS:
            keep[k] = os.environ[k]
    return keep


def _preexec_rlimits():
    import resource

    def apply():
        for res, lim in ((resource.RLIMIT_CPU, CPU_LIMIT_SEC),
                         (resource.RLIMIT_FSIZE, FSIZE_LIMIT),
                         (resource.RLIMIT_CORE, 0)):
            try:
                resource.setrlimit(res, (lim, lim))
            except Exception:
                pass
    return apply


def constrained_run(log: Log, argv, cwd, home, timeout, label="") -> Res:
    """Run a build/probe command in its own process group with rlimits, a scrubbed env, a
    wall timeout (whole group killed on expiry), and output bounded to OUTPUT_CAP/stream."""
    argv = [str(a) for a in argv]
    log._v("$ " + " ".join(argv) + (f"   ({cwd})" if cwd else ""))
    preexec = _preexec_rlimits() if os.name == "posix" else None
    p = subprocess.Popen(argv, cwd=cwd, env=constrained_env(home), stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, preexec_fn=preexec, start_new_session=True)
    # capture the process-group id IMMEDIATELY (while the leader is alive) so we can kill the whole
    # group — including background children — even after the leader has been reaped.
    try:
        pgid = os.getpgid(p.pid)
    except Exception:
        pgid = None

    sinks = {"out": [], "err": []}
    totals = {"out": 0, "err": 0}

    def reader(stream, key):
        got = 0
        try:
            while True:
                b = stream.read(65536)
                if not b:
                    break
                if got < OUTPUT_CAP:
                    sinks[key].append(b[:OUTPUT_CAP - got])
                got += len(b)
        except Exception:
            pass
        totals[key] = got

    def kill_group():
        if pgid is not None:
            try:
                os.killpg(pgid, signal.SIGKILL); return
            except Exception:
                pass
        try:
            p.kill()
        except Exception:
            pass

    t1 = threading.Thread(target=reader, args=(p.stdout, "out"))
    t2 = threading.Thread(target=reader, args=(p.stderr, "err"))
    t1.start(); t2.start()
    timed_out = False
    try:
        p.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    # kill the SAVED group after normal completion or timeout, BEFORE joining the readers — so a
    # lingering background child is reaped and the reader threads see EOF.
    kill_group()
    try:
        p.wait(timeout=5)
    except Exception:
        pass
    t1.join(timeout=5); t2.join(timeout=5)
    for s in (p.stdout, p.stderr):
        try:
            s.close()
        except Exception:
            pass
    out = b"".join(sinks["out"]).decode("utf-8", "replace")
    err = b"".join(sinks["err"]).decode("utf-8", "replace")
    truncated = totals["out"] > OUTPUT_CAP or totals["err"] > OUTPUT_CAP
    res = Res(p.returncode, out, err, timed_out)
    log.cmds.append(Cmd(argv, str(cwd or ""), p.returncode, out, err, timed_out, label,
                        totals["out"], totals["err"], truncated))
    return res


# ---------------------------------------------------------------------------
# recipe + internal allowlist (no caller-controlled trust)
# ---------------------------------------------------------------------------
@dataclass
class Probe:
    name: str
    content: Callable[[], bytes]     # returns the crafted input BYTES; Mitos writes them safely
    filename: str
    expectation: str                 # "identical" | "rejected_after_only"
    loader: str = ""
    expect_exit_code: Optional[int] = None
    expect_diagnostic: str = ""


@dataclass
class Recipe:
    key: str                          # stable identity; must be in _ALLOWED_RECIPES to run
    name: str
    upstream_repo: str
    upstream_fix_sha: str
    upstream_parent_sha: str
    upstream_path: str
    downstream_repo: str
    downstream_sha: str
    downstream_path: str
    build_subdir: str
    build_cmd: list
    clean_cmd: list
    build_artifact: str
    run_argv: Callable[[str, str], list]
    probes: list
    marker: str = ""
    modified_loaders: Optional[list] = None      # all loaders the merge guards (structural)
    reachable_loaders: Optional[list] = None      # loaders whose guard a crafted input can reach
    coverage_note: str = ""
    # Independently-reviewed golden attestation of the EXACT expected postimage for this pinned
    # repair. When set, the merged file (and optionally fix.diff) must hash to these — a hard gate
    # that closes PM1 around this exact repair rather than trusting generic positional verification.
    expected_merged_sha256: str = ""
    expected_fix_diff_sha256: str = ""
    # Extra sources written beside the vendored file before build (relpath-in-build_subdir, bytes|str).
    # Lets a recipe compile the copy's ACTUAL translation unit + a Mitos-shipped harness under a
    # sanitizer when the downstream has no small buildable consumer of its own.
    harness_sources: Optional[list] = None
    # Human-facing canonical URLs for PR/evidence when cloning from a local offline mirror (file://).
    upstream_display_url: str = ""
    downstream_display_url: str = ""


def recipe_digest(recipe: Recipe) -> str:
    probe_spec = [[p.name, p.filename, p.expectation, p.loader, p.expect_exit_code, p.expect_diagnostic]
                  for p in recipe.probes]
    ident = json.dumps({
        "key": recipe.key, "upstream_repo": recipe.upstream_repo, "upstream_fix": recipe.upstream_fix_sha,
        "upstream_parent": recipe.upstream_parent_sha, "upstream_path": recipe.upstream_path,
        "downstream_repo": recipe.downstream_repo, "downstream_sha": recipe.downstream_sha,
        "downstream_path": recipe.downstream_path, "build_subdir": recipe.build_subdir,
        "build_cmd": recipe.build_cmd, "clean_cmd": recipe.clean_cmd, "build_artifact": recipe.build_artifact,
        "marker": recipe.marker, "modified_loaders": recipe.modified_loaders,
        "reachable_loaders": recipe.reachable_loaders, "coverage_note": recipe.coverage_note,
        "expected_merged_sha256": recipe.expected_merged_sha256,
        "expected_fix_diff_sha256": recipe.expected_fix_diff_sha256,
        "probes": probe_spec,
    }, sort_keys=True)
    return sha256_text(ident)


# ---------------------------------------------------------------------------
# crafted inputs
# ---------------------------------------------------------------------------
def normal_bmp() -> bytes:
    w, h = 4, 4
    px = b"".join(bytes([(x * 60) & 255, (y * 60) & 255, 128]) for y in range(h) for x in range(w))
    hdr = b"BM" + struct.pack("<I", 14 + 40 + len(px)) + struct.pack("<HH", 0, 0) + struct.pack("<I", 54)
    info = struct.pack("<IiiHHIIIiII", 40, w, h, 1, 24, 0, len(px), 2835, 2835, 0, 0)
    return hdr + info + px


def oversized_bmp() -> bytes:
    w, h = 20_000_000, 1
    hdr = b"BM" + struct.pack("<I", 54) + struct.pack("<HH", 0, 0) + struct.pack("<I", 54)
    info = struct.pack("<IiiHHIIIiII", 40, w, h, 1, 24, 0, 0, 0, 0, 0, 0)
    return hdr + info


def oversized_pnm() -> bytes:
    return b"P6\n20000000 1\n255\n\x00\x00\x00"


BLURHASH_KEY = "woltapp/blurhash<-nothings/stb@STBI_MAX_DIMENSIONS"


def _blurhash_stb_recipe() -> Recipe:
    """INTERNAL factory. Every repo/command/probe/run_argv is defined here; a caller of the
    public run_repair(recipe_key) can never influence what executes."""
    return Recipe(
        key=BLURHASH_KEY,
        name="woltapp/blurhash <- nothings/stb STBI_MAX_DIMENSIONS",
        upstream_repo="https://github.com/nothings/stb",
        upstream_fix_sha="d60594847ecca4553b18e7607d01328c58d95a42",
        upstream_parent_sha="98ca24b8c7a69e1fc80e3d6a1e014b0e113980b8",
        upstream_path="stb_image.h",
        downstream_repo="https://github.com/woltapp/blurhash",
        downstream_sha="712a47f946b98c30097eb1ada086ea00b18681ec",
        downstream_path="C/stb_image.h",
        build_subdir="C",
        build_cmd=["make", "blurhash_encoder"],
        clean_cmd=["make", "clean"],
        build_artifact="blurhash_encoder",
        run_argv=lambda binary, inp: [binary, "4", "3", inp],
        marker="STBI_MAX_DIMENSIONS",
        modified_loaders=["JPEG", "PNG", "BMP", "TGA", "PSD", "PIC", "GIF", "HDR", "PNM"],
        # Loaders whose STBI_MAX_DIMENSIONS guard a crafted oversized input can reach at the default
        # 1<<24 limit: BMP/PSD read 32-bit dims, PNG 31-bit, HDR/PNM parse ASCII -> all can exceed
        # 1<<24. JPEG/GIF/TGA/PIC read 16-bit dims (<=65535 < 1<<24) so their guard is unreachable by
        # any input -- structurally merged, defence-in-depth only.
        reachable_loaders=["BMP", "PNG", "PSD", "HDR", "PNM"],
        coverage_note=("PNG already rejected dimensions > 1<<24 before this fix (its own check), so the "
                       "fix's newly-introduced default behavioural paths are BMP, PSD, HDR, PNM (4); of "
                       "those, BMP and PNM are exercised here (2/4)."),
        # Independently reviewed. The gate compares the run's computed sha to THESE constants — it
        # never learns the expected value from the run being certified.
        expected_merged_sha256="d3b5c868881d943ee6f37a655d6af11cf54a75c5dac2148b168a9490e3c8ab3b",
        expected_fix_diff_sha256="9af882036b40e5ec7a5fc79b4b512169247ce0e9247b10d1219398d542b7dd9e",
        probes=[
            Probe("normal-image (4x4 BMP)", normal_bmp, "normal.bmp", "identical", loader="BMP"),
            Probe("oversized BMP (20000000x1)", oversized_bmp, "oversized.bmp",
                  "rejected_after_only", loader="BMP", expect_exit_code=1, expect_diagnostic="Failed to load"),
            Probe("oversized PNM (P6 20000000x1)", oversized_pnm, "oversized.pnm",
                  "rejected_after_only", loader="PNM", expect_exit_code=1, expect_diagnostic="Failed to load"),
        ],
    )


# The ONLY recipes production may execute — resolved by key to an internal factory. A caller
# passes a key string to run_repair(); it can never supply build_cmd/repos/probes.
_REGISTRY = {BLURHASH_KEY: _blurhash_stb_recipe}


# ---------------------------------------------------------------------------
# git plumbing — fresh Mitos-owned 0700 clone, validated; parent from raw object
# ---------------------------------------------------------------------------
def _norm_url(u: str) -> str:
    return (u or "").strip().rstrip("/").removesuffix(".git").lower()


def prepare_clone(g: Git, url: str, dest: str) -> str:
    """Fresh clone Mitos owns (0700), validated. Never reuses a caller-provided cache."""
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    g("clone", "--quiet", url, dest, check=True, timeout=900, label="clone")
    try:
        os.chmod(dest, 0o700)
    except Exception:
        pass
    validate_clone(g, dest, url)
    return dest


def validate_clone(g: Git, cache: str, url: str):
    origin = g("-C", cache, "config", "--local", "--get", "remote.origin.url").stdout.strip()
    if _norm_url(origin) != _norm_url(url):
        raise SecurityError(f"cached clone origin {origin!r} != expected {url!r}")
    if g("-C", cache, "for-each-ref", "refs/replace").stdout.strip():
        raise SecurityError("replacement refs present in clone")
    gitdir = os.path.join(cache, ".git")
    for bad in ("info/grafts", "info/attributes", "shallow"):
        if os.path.exists(os.path.join(gitdir, bad)):
            raise SecurityError(f"unexpected {bad} in clone")
    cfg = g("-C", cache, "config", "--local", "--list").stdout.lower()
    for needle in ("insteadof", "filter.", "core.hookspath", "core.fsmonitor",
                   "core.sshcommand", "core.gitproxy", "core.attributesfile", "uploadpack.packobjectshook"):
        if needle in cfg:
            raise SecurityError(f"unexpected local git config: {needle}")


def parent_of(g: Git, cache: str, sha: str) -> Optional[str]:
    """First parent from the RAW commit object (not rev-parse ^, which honours grafts/replace)."""
    body = g("-C", cache, "cat-file", "-p", sha, check=True, label="cat-file").stdout
    for line in body.splitlines():
        if line == "":                       # end of header block; message follows
            break
        if line.startswith("parent "):
            return line.split()[1]
    return None


def resolve(g: Git, cache: str, rev: str) -> Optional[str]:
    r = g("-C", cache, "rev-parse", "--verify", "--quiet", rev + "^{commit}")
    return r.stdout.strip() or None


def git_show(g: Git, cache: str, sha: str, path: str) -> str:
    return g("-C", cache, "show", f"{sha}:{path}", check=True, label="show").stdout


def add_worktree(g: Git, cache: str, sha: str, wt: str) -> str:
    if os.path.isdir(wt):
        g("-C", cache, "worktree", "remove", "--force", wt)
        shutil.rmtree(wt, ignore_errors=True)
    g("-C", cache, "worktree", "add", "--quiet", "--detach", wt, sha, check=True, label="worktree")
    head = g("-C", wt, "rev-parse", "HEAD").stdout.strip()
    if head != sha:
        raise RuntimeError(f"worktree HEAD {head} != pinned {sha}")
    return wt


# ---------------------------------------------------------------------------
# three-way merge
# ---------------------------------------------------------------------------
def three_way_merge(g: Git, workdir: str, current: str, base: str, other: str):
    """(merged_text, n_conflicts, merge_rc). base=parent, other=child, current=copy.
    Inputs written with O_EXCL|O_NOFOLLOW into a fresh dir."""
    cp, bp, op = (os.path.join(workdir, n) for n in ("current.h", "base.h", "other.h"))
    for path, data in ((cp, current), (bp, base), (op, other)):
        _excl_write(path, data.encode())
    r = g("merge-file", "-p", "--diff3", cp, bp, op, label="merge-file")
    merged = r.stdout
    rc = r.returncode if r.returncode is not None else -1
    n_conflicts = merged.count("<<<<<<<")
    return merged, n_conflicts, rc


def _conflict_ranges(merged: str):
    ranges, start = [], None
    for i, ln in enumerate(merged.splitlines()):
        if ln.startswith("<<<<<<<"):
            start = i
        elif ln.startswith(">>>>>>>") and start is not None:
            ranges.append((start, i))
            start = None
    return ranges


# ---------------------------------------------------------------------------
# positional hunk verification
# ---------------------------------------------------------------------------
@dataclass
class HunkCheck:
    header_function: str
    actual_scope: str
    nature: str
    added: int
    removed: int
    matched_regions: int          # localized change regions equal to this hunk's add/remove
    removal_ok: bool
    anchored: bool                # the edit region is pinned by a surviving context anchor
    status: str                   # applied | already_present | wrong_position | ambiguous
    #                              | obsolete_remains | not_applied | conflicted | ambiguous_scope
    verified: bool
    sample: str


def count_patch_hunks(patch: str) -> int:
    return sum(1 for l in patch.splitlines() if l.startswith("@@ "))


def _parse_hunks(patch: str):
    hunks, cur = [], None
    for line in patch.splitlines():
        if line.startswith("@@"):
            if cur:
                hunks.append(cur)
            m = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            cur = {"function": line.split("@@")[-1].strip(),
                   "new_start": int(m.group(1)) if m else 1, "body": []}
        elif cur is not None:
            if line.startswith("+") and not line.startswith("+++"):
                cur["body"].append(("+", line[1:]))
            elif line.startswith("-") and not line.startswith("---"):
                cur["body"].append(("-", line[1:]))
            elif line.startswith(" ") or line == "":
                cur["body"].append((" ", line[1:] if line.startswith(" ") else ""))
    if cur:
        hunks.append(cur)
    return hunks


def _func_name(header: str) -> str:
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", header or "")
    return m.group(1) if m else ""


def _target_line(h):
    newno, first = h["new_start"] - 1, None
    for tag, _ in h["body"]:
        if tag == "+" and first is None:
            first = newno
        if tag in (" ", "+"):
            newno += 1
    return first if first is not None else h["new_start"] - 1


def _enclosing(idx, spans):
    best = None
    for nm, s, e in spans:
        if s <= idx <= e and (best is None or (e - s) < (best[2] - best[1])):
            best = (nm, s, e)
    return best[0] if best else None


def _hunk_anchors(body):
    added = [t.strip() for tag, t in body if tag == "+" and t.strip()]
    removed = [t.strip() for tag, t in body if tag == "-" and t.strip()]
    idxs = [i for i, (tag, _) in enumerate(body) if tag in ("+", "-")]
    first, last = (idxs[0], idxs[-1]) if idxs else (len(body), -1)
    lead = [t.strip() for tag, t in body[:first] if tag == " " and t.strip()]
    trail = [t.strip() for tag, t in body[last + 1:] if tag == " " and t.strip()]
    return added, removed, lead, trail          # lead/trail are COMPLETE non-blank context sequences


def _pp_stack(text: str, target_idx: int):
    """The normalized #if/#elif/#else branch stack enclosing line target_idx — comment/string-aware
    (via the C lexer) so `#if` inside a comment doesn't count. Each entry is (directive, expr, branch)."""
    from .applyfix import code_line_flags
    flags, lines = code_line_flags(text, frozenset())
    stack = []
    for i in range(min(target_idx, len(lines))):
        if flags[i].get("in_comment"):
            continue
        s = lines[i].strip()
        if not s.startswith("#"):
            continue
        d = s[1:].lstrip()
        head = d.split()[0].split("(")[0] if d else ""
        if head in ("ifdef", "ifndef", "if"):
            stack.append([head, " ".join(d[len(head):].split()), "if"])
        elif head == "elif" and stack:
            stack[-1][2] = "elif:" + " ".join(d[4:].split())
        elif head == "else" and stack:
            stack[-1][2] = "else"
        elif head == "endif" and stack:
            stack.pop()
    return [tuple(e) for e in stack]


def _regions(cur_body, mrg_body):
    """Maximal contiguous change regions between the two bodies: (start_in_mrg, inserted, deleted)."""
    ops = difflib.SequenceMatcher(None, cur_body, mrg_body, autojunk=False).get_opcodes()
    regions, cur = [], None
    for tag, a1, a2, b1, b2 in ops:
        if tag == "equal":
            if cur:
                regions.append(cur); cur = None
        else:
            if cur is None:
                cur = [a1, a2, b1, b2]
            else:
                cur[1], cur[3] = a2, b2
    if cur:
        regions.append(cur)
    return [(b1, mrg_body[b1:b2], cur_body[a1:a2]) for a1, a2, b1, b2 in regions]


def _contig(body, block):
    if not block:
        return 0
    n = len(block)
    return sum(1 for i in range(len(body) - n + 1) if body[i:i + n] == block)


def _scope_body(target, spans, lines):
    """(non-blank stripped lines of the target scope, their original indices) or (None,None)
    if a named function is missing or duplicated (fail closed)."""
    if target is None:
        idxs = [i for i, l in enumerate(lines) if l.strip()]
    else:
        sp = [(s, e) for nm, s, e in spans if nm == target]
        if len(sp) != 1:
            return None, None
        s, e = sp[0]
        idxs = [i for i in range(s, e + 1) if lines[i].strip()]
    return [lines[i].strip() for i in idxs], idxs


def verify_hunks(patch: str, other: str, current: str, merged: str, n_conflicts: int):
    """Positional per-hunk cross-check — an EXPERIMENTAL check, not the acceptance guarantee.

    For each hunk, the target scope is the enclosing function of the hunk's coordinates in the
    upstream child (`other`), or file scope. Inside that scope we diff the copy against the merge
    and require exactly ONE localized change region whose inserted lines equal the hunk's additions
    and whose deleted lines equal its removals, pinned to a surviving leading/trailing context
    anchor (both, for file-scope preprocessor context).

    This rejects the covered regression cases (guard-after-return, an edit on the wrong one of two
    identical calls, a macro under the wrong `#if` branch, an obsolete line left beside its
    replacement — see tests/test_repair.py). It is NOT a general proof that every mislocated or
    ambiguous mapping is caught. For a golden-attested recipe the authoritative acceptance guarantee
    is the independently-reviewed expected-postimage hash gate (see run_repair / decide)."""
    cur_lines, mrg_lines = current.split("\n"), merged.split("\n")
    oth_spans = enclosing_functions(other)
    cur_spans = enclosing_functions(current)
    mrg_spans = enclosing_functions(merged)
    conflicts = _conflict_ranges(merged) if n_conflicts else []

    out = []
    for h in _parse_hunks(patch):
        added, removed, lead_seq, trail_seq = _hunk_anchors(h["body"])
        lead = lead_seq[-1] if lead_seq else None
        trail = trail_seq[0] if trail_seq else None
        if not added and not removed:
            continue
        nature = "preproc_or_comment" if added and all(
            a.startswith(("#", "//", "/*", "*")) for a in added) else "statement"
        other_target_line = _target_line(h)
        target = _enclosing(other_target_line, oth_spans)      # None => file scope
        cur_body, _ = _scope_body(target, cur_spans, cur_lines)
        mrg_body, mrg_idx = _scope_body(target, mrg_spans, mrg_lines)

        def mk(status, verified, anchored=False, regions=0, scope=None):
            return HunkCheck(_func_name(h["function"]) or "(none)", scope or (target or "file-scope"),
                             nature, len(added), len(removed), regions,
                             status in ("applied", "already_present"), anchored, status, verified,
                             (added[:1] or removed[:1] or [""])[0][:74])

        if cur_body is None or mrg_body is None:
            out.append(mk("ambiguous_scope", False)); continue

        def in_conflict_at(pos):
            sline = mrg_idx[pos] if pos < len(mrg_idx) else None
            return sline is not None and any(s <= sline <= e for s, e in conflicts)

        if target is None:
            # File scope: an anchored contiguous block search — whole-file diff mis-aligns on
            # ubiquitous lines like `#endif`. BOTH context anchors must match, so the added block
            # keeps its surrounding preprocessor/conditional context (a wrong `#if` branch fails).
            n = len(added)

            def fs_hits(body):
                hits = []
                for i in range(len(body) - n + 1):
                    if (body[i:i + n] == added
                            and (lead is None or (i > 0 and body[i - 1] == lead))
                            and (trail is None or (i + n < len(body) and body[i + n] == trail))):
                        hits.append(i)
                return hits

            mh, ch = fs_hits(mrg_body), fs_hits(cur_body)
            removed_gone = all(r not in mrg_body for r in removed) if removed else True
            # the added block must sit under the SAME preprocessor branch stack as upstream — a macro
            # that landed under a different #if/#elif/#else branch (even with identical adjacent lines)
            # is not verified.
            branch_ok = True
            if mh:
                merged_line = mrg_idx[mh[0]]
                branch_ok = _pp_stack(other, other_target_line) == _pp_stack(merged, merged_line)
            if len(mh) > 1:
                out.append(mk("ambiguous", False, regions=len(mh)))
            elif len(mh) == 1 and in_conflict_at(mh[0]):
                out.append(mk("conflicted", False, regions=1))
            elif len(mh) == 1 and not branch_ok:
                out.append(mk("wrong_branch", False, regions=1))
            elif len(mh) == 1 and len(ch) == 0 and removed_gone:
                out.append(mk("applied", True, anchored=True, regions=1))
            elif len(mh) >= 1 and len(ch) >= 1 and removed_gone and branch_ok:
                out.append(mk("already_present", True, anchored=True, regions=1))
            elif removed and _contig(mrg_body, added) >= 1 and any(r in mrg_body for r in removed):
                out.append(mk("obsolete_remains", False))
            else:
                out.append(mk("not_applied", False, regions=len(mh)))
            continue

        # Function scope: diff the copy's function body against the merge's; require exactly one
        # localized change region equal to the hunk's adds/removes, pinned by a surviving anchor.
        regions = _regions(cur_body, mrg_body)
        matching = [(b1, ins, dele) for (b1, ins, dele) in regions if ins == added and dele == removed]

        def _seq_hits(seq):
            if not seq:
                return 0
            k = len(seq)
            return sum(1 for i in range(len(mrg_body) - k + 1) if mrg_body[i:i + k] == seq)

        def anchored_at(b1, ins):
            # pin position with the leading/trailing context sequence, CLAMPED to the target scope
            # (the hunk's file-level context can spill past a function boundary), and only when the
            # matched sequence maps UNIQUELY in the scope — a single line, or a repeated sequence, is
            # insufficient (a second identical call site cannot disambiguate which one was edited).
            kl = min(len(lead_seq), b1)
            before = (kl > 0 and mrg_body[b1 - kl:b1] == lead_seq[-kl:] and _seq_hits(lead_seq[-kl:]) == 1)
            ta = b1 + len(ins)
            kt = min(len(trail_seq), len(mrg_body) - ta)
            after = (kt > 0 and mrg_body[ta:ta + kt] == trail_seq[:kt] and _seq_hits(trail_seq[:kt]) == 1)
            return before or after or (not lead_seq and not trail_seq)

        if len(matching) == 1:
            b1, ins, dele = matching[0]
            if in_conflict_at(b1):
                out.append(mk("conflicted", False, regions=1))
            elif anchored_at(b1, ins):
                out.append(mk("applied", True, anchored=True, regions=1))
            else:
                out.append(mk("wrong_position", False, regions=1))
        elif len(matching) > 1:
            out.append(mk("ambiguous", False, regions=len(matching)))
        else:
            post = [t.strip() for tag, t in h["body"] if tag in (" ", "+") and t.strip()]
            removed_absent_cur = all(r not in cur_body for r in removed) if removed else True
            if added and _contig(cur_body, post) == 1 and _contig(mrg_body, post) >= 1 and removed_absent_cur:
                out.append(mk("already_present", True, anchored=True))
            elif removed and _contig(mrg_body, added) >= 1 and any(r in mrg_body for r in removed):
                out.append(mk("obsolete_remains", False))         # replacement added, obsolete line remains
            else:
                out.append(mk("not_applied", False))
    return out


# ---------------------------------------------------------------------------
# build — strict provenance order
# ---------------------------------------------------------------------------
@dataclass
class BuildResult:
    ok: bool
    status: str
    clean_rc: Optional[int]
    build_rc: Optional[int]
    timed_out: bool
    artifact_fresh: bool
    sha256: str
    binary: Optional[str]
    log: str


def _fail(status, clean_rc=None, build_rc=None, timed_out=False, log=""):
    return BuildResult(False, status, clean_rc, build_rc, timed_out, False, "", None, log)


def build_once(log: Log, recipe: Recipe, wt: str, home: str, header_text: str, out_binary: str,
               timeout: int = BUILD_TIMEOUT) -> BuildResult:
    """Order: clean -> write+hash intended header -> delete artifact -> build -> verify header
    hash unchanged -> lstat a newly-created regular non-symlink artifact inside the worktree ->
    hash + copy."""
    bdir = safe_subpath(wt, recipe.build_subdir)          # cwd for clean/build (a plain path is fine)
    hdr_rel = recipe.downstream_path                       # worktree-relative; walked O_NOFOLLOW below
    art_rel = os.path.join(recipe.build_subdir, recipe.build_artifact)
    header_sha = sha256_text(header_text)

    # 1. clean first (on whatever is there)
    rc = constrained_run(log, recipe.clean_cmd, bdir, home, timeout, "clean")
    if rc.timed_out:
        return _fail("timeout", timed_out=True, log=rc.stdout + rc.stderr)
    if rc.returncode != 0:
        return _fail("clean_failed", clean_rc=rc.returncode, log=rc.stdout + rc.stderr)

    # 2. write the intended header AFTER clean — dirfd-relative, so clean cannot have swapped an
    #    intermediate dir for a symlink to redirect this write.
    _write_at(wt, hdr_rel, header_text.encode())

    # 2b. write any Mitos-shipped harness sources beside the header (same dirfd-relative O_NOFOLLOW path)
    for rel, data in (recipe.harness_sources or []):
        _write_at(wt, os.path.join(recipe.build_subdir, rel),
                  data if isinstance(data, bytes) else data.encode())

    # 3. delete the expected artifact (so "present afterwards" => this build created it)
    try:
        st = _lstat_at(wt, art_rel)
        if statmod.S_ISLNK(st.st_mode):
            return _fail("artifact_is_symlink", clean_rc=rc.returncode, log="artifact path is a symlink")
        _unlink_at(wt, art_rel)
    except FileNotFoundError:
        pass

    # 4. build
    rb = constrained_run(log, recipe.build_cmd, bdir, home, timeout, "build")
    logtxt = rb.stdout + rb.stderr
    if rb.timed_out:
        return _fail("timeout", clean_rc=rc.returncode, timed_out=True, log=logtxt)
    if rb.returncode != 0:
        return _fail("build_failed", clean_rc=rc.returncode, build_rc=rb.returncode, log=logtxt)

    # 5. the certified source must be UNCHANGED by the build
    try:
        if sha256_bytes(_read_at(wt, hdr_rel)) != header_sha:
            return _fail("source_overwritten", clean_rc=rc.returncode, build_rc=rb.returncode, log=logtxt)
    except OSError:
        return _fail("header_unreadable", clean_rc=rc.returncode, build_rc=rb.returncode, log=logtxt)

    # 6. artifact must be a newly-created regular, non-symlink file (dirfd-walk keeps it in the worktree)
    try:
        st = _lstat_at(wt, art_rel)
    except FileNotFoundError:
        return _fail("stale_artifact", clean_rc=rc.returncode, build_rc=rb.returncode, log=logtxt)
    if statmod.S_ISLNK(st.st_mode) or not statmod.S_ISREG(st.st_mode):
        return _fail("artifact_not_regular", clean_rc=rc.returncode, build_rc=rb.returncode, log=logtxt)

    # 7. hash + copy safely (no symlink follow on read; exclusive create on write; keep executable)
    data = _read_at(wt, art_rel)
    if os.path.lexists(out_binary):
        os.remove(out_binary)
    _excl_write(out_binary, data)
    os.chmod(out_binary, 0o700)
    return BuildResult(True, "ok", rc.returncode, rb.returncode, False, True, sha256_bytes(data), out_binary, logtxt)


# ---------------------------------------------------------------------------
# behavioural probes
# ---------------------------------------------------------------------------
@dataclass
class ProbeResult:
    name: str
    loader: str
    expectation: str
    before_rc: Optional[int]
    after_rc: Optional[int]
    before_out: str
    after_out: str
    after_timed_out: bool
    after_signal: bool
    ok: bool
    detail: str


def run_probes(log: Log, recipe: Recipe, before_bin: str, after_bin: str, workdir: str, home: str,
               timeout: int = PROBE_TIMEOUT, probe_dir: Optional[str] = None):
    # crafted inputs are BYTES from the recipe, written by Mitos O_EXCL|O_NOFOLLOW into a fresh dir
    if probe_dir is None:
        probe_dir = tempfile.mkdtemp(dir=workdir, prefix="probes_")
        os.chmod(probe_dir, 0o700)
    results = []
    for p in recipe.probes:
        inp = os.path.join(probe_dir, p.filename)
        _excl_write(inp, p.content())
        rb = constrained_run(log, recipe.run_argv(before_bin, inp), workdir, home, timeout, "probe-before")
        ra = constrained_run(log, recipe.run_argv(after_bin, inp), workdir, home, timeout, "probe-after")
        clean = lambda s: (s or "").strip().replace(inp, os.path.basename(inp))
        bo, ao = clean(rb.stdout), clean(ra.stdout)
        a_signal = (ra.returncode is not None and ra.returncode < 0)
        a_crash = ra.timed_out or a_signal or ra.returncode is None
        if p.expectation == "identical":
            ok = (rb.returncode == 0 and ra.returncode == 0 and not rb.timed_out and not ra.timed_out
                  and bo == ao and bo != "")
            detail = f"before rc={rb.returncode} out={bo!r}; after rc={ra.returncode} out={ao!r}; identical={bo == ao}"
        elif p.expectation == "rejected_after_only":
            before_accepts = (rb.returncode == 0 and not rb.timed_out)
            exact = (ra.returncode == p.expect_exit_code)
            diag = p.expect_diagnostic in (ra.stdout + ra.stderr)
            ok = before_accepts and not a_crash and exact and diag
            why = ("crash/signal" if a_signal else "timeout" if ra.timed_out else
                   f"rc={ra.returncode}!={p.expect_exit_code}" if not exact else
                   "missing diagnostic" if not diag else "ok")
            detail = f"before rc={rb.returncode} (accepted); after rc={ra.returncode} diag={'yes' if diag else 'NO'} [{why}]"
        elif p.expectation == "crash_before_only":
            # before = memory-safety fault under a sanitizer (signal / nonzero / timeout);
            # after = clean exit 0. Proves the transplant removes the fault, not merely relocates code.
            before_crashed = rb.timed_out or rb.returncode is None or rb.returncode != 0
            after_clean = (ra.returncode == 0 and not ra.timed_out)
            san = ""
            for ln in (rb.stderr or "").splitlines():
                if "ERROR: AddressSanitizer" in ln or "SUMMARY:" in ln or "runtime error:" in ln:
                    san = ln.strip(); break
            ok = before_crashed and after_clean
            detail = (f"before rc={rb.returncode} crash={before_crashed} [{san or 'nonzero exit'}]; "
                      f"after rc={ra.returncode} clean={after_clean}")
        else:
            ok, detail = False, f"unknown expectation {p.expectation}"
        results.append(ProbeResult(p.name, p.loader, p.expectation, rb.returncode, ra.returncode,
                                   bo, ao[:200], ra.timed_out, a_signal, ok, detail))
    return results


# ---------------------------------------------------------------------------
# pure verdict
# ---------------------------------------------------------------------------
def decide(*, parent_verified, origin_ok, clone_validated, generator_clean, hunk_count_ok, merge_rc,
           n_conflicts, hunks, baseline, patched, probes, modified_loaders, reachable_loaders,
           behavioural_loaders, golden_attested, golden_ok):
    """(verdict, reasons). NEEDS_REVIEW on any hard-gate failure; VERIFIED_SCOPED when all hard
    gates pass but only a subset of reachable loaders were behaviourally exercised; VERIFIED only
    when every reachable loader was exercised. For a golden-attested recipe the AUTHORITATIVE gate is
    the exact expected postimage (golden_ok); the per-hunk `verified` flag is an experimental
    positional cross-check that must also hold. Enforces behavioural ⊆ reachable ⊆ modified with
    nonempty reviewed reachability."""
    reasons = []
    if golden_attested and not golden_ok:
        reasons.append("golden postimage mismatch (merged/fix.diff sha256 != independently-reviewed expected)")
    if not parent_verified:
        reasons.append("stated parent != raw-commit first parent")
    if not origin_ok:
        reasons.append("clone origin mismatch")
    if not clone_validated:
        reasons.append("clone failed integrity validation")
    if not generator_clean:
        reasons.append("generator tree is dirty (provenance not reproducible)")
    if not hunk_count_ok:
        reasons.append("parsed hunk count != patch hunk count")
    if merge_rc != 0:
        reasons.append(f"merge returned {merge_rc} (require 0)")
    if n_conflicts:
        reasons.append(f"{n_conflicts} merge conflict(s)")
    if not hunks:
        reasons.append("no hunks parsed")
    unverified = [h for h in hunks if not h["verified"]]
    if unverified and not (golden_attested and golden_ok):
        reasons.append(f"{len(unverified)} hunk(s) not verified ({', '.join(sorted({h['status'] for h in unverified}))})")
    if not baseline.get("ok"):
        reasons.append(f"baseline build not ok ({baseline.get('status')})")
    if not patched.get("ok"):
        reasons.append(f"patched build not ok ({patched.get('status')})")
    if not probes:
        reasons.append("behavioural probes did not run")
    failed = [p for p in probes if not p["ok"]]
    if failed:
        reasons.append(f"{len(failed)} behavioural probe(s) failed")
    if not behavioural_loaders:
        reasons.append("no loader behaviourally verified (a passing unrelated probe does not count)")
    # reachability metadata must be reviewed (nonempty) and nest: behavioural ⊆ reachable ⊆ modified
    mod, reach, beh = set(modified_loaders or []), set(reachable_loaders or []), set(behavioural_loaders or [])
    if not reach:
        reasons.append("empty reviewed reachability metadata")
    if not (beh <= reach):
        reasons.append(f"coverage invariant: behavioural {sorted(beh)} ⊄ reachable {sorted(reach)}")
    if not (reach <= mod):
        reasons.append(f"coverage invariant: reachable {sorted(reach)} ⊄ modified {sorted(mod)}")
    if reasons:
        return "NEEDS_REVIEW", reasons
    missing = [l for l in reachable_loaders if l not in behavioural_loaders]
    if missing:
        return "VERIFIED_SCOPED", [f"behavioural coverage is scoped: {len(behavioural_loaders)}/"
                                   f"{len(reachable_loaders)} reachable loaders exercised; not exercised: "
                                   f"{', '.join(missing)}"]
    return "VERIFIED", []


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------
@dataclass
class RepairResult:
    recipe: str
    recipe_digest: str
    generator_commit: str
    generator_tree: str
    generator_clean: bool
    verification_command: str
    execution_model: str
    upstream: dict
    downstream: dict
    parent_verified: bool
    origin_ok: bool
    clone_validated: bool
    hunk_count_ok: bool
    merge: dict
    golden_attestation: dict
    hunks: list
    hunk_certification: dict
    coverage: dict
    baseline_build: dict
    patched_build: dict
    probes: list
    verdict: str
    reasons: list
    hashes: dict
    toolchain: dict
    fix_diff: str = ""
    path_tokens: dict = field(default_factory=dict)
    commands: list = field(default_factory=list)


def _toolchain(log: Log):
    def one(argv):
        try:
            return log.run(argv).stdout.splitlines()[0].strip()
        except Exception:
            return ""
    return {"cc": one(["cc", "--version"]), "make": one(["make", "--version"]),
            "git": one(["git", "--version"])}


def _repo_head(repo_dir, home):
    """Generator commit/tree via the isolated Git env; reject a dirty tree (provenance would not
    reflect committed code). Returns (commit, tree, clean)."""
    env = git_env(home)

    def run(*a):
        return subprocess.run(["git", *_GIT_HARDEN, "-C", repo_dir, *a], capture_output=True, text=True, env=env)
    try:
        rc, rt, rs = run("rev-parse", "HEAD"), run("rev-parse", "HEAD^{tree}"), run("status", "--porcelain")
        commit, tree = rc.stdout.strip(), rt.stdout.strip()
        # a non-Git directory (e.g. a source tarball) fails rev-parse -> fail closed
        ok = rc.returncode == 0 and rt.returncode == 0 and rs.returncode == 0 and bool(commit) and bool(tree)
        clean = ok and rs.stdout.strip() == ""
        return (commit if ok else ""), (tree if ok else ""), clean
    except Exception:
        return "", "", False


def run_repair(recipe_key: str, work_parent: str, verbose: Optional[Callable[[str], None]] = None,
               verification_command: Optional[str] = None) -> RepairResult:
    """PUBLIC entrypoint. Resolves an internal recipe KEY to a factory that defines every repo,
    command, probe and run_argv internally — a caller can never supply what executes."""
    factory = _REGISTRY.get(recipe_key) if isinstance(recipe_key, str) else None
    if factory is None:
        raise SecurityError(f"unknown recipe key {recipe_key!r}; host execution runs only internal "
                            "registry recipes — there is no way to inject build_cmd/repos/probes")
    return _execute(factory(), work_parent, verbose, verification_command)


def _execute(recipe: Recipe, work_parent: str, verbose: Optional[Callable[[str], None]] = None,
             verification_command: Optional[str] = None) -> RepairResult:
    """Private, test-only executor of a fully-specified Recipe. Production reaches it ONLY via
    run_repair(recipe_key); tests inject synthetic recipes here directly."""
    log = Log(verbose)
    # --work is a PARENT: create a fresh, unpredictable 0700 run dir beneath it. NEVER remove the
    # caller's directory.
    os.makedirs(work_parent, exist_ok=True)
    run_root = tempfile.mkdtemp(dir=work_parent, prefix="mitos_run_")
    os.chmod(run_root, 0o700)
    home = os.path.join(run_root, "home")
    merged_dir = os.path.join(run_root, "merge")
    os.makedirs(home, 0o700)
    os.makedirs(merged_dir, 0o700)
    g = Git(log, home)

    up_cache = prepare_clone(g, recipe.upstream_repo, os.path.join(run_root, "clones", "upstream"))
    dn_cache = prepare_clone(g, recipe.downstream_repo, os.path.join(run_root, "clones", "downstream"))
    clone_validated = True                      # prepare_clone raises SecurityError otherwise
    origin_ok = True

    fix = resolve(g, up_cache, recipe.upstream_fix_sha)
    parent_actual = parent_of(g, up_cache, fix)     # raw commit object, not rev-parse ^
    parent_verified = parent_actual == recipe.upstream_parent_sha
    parent = recipe.upstream_parent_sha
    dn_sha = resolve(g, dn_cache, recipe.downstream_sha)

    base = git_show(g, up_cache, parent, recipe.upstream_path)
    other = git_show(g, up_cache, fix, recipe.upstream_path)
    current = git_show(g, dn_cache, dn_sha, recipe.downstream_path)
    real_patch = g("-C", up_cache, "diff", parent, fix, "--", recipe.upstream_path, label="diff").stdout

    merged, n_conflicts, merge_rc = three_way_merge(g, merged_dir, current, base, other)
    hunks = verify_hunks(real_patch, other, current, merged, n_conflicts)
    hunk_count_ok = (count_patch_hunks(real_patch) == len(hunks)) and len(hunks) > 0
    fix_diff = "".join(difflib.unified_diff(
        current.splitlines(keepends=True), merged.splitlines(keepends=True),
        fromfile=f"a/{recipe.downstream_path}", tofile=f"b/{recipe.downstream_path}"))

    wt = add_worktree(g, dn_cache, dn_sha, os.path.join(run_root, "downstream_wt"))
    before_bin = os.path.join(run_root, "encoder_before")
    after_bin = os.path.join(run_root, "encoder_after")
    baseline = build_once(log, recipe, wt, home, current, before_bin)
    patched = (build_once(log, recipe, wt, home, merged, after_bin)
               if baseline.ok else _fail("skipped_baseline_failed"))
    g("-C", wt, "checkout", "--", recipe.downstream_path)

    probe_dir = tempfile.mkdtemp(dir=run_root, prefix="probes_")
    os.chmod(probe_dir, 0o700)
    probes = (run_probes(log, recipe, before_bin, after_bin, run_root, home, probe_dir=probe_dir)
              if (baseline.ok and patched.ok) else [])

    gen_commit, gen_tree, gen_clean = _repo_head(str(Path(__file__).resolve().parents[1]), home)

    # golden attestation: compare the run's computed sha to the recipe's INDEPENDENTLY-REVIEWED
    # constants (never learned from this run). Only a recipe carrying an expected merged sha is
    # "golden-attested"; generic recipes fall back to positional verification (experimental).
    actual_merged_sha = sha256_text(merged)
    actual_fix_diff_sha = sha256_text(fix_diff)
    golden_attested = bool(recipe.expected_merged_sha256)
    merged_match = (actual_merged_sha == recipe.expected_merged_sha256) if recipe.expected_merged_sha256 else None
    fix_diff_match = (actual_fix_diff_sha == recipe.expected_fix_diff_sha256) if recipe.expected_fix_diff_sha256 else None
    golden_ok = (merged_match is True) and (fix_diff_match in (True, None))
    golden_attestation = {
        "attested": golden_attested,
        "expected_merged_sha256": recipe.expected_merged_sha256 or None,
        "actual_merged_sha256": actual_merged_sha, "merged_match": merged_match,
        "expected_fix_diff_sha256": recipe.expected_fix_diff_sha256 or None,
        "actual_fix_diff_sha256": actual_fix_diff_sha, "fix_diff_match": fix_diff_match,
        "note": ("Exact expected postimage, independently reviewed and pinned in the recipe. This closes "
                 "PM1 around this exact repair; generic positional verification beyond a golden-attested "
                 "recipe is experimental." if golden_attested else
                 "No golden attestation for this recipe — generic positional verification only (experimental)."),
    }

    hunk_dicts = [asdict(h) for h in hunks]
    probe_dicts = [asdict(p) for p in probes]
    baseline_d, patched_d = asdict(baseline), asdict(patched)
    behavioural = sorted({p.loader for p in probes
                          if p.expectation in ("rejected_after_only", "crash_before_only") and p.ok})
    verdict, reasons = decide(
        parent_verified=parent_verified, origin_ok=origin_ok, clone_validated=clone_validated,
        generator_clean=gen_clean, hunk_count_ok=hunk_count_ok, merge_rc=merge_rc, n_conflicts=n_conflicts,
        hunks=hunk_dicts, baseline=baseline_d, patched=patched_d, probes=probe_dicts,
        modified_loaders=recipe.modified_loaders or [], reachable_loaders=recipe.reachable_loaders or [],
        behavioural_loaders=behavioural, golden_attested=golden_attested, golden_ok=golden_ok)

    verified_applied = [h for h in hunks if h.verified and h.status == "applied"]
    coverage = {
        "structurally_merged_loaders": recipe.modified_loaders or [],
        "structurally_merged_count": len(recipe.modified_loaders or []),
        "reachable_loaders": recipe.reachable_loaders or [],
        "reachable_count": len(recipe.reachable_loaders or []),
        "behaviourally_verified_loaders": behavioural,
        "behaviourally_verified_count": len(behavioural),
        "invariant": "behavioural ⊆ reachable ⊆ modified",
        "note": recipe.coverage_note or "",
    }
    certification = {
        "upstream_hunks": len(hunks),
        "verified": sum(1 for h in hunks if h.verified),
        "verified_applied": len(verified_applied),
        "already_present": sum(1 for h in hunks if h.status == "already_present"),
        "unverified": [f"{h.status}:{h.actual_scope}:{h.sample[:28]}" for h in hunks if not h.verified],
        "claim": (f"clean three-way merge (merge_rc=0, 0 conflicts); acceptance rests on the golden "
                  f"expected-postimage hash gate; {len(verified_applied)}/{len(hunks)} upstream hunks also "
                  "pass the experimental positional cross-check (rejects the covered regression cases, not "
                  "a general mislocation proof)"),
    }
    hashes = {
        "base_upstream_parent": sha256_text(base),
        "other_upstream_fix": sha256_text(other),
        "current_downstream_copy": sha256_text(current),
        "merged": sha256_text(merged),
        "upstream_real_patch": sha256_text(real_patch),
        "fix_diff": sha256_text(fix_diff),
        "encoder_before": baseline.sha256,
        "encoder_after": patched.sha256,
    }
    # canonicalise every run-specific path to a stable token so two runs in different dirs produce
    # byte-identical evidence (longest paths first — sanitize() sorts by length).
    tokens = {os.path.join(run_root, "clones", "upstream"): "$UPSTREAM",
              os.path.join(run_root, "clones", "downstream"): "$DOWNSTREAM",
              probe_dir: "$PROBES", merged_dir: "$MERGE", home: "$HOME", run_root: "$RUN"}

    return RepairResult(
        recipe=recipe.name, recipe_digest=recipe_digest(recipe),
        generator_commit=gen_commit, generator_tree=gen_tree, generator_clean=gen_clean,
        verification_command=verification_command or f"python -m mitos repair   # recipe: {recipe.key}",
        execution_model=("constrained host execution: build/probe run their own process group with a "
                         "scrubbed no-credentials env, CPU/file-size/core rlimits, wall timeouts (group "
                         "killed on expiry) and bounded output; git runs from a from-scratch whitelisted "
                         "env with isolated HOME into a fresh 0700 Mitos-owned validated clone. No "
                         "network/PID/memory namespace isolation — internal allowlisted recipes only."),
        upstream={"repo": recipe.upstream_display_url or recipe.upstream_repo, "fix": fix,
                  "parent_expected": parent, "parent_actual": parent_actual, "path": recipe.upstream_path},
        downstream={"repo": recipe.downstream_display_url or recipe.downstream_repo, "sha": dn_sha,
                    "path": recipe.downstream_path, "current_lines": len(current.splitlines())},
        parent_verified=parent_verified, origin_ok=origin_ok, clone_validated=clone_validated,
        hunk_count_ok=hunk_count_ok,
        merge={"tool": "git merge-file --diff3", "returncode": merge_rc, "conflicts": n_conflicts,
               "clean": merge_rc == 0 and n_conflicts == 0, "merged_lines": len(merged.splitlines()),
               "marker": recipe.marker, "marker_before": current.count(recipe.marker) if recipe.marker else None,
               "marker_after": merged.count(recipe.marker) if recipe.marker else None},
        golden_attestation=golden_attestation,
        hunks=hunk_dicts, hunk_certification=certification, coverage=coverage,
        baseline_build=baseline_d, patched_build=patched_d, probes=probe_dicts,
        verdict=verdict, reasons=reasons, hashes=hashes, toolchain=_toolchain(log),
        fix_diff=fix_diff, path_tokens=tokens, commands=[asdict(c) for c in log.cmds])


# ---------------------------------------------------------------------------
# deterministic sanitization + artifacts
# ---------------------------------------------------------------------------
def sanitize(text: str, tokens: dict) -> str:
    if not isinstance(text, str):
        return text
    for path, tok in sorted(tokens.items(), key=lambda kv: -len(kv[0])):
        if path:
            text = text.replace(path, tok)
    return text


def _deep_sanitize(obj, tokens):
    if isinstance(obj, str):
        return sanitize(obj, tokens)
    if isinstance(obj, list):
        return [_deep_sanitize(x, tokens) for x in obj]
    if isinstance(obj, dict):
        return {k: _deep_sanitize(v, tokens) for k, v in obj.items()}
    return obj


_ARTIFACT_NAMES = ("fix.diff", "full_command_log.txt", "commands.log", "evidence.json", "PR_BODY.md")


def write_artifacts(res: RepairResult, out_dir: str, force: bool = False):
    """Write the five artifacts into a fresh no-follow staging dir, then atomically rename into
    out_dir. Refuses to clobber an existing output (symlink or file) unless force=True. All command
    streams are path-canonicalised BEFORE hashing so two runs in different dirs reproduce byte-for-
    byte."""
    os.makedirs(out_dir, exist_ok=True)
    tok = res.path_tokens
    for name in _ARTIFACT_NAMES:
        dst = os.path.join(out_dir, name)
        if os.path.lexists(dst) and not force:
            raise SecurityError(f"refusing to overwrite existing output {name} (pass force=True)")

    full = []
    for c in res.commands:
        is_dump = ("show" in c["argv"] or "merge-file" in c["argv"] or "cat-file" in c["argv"])
        full.append("$ " + " ".join(sanitize(a, tok) for a in c["argv"]) +
                    (f"   ({sanitize(c['cwd'], tok)})" if c["cwd"] else ""))
        trunc = "  [TRUNCATED]" if c.get("truncated") else ""
        full.append(f"  rc={c['returncode']} timed_out={c['timed_out']}{trunc}")
        for stream in ("stdout", "stderr"):
            canon = sanitize(c[stream], tok)            # canonicalise run paths BEFORE hashing/display
            body = canon.rstrip()
            if not body:
                continue
            if is_dump and len(canon) > 2000:           # elide a whole-file dump, keep its hash
                full.append(f"  --- {stream} elided: {len(canon)} bytes, sha256 {sha256_text(canon)[:16]} "
                            f"(file content — a hashed input) ---")
            else:
                full.append(f"  --- {stream} ---")
                full.extend(("    " + ln).rstrip() for ln in body.splitlines())
    full_log = "\n".join(full) + "\n"

    compact = []
    for c in res.commands:
        compact.append("$ " + " ".join(sanitize(a, tok) for a in c["argv"]) +
                       (f"   ({sanitize(c['cwd'], tok)})" if c["cwd"] else ""))
        compact.append(f"  -> rc={c['returncode']}" + ("  [TIMEOUT]" if c["timed_out"] else "") +
                       ("  [TRUNCATED]" if c.get("truncated") else ""))
        last = (sanitize(c["stdout"], tok).strip().splitlines() or [""])[-1]
        if last.strip():
            compact.append(("  stdout: " + last[:200]).rstrip())
    compact_log = "\n".join(compact) + "\n"

    evd = asdict(res)
    evd.pop("fix_diff", None)
    evd.pop("path_tokens", None)
    for c in evd["commands"]:
        truncated = bool(c.get("truncated"))
        for stream in ("stdout", "stderr"):
            canon = sanitize(c[stream], tok)            # canonicalise BEFORE hashing/measuring
            c[f"{stream}_sha256"] = sha256_text(canon)
            # canonicalised captured length is path-independent (the run path is fully replaced by a
            # fixed token); the raw byte total is NOT, so it is never frozen into evidence.
            c[f"{stream}_bytes"] = len(canon)
            c[f"{stream}_tail"] = canon[-240:]
            del c[stream]
        c["truncated"] = truncated                      # honest truncation flag; no path-dependent total
        c.pop("stdout_total", None); c.pop("stderr_total", None)
    evd = _deep_sanitize(evd, tok)
    evd["hashes"]["full_command_log"] = sha256_text(full_log)
    evd["evidence_sha256"] = sha256_text(json.dumps(evd, indent=2, sort_keys=True))
    evidence_json = json.dumps(evd, indent=2)

    # stage with O_EXCL|O_NOFOLLOW, then atomically rename each into place
    staging = tempfile.mkdtemp(dir=out_dir, prefix=".stage_")
    os.chmod(staging, 0o700)
    try:
        contents = {"fix.diff": res.fix_diff, "full_command_log.txt": full_log,
                    "commands.log": compact_log, "evidence.json": evidence_json,
                    "PR_BODY.md": pr_body(res)}
        for name, text in contents.items():
            _excl_write(os.path.join(staging, name), text.encode())
        for name in _ARTIFACT_NAMES:
            dst = os.path.join(out_dir, name)
            if os.path.islink(dst):                     # replace the link itself; never write through it
                os.remove(dst)
            os.replace(os.path.join(staging, name), dst)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return out_dir


def pr_body(res: RepairResult) -> str:
    cert, cov = res.hunk_certification, res.coverage
    hunk_rows = "\n".join(
        f"| `{(h['sample'] or h['header_function'])[:44]}` | {h['nature']} | {h['actual_scope'][:24]} | "
        f"+{h['added']}/−{h['removed']} | {'anchored' if h['anchored'] else '—'} | "
        f"{'✅' if h['verified'] else '⚠️'} {h['status']} |"
        for h in res.hunks)
    probe_rows = "\n".join(
        f"| {p['name']} | {p['loader']} | `{p['expectation']}` | {'✅ pass' if p['ok'] else '❌ fail'} | {p['detail']} |"
        for p in res.probes)
    if res.verdict == "VERIFIED":
        verdict_line = ("**VERIFIED** — the independently-reviewed golden expected-postimage matched (the "
                        "authoritative guarantee), the experimental positional cross-check passed on every "
                        "hunk, both fresh builds green, and every reachable loader was behaviourally exercised.")
    elif res.verdict == "VERIFIED_SCOPED":
        verdict_line = (f"**VERIFIED_SCOPED** — origin/parent validated, clean three-way merge matching the "
                        f"independently-reviewed golden postimage (the authoritative guarantee); "
                        f"{cert['verified_applied']}/{cert['upstream_hunks']} hunks also pass the experimental "
                        f"positional cross-check (any remainder is advisory — identical/duplicate edits certified "
                        f"byte-exact by the golden postimage); both fresh builds green; probes met their exact "
                        f"expectation; behavioural coverage is a subset of the reachable loaders: "
                        + "; ".join(res.reasons))
    else:
        verdict_line = "**NEEDS_REVIEW** — " + "; ".join(res.reasons)
    return f"""# Vendored `{res.downstream['path'].split('/')[-1]}`: apply the upstream security fix

*Generated by Mitos — a real parent→child patch applied via three-way merge, gated on an
independently-reviewed golden expected-postimage hash and checked through this repository's own build
and binary. Positional per-hunk placement is an experimental cross-check. Not auto-submitted.*

## Target & provenance

- **Upstream fix:** `{res.upstream['repo']}` @ `{res.upstream['fix']}`
- **Upstream parent (from raw commit object):** `{res.upstream['parent_actual']}` (expected `{res.upstream['parent_expected']}`, match `{res.parent_verified}`)
- **This copy pinned at:** `{res.downstream['sha']}`  ·  clone origin validated: `{res.origin_ok and res.clone_validated}`
- **Generator commit:** `{res.generator_commit}` (tree clean: `{res.generator_clean}`)  ·  **recipe digest:** `{res.recipe_digest[:16]}`
- **Golden attestation:** attested=`{res.golden_attestation['attested']}`, merged sha256 match=`{res.golden_attestation['merged_match']}`, fix.diff match=`{res.golden_attestation['fix_diff_match']}` — the exact expected postimage is independently reviewed and pinned in the recipe; the run is compared to it (a hard gate). Generic positional verification beyond this golden-attested recipe is **experimental**.
- **Reproduce:** `{res.verification_command}` (two cold runs in different dirs reproduce every artifact byte-for-byte)

## Merge

`git diff {res.upstream['parent_expected'][:8]} {res.upstream['fix'][:8]} -- {res.upstream['path']}` applied via
`{res.merge['tool']}`. **`merge_rc == {res.merge['returncode']}`, {res.merge['conflicts']} conflicts**
({'clean' if res.merge['clean'] else 'NOT clean'}); marker `{res.merge['marker']}`
{res.merge['marker_before']} → {res.merge['marker_after']}. Parsed hunks == patch hunks: `{res.hunk_count_ok}`.

### Positional hunk cross-check (experimental — golden postimage is authoritative)

Alongside the golden gate, each hunk's target scope is the enclosing function of its coordinates in
the upstream child; inside that scope the copy is diffed against the merge and the change must be
exactly the hunk's additions and removals in one localized region, pinned to a surviving context
anchor (both sides for file-scope preprocessor context). This **rejects the covered regression cases**
(guard-after-return, second-of-two-identical-calls, wrong `#if` branch, obsolete-line-remaining) — it
is **not** a general proof that every mislocated/ambiguous mapping is caught. Acceptance rests on the
golden expected-postimage hash above.

| added code (sample) | nature | actual scope | Δ | pin | verified |
|---|---|---|---|---|---|
{hunk_rows}

> {cert['claim']}.

## Coverage — structural vs behavioural (scoped)

- **Structurally merged loaders ({cov['structurally_merged_count']}):** {', '.join(cov['structurally_merged_loaders'])}
- **Reachable loaders ({cov.get('reachable_count', len(cov['reachable_loaders']))}):** {', '.join(cov['reachable_loaders'])}
- **Behaviourally verified ({cov['behaviourally_verified_count']}):** {', '.join(cov['behaviourally_verified_loaders']) or '—'}
- **Invariant enforced:** `{cov.get('invariant', 'behavioural ⊆ reachable ⊆ modified')}`

{cov['note']}

## Build + behaviour (constrained host execution)

- Baseline build: **{res.baseline_build['status']}** (fresh artifact `{res.baseline_build['artifact_fresh']}`, sha256 `{res.baseline_build['sha256'][:16]}`)
- Patched build: **{res.patched_build['status']}** (fresh `{res.patched_build['artifact_fresh']}`, sha256 `{res.patched_build['sha256'][:16]}`)

A rejection counts only on the exact allowed exit code **and** the expected diagnostic; signals,
crashes and timeouts always fail.

| behavioural probe | loader | expectation | result | detail |
|---|---|---|---|---|
{probe_rows}

## Verdict

{verdict_line}

<sub>{res.execution_model}</sub>
<sub>toolchain: {res.toolchain.get('cc','')} · {res.toolchain.get('git','')}</sub>
"""
