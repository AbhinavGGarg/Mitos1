"""From a repository to a verified patch, with nothing supplied by hand.

`mitos fix` already transplants a real upstream fix into a real stale copy, but it needs
a human to know five coordinates: which upstream repo, which commit, which file in it,
which copy, and where that copy lives. Every one of those except the copy's own path is a
per-library constant, and the path is discoverable. This module holds those constants and
closes the loop, so one repository name is enough.

The catalog is deliberately small. A library belongs here only when its fix marker has
been checked against the upstream commit — absent in the fix's parent, present at the fix
and at HEAD — because a marker that is merely plausible produces confident nonsense.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field

from . import behavioral
from .applyfix import (apply_fix, audit_placement, compile_delta, compile_header,
                       fetch_commit_patch, fetch_file, primary_marker, unified)
from .ghsearch import _gh_api, search_code


@dataclass(frozen=True)
class Library:
    name: str
    symbol: str              # public entry point; what code search looks for
    identity: tuple          # implementation internals — a caller of the library has none of these
    fix_marker: str          # a symbol the fix itself introduced; absent in the fix's parent
    upstream: str            # owner/name the fix lives in
    fix_sha: str
    fix_path: str            # the changed file's path upstream
    defines: tuple = ()      # macros the verification build needs
    cves: str = ""


CATALOG = (
    Library(
        name="stb_image", symbol="stbi_load_from_memory",
        identity=("stbi__context", "stbi__jpeg_decode_block", "stbi__parse_png_file"),
        fix_marker="stbi__addints_valid",
        upstream="nothings/stb", fix_sha="47164e4086c1349ef3042fb04e0f7f7ceaf1fcee",
        fix_path="stb_image.h", defines=("STB_IMAGE_IMPLEMENTATION",),
        cves="signed integer overflow in the JPEG decode path"),
    Library(
        name="stb_vorbis", symbol="stb_vorbis_get_samples_float",
        identity=("compute_codewords", "start_decoder", "vorbis_decode_packet"),
        fix_marker="ForAllSecure",
        upstream="nothings/stb", fix_sha="98fdfc6df88b1e34a736d5e126e6c8139c8de1a6",
        fix_path="stb_vorbis.c", defines=(),
        cves="CVE-2019-13217..13223 (7)"),
)

BY_NAME = {lib.name: lib for lib in CATALOG}


@dataclass
class Copy:
    lib: Library
    repo: str
    path: str
    lines: int
    patched: bool


def _raw(repo: str, path: str) -> str | None:
    try:
        return _gh_api(["-X", "GET", f"repos/{repo}/contents/{path}",
                        "-H", "Accept: application/vnd.github.raw"])
    except Exception:
        return None


def discover(target_repo: str, libs=CATALOG, verbose=lambda *_: None):
    """Implementation copies of catalog libraries inside one repository.

    A file that merely calls the library is excluded rather than reported: it has the
    public symbol but none of the implementation internals. Both the excluded files and
    the already-patched ones are returned, because "we looked and it was fine" and "we
    did not look" must not render the same way.
    """
    found, excluded = [], []
    for lib in libs:
        verbose(f"searching {target_repo} for {lib.name}")
        try:
            hits = search_code(f"repo:{target_repo} {lib.symbol}", max_results=8, per_page=8)
        except Exception as e:
            verbose(f"  search failed for {lib.name}: {e}")
            continue
        for h in hits:
            text = _raw(h.repo, h.path)
            if text is None:
                continue
            if not all(m in text for m in lib.identity):
                excluded.append((lib.name, h.path, "references the library but is not a copy "
                                                   "of its implementation"))
                continue
            found.append(Copy(lib=lib, repo=h.repo, path=h.path,
                              lines=len(text.splitlines()),
                              patched=lib.fix_marker in text))
    return found, excluded


SOURCE_EXT = (".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hh", ".inl")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "build", "dist", "target",
             ".tox", "__pycache__", ".mypy_cache", "vendor.bundle"}
MAX_SOURCE_BYTES = 8 * 1024 * 1024


def discover_checkout(root: str, libs=CATALOG, verbose=lambda *_: None):
    """The same question as discover(), asked of a working tree instead of the API.

    In CI the files are already on disk, so walking them is both cheaper and more truthful
    than code search: it sees the branch under test, it has no quota, and it cannot miss a
    copy because the search index lagged. Identity markers do the same job here — a file
    that merely calls the library is excluded rather than reported.
    """
    found, excluded = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if not fn.endswith(SOURCE_EXT):
                continue
            full = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(full) > MAX_SOURCE_BYTES:
                    continue
                with open(full, "r", encoding="utf8", errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            rel = os.path.relpath(full, root)
            for lib in libs:
                if lib.symbol not in text:
                    continue
                if not all(m in text for m in lib.identity):
                    excluded.append((lib.name, rel, "references the library but is not a copy "
                                                    "of its implementation"))
                    continue
                verbose(f"{rel}: {lib.name} implementation copy")
                found.append(Copy(lib=lib, repo=root, path=rel,
                                  lines=len(text.splitlines()),
                                  patched=lib.fix_marker in text))
    return found, excluded


@dataclass
class Transplant:
    target: str
    target_path: str
    upstream: str
    sha: str
    marker: str
    message: str = ""
    date: str = ""
    applied: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    records: list = field(default_factory=list)
    placement_ok: bool = False
    compiles_before: bool = False
    compiles_after: bool = False
    delta: dict = field(default_factory=dict)
    behaviour: object = None
    patched_text: str = ""
    original_text: str = ""
    verdict: str = "NOT_VERIFIED"
    out_dir: str = ""

    @property
    def why_not(self) -> str:
        if not self.applied:
            return "no sites applied"
        if not self.compiles_after:
            return "patched copy failed to compile"
        if not self.compiles_before:
            return "original did not compile"
        bad = [r for r in self.records if not r["ok"]]
        return (f"{len(bad)} inserted line(s) misplaced (dead/comment/wrong-function) — "
                "refusing to call this verified")


class _NotRun:
    """Stands in for a behavioural probe that was deliberately not executed."""
    ran = False
    fires_only_after = False
    probe = before = after = None

    def __init__(self, detail):
        self.detail = detail


def transplant(upstream: str, sha: str, fix_path: str, target: str, target_path: str,
               marker: str | None = None, defined=frozenset(), out_dir: str | None = None,
               write: bool = True, execute: bool = True, source_text: str | None = None,
               write_back: str | None = None) -> Transplant:
    """Fetch, transplant, and verify. The verdict ladder is decided here, once.

    Two compile outcomes count and they are NOT the same claim: `clean` means both sides
    build standalone, so the patched copy is known good; `no regression` means neither
    builds standalone — a vendored file usually needs the host project's flags — but the
    transplant introduced no new diagnostic.

    `execute` gates the behavioural probe, which builds a binary from the target's own
    source and RUNS it. That is the right thing to do in the repository owner's CI, where
    their code already runs, and the wrong thing to do on a machine processing repositories
    submitted by strangers. Turning it off costs the VERIFIED_BEHAVIOURAL rung and nothing
    else; placement and compilation still decide the rest of the ladder.

    `source_text` reads the copy from a checkout instead of the network, and `write_back`
    puts the patched file back on disk so a pull request can be opened from it.
    """
    patch, msg, date = fetch_commit_patch(upstream, sha, fix_path)
    original = source_text if source_text is not None else fetch_file(target, target_path)
    marker = marker or primary_marker(patch)
    if not marker:
        raise ValueError("could not derive a fix marker to verify against")

    patched, sites, inserted = apply_fix(original, patch, defined)
    applied = [s for s in sites if s.status == "applied"]
    skipped = [s for s in sites if s.status == "skipped"]

    tmp = tempfile.mkdtemp(prefix="mitos_fix_")
    ok_before, err_b = compile_header(original, tmp, "before", defined)
    ok_after, err_a = compile_header(patched, tmp, "after", defined)
    delta = compile_delta(err_b, err_a)
    placement_ok, records = audit_placement(patched, inserted, defined)
    beh = (behavioral.verify(original, patched, tmp, marker, defined) if execute else
           _NotRun("behavioural probe not run — execution disabled for this target"))

    compiles_clean = ok_before and ok_after
    no_regression = (not compiles_clean) and delta["no_new_errors"]
    sites_ok = placement_ok and len(applied) > 0 and len(records) > 0
    placement_pass = sites_ok and (compiles_clean or no_regression)
    behavioural_ok = beh.ran and beh.fires_only_after
    verdict = ("VERIFIED_BEHAVIOURAL" if placement_pass and behavioural_ok and compiles_clean
               else "VERIFIED_PLACEMENT" if placement_pass and compiles_clean
               else "VERIFIED_PLACEMENT_NO_REGRESSION" if placement_pass
               else "NOT_VERIFIED")

    out = out_dir or os.path.join(os.getcwd(), "mitos-out", target.replace("/", "__"))
    t = Transplant(target=target, target_path=target_path, upstream=upstream, sha=sha,
                   marker=marker, message=msg, date=date, applied=applied, skipped=skipped,
                   records=records, placement_ok=placement_ok, compiles_before=ok_before,
                   compiles_after=ok_after, delta=delta, behaviour=beh, patched_text=patched,
                   original_text=original, verdict=verdict, out_dir=out)

    if write and placement_pass:
        write_artifacts(t)
    if write_back and placement_pass:
        with open(write_back, "w") as f:
            f.write(patched)
    return t


def report_markdown(target: str, copies, results, executed: bool) -> str:
    """What a requester gets back. States what was checked, what was found, and — where
    Mitos refused — why, since a refusal a reader cannot act on is worse than no answer."""
    stale = [c for c in copies if not c.patched]
    ok = [t for t in results if t.verdict.startswith("VERIFIED")]
    out = [f"Mitos audited **{target}**.", ""]

    if not copies:
        out += ["No implementation copies of catalog libraries were found.", "",
                "_This checks a small set of commonly copied C libraries whose fix markers "
                "have been verified against the upstream commit. Absence here is not "
                "evidence of absence._"]
        return "\n".join(out)

    out += ["| library | path | state |", "| --- | --- | --- |"]
    for c in copies:
        out.append(f"| `{c.lib.name}` | `{c.path}` | "
                   f"{'carries the fix' if c.patched else '**missing the fix**'} |")
    out.append("")

    if not stale:
        out.append("Every copy already carries its upstream fix. Nothing to backport.")
        return "\n".join(out)

    out += [f"### {len(ok)} of {len(stale)} patched and verified", ""]
    for t in results:
        head = f"**`{t.target_path}`** — `{t.verdict}`"
        if t.verdict.startswith("VERIFIED"):
            out += [f"- {head}: {len(t.applied)} site(s) transplanted, "
                    f"{len(t.records)} inserted line(s) audited, compiles "
                    f"{'yes' if t.compiles_before else 'no'} → "
                    f"{'yes' if t.compiles_after else 'no'}."]
        else:
            out += [f"- {head}: {t.why_not}."]
        if t.skipped:
            out.append(f"  - {len(t.skipped)} hunk(s) skipped rather than guessed: "
                       + "; ".join(sorted({s.reason for s in t.skipped}))[:300])
    out.append("")
    if not executed:
        out += ["_The behavioural probe was not run: it builds and executes a binary from "
                "the scanned source, which is appropriate in your own CI and not on our "
                "machine. Placement and compilation were verified._", ""]
    out += ["A verified placement means every transplanted line is live code in the expected "
            "function and the file still compiles. It is not a claim that your shipped "
            "application was exploitable, nor that your test suite was run."]
    return "\n".join(out)


def write_artifacts(t: Transplant):
    """The patched file, the diff a reviewer reads, and the evidence behind the verdict."""
    os.makedirs(t.out_dir, exist_ok=True)
    with open(os.path.join(t.out_dir, os.path.basename(t.target_path) + ".patched"), "w") as f:
        f.write(t.patched_text)
    with open(os.path.join(t.out_dir, "fix.diff"), "w") as f:
        f.write(unified(t.original_text, t.patched_text, t.target_path))
    beh = t.behaviour
    with open(os.path.join(t.out_dir, "evidence.json"), "w") as f:
        json.dump({
            "target": t.target, "target_path": t.target_path,
            "upstream_fix": {"repo": t.upstream, "sha": t.sha, "date": t.date,
                             "message": t.message},
            "sites_applied": len(t.applied), "sites_skipped": [s.reason for s in t.skipped],
            "verification": {
                "original_compiles": t.compiles_before, "patched_compiles": t.compiles_after,
                "inserted_lines": len(t.records), "all_executable": t.placement_ok,
                "placement_audit": t.records,
                "behavioural": {"ran": beh.ran, "probe": beh.probe, "before": beh.before,
                                "after": beh.after, "guard_fires_only_after": beh.fires_only_after,
                                "detail": beh.detail},
                "compiler": "clang -O0"},
            "verdict": t.verdict,
        }, f, indent=2)
