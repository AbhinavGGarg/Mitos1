"""Fix-fingerprint discrimination: given a real upstream fix commit, tell which
copies in the wild already have the fix (IMMUNE) from those that don't (STALE).

This is the precision leg. Instead of flagging any risky-looking code, we derive
a fingerprint from the *actual patch* — the distinctive symbol(s) the fix
introduced and the enclosing vulnerable function — and check each real copy for
their presence. A STALE verdict is made by reading the copy's own bytes, so it is
correct by direct observation, not a guess.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .ghsearch import _gh_api, search_code, fetch_source, file_last_commit_iso

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
STRLIT = re.compile(r'"(?:[^"\\]|\\.)*"')
COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
HUNK = re.compile(r"@@.*@@\s*(.*)")
KEYWORDS = {"if", "return", "int", "for", "while", "else", "const", "static",
            "void", "char", "unsigned", "sizeof", "struct", "define", "ifndef", "endif"}


def _distinctive(t: str) -> bool:
    """A usable fingerprint token: a code identifier, not an English word.

    Keep ALL_CAPS macros, snake_case, names with digits, or camelCase. Drop
    plain lowercase words (which leak in from comments/prose and match everywhere).
    """
    return (t.isupper() or "_" in t or any(c.isdigit() for c in t)
            or (t != t.lower() and t != t.upper()))


@dataclass
class FixFingerprint:
    repo: str
    sha: str
    file: str
    fix_markers: list      # distinctive symbols the fix introduced (e.g. STBI_MAX_DIMENSIONS)
    context_marker: str    # enclosing vulnerable function present before & after
    fix_date: str
    message: str


def _commit(repo, sha):
    return json.loads(_gh_api([f"repos/{repo}/commits/{sha}"]))


def _toks(line: str):
    return IDENT.findall(STRLIT.sub('""', COMMENT.sub(" ", line)))


def fingerprint_from_commit(repo: str, sha: str, path: str | None = None) -> FixFingerprint:
    c = _commit(repo, sha)
    files = [f for f in c.get("files", []) if f["filename"].endswith((".c", ".h", ".cc", ".cpp"))]
    if path:
        files = [f for f in files if f["filename"] == path] or files
    if not files:
        raise ValueError("no C/C++ files changed in that commit")
    files.sort(key=lambda f: f.get("additions", 0), reverse=True)
    tgt = files[0]
    patch = tgt.get("patch", "")
    if not patch:
        raise ValueError("commit patch unavailable (file too large?) — pass --path")

    added, context, func_names = [], [], []
    for line in patch.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith("@@"):
            m = HUNK.search(line)
            if m:
                func_names += _toks(m.group(1))
            continue
        if line.startswith("+"):
            added += _toks(line[1:])
        else:
            context += _toks(line[1:] if line.startswith("-") else line)

    context_set = set(context)
    introduced = [t for t in dict.fromkeys(added)
                  if t not in context_set and t not in KEYWORDS and _distinctive(t)]
    introduced.sort(key=lambda t: (t.isupper(), "__" in t, len(t)), reverse=True)
    fix_markers = introduced[:4]

    ctx_cands = [t for t in func_names if "__" in t or len(t) >= 10]
    ctx_cands.sort(key=len, reverse=True)
    context_marker = ctx_cands[0] if ctx_cands else (fix_markers[0] if fix_markers else "")

    return FixFingerprint(repo=repo, sha=sha, file=tgt["filename"], fix_markers=fix_markers,
                          context_marker=context_marker,
                          fix_date=c["commit"]["committer"]["date"], message=c["commit"]["message"].split("\n")[0])


@dataclass
class CopyVerdict:
    repo: str
    path: str
    status: str            # STALE | IMMUNE | NO_MATCH | UNREADABLE
    last_commit: str | None
    predates_fix: bool | None


def discriminate(fp: FixFingerprint, max_results: int = 20, want_dates: bool = True,
                 verbose=lambda *_: None) -> list:
    query = f"{fp.context_marker} language:c"
    verbose(f"searching copies of {fp.context_marker}()")
    hits = search_code(query, max_results=max_results, verbose=verbose)
    out = []
    for h in hits:
        src = fetch_source(h)
        if src is None:
            out.append(CopyVerdict(h.repo, h.path, "UNREADABLE", None, None))
            continue
        text = src.decode("utf8", "replace")
        has_ctx = fp.context_marker in text
        primary = fp.fix_markers[0] if fp.fix_markers else None
        has_fix = bool(primary and primary in text)   # decide on the single distinctive introduced symbol
        status = "IMMUNE" if has_fix else ("STALE" if has_ctx else "NO_MATCH")
        date = file_last_commit_iso(h.repo, h.path) if want_dates and status != "NO_MATCH" else None
        predates = (date < fp.fix_date) if (date and status != "NO_MATCH") else None
        out.append(CopyVerdict(h.repo, h.path, status, date, predates))
    return out
