"""Close the loop: transplant a real upstream fix commit into a real stale copy.

Given a fix commit and a target copy, we take the fix's added lines and splice
them into the copy at the matching local context. Two things make this trustworthy
rather than a text search:

  1. Anchoring is code-aware. We never anchor on a blank or comment line, we
     require the anchor to match *exactly once* among the copy's real code lines,
     and the match must sit inside a function body. If we can't place a hunk
     safely we skip it (needs-review) instead of guessing.
  2. Verification audits placement. After patching we re-lex the file and confirm
     every inserted guard lands in executable code (inside a function, not in a
     comment or string). A guard that compiles but never runs is NOT a pass.

This is the fix for the false-verification bug where guards were dumped into the
opening comment and still reported "verified" because the file compiled.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
from collections import defaultdict
from dataclasses import dataclass

from .ghsearch import _gh_api
from . import astutils

IMPL_MARKER = "#ifdef STB_IMAGE_IMPLEMENTATION"

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_STR = re.compile(r'"(?:[^"\\]|\\.)*"')
_COM = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_KW = {"if", "return", "int", "for", "while", "else", "const", "static", "void",
       "char", "unsigned", "sizeof", "struct", "define", "ifndef", "endif"}


# common C types + reserved/standard macros: distinctive-looking but useless as fix markers
# (they appear in essentially every copy, so their presence/absence means nothing).
_STOP = {"size_t", "ssize_t", "ptrdiff_t", "wchar_t", "intptr", "uintptr",
         "uint", "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64",
         "uint8_t", "uint16_t", "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
         "uchar", "ushort", "char", "short", "int", "long", "unsigned", "signed", "float", "double",
         "void", "bool", "TRUE", "FALSE", "NULL", "EOF", "stbi_uc", "stbi__uint16", "stbi__uint32",
         # standard <limits.h>/<stdint.h>/<math.h> constants: distinctive-looking, useless as markers
         "SHRT_MAX", "SHRT_MIN", "USHRT_MAX", "INT_MAX", "INT_MIN", "UINT_MAX", "LONG_MAX", "LONG_MIN",
         "ULONG_MAX", "LLONG_MAX", "LLONG_MIN", "SIZE_MAX", "SSIZE_MAX", "CHAR_BIT", "CHAR_MAX", "CHAR_MIN",
         "UCHAR_MAX", "SCHAR_MAX", "SCHAR_MIN", "PTRDIFF_MAX", "RAND_MAX", "INFINITY", "NAN", "M_PI",
         "INT8_MAX", "INT16_MAX", "INT32_MAX", "INT64_MAX", "UINT8_MAX", "UINT16_MAX", "UINT32_MAX", "UINT64_MAX"}


def _reserved(t: str) -> bool:
    return t.startswith("__") or (len(t) >= 2 and t[0] == "_" and t[1].isupper())


def _distinct(t: str) -> bool:
    return ((t.isupper() or "_" in t or any(c.isdigit() for c in t)
             or (t != t.lower() and t != t.upper()))
            and t not in _STOP and not _reserved(t))


def primary_marker(patch: str) -> str:
    """The single most distinctive code symbol the fix introduces — used both to
    detect 'already fixed' and to audit that our inserted lines are executable.
    Excludes common types and reserved/standard macros (useless as markers)."""
    added, ctx = [], set()
    for raw in patch.splitlines():
        if raw.startswith(("@@", "+++", "---")) or not raw:
            continue
        toks = _IDENT.findall(_STR.sub('""', _COM.sub(" ", raw[1:])))
        if raw.startswith("+"):
            added += toks
        elif raw.startswith((" ", "-")):
            ctx.update(toks)
    intro = [t for t in dict.fromkeys(added) if t not in ctx and t not in _KW and _distinct(t)]
    intro.sort(key=lambda t: (t.isupper(), "__" in t, len(t)), reverse=True)
    return intro[0] if intro else ""


# ---------------------------------------------------------------- github I/O
def _file_at(repo: str, path: str, ref: str | None) -> str:
    args = ["-X", "GET", f"repos/{repo}/contents/{path}"]
    if ref:
        args += ["-f", f"ref={ref}"]
    args += ["-H", "Accept: application/vnd.github.raw"]
    return _gh_api(args)


def _message_date_parent(repo: str, sha: str):
    # light list endpoint (no per-file patches) → metadata + parent sha
    data = json.loads(_gh_api(["-X", "GET", f"repos/{repo}/commits", "-f", f"sha={sha}", "-f", "per_page=2"]))
    top = data[0]
    parent = data[1]["sha"] if len(data) > 1 else (top.get("parents") or [{}])[0].get("sha")
    return top["commit"]["message"].split("\n")[0], top["commit"]["committer"]["date"], parent


def _annotate_hunk_funcs(patch: str, before_text: str) -> str:
    """Append the enclosing function to each @@ header (like git does), so
    difflib-reconstructed patches carry the function name for wrong-function checks."""
    spans = enclosing_functions(before_text)

    def at(line0):
        best = None
        for name, s, e in spans:
            if s <= line0 <= e:
                best = name
        return best

    out = []
    for ln in patch.splitlines(keepends=True):
        stripped = ln.rstrip("\n")
        m = re.match(r"@@ -(\d+)(?:,\d+)? \+\d+", stripped)
        if m and stripped.endswith("@@"):
            fn = at(int(m.group(1)) - 1)
            if fn:
                ln = stripped + " " + fn + "\n"
        out.append(ln)
    return "".join(out)


def fetch_commit_patch(repo: str, sha: str, fix_path: str):
    """Reconstruct the fix's patch WITHOUT the heavy/flaky commit-patch endpoint:
    diff the file at the parent commit against the file at the fix commit. Both come
    from the reliable `contents` endpoint."""
    msg, date, parent = _message_date_parent(repo, sha)
    after = _file_at(repo, fix_path, sha)
    before = _file_at(repo, fix_path, parent) if parent else ""
    patch = "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                         fromfile=f"a/{fix_path}", tofile=f"b/{fix_path}", n=3))
    return _annotate_hunk_funcs(patch, before), msg, date


def fetch_file(repo: str, path: str) -> str:
    return _file_at(repo, path, None)


def _norm(s: str) -> str:
    return " ".join(s.split())


# ---------------------------------------------------------------- C lexing (comment/string/brace + #if 0 aware)
_PP = re.compile(r"(ifdef|ifndef|if|elif|else|endif)\b(.*)")


def _pp_directive(line: str):
    s = line.lstrip()
    if not s.startswith("#"):
        return None
    m = _PP.match(s[1:].lstrip())
    return (m.group(1), m.group(2).strip()) if m else None


def _classify_pp(expr: str) -> str:
    """Resolve an #if/#elif condition we can decide literally; else 'unknown'.
    Handles `0`, `(0)`, `1`, `false/true` (any spacing). Anything requiring a macro
    value (e.g. `#ifdef FOO`, `#if VER > 2`) is unknown → treated as UNRESOLVED, so a
    guard there is reported unverified rather than assumed to run."""
    e = re.sub(r"\s", "", expr).strip("()")
    if e in ("0", "false", "FALSE"):
        return "if0"
    if e in ("1", "true", "TRUE"):
        return "if1"
    return "unknown"


def code_line_flags(text: str, defined=frozenset()):
    """Per line: brace depth at line start, whether it holds real code, whether it
    starts inside a block comment, and its preprocessor state — "live", "dead"
    (`#if 0`, dead side of `#if 1/#else`), or "unresolved" (a conditional we can't
    evaluate). `defined` is the set of macros the verification build defines (e.g.
    STB_IMAGE_IMPLEMENTATION): `#ifdef`/`#ifndef` on those resolve to live/dead;
    anything else is UNRESOLVED, so a guard there is reported unverified rather than
    assumed to run. Braces/quotes in comments, strings, and dead branches are ignored,
    so 'depth >= 1 and live' reliably means 'inside a live function body'."""
    lines = text.split("\n")
    flags = []
    depth = 0
    in_block = False
    ppstack = []  # frames: [kind, in_else]; kind in {"if0", "if1", "unknown"}

    def _fstate(kind, in_else):
        if kind == "if0":
            return "live" if in_else else "dead"
        if kind == "if1":
            return "dead" if in_else else "live"
        return "unresolved"

    def pp_state():
        st = "live"
        for kind, in_else in ppstack:
            s = _fstate(kind, in_else)
            if s == "dead":
                return "dead"
            if s == "unresolved":
                st = "unresolved"
        return st

    for line in lines:
        pp = _pp_directive(line)
        if pp and pp[0] == "endif" and ppstack:
            ppstack.pop()                       # #endif sits outside the block it closes
        state = pp_state()
        start_depth, start_in_block, has_code = depth, in_block, False
        if state != "dead":                     # process live + unresolved (keep braces balanced); skip dead
            i, in_line_comment, in_str = 0, False, None
            while i < len(line):
                c = line[i]
                nxt = line[i + 1] if i + 1 < len(line) else ""
                if in_block:
                    if c == "*" and nxt == "/":
                        in_block = False; i += 2; continue
                    i += 1; continue
                if in_line_comment:
                    break
                if in_str is not None:
                    has_code = True
                    if c == "\\":
                        i += 2; continue
                    if c == in_str:
                        in_str = None
                    i += 1; continue
                if c == "/" and nxt == "/":
                    in_line_comment = True; break
                if c == "/" and nxt == "*":
                    in_block = True; i += 2; continue
                if c in ('"', "'"):
                    in_str = c; has_code = True; i += 1; continue
                if not c.isspace():
                    has_code = True
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                i += 1
        flags.append({"depth": start_depth, "has_code": has_code,
                      "in_comment": start_in_block, "pp": state, "pp_disabled": state == "dead"})
        if pp:                                   # apply open/toggle for subsequent lines
            tok, rest = pp
            if tok == "if":
                ppstack.append([_classify_pp(rest), False])
            elif tok == "ifdef":
                # closed-world vs the build's declared macros: defined → live, else undefined → dead
                name = rest.split()[0] if rest else ""
                ppstack.append(["if1" if name in defined else "if0", False])
            elif tok == "ifndef":
                name = rest.split()[0] if rest else ""
                ppstack.append(["if0" if name in defined else "if1", False])
            elif tok == "elif" and ppstack:
                k = _classify_pp(rest)
                ppstack[-1] = [k if k == "if0" else "unknown", False]   # only `#elif 0` is provably dead
            elif tok == "else" and ppstack:
                ppstack[-1][1] = True
    return flags, lines


# ---------------------------------------------------------------- patch parsing
_ATFUNC = re.compile(r"@@.*?@@\s*(.*)")
_FUNCNAME = re.compile(r"([A-Za-z_]\w*)\s*\(")


def hunk_header_func(at_line: str):
    """The enclosing function git names on an `@@ … @@ <sig>` header, e.g.
    `static int stbi__process_frame_header(...)` → 'stbi__process_frame_header'."""
    m = _ATFUNC.match(at_line)
    if not m:
        return None
    fm = _FUNCNAME.search(m.group(1))
    return fm.group(1) if fm else None


def parse_hunks(patch: str):
    """Each hunk: {context, added, removed_since, func}. `func` is the enclosing
    function named on the @@ header (used to reject wrong-function insertions)."""
    hunks, ctx, added, removed_since, cur_func = [], [], [], False, None

    def flush():
        nonlocal added
        if added:
            hunks.append({"context": list(ctx), "added": list(added),
                          "removed_since": removed_since, "func": cur_func})
            added = []

    for raw in patch.splitlines():
        if raw.startswith("@@"):
            flush(); ctx, removed_since = [], False
            cur_func = hunk_header_func(raw)
            continue
        if raw.startswith(("+++", "---")):
            continue
        if raw.startswith("+"):
            added.append(raw[1:]); continue
        flush()
        if raw.startswith("-"):
            removed_since = True
        else:
            ctx.append(raw[1:] if raw.startswith(" ") else raw)
            removed_since = False
    flush()
    return hunks


def _choose_anchor(ctx):
    """Last context line that is real code — never a blank or comment line."""
    for line in reversed(ctx):
        s = line.strip()
        if not s or s.startswith(("*", "//", "/*")):
            continue
        return line
    return None


# ---------------------------------------------------------------- apply
@dataclass
class Site:
    added: list
    status: str          # "applied" | "skipped"
    anchor: str = ""
    reason: str = ""

    def first_code(self):
        return next((a.strip() for a in self.added if a.strip() and not a.lstrip().startswith("//")), "")


def apply_fix(target_text: str, patch: str, defined=frozenset()):
    flags, lines = code_line_flags(target_text, defined)
    code_index = defaultdict(list)
    for i, l in enumerate(lines):
        if flags[i]["has_code"] and not flags[i]["in_comment"]:
            code_index[_norm(l)].append(i)

    impl = code_index.get(_norm(IMPL_MARKER), [])
    impl_idx = impl[0] if impl else None

    sites, insertions = [], []
    for h in parse_hunks(patch):
        added = h["added"]
        code = [a for a in added if a.strip() and not a.lstrip().startswith("//")]
        if not code:
            continue
        is_define = any(a.lstrip().startswith(("#define ", "#ifndef ")) for a in added)

        if _norm(code[0]) in code_index:
            sites.append(Site(added, "skipped", reason="already present")); continue

        if is_define:
            if impl_idx is None:
                sites.append(Site(added, "skipped", reason="no file-scope anchor for macro")); continue
            insertions.append((impl_idx, added, "define", None))
            sites.append(Site(added, "applied", anchor=IMPL_MARKER)); continue

        if h["removed_since"]:
            sites.append(Site(added, "skipped", reason="modify hunk (delete+add) — needs review")); continue

        anchor = _choose_anchor(h["context"])
        if not anchor:
            sites.append(Site(added, "skipped", reason="no code anchor (blank/comment context)")); continue

        cand = code_index.get(_norm(anchor), [])
        if len(cand) == 0:
            sites.append(Site(added, "skipped", anchor=anchor, reason="anchor not found in copy")); continue
        if len(cand) > 1:
            sites.append(Site(added, "skipped", anchor=anchor, reason=f"ambiguous anchor ({len(cand)}x)")); continue
        idx = cand[0]
        if flags[idx]["depth"] < 1:
            sites.append(Site(added, "skipped", anchor=anchor, reason="anchor is not inside a function")); continue

        insertions.append((idx, added, "guard", h.get("func")))
        sites.append(Site(added, "applied", anchor=anchor))

    # insert ascending, tracking the exact final index of every inserted line
    inserted, offset = [], 0
    for idx, added, kind, efunc in sorted(insertions, key=lambda t: t[0]):
        pos = idx + 1 + offset
        lines[pos:pos] = added
        for j, a in enumerate(added):
            if not a.strip() or a.lstrip().startswith("//"):
                continue                     # cosmetic blank / comment line — inserted but not audited
            directive = a.lstrip().startswith("#")
            inserted.append({"line": pos + j, "text": a, "directive": directive,
                             "expected_func": None if (directive or kind == "define") else efunc})
        offset += len(added)
    return "\n".join(lines), sites, inserted


# ---------------------------------------------------------------- verification: real placement audit
def audit_insertions(patched_text: str, marker: str, defined=frozenset()):
    """Every inserted line mentioning `marker` must be executable: real code, not
    in a comment or an unresolved/dead preprocessor branch; guards must be inside a
    function (depth>=1), directives may be file scope. Returns (all_ok, [records])."""
    flags, lines = code_line_flags(patched_text, defined)
    records, all_ok = [], True
    for i, l in enumerate(lines):
        if marker not in l:
            continue
        s = l.strip()
        directive = s.startswith("#")
        pp = flags[i].get("pp", "live")
        bad_pp = pp != "live"                                  # dead (#if 0) or unresolved (#ifdef) → not verified
        if directive:
            ok = (not flags[i]["in_comment"]) and not bad_pp   # a macro at file scope is fine
        else:
            ok = flags[i]["has_code"] and not flags[i]["in_comment"] and not bad_pp and flags[i]["depth"] >= 1
        all_ok = all_ok and ok
        records.append({"line": i + 1, "text": s[:72], "ok": ok, "in_comment": flags[i]["in_comment"],
                        "pp": pp, "pp_disabled": pp == "dead", "depth": flags[i]["depth"], "directive": directive})
    return all_ok, records


def enclosing_functions(text: str):
    """(name, start_line, end_line) for each function, from tree-sitter — 0-based line
    numbers aligned with text.split(chr(10)). Used to check *which* function a line is in."""
    b = text.encode() if isinstance(text, str) else text
    spans = []
    for f in astutils.extract_functions(b):
        spans.append((f.name, b.count(b"\n", 0, f.node.start_byte), b.count(b"\n", 0, f.node.end_byte)))
    return spans


def _code_of_line(line: str) -> str:
    """The line with comment and string *content* removed (structure kept), so a token
    can be tested for being real code. Assumes the line does not start inside a block
    comment (callers skip those)."""
    out, i, in_str, in_block = [], 0, None, False
    while i < len(line):
        c = line[i]
        nxt = line[i + 1] if i + 1 < len(line) else ""
        if in_block:
            if c == "*" and nxt == "/":
                in_block = False; i += 2; continue
            i += 1; continue
        if in_str is not None:
            if c == "\\":
                i += 2; continue
            if c == in_str:
                in_str = None
            i += 1; continue
        if c == "/" and nxt == "/":
            break
        if c == "/" and nxt == "*":
            in_block = True; i += 2; continue
        if c in ('"', "'"):
            in_str = c; i += 1; continue
        out.append(c); i += 1
    return "".join(out)


def marker_in_code(text: str, marker: str, defined=frozenset()) -> bool:
    """True iff `marker` appears as a real code token somewhere in `text` — not only in
    comments, strings, or a dead (#if 0) preprocessor branch. Used to validate that a
    mined fix marker was introduced in *executable* code."""
    flags, lines = code_line_flags(text, defined)
    pat = re.compile(r"\b" + re.escape(marker) + r"\b")
    for i, line in enumerate(lines):
        if marker not in line or flags[i]["pp"] == "dead" or flags[i]["in_comment"]:
            continue
        if pat.search(_code_of_line(line)):
            return True
    return False


def audit_placement(patched_text: str, inserted: list, defined=frozenset()):
    """The real verifier: audit the EXACT lines each hunk inserted. A line passes only
    if it is live code (not comment, not #if 0 dead, not an unresolved #ifdef branch —
    resolved against `defined`, the build's macros) and — for a statement guard —
    inside a function that MATCHES the upstream hunk's enclosing function. Wrong-function
    or unknown-function insertions fail. Directives (macros) are allowed at file scope."""
    flags, lines = code_line_flags(patched_text, defined)
    spans = enclosing_functions(patched_text)

    def enclosing(idx):
        best = None
        for name, s, e in spans:
            if s <= idx <= e:
                best = name
        return best

    records, all_ok = [], True
    for ins in inserted:
        idx = ins["line"]
        f = flags[idx] if 0 <= idx < len(flags) else {"pp": "live", "in_comment": False, "depth": 0}
        pp, in_comment, depth = f.get("pp", "live"), f.get("in_comment", False), f.get("depth", 0)
        directive, expected = ins["directive"], ins.get("expected_func")
        actual = enclosing(idx)
        if in_comment:
            reason = "inside a comment"
        elif pp == "dead":
            reason = "in #if 0 dead code"
        elif pp == "unresolved":
            reason = "in unresolved #if/#ifdef (unverified)"
        elif directive:
            reason = None                                   # file-scope macro, live, not comment
        elif depth < 1:
            reason = "not inside a function"
        elif not expected:
            reason = "expected function unknown (unverified)"
        elif actual != expected:
            reason = f"wrong function: in {actual!r}, expected {expected!r}"
        else:
            reason = None
        ok = reason is None
        all_ok = all_ok and ok
        records.append({"line": idx + 1, "text": (lines[idx].strip() if 0 <= idx < len(lines) else "")[:72],
                        "ok": ok, "reason": reason, "actual_func": actual, "expected_func": expected,
                        "pp": pp, "depth": depth, "directive": directive})
    return all_ok, records


def clang_define_args(defined) -> list:
    """The -D flags for a build. The SAME `defined` set is passed here (to the real
    compiler) and to code_line_flags/audit (the static view), so the two can't diverge."""
    return [f"-D{m}" for m in sorted(defined)]


def compile_header(header_text: str, workdir: str, tag: str, defined=frozenset()):
    hp = os.path.join(workdir, f"{tag}.h")
    cp = os.path.join(workdir, f"{tag}.c")
    bp = os.path.join(workdir, f"{tag}.bin")
    with open(hp, "w") as fh:
        fh.write(header_text)
    with open(cp, "w") as fh:
        fh.write(f'#include "{tag}.h"\nint main(void){{return 0;}}\n')
    args = ["clang", "-w", "-O0", *clang_define_args(defined), cp, "-o", bp]
    r = subprocess.run(args, capture_output=True, text=True, timeout=180)
    return r.returncode == 0, (r.stderr or "").strip()


def unified(before: str, after: str, path: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}", n=2))
