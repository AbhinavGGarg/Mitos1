"""Mine + mechanically validate CANDIDATE fix markers across copied C libraries.

Rows are CANDIDATES for human review, never "fixes". For each fix-keyworded commit in a
file's COMPLETE history we extract the distinctive symbol it introduced and check it:

  - absent_from_parent : absent from EVERY parent file (merge commits have >1 parent)
  - introduced_in_code : appears as real code in the child (not comment/string)
  - not_hex_or_numeric : not a hex/number fragment (incl. xff000000-style)
  - preprocess         : the ACTUAL clang preprocessor with declared defines →
                         {status ok/error/timeout, returncode, active_in_declared_config}
  - conditional_context: which kind of #if gates the marker — include_guard /
                         implementation_gate / feature_gate / compiler_gate (may be several)

Mechanical validity = preprocess ok AND the probe is active. Enclosing function comes from
tree-sitter on the child. Provenance (parents, patch-id, HEAD, paths, lines) is recorded so
the corpus can be frozen and reproduced; `model_label` is kept out of the review packets;
`ground_truth`/`logical_family_id` are null for humans.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile

from . import applyfix

# marker-event-level rubric (item 5) — a human fills these; kept null in the corpus/packet
RUBRIC = {"is_actual_fix": None, "fix_class": None, "marker_necessary": None, "marker_sufficient": None,
          "logical_family_id": None, "evidence": None, "confidence": None, "reviewer": None}

FIX_KEYWORDS = re.compile(
    r"\b(fix|overflow|overrun|underflow|bounds|out[- ]of[- ]?(bounds|range)|oob|corrupt|invalid|reject|"
    r"guard|security|cve|clamp|sanitiz|leak|truncat|integer|unchecked|validate|missing|"
    r"too[- ](large|big|small|long)|null|crash|heap|read past|write past)\b", re.I)

_SECURITY = re.compile(
    r"overflow|overrun|underflow|over[- ]?read|\boob\b|out[- ]of[- ]?(bounds|range)|bounds|\bcve\b|"
    r"leak|corrupt|crash|heap|read past|write past|sanitiz|use[- ]after|double[- ]free|integer|unchecked", re.I)
_COSMETIC = re.compile(
    r"typo|warning|whitespace|rename|comment|\bdoc|format|style|unused|build|compil|msvc|gcc|"
    r"clang|constexpr|\bcast\b|sign[- ]compare|\bci\b|indent|spelling", re.I)
_CORRECTNESS = re.compile(r"\bfix\b|incorrect|wrong|\bbug\b|invalid|missing|reject|guard|clamp|validate|truncat", re.I)

_HEXISH = re.compile(r"(0x|x|u|U)?[0-9A-Fa-f]{4,}")
_NUMISH = re.compile(r"[A-Za-z]?\d+")
_COMPILER_HINT = re.compile(r"_MSC_VER|_WIN32|_WIN64|__GNUC__|__clang__|__cplusplus|SSE|NEON|AVX|__has_|__STDC")
_PROBE = "MITOS_LIVE_PROBE_9Q7X"


# ---------------------------------------------------------------- pure helpers
def is_hexish(marker: str) -> bool:
    if _NUMISH.fullmatch(marker):
        return True
    if _HEXISH.fullmatch(marker):
        body = re.sub(r"^(0x|x|u|U)", "", marker)
        return bool(re.fullmatch(r"[0-9A-Fa-f]+", body)) and len(body) >= 4
    return False


def classify_fix(msg: str) -> str:
    if _COSMETIC.search(msg) and not _SECURITY.search(msg):
        return "cosmetic"
    if _SECURITY.search(msg):
        return "security"
    if _CORRECTNESS.search(msg):
        return "correctness"
    return "other"


def marker_identifies_fix(marker: str, fix_class: str) -> bool:
    distinctive = len(marker) >= 10 or marker.count("_") >= 2 or (marker.isupper() and len(marker) >= 6)
    return bool(distinctive and fix_class in ("security", "correctness"))


def marker_occurrences(child_text: str, marker: str):
    """Every real-code line index (0-based) where the marker appears as a token."""
    flags, lines = applyfix.code_line_flags(child_text)
    pat = re.compile(r"\b" + re.escape(marker) + r"\b")
    return [i for i, l in enumerate(lines)
            if marker in l and not flags[i]["in_comment"] and pat.search(applyfix._code_of_line(l))]


def locate_marker(child_text: str, marker: str):
    occ = marker_occurrences(child_text, marker)
    if not occ:
        return None, None, False
    i = occ[0]
    spans = applyfix.enclosing_functions(child_text)
    fn = next((name for name, s, e in spans if s <= i <= e), None)
    return i + 1, fn, True


# ---- preprocessor conditional context ---------------------------------------
def canonical_include_guard(text: str):
    """The single outermost file include guard: the first *non-comment* `#ifndef X`
    whose next non-blank code line is `#define X`. Directives inside doc comments
    (stb ships #if/#define examples in its banner) are ignored. Nested
    `#ifndef Y / #define Y` config defaults are NOT the guard. Returns X or None."""
    flags, lines = applyfix.code_line_flags(text)
    depth = 0
    for i, line in enumerate(lines):
        if flags[i]["in_comment"]:
            continue
        d = applyfix._pp_directive(line)
        if not d:
            continue
        tok = d[0]
        if tok == "ifndef" and depth == 0 and d[1]:         # only a depth-0 #ifndef X / #define X is the guard
            g = d[1].split()[0]
            j = i + 1
            while j < len(lines) and (flags[j]["in_comment"] or not lines[j].strip()):
                j += 1
            if j < len(lines) and re.match(rf"#\s*define\s+{re.escape(g)}\b", lines[j].strip()):
                return g
            depth += 1                                       # not a guard — an ordinary conditional
        elif tok in ("if", "ifdef", "ifndef"):
            depth += 1                                        # skip balanced blocks (e.g. a leading #if 0)
        elif tok == "endif":
            depth = max(0, depth - 1)
    return None


def enclosing_conditions(text: str, line0: int):
    """Stack of enclosing preprocessor conditions, retaining the actual expression and
    which branch (if/elif/else) the line sits in. STATIC parse of the directive tree;
    directives inside comments (doc examples) are ignored."""
    flags, lines = applyfix.code_line_flags(text)
    stack = []
    for i, line in enumerate(lines):
        if i >= line0:
            break
        if flags[i]["in_comment"]:
            continue
        d = applyfix._pp_directive(line)
        if not d:
            continue
        tok, rest = d
        if tok in ("if", "ifdef", "ifndef"):
            stack.append({"directive": tok, "expr": rest.strip(), "branch": "if"})
        elif tok == "elif" and stack:
            stack[-1]["branch"] = "elif"; stack[-1]["expr"] = rest.strip()
        elif tok == "else" and stack:
            stack[-1]["branch"] = "else"
        elif tok == "endif" and stack:
            stack.pop()
    return stack


def classify_condition(cond: dict, guard) -> str:
    expr = cond["expr"]
    m = re.search(r"defined\s*\(?\s*!?\s*(\w+)", expr)
    macro = m.group(1) if m else (re.sub(r"[()!]", "", expr).split()[0] if expr.strip() else "")
    if macro and macro == guard:
        return "include_guard"
    if re.search(r"IMPLEMENTATION", expr, re.I):
        return "implementation_gate"
    if macro.startswith("__") or re.match(r"_[A-Z]", macro) or _COMPILER_HINT.search(expr):
        return "compiler_gate"
    return "feature_gate"


def conditional_context(text: str, line0: int):
    """STATIC classification of the enclosing #if directives (NOT a clang result)."""
    guard = canonical_include_guard(text)
    conds = enclosing_conditions(text, line0)
    return {"categories": sorted({classify_condition(c, guard) for c in conds}),
            "conditions": conds, "classification": "static"}


def gate_bucket(cats):
    if "implementation_gate" in cats or "feature_gate" in cats:
        return "implementation_or_feature_gated"
    if "compiler_gate" in cats and "include_guard" in cats:
        return "include_guard_plus_compiler"
    if cats == ["include_guard"]:
        return "include_guard_only"
    if cats == ["compiler_gate"]:
        return "compiler_only"
    if not cats:
        return "unconditional"
    return "other"


# ---- clang preprocessor liveness --------------------------------------------
def clang_version_target():
    try:
        r = subprocess.run(["clang", "--version"], capture_output=True, text=True, timeout=30)
    except Exception:
        return "", ""
    ver = (r.stdout or "").splitlines()[0].strip() if r.stdout else ""
    m = re.search(r"Target:\s*(\S+)", r.stdout or "")
    return ver, (m.group(1) if m else "")


def preprocess(child_text: str, marker_line0: int, defined, include_name: str):
    lines = child_text.split("\n")
    injected = lines[:marker_line0 + 1] + [f"int {_PROBE};"] + lines[marker_line0 + 1:]
    tmp = tempfile.mkdtemp(prefix="mitos_pp_")
    with open(os.path.join(tmp, include_name), "w") as fh:
        fh.write("\n".join(injected))
    wrap = os.path.join(tmp, "wrap.c")
    with open(wrap, "w") as fh:
        fh.write(f'#include "{include_name}"\n')
    args = ["clang", "-E", "-P", "-w", "-ferror-limit=0", *applyfix.clang_define_args(defined), "-I", tmp, wrap]
    base = {"defines": sorted(defined)}
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return {**base, "status": "timeout", "returncode": None, "active_in_declared_config": False}
    except OSError as e:
        return {**base, "status": "error", "returncode": None, "active_in_declared_config": False,
                "error": str(e)[:120]}
    active = re.search(r"\b" + _PROBE + r"\b", r.stdout or "") is not None
    # ok ONLY on a clean clang return. A visible probe with a nonzero return code is still error.
    return {**base, "status": "ok" if r.returncode == 0 else "error",
            "returncode": r.returncode, "active_in_declared_config": active}


# ---------------------------------------------------------------- git I/O
def _run(args, timeout=180):
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ""
    return r.stdout if r.returncode == 0 else ""


def clone(url, dest):
    subprocess.run(["git", "clone", "--quiet", url, dest], capture_output=True, text=True, timeout=600)


def checkout(repo, ref):
    subprocess.run(["git", "-C", repo, "checkout", "--quiet", ref], capture_output=True, text=True, timeout=120)


def repo_head(repo):
    return _run(["git", "-C", repo, "rev-parse", "HEAD"]).strip()


def parents(repo, sha):
    out = _run(["git", "-C", repo, "show", "--no-patch", "--format=%P", sha]).strip()
    return out.split() if out else []


def file_commits(repo, path):
    rows = []
    for line in _run(["git", "-C", repo, "log", "--format=%H|%ci|%s", "--", path]).splitlines():
        p = line.split("|", 2)
        if len(p) == 3:
            rows.append({"sha": p[0], "date": p[1][:10], "msg": p[2]})
    return rows


def full_message(repo, sha):
    return _run(["git", "-C", repo, "show", "--no-patch", "--format=%B", sha]).rstrip()


def file_at(repo, ref, path):
    return _run(["git", "-C", repo, "show", f"{ref}:{path}"]) if ref else ""


def commit_diff(repo, sha, path):
    return _run(["git", "-C", repo, "show", "--format=", "--unified=3", sha, "--", path])


def commit_diff_all(repo, sha):
    return _run(["git", "-C", repo, "show", "--format=", "--unified=3", sha])


def changed_files(repo, sha):
    files = []
    for line in _run(["git", "-C", repo, "show", "--format=", "--name-status", sha]).splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            files.append({"status": parts[0], "path": parts[-1]})
    return files


def hunk_coords(diff, marker):
    """(-a,b +c,d) of the hunk whose added lines introduce the marker."""
    pat, cur = re.compile(r"\b" + re.escape(marker) + r"\b"), None
    for raw in diff.splitlines():
        m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", raw)
        if m:
            cur = (int(m.group(1)), int(m.group(2) or 1), int(m.group(3)), int(m.group(4) or 1))
        elif raw.startswith("+") and not raw.startswith("+++") and cur and pat.search(raw[1:]):
            return cur
    return None


def patch_id(repo, sha):
    show = subprocess.run(["git", "-C", repo, "show", sha], capture_output=True, text=True, timeout=90)
    pid = subprocess.run(["git", "-C", repo, "patch-id", "--stable"],
                         input=show.stdout, capture_output=True, text=True, timeout=90)
    return pid.stdout.split()[0] if pid.stdout.strip() else ""


def absent_from_all_parents(repo, parent_list, path, marker):
    for p in parent_list:
        if marker in file_at(repo, p, path):
            return False
    return True


def _issue_and_test_links(msg, diff):
    issues = sorted(set(re.findall(r"#(\d+)", msg)))
    tests = sorted({l.split()[-1] for l in diff.splitlines()
                    if l.startswith(("+++", "---")) and re.search(r"test", l, re.I)})
    return {"issues": issues, "test_paths": tests}


# ---------------------------------------------------------------- mining (complete history; cap AFTER validation)
def mine_file(repo, path, defines, cap_valid):
    candidates, seen, valid_count = [], set(), 0
    for c in file_commits(repo, path):
        if not FIX_KEYWORDS.search(c["msg"]):
            continue
        diff = commit_diff(repo, c["sha"], path)
        marker = applyfix.primary_marker(diff)
        if not marker or marker in seen:
            continue
        seen.add(marker)
        par = parents(repo, c["sha"])
        child = file_at(repo, c["sha"], path)
        in_parents = [p for p in par if marker in file_at(repo, p, path)]   # merge-aware absence
        absent = len(in_parents) == 0
        child_line, enc_fn, in_code = locate_marker(child, marker)
        not_hex = not is_hexish(marker)
        clines = child.split("\n")
        rec = {
            "marker": marker, "child_path": path, "parent_path": path, "sha": c["sha"],
            "parents": par, "is_merge": len(par) > 1, "marker_in_parents": in_parents,
            "child_line": child_line, "parent_line": None,
            "marker_source_line": (clines[child_line - 1].strip() if child_line else ""),
            "marker_occurrences": [i + 1 for i in marker_occurrences(child, marker)],
            "enclosing_function": enc_fn, "fix_date": c["date"], "message_summary": c["msg"][:100],
            "patch_id": "", "preprocess": None, "conditional_context": None,
            "validity": {"absent_from_parent": absent, "introduced_in_code": in_code,
                         "not_hex_or_numeric": not_hex, "preprocess_status": None,
                         "active_in_declared_config": None, "mechanically_valid": False},
            "model_label": None, "logical_family_id": None, "ground_truth": None,
        }
        if absent and in_code and not_hex:
            rec["patch_id"] = patch_id(repo, c["sha"])
            pp = preprocess(child, child_line - 1, frozenset(defines), os.path.basename(path))
            rec["preprocess"] = pp
            rec["conditional_context"] = conditional_context(child, child_line - 1)
            rec["validity"]["preprocess_status"] = pp["status"]
            rec["validity"]["active_in_declared_config"] = pp["active_in_declared_config"]
            rec["validity"]["mechanically_valid"] = pp["status"] == "ok" and pp["active_in_declared_config"]
            fc = classify_fix(full_message(repo, c["sha"]))
            rec["model_label"] = {"fix_class": fc, "marker_identifies_fix": marker_identifies_fix(marker, fc)}
            if rec["validity"]["mechanically_valid"]:
                valid_count += 1
        candidates.append(rec)
        if cap_valid and valid_count >= cap_valid:
            break
    return candidates


def _selected_hunk(diff, marker):
    pat = re.compile(r"\b" + re.escape(marker) + r"\b")
    for h in re.split(r"(?m)^(?=@@ )", diff):
        if h.startswith("@@") and any(l.startswith("+") and not l.startswith("+++") and pat.search(l)
                                      for l in h.splitlines()):
            return h.strip()
    return ""


def build_packet(repo_dir, repo_name, path, rec):
    """A BLINDED human-review packet: full evidence, rubric template, NO model_label."""
    sha = rec["sha"]
    target_diff = commit_diff(repo_dir, sha, path)
    full_diff = commit_diff_all(repo_dir, sha)
    files = changed_files(repo_dir, sha)
    test_diffs = {f["path"]: commit_diff(repo_dir, sha, f["path"])
                  for f in files if re.search(r"(^|/)(test|tests)(/|_|\.)", f["path"], re.I)}
    child = file_at(repo_dir, sha, path).split("\n")
    parent0 = file_at(repo_dir, rec["parents"][0], path).split("\n") if rec["parents"] else []
    spans = applyfix.enclosing_functions("\n".join(child))

    def enc(line1):
        i = line1 - 1
        return next((n for n, s, e in spans if s <= i <= e), None)   # None == file scope (not "missing")

    coords = hunk_coords(target_diff, rec["marker"])
    if coords:
        a, b, c, dd = coords
        before_ctx = "\n".join(parent0[max(0, a - 1):a - 1 + max(b, 1)]) if parent0 else "(no parent revision)"
        after_ctx = "\n".join(child[max(0, c - 1):c - 1 + max(dd, 1)])
    else:
        cl = rec["child_line"] or 1
        before_ctx, after_ctx = "(hunk coordinates not located)", "\n".join(child[max(0, cl - 6):cl + 5])
    msg = full_message(repo_dir, sha)
    return {
        "packet_id": hashlib.sha256((rec["marker"] + sha).encode()).hexdigest()[:16],
        "repo": repo_name, "file": path, "sha": sha, "parents": rec["parents"],
        "is_merge": rec["is_merge"], "marker_in_parents": rec["marker_in_parents"],
        "marker": rec["marker"], "enclosing_function": rec["enclosing_function"],
        "marker_scope": "function" if rec["enclosing_function"] else "file",
        "full_commit_message": msg,
        "complete_commit_diff": full_diff, "target_file_diff": target_diff,
        "changed_files": files, "changed_test_file_diffs": test_diffs,
        "selected_hunk": _selected_hunk(target_diff, rec["marker"]), "hunk_coords": coords,
        "before_context": before_ctx, "after_context": after_ctx,
        "marker_occurrences": [{"line": i, "text": (child[i - 1].strip() if 0 < i <= len(child) else ""),
                                "context": "\n".join(child[max(0, i - 4):i + 3]), "enclosing_function": enc(i)}
                               for i in rec["marker_occurrences"]],
        "linked": _issue_and_test_links(msg, full_diff),
        "label_template": dict(RUBRIC),
    }


def mine(libs, cap_valid=None, verbose=lambda *_: None):
    tmp = tempfile.mkdtemp(prefix="mitos_mine_")
    clones, corpora, packets = {}, [], []
    for lib in libs:
        url = lib["clone_url"]
        if url not in clones:
            dest = os.path.join(tmp, re.sub(r"\W+", "_", url))
            verbose(f"cloning {url} …")
            clone(url, dest); clones[url] = dest
        dest = clones[url]
        if not os.path.isdir(os.path.join(dest, ".git")):
            verbose(f"  {lib['name']}: clone failed — skipped"); continue
        if lib.get("pinned_head"):                       # freeze: mine the pinned upstream commit
            checkout(dest, lib["pinned_head"])
        cands = mine_file(dest, lib["file"], lib.get("build_defines", []), cap_valid)
        valid = [c for c in cands if c["validity"]["mechanically_valid"]]
        verbose(f"  {lib['name']} ({lib['file']}): {len(cands)} candidates, {len(valid)} mechanically valid")
        corpora.append({"library": lib["name"], "repo": lib.get("repo", ""), "file": lib["file"],
                        "upstream_head_sha": repo_head(dest), "discovery_query": lib["discovery_query"],
                        "build_defines": lib.get("build_defines", []), "candidates": cands})
        packets.extend(build_packet(dest, lib.get("repo", ""), lib["file"], c) for c in valid)
    return corpora, packets


def content_hash(summary, corpora) -> str:
    import json
    return hashlib.sha256(json.dumps({"summary": summary, "libraries": corpora}, sort_keys=True).encode()).hexdigest()


def packets_hash(packets) -> str:
    import json
    return hashlib.sha256(json.dumps(packets, sort_keys=True).encode()).hexdigest()


def summarize(corpora):
    cands = [c for lib in corpora for c in lib["candidates"]]
    valid = [c for c in cands if c["validity"]["mechanically_valid"]]
    from collections import Counter
    buckets = Counter(gate_bucket((c["conditional_context"] or {}).get("categories", [])) for c in valid)
    sec_corr = [c for c in valid if c["model_label"] and c["model_label"]["fix_class"] in ("security", "correctness")]
    identifying = [c for c in valid if c["model_label"] and c["model_label"]["marker_identifies_fix"]]
    repos = {lib["repo"] for lib in corpora if any(x["validity"]["mechanically_valid"] for x in lib["candidates"])}
    files = {lib["file"] for lib in corpora if any(x["validity"]["mechanically_valid"] for x in lib["candidates"])}
    return {"candidates_examined": len(cands),
            "mechanically_valid_marker_candidates": len(valid),
            "all_survive_preprocessing": sum(1 for c in valid if c["preprocess"]["active_in_declared_config"]),
            "gate_breakdown": dict(buckets),
            "model_security_or_correctness": len(sec_corr), "model_fix_identifying_markers": len(identifying),
            "independent_repos_with_valid": len(repos), "independent_files_with_valid": len(files),
            "unique_patch_ids": len({c["patch_id"] for c in valid if c["patch_id"]})}
