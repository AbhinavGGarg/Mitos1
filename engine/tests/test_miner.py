"""Regression tests for the review-readiness corrections: strict preprocess status
(ok only on clang return 0; #error/missing-include/malformed → error), canonical
include-guard + branch-aware conditional context, merge-parent absence, enriched
multi-file/context-accurate packets, blinded labeling bundles, reproducible hashes."""
import os
import subprocess
import tempfile

from mitos import miner
from mitos.miner import (is_hexish, classify_condition, conditional_context, canonical_include_guard,
                         gate_bucket, preprocess, parents, absent_from_all_parents, build_packet,
                         content_hash, packets_hash, summarize, RUBRIC)


def _git(d, *a):
    subprocess.run(["git", "-C", d, *a], capture_output=True, text=True)


def _head(d):
    return subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def _init(d):
    _git(d, "init", "-q", "-b", "main"); _git(d, "config", "user.email", "t@t"); _git(d, "config", "user.name", "t")


def _merge_repo():
    d = tempfile.mkdtemp(); _init(d)
    open(f"{d}/f.h", "w").write("int base;\n"); _git(d, "add", "f.h"); _git(d, "commit", "-qm", "c0")
    c0 = _head(d)
    _git(d, "checkout", "-q", "-b", "side", c0)
    open(f"{d}/f.h", "w").write("int base;\nint MERGEMARK;\n"); _git(d, "add", "f.h"); _git(d, "commit", "-qm", "side")
    side = _head(d)
    _git(d, "checkout", "-q", "main")
    open(f"{d}/g.h", "w").write("int other;\n"); _git(d, "add", "g.h"); _git(d, "commit", "-qm", "main g.h")
    _git(d, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    return d, _head(d), side


def _multifile_repo():
    d = tempfile.mkdtemp(); _init(d)
    os.makedirs(f"{d}/tests")
    open(f"{d}/lib.h", "w").write("int base;\n"); open(f"{d}/tests/t_lib.c", "w").write("void old(void){}\n")
    _git(d, "add", "-A"); _git(d, "commit", "-qm", "c0")
    c0 = _head(d)
    open(f"{d}/lib.h", "w").write("int base;\nstatic int NEWSYM(int x){ return x; }\n")
    open(f"{d}/tests/t_lib.c", "w").write("void old(void){}\nvoid test_newsym(void){ NEWSYM(1); }\n")
    _git(d, "add", "-A"); _git(d, "commit", "-qm", "fix overflow: add NEWSYM #42")
    return d, _head(d), c0


# ---- item 7 ------------------------------------------------------------------
def test_hexish_includes_xff000000():
    assert is_hexish("xff000000") and is_hexish("0xdeadbeef") and not is_hexish("json_parse")


# ---- item 1: strict preprocess status ---------------------------------------
def test_preprocess_ok_only_on_clean_return():
    p = preprocess("int MARKERSYM;\n", 0, frozenset(), "t.h")
    assert p["status"] == "ok" and p["active_in_declared_config"] is True and p["returncode"] == 0


def test_preprocess_if0_active_false_but_ok():
    p = preprocess("#if 0\nint MARKERSYM;\n#endif\n", 1, frozenset(), "t.h")
    assert p["status"] == "ok" and p["active_in_declared_config"] is False


def test_preprocess_error_directive_is_error_even_if_probe_visible():
    p = preprocess("#error boom\nint MARKERSYM;\n", 1, frozenset(), "t.h")
    assert p["status"] == "error" and p["returncode"] not in (0, None)


def test_preprocess_missing_include_is_error():
    p = preprocess('#include "definitely_missing_zzz.h"\nint MARKERSYM;\n', 1, frozenset(), "t.h")
    assert p["status"] == "error"


def test_preprocess_malformed_conditional_is_error():
    p = preprocess("#if 1\nint MARKERSYM;\n", 1, frozenset(), "t.h")   # no #endif
    assert p["status"] == "error"


# ---- item 2: canonical include guard + branch-aware context ------------------
def test_canonical_include_guard_only_the_outer_one():
    text = "\n".join(["#ifndef LIB_H", "#define LIB_H", "int decl;",
                      "#ifndef LIB_MAX", "#define LIB_MAX 8", "#endif", "#endif"])
    assert canonical_include_guard(text) == "LIB_H"                    # not LIB_MAX (nested config default)


def test_conditional_context_categories_and_expressions():
    guard = "LIB_H"
    assert classify_condition({"directive": "ifndef", "expr": "LIB_H", "branch": "if"}, guard) == "include_guard"
    assert classify_condition({"directive": "ifdef", "expr": "STB_IMAGE_IMPLEMENTATION", "branch": "if"}, guard) == "implementation_gate"
    assert classify_condition({"directive": "ifndef", "expr": "STBI_NO_JPEG", "branch": "if"}, guard) == "feature_gate"
    assert classify_condition({"directive": "ifdef", "expr": "_MSC_VER", "branch": "if"}, guard) == "compiler_gate"


def test_conditional_context_over_file_and_branches():
    text = "\n".join(["#ifndef LIB_H", "#define LIB_H", "int decl;", "#ifdef LIB_IMPLEMENTATION",
                      "int impl;", "#else", "int noimpl;", "#endif", "#endif"])
    cc = conditional_context(text, 2)
    assert cc["categories"] == ["include_guard"] and cc["classification"] == "static"
    cc2 = conditional_context(text, 6)                                # 'int noimpl;' is in the #else branch
    assert cc2["conditions"][-1]["branch"] == "else" and "implementation_gate" in cc2["categories"]
    assert gate_bucket(["include_guard"]) == "include_guard_only"


# ---- item 4/6: merge parents -------------------------------------------------
def test_merge_parent_marker_is_not_introduced():
    d, merge, side = _merge_repo()
    ps = parents(d, merge)
    assert len(ps) == 2 and side in ps
    assert absent_from_all_parents(d, ps, "f.h", "MERGEMARK") is False
    assert absent_from_all_parents(d, ps, "f.h", "TOTALLY_NEW") is True


# ---- item 3: enriched, context-accurate, multi-file packets ------------------
def test_packet_multifile_evidence_and_context():
    d, sha, c0 = _multifile_repo()
    rec = {"marker": "NEWSYM", "sha": sha, "parents": [c0], "is_merge": False, "marker_in_parents": [],
           "child_line": 2, "enclosing_function": "NEWSYM", "marker_occurrences": [2]}
    pkt = build_packet(d, "acme/lib", "lib.h", rec)
    assert "model_label" not in pkt and set(pkt["label_template"]) == set(RUBRIC)     # blinded
    assert "tests/t_lib.c" in pkt["complete_commit_diff"] and "tests/t_lib.c" not in pkt["target_file_diff"]
    assert {f["path"] for f in pkt["changed_files"]} == {"lib.h", "tests/t_lib.c"}
    assert "tests/t_lib.c" in pkt["changed_test_file_diffs"]
    assert "42" in pkt["linked"]["issues"]
    assert "NEWSYM" in pkt["after_context"] and pkt["hunk_coords"] is not None        # context via hunk coords
    assert pkt["marker_occurrences"][0]["enclosing_function"] == "NEWSYM" and pkt["marker_occurrences"][0]["context"]


def test_packet_file_scope_marker_not_called_missing_function():
    d, sha, c0 = _multifile_repo()
    # a file-scope marker: enclosing_function is None → scope 'file', not a "missing function" message
    rec = {"marker": "NEWSYM", "sha": sha, "parents": [c0], "is_merge": False, "marker_in_parents": [],
           "child_line": 2, "enclosing_function": None, "marker_occurrences": [2]}
    pkt = build_packet(d, "acme/lib", "lib.h", rec)
    assert pkt["marker_scope"] == "file" and "missing" not in pkt["before_context"].lower()


# ---- item 1: reproducible hashing + renamed summary --------------------------
def _cand(pid, cats):
    return {"validity": {"mechanically_valid": True}, "preprocess": {"active_in_declared_config": True},
            "conditional_context": {"categories": cats}, "patch_id": pid,
            "model_label": {"fix_class": "security", "marker_identifies_fix": True}}


def test_summary_and_hash_determinism():
    corpora = [{"repo": "r", "file": "a.h", "candidates": [_cand("P1", ["include_guard"]),
                                                           _cand("P2", ["implementation_gate", "include_guard"])]}]
    s = summarize(corpora)
    assert s["mechanically_valid_marker_candidates"] == 2
    assert s["gate_breakdown"]["include_guard_only"] == 1 and s["gate_breakdown"]["implementation_or_feature_gated"] == 1
    assert content_hash(s, corpora) == content_hash(s, corpora)
    assert packets_hash([{"a": 1}]) != packets_hash([{"a": 2}])
