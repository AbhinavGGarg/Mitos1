"""Adversarial precision tests for the fix transplanter.

These encode the false-verification bug directly: a guard that lands in a comment
(or otherwise outside a function) must NOT be reported as applied/verified. Every
test here would have failed against the buggy first version.
"""
from mitos.applyfix import (code_line_flags, apply_fix, audit_insertions, audit_placement, primary_marker)


# ---- the C lexer that the whole audit depends on ----------------------------
def test_lexer_distinguishes_comment_code_and_depth():
    text = "\n".join([
        "/* header",
        "   if (x > Y) return;   // code-shaped text INSIDE a block comment",
        "*/",
        "int g;",
        "void f(void) {",
        "    int a = 0;",
        "}",
    ])
    flags, _ = code_line_flags(text)
    assert flags[1]["in_comment"] and not flags[1]["has_code"]     # dead text in comment
    assert not flags[3]["in_comment"] and flags[3]["depth"] == 0    # file-scope code
    assert flags[5]["depth"] == 1                                   # inside the function body


# ---- the audit: dead guards must fail verification --------------------------
def test_audit_flags_guard_in_comment_as_dead():
    patched = "\n".join([
        "/* note:",
        "   if (x > MAX_DIM) return -1;",   # dead — inside the comment
        "*/",
        "static int f(int x) {",
        "    if (x > MAX_DIM) return -1;",   # live — inside the function
        "    return x;",
        "}",
    ])
    all_ok, records = audit_insertions(patched, "MAX_DIM")
    assert len(records) == 2
    assert not all_ok                                   # the comment one sinks the verdict
    assert sum(1 for r in records if r["ok"]) == 1      # exactly one is real


# ---- the whole point: never insert a guard into the opening comment ---------
COMMENT_HEADY_TARGET = "\n".join([
    "/* Big header comment.",
    "",
    "   Docs with blank lines — the first blank line in the file lives HERE.",
    "",
    "*/",
    "#define MAX_DIM 100",
    "static int loader(int w, int h) {",
    "    int a = w * h;",
    "    a = normalize(a);",
    "",
    "    return a;",
    "}",
    "",
])

# hunk whose *immediate* preceding context is a blank line (the exact shape that
# broke the first version — a blank anchor matched the first blank line up in the
# comment). The real code anchor sits one line above.
BLANK_ANCHOR_PATCH = "\n".join([
    "@@ -8,4 +8,5 @@ static int loader(int w, int h)",
    "     a = normalize(a);",
    " ",
    "+    if (w > MAX_DIM) return -1;",
    "     return a;",
])


def test_guard_never_lands_in_comment():
    patched, sites, _ins = apply_fix(COMMENT_HEADY_TARGET, BLANK_ANCHOR_PATCH)
    applied = [s for s in sites if s.status == "applied"]
    assert len(applied) == 1
    # placed at the real code anchor, inside the function
    assert "    a = normalize(a);\n    if (w > MAX_DIM) return -1;" in patched
    # and NOT anywhere above the function (i.e., not in the header comment)
    assert patched.index("if (w > MAX_DIM)") > patched.index("static int loader")
    all_ok, records = audit_insertions(patched, "MAX_DIM")
    assert all_ok and any(r["depth"] >= 1 and not r["directive"] for r in records)


def test_blank_or_comment_only_context_is_skipped_not_guessed():
    patch = "\n".join([
        "@@ -1,1 +1,2 @@",
        " ",
        "+    if (w > MAX_DIM) return -1;",
    ])
    patched, sites, _ins = apply_fix(COMMENT_HEADY_TARGET, patch)
    assert patched == COMMENT_HEADY_TARGET                     # nothing inserted
    assert sites and sites[-1].status == "skipped"
    assert "no code anchor" in sites[-1].reason


def test_ambiguous_anchor_is_skipped():
    target = "\n".join([
        "static int a(int x){",
        "    x = read();",
        "    return x;",
        "}",
        "static int b(int x){",
        "    x = read();",          # identical anchor line appears twice
        "    return x;",
        "}",
    ])
    patch = "\n".join([
        "@@ @@",
        "     x = read();",
        "+    if (x > MAX_DIM) return -1;",
    ])
    patched, sites, _ins = apply_fix(target, patch)
    assert patched == target
    assert any(s.status == "skipped" and "ambiguous" in s.reason for s in sites)


DEAD_CODE_TARGET = "\n".join([
    "static int f(int x) {",
    "#if 0",
    "    if (x > MAX_DIM) return -1;",   # dead — preprocessor-disabled
    "#endif",
    "    return x;",
    "}",
])


def test_lexer_marks_if0_region_dead():
    flags, _ = code_line_flags(DEAD_CODE_TARGET)
    assert flags[2]["pp_disabled"] and not flags[2]["has_code"]   # inside #if 0
    assert not flags[4]["pp_disabled"]                            # 'return x' is live


def test_audit_flags_guard_in_if0_as_dead():
    all_ok, records = audit_insertions(DEAD_CODE_TARGET, "MAX_DIM")
    assert len(records) == 1
    assert records[0]["pp_disabled"] and not records[0]["ok"]
    assert not all_ok                                             # #if 0 guard never runs → not verified


def test_if0_else_branch_is_live():
    text = "\n".join([
        "static int f(int x) {",
        "#if 0",
        "    int dead;",
        "#else",
        "    if (x > MAX_DIM) return -1;",   # live: the #else of #if 0
        "#endif",
        "    return x;",
        "}",
    ])
    all_ok, records = audit_insertions(text, "MAX_DIM")
    assert all_ok and records and records[0]["ok"] and not records[0]["pp_disabled"]


def test_apply_will_not_anchor_inside_if0():
    target = "\n".join([
        "static int f(int x) {",
        "#if 0",
        "    x = special_marker();",        # only occurrence is dead code
        "#endif",
        "    return x;",
        "}",
    ])
    patch = "\n".join([
        "@@ @@",
        "     x = special_marker();",
        "+    if (x > MAX_DIM) return -1;",
    ])
    patched, sites, _ins = apply_fix(target, patch)
    assert patched == target                                     # refused to anchor into dead code
    assert any(s.status == "skipped" and "anchor not found" in s.reason for s in sites)


def test_if_paren_zero_is_dead():
    text = "\n".join([
        "static int f(int x) {",
        "#if (0)",                          # parenthesised literal — must still be dead
        "    if (x > MAX_DIM) return -1;",
        "#endif",
        "    return x;",
        "}",
    ])
    all_ok, records = audit_insertions(text, "MAX_DIM")
    assert records and records[0]["pp"] == "dead" and not records[0]["ok"]
    assert not all_ok


def test_elif_zero_is_dead():
    text = "\n".join([
        "static int f(int x) {",
        "#if 1",
        "    x += 1;",
        "#elif 0",                          # provably-dead elif branch
        "    if (x > MAX_DIM) return -1;",
        "#endif",
        "    return x;",
        "}",
    ])
    all_ok, records = audit_insertions(text, "MAX_DIM")
    assert records and records[0]["pp"] == "dead" and not records[0]["ok"]


def test_undefined_ifdef_is_dead_not_verified():
    # #ifdef on a macro the build does NOT define → that branch isn't compiled → dead → not verified
    text = "\n".join([
        "static int f(int x) {",
        "#ifdef SOME_MACRO_THE_BUILD_DOES_NOT_DEFINE",
        "    if (x > MAX_DIM) return -1;",
        "#endif",
        "    return x;",
        "}",
    ])
    all_ok, records = audit_insertions(text, "MAX_DIM")     # empty define set → macro undefined
    assert records and records[0]["pp"] == "dead" and not records[0]["ok"]


def test_unevaluable_if_expr_is_unresolved():
    # a real expression we cannot evaluate statically → unresolved → not verified (never assumed live)
    text = "\n".join([
        "static int f(int x) {",
        "#if CONFIG_VERSION > 2",
        "    if (x > MAX_DIM) return -1;",
        "#endif",
        "    return x;",
        "}",
    ])
    all_ok, records = audit_insertions(text, "MAX_DIM")
    assert records and records[0]["pp"] == "unresolved" and not records[0]["ok"]


def test_ifdef_resolves_against_build_defines():
    # the stb pattern: code inside `#ifdef IMPL` is live iff the build defines IMPL
    text = "\n".join([
        "#ifdef IMPL",
        "static int f(int x) {",
        "    if (x > MAX_DIM) return -1;",
        "    return x;",
        "}",
        "#endif",
    ])
    ok_def, recs_def = audit_insertions(text, "MAX_DIM", defined=frozenset({"IMPL"}))
    assert ok_def and recs_def[0]["pp"] == "live"           # build defines IMPL → live
    ok_undef, recs_undef = audit_insertions(text, "MAX_DIM")
    assert not ok_undef and recs_undef[0]["pp"] == "dead"   # build doesn't → dead


def test_compiler_and_audit_share_one_build_config():
    # item 8: the SAME `defined` set drives clang (-D flags) and the static audit.
    import tempfile
    from mitos.applyfix import clang_define_args, compile_header, code_line_flags
    assert clang_define_args(frozenset({"FOO", "BAR"})) == ["-DBAR", "-DFOO"]

    # a program that only compiles/links when FOO is defined
    hdr = "\n".join(["#ifdef FOO", "static int helper(void){ return 1; }", "#endif",
                     "int use(void){ return helper(); }", ""])
    tmp = tempfile.mkdtemp()
    ok_with, _ = compile_header(hdr, tmp, "w", frozenset({"FOO"}))
    ok_without, _ = compile_header(hdr, tmp, "wo", frozenset())
    assert ok_with and not ok_without                     # compiler honours the defines

    # the static audit, given the same defines, agrees about what's live
    flags_with, lines = code_line_flags(hdr, frozenset({"FOO"}))
    i = next(k for k, l in enumerate(lines) if "helper(void)" in l)
    flags_without, _ = code_line_flags(hdr, frozenset())
    assert flags_with[i]["pp"] == "live" and flags_without[i]["pp"] == "dead"


def test_wrong_function_insertion_is_rejected():
    # the reviewer's case: a patch whose @@ header targets intended(), but whose anchor
    # only matches inside wrong(). The guard DOES get inserted (anchor is unique) — the
    # audit must catch that it landed in the wrong function.
    target = "\n".join([
        "static int wrong(int x) {",
        "    x = normalize(x);",
        "    return x;",
        "}",
    ])
    patch = "\n".join([
        "@@ -2,2 +2,3 @@ static int intended(int x)",
        "     x = normalize(x);",
        "+    if (x > MAX_DIM) return -1;",
        "     return x;",
    ])
    patched, sites, inserted = apply_fix(target, patch)
    assert any(s.status == "applied" for s in sites)          # it inserted (anchor matched)
    all_ok, records = audit_placement(patched, inserted)
    assert not all_ok                                          # ...but placement audit rejects it
    guard = [r for r in records if not r["directive"]][0]
    assert guard["actual_func"] == "wrong" and guard["expected_func"] == "intended"
    assert guard["reason"].startswith("wrong function")


def test_right_function_insertion_passes():
    target = "\n".join([
        "static int intended(int x) {",
        "    x = normalize(x);",
        "    return x;",
        "}",
    ])
    patch = "\n".join([
        "@@ -2,2 +2,3 @@ static int intended(int x)",
        "     x = normalize(x);",
        "+    if (x > MAX_DIM) return -1;",
        "     return x;",
    ])
    patched, sites, inserted = apply_fix(target, patch)
    all_ok, records = audit_placement(patched, inserted)
    assert all_ok
    guard = [r for r in records if not r["directive"]][0]
    assert guard["actual_func"] == "intended" == guard["expected_func"]


def test_primary_marker_ignores_comment_words():
    # added lines contain prose in a comment plus the real introduced symbol
    patch = "\n".join([
        "@@ @@",
        " some_context();",
        "+// reject disproportionate images during processing",
        "+#define MAX_DIM 100",
        "+    if (w > MAX_DIM) return -1;",
    ])
    assert primary_marker(patch) == "MAX_DIM"


# ---- new helper definitions: the commonest shape of a real security fix ------
# "Add a validation helper, then call it." The helper's own hunk has generic context
# (a blank line and a closing brace), so context matching goes ambiguous and drops it —
# leaving the call sites transplanted and the helper undefined, which does not compile.
# Real case: nothings/stb@47164e40 adds stbi__addints_valid + stbi__mul2shorts_valid and
# calls them; three of five live stale copies failed to compile until the helper landed.
HELPER_PATCH = "\n".join([
    "@@ @@",
    "+// returns 1 if the sum is valid",
    "+static int ck_add(int a, int b)",
    "+{",
    "+    return a <= 2147483647 - b;",
    "+}",
    "+",
    "@@ @@ decode",
    "     int diff = get();",
    "+    if (!ck_add(acc, diff)) return -1;",
])

HELPER_TARGET = "\n".join([
    "static int helper(int q){",
    "    return q + 1;",
    "}",
    "static int decode(int acc){",
    "    int diff = get();",
    "    return acc + diff;",
    "}",
])


def test_new_helper_is_transplanted_and_lands_before_its_caller():
    patched, sites, ins = apply_fix(HELPER_TARGET, HELPER_PATCH)
    assert all(s.status == "applied" for s in sites), [s.reason for s in sites]

    lines = patched.split("\n")
    defn = next(i for i, l in enumerate(lines) if l.strip().startswith("static int ck_add"))
    call = next(i for i, l in enumerate(lines) if "ck_add(acc, diff)" in l)
    assert defn < call, "a C helper must be defined before it is used"

    # file scope, and outside the function that calls it
    flags, _ = code_line_flags(patched)
    assert flags[defn]["depth"] == 0
    holder = next(i for i, l in enumerate(lines) if l.strip().startswith("static int decode"))
    assert defn < holder, "the helper must not be nested inside its caller"

    ok, records = audit_placement(patched, ins)
    assert ok, [r for r in records if not r["ok"]]


def test_helper_defined_twice_fails_the_audit():
    """Transplanting a helper the copy already has would define it twice; the audit must
    catch that rather than report a clean placement."""
    already = HELPER_TARGET.replace(
        "static int helper(int q){",
        "static int ck_add(int a, int b){ return 1; }\nstatic int helper(int q){")
    patched, sites, ins = apply_fix(already, HELPER_PATCH)
    dup = [r for r in audit_placement(patched, ins)[1] if not r["ok"]]
    assert not dup or all("exactly once" in (r["reason"] or "") for r in dup)
    # either the hunk was recognised as already present, or the duplicate is reported
    assert (any("already present" in (s.reason or "") for s in sites)
            or dup), "a duplicate definition must not pass silently"


def test_uncalled_helper_is_skipped_not_guessed():
    """A helper nothing calls has no defensible position, so it is skipped honestly."""
    patch = "\n".join(HELPER_PATCH.split("\n")[:7])   # the definition hunk only
    patched, sites, _ins = apply_fix(HELPER_TARGET, patch)
    assert patched == HELPER_TARGET
    assert any(s.status == "skipped" and "calls it" in (s.reason or "") for s in sites), \
        [(s.status, s.reason) for s in sites]


# ---- the catalog: a bad entry here produces confident nonsense ----------------
def test_catalog_entries_are_well_formed():
    """Discovery trusts these constants completely, so they get checked mechanically.
    A fix marker that is also an identity marker would mark every copy as patched; a
    truncated SHA would silently resolve to the wrong commit."""
    from mitos.backport import CATALOG, BY_NAME
    assert CATALOG and len(BY_NAME) == len(CATALOG), "library names must be unique"
    for lib in CATALOG:
        assert lib.identity, f"{lib.name}: needs implementation markers to exclude callers"
        assert lib.fix_marker not in lib.identity, \
            f"{lib.name}: fix marker doubles as an identity marker — every copy would look patched"
        assert lib.symbol not in lib.identity, \
            f"{lib.name}: the public symbol is not implementation-only"
        assert len(lib.fix_sha) == 40 and all(c in "0123456789abcdef" for c in lib.fix_sha), \
            f"{lib.name}: fix_sha must be a full 40-hex commit"
        assert "/" in lib.upstream and lib.fix_path
