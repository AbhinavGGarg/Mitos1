"""mitos command line: analyze / scan / run / demo.

    mitos analyze <before.c> <after.c>       -> print the patch signature
    mitos scan <before.c> <after.c> <corpus> -> classify descendants
    mitos run  <before.c> <after.c> <corpus> [--out DIR]  -> full pipeline
    mitos demo                                -> run the bundled example
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import astutils as A
from .signature import analyze, signature_from_vuln, PatchSignature
from .discover import scan_corpus, classify, STALE, IMMUNE, NO_MATCH
from .transplant import transplant
from .verify import verify
from .ghsearch import search_code, fetch_source, file_last_commit_iso, GhError

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "memcpy_bounds"

# ---- tiny ANSI helpers -------------------------------------------------------
def _c(s, code): return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else s
def bold(s): return _c(s, "1")
def green(s): return _c(s, "32")
def red(s): return _c(s, "31")
def yellow(s): return _c(s, "33")
def dim(s): return _c(s, "2")
def cyan(s): return _c(s, "36")


def _read(p): return Path(p).read_bytes()


def _load_sig(before, after) -> PatchSignature:
    return analyze(_read(before), _read(after))


def cmd_analyze(a):
    sig = _load_sig(a.before, a.after)
    print(sig.to_json())


def cmd_scan(a):
    sig = _load_sig(a.before, a.after)
    for d in scan_corpus(a.corpus, sig):
        tag = {STALE: red("STALE"), IMMUNE: cyan("IMMUNE"), NO_MATCH: dim("NO_MATCH")}[d.status]
        print(f"  {d.func.name:16} {os.path.basename(d.path):18} {tag:22} lineage {d.lineage:.2f}  {dim(d.reason)}")


def _pipeline(before, after, corpus, out_dir):
    sig = _load_sig(before, after)
    print(bold("\nMitos") + dim("  —  analyze → discover → transplant → verify\n"))
    print(f"  upstream fix : {bold(sig.upstream_func)}  {dim('(' + sig.label + ')')}")
    print(f"  signature    : guard  {cyan(sig.callee + '()')}  size=arg{sig.size_arg_index}  "
          f"op '{sig.op}'  return {sig.error_return}\n")

    descendants = scan_corpus(corpus, sig)
    print(bold(f"  scanned {len(descendants)} function(s) across corpus:"))
    for d in descendants:
        tag = {STALE: red("STALE   "), IMMUNE: cyan("IMMUNE  "), NO_MATCH: dim("NO_MATCH")}[d.status]
        extra = "" if d.status == STALE else dim(f"— {d.reason}")
        print(f"    {tag} {d.func.name:15} {dim(os.path.basename(d.path)):28} lineage {d.lineage:.2f}  {extra}")

    stale = [d for d in descendants if d.status == STALE]
    print(bold(f"\n  transplanting into {len(stale)} stale descendant(s):"))
    results = []
    for d in stale:
        patch = transplant(d, sig)
        if patch.conflict:
            print(f"    {yellow('⚠ ' + d.func.name):24} {yellow(patch.conflict)}")
            results.append((d, patch, None))
            continue
        print(f"    {d.func.name:15} insert  {green(patch.guard_line):40} "
              f"{dim('[cap: ' + patch.mapping['capacity_reason'] + ']')}  conf {patch.confidence}")
        ev = verify(d, patch, sig)
        results.append((d, patch, ev))

    print(bold("\n  verifying under AddressSanitizer:"))
    verified = 0
    for d, patch, ev in results:
        if ev is None:
            print(f"    {yellow(d.func.name):24} skipped (needs review)")
            continue
        b = red("overflow") if ev.before_overflow else yellow("no-repro")
        aft = green("clean, returns " + ev.after_result) if not ev.after_overflow else red("STILL OVERFLOWS")
        verdict = green("PASS") if ev.passed else red("FAIL")
        print(f"    {d.func.name:15} before {b:20} after {aft:28} {verdict}")
        if not ev.passed and ev.detail:
            print(f"        {dim(ev.detail)}")
        if ev.passed:
            verified += 1

    if out_dir:
        _write_out(out_dir, sig, results)
    total_applicable = len(stale)
    print(bold(f"\n  {green(str(verified))}/{total_applicable} descendants patched & verified") +
          (f"   {dim('→ ' + out_dir)}" if out_dir else "") + "\n")
    return verified, total_applicable


def _write_out(out_dir, sig, results):
    os.makedirs(out_dir, exist_ok=True)
    for d, patch, ev in results:
        if ev is None or not ev.passed:
            continue
        stem = os.path.join(out_dir, patch.func_name)
        Path(stem + ".patched.c").write_text(patch.patched)
        evidence = {
            "func": patch.func_name,
            "source_file": d.path,
            "lineage_confidence": round(d.lineage, 3),
            "patch_confidence": patch.confidence,
            "guard_inserted": patch.guard_line,
            "role_mapping": patch.mapping,
            "verification": {
                "compiler": "clang -fsanitize=address",
                "before": "heap-buffer-overflow" if ev.before_overflow else "no-repro",
                "after": f"clean exit, returns {ev.after_result}",
                "passed": ev.passed,
            },
            "upstream_fix": {"function": sig.upstream_func, "label": sig.label},
        }
        Path(stem + ".evidence.json").write_text(json.dumps(evidence, indent=2))


def cmd_run(a):
    _pipeline(a.before, a.after, a.corpus, a.out)


def _scan_file(src: bytes, sig, upstream_tokens):
    """Classify one fetched file. Returns (status, n_unguarded, best_lineage, sample_func)."""
    matching = []
    for f in A.extract_functions(src):
        if f.calls(sig.callee):
            matching.append(classify(f, sig, upstream_tokens))
    if not matching:
        return NO_MATCH, 0, 0.0, ""
    stale = [d for d in matching if d.status == STALE]
    immune = [d for d in matching if d.status == IMMUNE]
    status = STALE if stale else (IMMUNE if immune else NO_MATCH)
    lineage = max((d.lineage for d in matching), default=0.0)
    sample = (stale or immune or matching)[0].func.name
    return status, len(stale), lineage, sample


def cmd_hunt(a):
    if a.vuln:
        sig = signature_from_vuln(_read(a.vuln))
        query = a.query or f"{sig.upstream_func} language:{a.lang}"
        upstream_tokens = A.normalize_tokens(A.extract_functions(sig.upstream_before)[0].body,
                                             sig.upstream_before)
    else:
        if not (a.query and a.callee):
            print(red("hunt needs either a VULN file, or --query and --callee")); sys.exit(2)
        from .signature import SIZE_ARG
        sig = PatchSignature(kind="bounds_guard", callee=a.callee,
                             size_arg_index=a.size_arg if a.size_arg is not None else SIZE_ARG.get(a.callee, 2),
                             dest_arg_index=0, op=">", error_return="-1",
                             upstream_func="?", upstream_before="", upstream_after="")
        query = a.query
        upstream_tokens = []

    print(bold("\nMitos") + dim("  —  hunt  (live GitHub Code Search)\n"))
    print(f"  query   : {cyan(query)}")
    print(f"  pattern : unguarded {sig.callee}()  size=arg{sig.size_arg_index}\n")

    try:
        hits = search_code(query, max_results=a.max, verbose=lambda m: print(dim("  " + m)))
    except GhError as e:
        print(red(f"  code search failed: {e}")); sys.exit(1)

    print(bold(f"\n  scanning {len(hits)} real descendant(s):"))
    counts = {STALE: 0, IMMUNE: 0, NO_MATCH: 0}
    unfetchable = 0
    for h in hits:
        src = fetch_source(h)
        if src is None:
            unfetchable += 1
            print(f"    {dim('· unreadable'):26} {dim(h.repo + '/' + h.path)}")
            continue
        status, n_unguarded, lineage, sample = _scan_file(src, sig, upstream_tokens)
        counts[status] += 1
        tag = {STALE: red("STALE   "), IMMUNE: cyan("IMMUNE  "), NO_MATCH: dim("NO_MATCH")}[status]
        date = ""
        if a.dates and status != NO_MATCH:
            d = file_last_commit_iso(h.repo, h.path)
            if d:
                date = dim(f"updated {d[:10]}")
        detail = red(f"{n_unguarded} unguarded") if status == STALE else (
            cyan("guarded") if status == IMMUNE else dim("no copy pattern"))
        print(f"    {tag} {h.repo[:34]:34} {dim(os.path.basename(h.path)):20} {detail:20} {date}")

    scanned = len(hits) - unfetchable
    print(bold("\n  ── live result ──"))
    print(f"  {scanned} real repos scanned · "
          f"{red(str(counts[STALE]))} carry the vulnerable pattern · "
          f"{cyan(str(counts[IMMUNE]))} already guarded · "
          f"{dim(str(counts[NO_MATCH]) + ' no-match')}"
          + (f" · {dim(str(unfetchable) + ' unreadable')}" if unfetchable else "") + "\n")


def cmd_cve(a):
    from .cve import fingerprint_from_commit, discriminate
    try:
        fp = fingerprint_from_commit(a.repo, a.sha, a.path)
    except Exception as e:
        print(red(f"could not fingerprint fix: {e}")); sys.exit(1)

    print(bold("\nMitos") + dim("  —  cve  (fix-fingerprint discrimination on real copies)\n"))
    print(f"  fix commit    : {cyan(a.repo + '@' + a.sha[:10])}  {dim(fp.fix_date[:10])}")
    print(f"  {dim(fp.message)}")
    print(f"  vulnerable fn : {bold(fp.context_marker)}   in {dim(fp.file)}")
    print(f"  fix marker(s) : {green(', '.join(fp.fix_markers) or '—')}   "
          f"{dim('(a copy missing these lacks the fix)')}\n")

    verdicts = discriminate(fp, max_results=a.max, want_dates=not a.no_dates,
                            verbose=lambda m: print(dim("  " + m)))
    print(bold(f"\n  {len([v for v in verdicts if v.status!='UNREADABLE'])} real copies read:"))
    stale = immune = corrob = 0
    for v in verdicts:
        if v.status == "UNREADABLE":
            print(f"    {dim('· unreadable ' + v.repo)}"); continue
        if v.status == "NO_MATCH":
            continue
        date = dim((v.last_commit or "")[:10])
        if v.status == "STALE":
            stale += 1
            note = dim("predates fix ✓") if v.predates_fix else dim("copied stale")
            print(f"    {red('STALE  ')} {v.repo[:38]:38} {date}  {note}")
            if v.predates_fix:
                corrob += 1
        else:
            immune += 1
            print(f"    {cyan('IMMUNE ')} {v.repo[:38]:38} {date}  {dim('has fix')}")

    total = stale + immune
    print(bold("\n  ── live precision result ──"))
    if total:
        pct = round(100 * stale / total)
        print(f"  {red(str(stale))} of {total} real copies are STALE "
              f"({pct}% still missing this fix) · {cyan(str(immune))} already fixed")
        print(dim(f"  every STALE call verified by reading the copy's own bytes; "
                  f"{corrob}/{stale} also predate the fix date ({fp.fix_date[:10]}) as corroboration"))
    else:
        print(dim("  no classifiable copies in this sample"))
    print()


def cmd_fix(a):
    import tempfile
    from .applyfix import (fetch_commit_patch, fetch_file, apply_fix, audit_placement,
                           compile_header, unified, primary_marker)
    print(bold("\nMitos") + dim("  —  fix  (transplant a real upstream fix into a real stale copy)\n"))
    try:
        patch, msg, date = fetch_commit_patch(a.repo, a.sha, a.fix_path)
        target = fetch_file(a.target, a.target_path)
    except Exception as e:
        print(red(f"fetch failed: {e}")); sys.exit(1)

    marker = a.marker or primary_marker(patch)
    if not marker:
        print(red("could not derive a fix marker to verify against; pass --marker")); sys.exit(1)

    print(f"  fix     : {cyan(a.repo + '@' + a.sha[:10])}  {dim(date[:10])}  {dim(msg)}")
    print(f"  target  : {cyan(a.target)}  {dim(a.target_path)}  ({len(target.splitlines())} lines)")
    print(f"  marker  : {green(marker)}  {dim('(audited for executable placement)')}\n")
    defined = frozenset(a.define or ["STB_IMAGE_IMPLEMENTATION"])   # macros the verification build defines
    patched, sites, inserted = apply_fix(target, patch, defined)
    applied = [s for s in sites if s.status == "applied"]
    skipped = [s for s in sites if s.status == "skipped"]

    print(bold(f"  transplanted {len(applied)} fix site(s):"))
    for s in applied:
        print(f"    {green('+')} {s.first_code()[:78]}")
    if skipped:
        print(bold(f"\n  skipped {len(skipped)} (honest — not guessed):"))
        for s in skipped:
            print(f"    {yellow('·')} {dim(s.first_code()[:44]):46} {dim(s.reason)}")

    from . import behavioral
    tmp = tempfile.mkdtemp(prefix="mitos_fix_")
    ok_before, _ = compile_header(target, tmp, "before", defined)
    ok_after, err_a = compile_header(patched, tmp, "after", defined)   # SAME defines as the audit
    placement_ok, records = audit_placement(patched, inserted, defined)  # exact lines: live code, right function?
    bad = [r for r in records if not r["ok"]]
    beh = behavioral.verify(target, patched, tmp, marker, defined)  # does the guard actually fire?

    print(bold("\n  verify:"))
    print(f"    original copy compiles : {green('yes') if ok_before else red('no')}")
    print(f"    patched copy  compiles : {green('yes') if ok_after else red('no')}"
          + ("" if ok_after else dim(f"   {err_a.splitlines()[0] if err_a else ''}")))
    ncode = len(records) - len(bad)
    tag = green(f"{ncode}/{len(records)} live & in the expected function") if placement_ok else \
        red(f"{len(bad)}/{len(records)} MISPLACED")
    print(f"    guard placement        : {tag}  {dim('← static placement audit')}")
    for r in bad[:6]:
        print(f"        {red('✗ line ' + str(r['line'])):18} {dim(r.get('reason') or 'misplaced')}: {dim(r['text'])}")
    if beh.ran:
        btag = green("guard FIRES on attack") if beh.fires_only_after else red("guard did NOT fire")
        print(f"    behaviour (live)       : {btag}  {dim('← ' + beh.detail)}")
    else:
        print(f"    behaviour (live)       : {dim('— ' + beh.detail)}")

    placement_pass = ok_before and ok_after and placement_ok and len(applied) > 0 and len(records) > 0
    behavioural_ok = beh.ran and beh.fires_only_after
    verdict = ("VERIFIED_BEHAVIOURAL" if placement_pass and behavioural_ok
               else "VERIFIED_PLACEMENT" if placement_pass else "NOT_VERIFIED")

    out = a.out or os.path.join(os.getcwd(), "mitos-out", a.target.replace("/", "__"))
    if placement_pass:
        os.makedirs(out, exist_ok=True)
        Path(os.path.join(out, os.path.basename(a.target_path) + ".patched")).write_text(patched)
        Path(os.path.join(out, "fix.diff")).write_text(unified(target, patched, a.target_path))
        Path(os.path.join(out, "evidence.json")).write_text(json.dumps({
            "target": a.target, "target_path": a.target_path,
            "upstream_fix": {"repo": a.repo, "sha": a.sha, "date": date, "message": msg},
            "sites_applied": len(applied), "sites_skipped": [s.reason for s in skipped],
            "verification": {"original_compiles": ok_before, "patched_compiles": ok_after,
                             "inserted_lines": len(records), "all_executable": placement_ok,
                             "placement_audit": records,
                             "behavioural": {"ran": beh.ran, "probe": beh.probe, "before": beh.before,
                                             "after": beh.after, "guard_fires_only_after": beh.fires_only_after,
                                             "detail": beh.detail},
                             "compiler": "clang -O0"},
            "verdict": verdict,
        }, indent=2))

    print(bold("\n  ── result ──"))
    if verdict == "VERIFIED_BEHAVIOURAL":
        print(f"  {green('VERIFIED (behavioural)')} for {bold(a.target)} — {len(applied)} sites, every guard live & in the\n"
              f"  expected function, and the guard rejects an attack the original accepts.  {dim('→ ' + out)}")
    elif verdict == "VERIFIED_PLACEMENT":
        extra = dim("no behavioural probe for this fix") if not beh.ran else red("behaviour probe did NOT fire — investigate")
        print(f"  {green('VERIFIED (placement)')} for {bold(a.target)} — {len(applied)} sites, every guard live & in the\n"
              f"  expected function (static).  {extra}  {dim('→ ' + out)}")
    else:
        why = ("no sites applied" if not applied else
               "patched copy failed to compile" if not ok_after else
               "original did not compile" if not ok_before else
               f"{len(bad)} inserted line(s) misplaced (dead/comment/wrong-function) — refusing to call this verified")
        print(f"  {red('NOT VERIFIED')} — {why}.")
    print(dim("\n  scope: behavioural verification uses one crafted probe (oversized-image) covering the\n"
              "  32-bit-dimension loaders; it does not yet run the target repo's own test suite. stb is a\n"
              "  drop-in header (favourable) — a copied fragment would need the repo's build to verify."))
    print()


def cmd_repair(a):
    """Trustworthy downstream repair: real patch, three-way merge, positional hunk verification,
    constrained own-build + own-binary probes. Fresh Mitos-owned clone every run."""
    from . import repair
    from . import recipes as _recipes                          # registers bundled recipes on import
    _key = getattr(a, "recipe", None) or repair.BLURHASH_KEY
    if _key not in repair._REGISTRY:
        _m = [k for k in repair._REGISTRY if _key.lower() in k.lower()]
        if len(_m) == 1:
            _key = _m[0]
        else:
            print(red(f"unknown --recipe {_key!r}; registered: {list(repair._REGISTRY)}")); sys.exit(2)
    recipe = repair._REGISTRY[_key]()          # display only; the run re-resolves the key
    work_parent = a.work or os.path.join(os.getcwd(), "mitos-out", "repair-run")

    print(bold("\nMitos") + dim("  —  repair  (exact golden-attested pinned repair · three-way merge · own-build)\n"))
    print(f"  target   : {cyan(recipe.downstream_repo)}  {dim(recipe.downstream_path)}")
    print(f"  pinned   : {dim(recipe.downstream_sha)}")
    print(f"  upstream : {cyan(recipe.upstream_repo)}  fix {dim(recipe.upstream_fix_sha[:12])}  parent {dim(recipe.upstream_parent_sha[:12])}\n")

    res = repair.run_repair(_key, work_parent,
                            verbose=(lambda m: print(dim("  " + m))) if a.verbose else (lambda m: None),
                            verification_command=f"python -m mitos repair --recipe {_key}")

    m = res.merge
    print(f"  parent (raw commit)    : {green('verified') if res.parent_verified else red('MISMATCH')}   "
          f"clone : {green('validated') if (res.origin_ok and res.clone_validated) else red('REJECTED')}   "
          f"hunk-count : {green('ok') if res.hunk_count_ok else red('MISMATCH')}")
    print(f"  three-way merge        : merge_rc={green('0') if m['returncode']==0 else red(str(m['returncode']))}  "
          f"{green('clean') if m['clean'] else red(str(m['conflicts'])+' conflict(s)')}  "
          f"{dim(str(m['marker']) + ' ' + str(m['marker_before']) + ' → ' + str(m['marker_after']))}")
    ga = res.golden_attestation
    print(f"  golden attestation     : {green('exact postimage match') if ga['merged_match'] else red('MISMATCH') if ga['attested'] else yellow('experimental (no attestation)')}"
          f"   {dim('merged '+str(ga['actual_merged_sha256'])[:12])}")
    cert = res.hunk_certification
    st = {}
    for h in res.hunks:
        st[h["status"]] = st.get(h["status"], 0) + 1
    print(f"  positional cross-check : {green(str(cert['verified_applied']))}/{cert['upstream_hunks']} passed {dim('(experimental; golden postimage is authoritative)')}  "
          + dim("  ".join(f"{v} {k}" for k, v in sorted(st.items()))))
    if cert["unverified"]:
        print(f"    {yellow('unverified:')} {dim(', '.join(h[:44] for h in cert['unverified']))}")
    print(f"  baseline build         : {green(res.baseline_build['status']) if res.baseline_build['ok'] else red(res.baseline_build['status'])}"
          f"   patched build : {green(res.patched_build['status']) if res.patched_build['ok'] else red(res.patched_build['status'])}"
          f"   {dim('fresh artifact + sha256')}")
    cov = res.coverage
    print(f"  coverage               : structural {cyan(str(cov['structurally_merged_count'])+' loaders')}  ·  "
          f"reachable {dim(', '.join(cov['reachable_loaders']))}  ·  behavioural {green(', '.join(cov['behaviourally_verified_loaders']) or '—')}")
    if res.probes:
        print(bold("\n  behavioural probes (exact exit code + diagnostic; signals/timeouts fail):"))
        for p in res.probes:
            tag = green("pass") if p["ok"] else red("FAIL")
            print(f"    {tag}  {p['name']:30} {dim(p['detail'][:92])}")

    out = a.out or os.path.join(os.getcwd(), "mitos-out", "real_world")
    repair.write_artifacts(res, out, force=a.force)

    print(bold("\n  ── result ──"))
    if res.verdict == "VERIFIED":
        print(f"  {green('VERIFIED')} — {cert['claim']}; every reachable loader behaviourally exercised.")
    elif res.verdict == "VERIFIED_SCOPED":
        print(f"  {green('VERIFIED_SCOPED')} — {cert['claim']};\n  {yellow(res.reasons[0])}")
    else:
        print(f"  {red('NEEDS_REVIEW')} — {('; '.join(res.reasons))}.")
    print(dim(f"  provenance: generator {res.generator_commit[:10]} · recipe {res.recipe_digest[:10]} · reproduce `{res.verification_command}`"))
    print(dim(f"  artifacts (fix.diff, evidence.json, commands.log, full_command_log.txt, PR_BODY.md) → {out}"))
    print(dim("  no external PR opened.\n"))
    sys.exit(0 if res.verdict in ("VERIFIED", "VERIFIED_SCOPED") else 1)


def cmd_state(a):
    """Structured product status — one JSON payload a UI can render a dashboard from."""
    from . import api
    st = api.product_state()
    if a.json:
        print(json.dumps(st, indent=2)); return
    fr = st["flagship_repair"] or {}
    bm = st["benchmark"]
    print(bold("\nMitos") + dim("  —  state  (product status; --json for a UI-consumable payload)\n"))
    if fr:
        v = fr["verdict"]
        tag = green(v) if v in ("VERIFIED", "VERIFIED_SCOPED") else red(v or "—")
        print(bold("  exact golden-attested pinned repair") + f"  {tag}")
        t = fr["target"]
        print(f"    {cyan(t['downstream_repo'])}  {dim(t['path'])}  ← {dim(t['upstream_repo'] + ' ' + (t['fix'] or '')[:10])}")
        pcc = fr["positional_cross_check"]
        ga = fr.get("golden_attestation", {})
        print(f"    merge rc={fr['merge']['returncode']} conflicts={fr['merge']['conflicts']}  ·  "
              f"golden postimage {green('match') if ga.get('merged_match') else red('MISMATCH')} {dim('(authoritative)')}  ·  "
              f"marker {fr['merge']['marker_before']}→{fr['merge']['marker_after']}")
        print(f"    positional cross-check {green(str(pcc['passed']))}/{pcc['total']} passed {dim('(experimental)')}")
        cov = fr["coverage"]
        print(f"    coverage: structural {cov['structurally_merged']}  ·  reachable {dim(', '.join(cov['reachable_loaders']))}"
              f"  ·  behavioural {green(', '.join(cov['behaviourally_verified']) or '—')}")
        print(f"    provenance: generator {dim((fr['provenance']['generator_commit'] or '')[:10])}  "
              f"reproduce `{fr['provenance']['reproduce']}`")
    print(bold("\n  benchmark") + f"  {dim(bm['library'] or '')}")
    print(f"    {bm['copies_scanned']} live copies  ·  marker-absence {int((bm['marker_absence_rate'] or 0)*100)}%  ·  "
          f"mined {bm['mined']['mechanically_valid']}/{bm['mined']['candidates_examined']} valid candidates")
    print(f"    {yellow('ground_truth: ' + bm['ground_truth'])}")
    print(bold("\n  human-gated (not automatable here):"))
    for h in st["human_gated"]:
        print(f"    {yellow('· ' + h['item'])} — {dim(h['detail'])}")
    print()


def cmd_bench(a):
    from . import benchmark
    corpus_path = a.corpus or str(Path(__file__).resolve().parents[1] / "examples" / "benchmark" / "corpus.json")
    corpus = json.loads(Path(corpus_path).read_text())
    corpus["_dir"] = os.path.dirname(corpus_path)
    print(bold("\nMitos") + dim("  —  bench  (real fixes × real copies)\n"))
    print(f"  library : {dim(corpus.get('library', ''))}")
    print(f"  fixes   : {bold(str(len(corpus['fixes'])))}   sampling up to {a.sample} live copies\n")
    rep = benchmark.run(corpus, a.sample, a.compile_sample, verbose=lambda m: print(dim("  " + m)))
    n = rep["copies_scanned"]

    print(bold(f"\n  marker-absence rate  ({n} deduped copies × {rep['fixes']} markers = {rep['total_judgments']} checks):"))
    for r in rep["marker_absence"]:
        cor = dim(f"  ({r['predate_corroboration']} predate fix ✓)") if r["predate_corroboration"] is not None else ""
        count = red(f"{r['absent']:>2}/{n} absent")
        pct = dim(f"{int(r['absence_rate'] * 100)}%")
        print(f"    {r['marker']:24} {count:22} {pct:5}{cor}")
    print(f"\n  {bold('overall')}: {red(str(rep['total_marker_absent']))}/{rep['total_judgments']} "
          f"checks absent — {int(rep['overall_marker_absence_rate'] * 100)}% of copies lack a given hardening marker")

    tp = rep["transplant_precision"]
    if tp:
        s = tp["summary"]
        print(bold(f"\n  syntactic placement pass  (transplant {cyan(tp['marker'])} into {n} real copies):"))
        print(f"    already fixed (skipped)                     : {s['already_fixed']}")
        print(f"    no sites applied (too drifted)              : {s['no_sites']}")
        print(f"    applicable                                  : {s['applicable']}")
        print(f"      {green('pass')} — every inserted line live & in the expected function : "
              f"{green(str(s['placement_pass']))}/{s['applicable']}")
        if s["placement_fail"]:
            print(f"      {red('fail')} — a line misplaced (dead/comment/wrong-fn)          : {red(str(s['placement_fail']))}")
        print(f"      wrong-function insertions detected        : {s['wrong_function_insertions']}")
        print(f"    compile+behaviour sample                    : {s['compiled']} compiled, "
              f"{green(str(s['behavioural_fired']))} behaviourally fire (BMP path)")
        print(dim("    note: 'placement pass' is a STATIC check (live code + right function), not behavioural proof."))

    out = a.out or os.path.join(os.getcwd(), "mitos-out", "benchmark_results.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    Path(out).write_text(json.dumps({k: v for k, v in rep.items()}, indent=2))
    print(dim(f"\n  full results → {out}\n"))


def cmd_mine(a):
    import subprocess
    from . import miner
    root = Path(__file__).resolve().parents[1]
    libs = json.loads(Path(a.libs or str(root / "examples" / "benchmark" / "libs.json")).read_text())

    if a.verify:
        existing = json.loads(Path(a.verify).read_text())
        pkt_path = os.path.join(os.path.dirname(a.verify), "review_packets.json")
        existing_pkt = json.loads(Path(pkt_path).read_text()) if os.path.exists(pkt_path) else None
        print(bold("\nMitos") + dim("  —  mine --verify  (regenerate from pinned upstream + compare corpus AND packets)\n"))
        corpora, packets = miner.mine(libs, verbose=lambda m: print(dim("  " + m)))
        ch, ph = miner.content_hash(miner.summarize(corpora), corpora), miner.packets_hash(packets)
        ok_c = ch == existing.get("corpus_hash")
        ok_p = existing_pkt is None or ph == existing_pkt.get("packets_hash")
        print(f"\n  corpus_hash  : recorded {existing.get('corpus_hash', '')[:16]}  recomputed {ch[:16]}  "
              + (green("✓") if ok_c else red("✗")))
        print(f"  packets_hash : recorded {(existing_pkt or {}).get('packets_hash', '—')[:16]}  recomputed {ph[:16]}  "
              + (green("✓") if ok_p else red("✗")))
        print(green("  ✓ corpus and packets reproduce") if ok_c and ok_p else red("  ✗ MISMATCH — not reproducible"))
        sys.exit(0 if ok_c and ok_p else 1)

    print(bold("\nMitos") + dim("  —  mine  (CANDIDATE fix markers across copied C libraries, via local git)\n"))
    corpora, packets = miner.mine(libs, cap_valid=a.per_lib, verbose=lambda m: print(dim("  " + m)))
    s = miner.summarize(corpora)
    ch, ph = miner.content_hash(s, corpora), miner.packets_hash(packets)
    cv, tgt = miner.clang_version_target()
    gen = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or None
    corpus = {"generator_commit": gen, "generated_by": "mitos mine",
              "toolchain": {"clang": cv, "target": tgt}, "corpus_hash": ch, "summary": s, "libraries": corpora}
    packet_doc = {"generator_commit": gen, "source_corpus_hash": ch, "packets_hash": ph,
                  "rubric_fields": list(miner.RUBRIC.keys()), "blinded": True, "packets": packets}
    gb = s["gate_breakdown"]

    print(bold("\n  per library (candidates → mechanically valid):"))
    for c in corpora:
        valid = sum(1 for x in c["candidates"] if x["validity"]["mechanically_valid"])
        print(f"    {c['library']:16} {dim(c['file']):22} {len(c['candidates']):>3} cand → {green(str(valid))} valid  "
              f"{dim('pinned ' + c['upstream_head_sha'][:10])}")

    print(bold("\n  ── corpus-integrity report ──"))
    print(f"    candidates examined                    : {s['candidates_examined']}")
    print(f"    mechanically valid marker candidates   : {green(str(s['mechanically_valid_marker_candidates']))}  "
          f"{dim('(absent from ALL parents + in code + not hex + clang preprocess ok & active)')}")
    print(f"    all survive preprocessing (active)     : {s['all_survive_preprocessing']}")
    print(f"    conditional context of the valid:")
    print(f"      · include_guard only                 : {gb.get('include_guard_only', 0)}")
    print(f"      · include_guard + compiler           : {gb.get('include_guard_plus_compiler', 0)}")
    print(f"      · implementation/feature gated       : {gb.get('implementation_or_feature_gated', 0)}")
    print(f"    model: security/correctness            : {s['model_security_or_correctness']}  {dim('(model_label, not ground truth)')}")
    print(f"    model: fix-identifying markers         : {s['model_fix_identifying_markers']}  {dim('(model_label, not ground truth)')}")
    print(f"    independent repos / files with valid   : {s['independent_repos_with_valid']} / {s['independent_files_with_valid']}")
    print(f"    unique patch ids (of valid)            : {s['unique_patch_ids']}")
    print(dim(f"    frozen: generator {gen[:10] if gen else '—'} · clang {cv.split()[-1] if cv else '?'} {tgt} · "
              f"corpus_hash {ch[:12]} · packets_hash {ph[:12]} · ground_truth null"))

    out = a.out or os.path.join(os.getcwd(), "mitos-out", "mined_corpus.json")
    pkt = os.path.join(os.path.dirname(out), "review_packets.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    Path(out).write_text(json.dumps(corpus, indent=2))
    Path(pkt).write_text(json.dumps(packet_doc, indent=2))
    print(dim(f"\n  corpus ({s['candidates_examined']} rows) → {out}\n  {len(packets)} blinded review packets → {pkt}\n"))


def cmd_bundle(a):
    from . import labeling
    packet_doc = json.loads(Path(a.packets).read_text())
    outdir = a.out or os.path.join(os.getcwd(), "mitos-out")
    os.makedirs(outdir, exist_ok=True)
    bpath = os.path.join(outdir, f"bundle_{a.reviewer}.json")
    lpath = os.path.join(outdir, f"labels_{a.reviewer}.json")
    for pth in (bpath, lpath):
        if os.path.exists(pth) and not a.force:
            print(red(f"  refusing to overwrite {pth} — pass --force")); sys.exit(2)
    try:
        bundle, labels = labeling.build_bundle(packet_doc, a.seed, a.reviewer)   # verifies packets_hash + rejects verdict/prefilled fields
    except ValueError as e:
        print(red(f"  {e}")); sys.exit(2)
    Path(bpath).write_text(json.dumps(bundle, indent=2))
    Path(lpath).write_text(json.dumps(labels, indent=2))
    print(bold("\nMitos") + dim("  —  bundle  (blinded, evidence-only, randomized reviewer packet set)\n"))
    print(f"  reviewer : {cyan(a.reviewer)}   seed {a.seed}   packets {len(bundle['packets'])}")
    print(f"  source_packets_hash : {dim(bundle['source_packets_hash'][:24])}  {green('verified')}")
    print(f"  bundle_hash         : {dim(labeling.bundle_hash(bundle)[:24])}")
    print(f"  {green('evidence-only bundle')} → {dim(bpath)}  {dim('(no label_template)')}")
    print(f"  {green('empty label file')}     → {dim(lpath)}  {dim('(keyed by packet_id; every field null)')}")
    print(dim("\n  A human fills the label file per review_protocol.md (values may be 'unknown').\n"
              "  Two blinded reviewers + adjudication → ground_truth; one reviewer → single-reviewer labels.\n"))


def _load_packet_ids(packets_path):
    doc = json.loads(Path(packets_path).read_text())
    return [p["packet_id"] for p in doc.get("packets", [])], doc.get("packets_hash")


def cmd_labels_validate(a):
    from . import labeling
    lf = json.loads(Path(a.file).read_text())
    pids, sph = (_load_packet_ids(a.packets) if a.packets else (None, None))
    errs = labeling.validate_label_file(lf, packet_ids=pids, source_packets_hash=sph, final=a.final)
    mode = "final" if a.final else "work-in-progress"
    print(bold("\nMitos") + dim(f"  —  labels validate  ({mode})\n"))
    if errs:
        print(red(f"  {len(errs)} problem(s):"))
        for e in errs[:40]:
            print(f"    {red('✗')} {e}")
        sys.exit(1)
    print(green(f"  ✓ label file valid ({mode}); reviewer {lf.get('reviewer')!r}, {len(lf.get('labels', {}))} packets\n"))


def cmd_labels_adjudicate(a):
    from . import labeling
    la, lb = json.loads(Path(a.a).read_text()), json.loads(Path(a.b).read_text())
    adj = labeling.adjudicate(la, lb)
    print(bold("\nMitos") + dim("  —  labels adjudicate  (decision fields; disagreements need a human)\n"))
    print(f"  reviewers : {adj['reviewers']}   shared packets : {adj['shared_packets']}")
    print(f"  field-level disagreements : {red(str(adj['disagreement_count'])) if adj['disagreement_count'] else green('0')}")
    if adj["only_in_a"] or adj["only_in_b"]:
        print(dim(f"  only in a: {len(adj['only_in_a'])} · only in b: {len(adj['only_in_b'])}"))
    if a.out:
        Path(a.out).write_text(json.dumps(adj, indent=2))
        print(dim(f"  adjudication (resolved on agreement; disagreements null) → {a.out}"))
    print(dim("  logical_family_id is a SEPARATE pass: `mitos labels family`. AI resolves nothing.\n"))


def cmd_labels_family(a):
    from . import labeling
    fg = labeling.family_groups(json.loads(Path(a.file).read_text()))
    print(bold("\nMitos") + dim("  —  labels family  (second-pass logical_family_id grouping)\n"))
    print(f"  {len(fg['groups'])} family group(s) from human-entered logical_family_id")
    if a.out:
        Path(a.out).write_text(json.dumps(fg, indent=2))
        print(dim(f"  groups → {a.out}"))
    print()


def cmd_demo(a):
    out = a.out or str(EXAMPLE / "out")
    v, n = _pipeline(str(EXAMPLE / "upstream_before.c"),
                     str(EXAMPLE / "upstream_after.c"),
                     str(EXAMPLE / "corpus"), out)
    sys.exit(0 if v == n and n > 0 else 1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="mitos", description="Dependabot for copied/vendored code with no manifest.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("analyze", help="extract a patch signature from a before/after fix")
    pa.add_argument("before"); pa.add_argument("after"); pa.set_defaults(fn=cmd_analyze)

    ps = sub.add_parser("scan", help="classify descendants in a corpus")
    ps.add_argument("before"); ps.add_argument("after"); ps.add_argument("corpus"); ps.set_defaults(fn=cmd_scan)

    pr = sub.add_parser("run", help="full pipeline: analyze -> discover -> transplant -> verify")
    pr.add_argument("before"); pr.add_argument("after"); pr.add_argument("corpus")
    pr.add_argument("--out", default=None); pr.set_defaults(fn=cmd_run)

    ph = sub.add_parser("hunt", help="find real descendants on GitHub via Code Search")
    ph.add_argument("vuln", nargs="?", default=None, help="optional vulnerable .c file to fingerprint")
    ph.add_argument("--query", default=None, help="Code Search query override (e.g. 'foo language:c')")
    ph.add_argument("--callee", default=None, help="copy function to match when no vuln file (e.g. memcpy)")
    ph.add_argument("--size-arg", dest="size_arg", type=int, default=None)
    ph.add_argument("--lang", default="c")
    ph.add_argument("--max", type=int, default=20)
    ph.add_argument("--dates", action="store_true", help="fetch each file's last-commit date (staleness)")
    ph.set_defaults(fn=cmd_hunt)

    pc = sub.add_parser("cve", help="fingerprint a real fix commit and discriminate stale vs fixed copies")
    pc.add_argument("--repo", required=True, help="e.g. nothings/stb")
    pc.add_argument("--sha", required=True, help="the fix commit SHA")
    pc.add_argument("--path", default=None, help="restrict to this changed file")
    pc.add_argument("--max", type=int, default=20)
    pc.add_argument("--no-dates", action="store_true")
    pc.set_defaults(fn=cmd_cve)

    pf = sub.add_parser("fix", help="transplant a real upstream fix into a real stale copy + verify it compiles")
    pf.add_argument("--repo", required=True, help="the fix's repo, e.g. nothings/stb")
    pf.add_argument("--sha", required=True, help="the fix commit SHA")
    pf.add_argument("--fix-path", dest="fix_path", required=True, help="changed file path in the fix repo")
    pf.add_argument("--target", required=True, help="stale copy repo, e.g. woltapp/blurhash")
    pf.add_argument("--target-path", dest="target_path", required=True, help="the copy's path in the target repo")
    pf.add_argument("--marker", default=None, help="distinctive fix symbol to audit (auto-derived if omitted)")
    pf.add_argument("--define", action="append", default=None,
                    help="macro the build defines (repeatable); used to resolve #ifdefs during the audit")
    pf.add_argument("--out", default=None)
    pf.set_defaults(fn=cmd_fix)

    pm = sub.add_parser("mine", help="mine + validate candidate fix markers across copied C libraries (local git)")
    pm.add_argument("--libs", default=None, help="libraries JSON (defaults to examples/benchmark/libs.json)")
    pm.add_argument("--per-lib", dest="per_lib", type=int, default=None,
                    help="optional cap on VALID candidates per library (applied AFTER validation; default: scan all)")
    pm.add_argument("--verify", default=None, metavar="CORPUS.json",
                    help="regenerate from pinned upstream and check the corpus_hash matches CORPUS.json")
    pm.add_argument("--out", default=None)
    pm.set_defaults(fn=cmd_mine)

    pst = sub.add_parser("state", help="structured product status (add --json for a UI dashboard payload)")
    pst.add_argument("--json", action="store_true", help="emit JSON instead of a human summary")
    pst.set_defaults(fn=cmd_state)

    prp = sub.add_parser("repair", help="exact golden-attested pinned repair (stb->blurhash): 3-way merge, golden postimage gate, own-build")
    prp.add_argument("--work", default=None, help="PARENT dir; a fresh 0700 run dir is created beneath it each run (default: mitos-out/repair-run)")
    prp.add_argument("--out", default=None, help="artifact dir (default: mitos-out/real_world)")
    prp.add_argument("--force", action="store_true", help="overwrite existing artifacts in --out")
    prp.add_argument("--verbose", action="store_true", help="stream every git/build command")
    prp.add_argument("--recipe", default=None,
                     help="recipe key or unique alias (default: blurhash); must be in repair._REGISTRY")
    prp.set_defaults(fn=cmd_repair)

    pb = sub.add_parser("bench", help="benchmark real fixes against a live sample of real copies")
    pb.add_argument("--corpus", default=None, help="corpus JSON (defaults to examples/benchmark/corpus.json)")
    pb.add_argument("--sample", type=int, default=25, help="how many live copies to sample")
    pb.add_argument("--compile-sample", dest="compile_sample", type=int, default=5,
                    help="how many transplants to also compile + behaviourally check")
    pb.add_argument("--out", default=None)
    pb.set_defaults(fn=cmd_bench)

    pu = sub.add_parser("bundle", help="build a blinded randomized reviewer bundle + empty label file")
    pu.add_argument("--packets", required=True, help="review_packets.json")
    pu.add_argument("--reviewer", required=True, help="reviewer id")
    pu.add_argument("--seed", type=int, required=True, help="shuffle seed (record it for reproducibility)")
    pu.add_argument("--out", default=None)
    pu.add_argument("--force", action="store_true", help="overwrite an existing bundle/label file")
    pu.set_defaults(fn=cmd_bundle)

    pl = sub.add_parser("labels", help="validate / adjudicate reviewer label files")
    plsub = pl.add_subparsers(dest="labels_cmd", required=True)
    plv = plsub.add_parser("validate", help="validate a reviewer label file")
    plv.add_argument("file"); plv.add_argument("--packets", default=None, help="review_packets.json (checks ID set + hash)")
    plv.add_argument("--final", action="store_true", help="require every decision field populated or 'unknown'")
    plv.set_defaults(fn=cmd_labels_validate)
    pla = plsub.add_parser("adjudicate", help="compare two reviewers' decision fields")
    pla.add_argument("a"); pla.add_argument("b"); pla.add_argument("--out", default=None)
    pla.set_defaults(fn=cmd_labels_adjudicate)
    plf = plsub.add_parser("family", help="second-pass logical_family_id grouping")
    plf.add_argument("file"); plf.add_argument("--out", default=None)
    plf.set_defaults(fn=cmd_labels_family)

    pd = sub.add_parser("demo", help="run the bundled memcpy-bounds example")
    pd.add_argument("--out", default=None); pd.set_defaults(fn=cmd_demo)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
