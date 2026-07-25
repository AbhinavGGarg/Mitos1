"""A benchmark of real fixes against real copies — honest metrics, not a hero example.

Two stages over a live, de-duplicated sample of real GitHub copies of a widely-copied file:

  1. Marker-absence: for each real fix (a distinctive symbol it introduced), what
     fraction of copies lack it? Judged from each copy's own bytes. This is a
     *marker-absence rate*, NOT a precision or exploitability claim.
  2. Syntactic placement pass: transplant one fix into every applicable copy and run
     the static placement audit — every inserted line must be live code (not comment,
     not #if 0 dead, not an unresolved #ifdef) AND inside the function the upstream
     hunk targeted. This measures wrong-function / dead-code insertions across dozens
     of independently-drifted copies. It is a *static* pass, not behavioural proof.

Copies are de-duplicated by content hash (byte-identical vendored copies are not
independent) and each is recorded with repo, path, blob SHA, and hash. Ground-truth
labels are left null for manual verification. Uses only reliable primitives
(Code Search + contents).
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass

from . import ghsearch, applyfix, behavioral


@dataclass
class Copy:
    repo: str
    path: str
    text: str
    date: str | None
    blob_sha: str
    content_hash: str


def fetch_copies(query: str, sample: int, want_dates=True, verbose=lambda *_: None):
    hits = ghsearch.search_code(query, max_results=sample * 3, verbose=verbose)
    copies, seen = [], set()
    for h in hits:
        if len(copies) >= sample:
            break
        src = ghsearch.fetch_source(h)
        if src is None:
            continue
        digest = hashlib.sha256(src).hexdigest()
        if digest in seen:                       # byte-identical copy → not an independent data point
            continue
        seen.add(digest)
        date = ghsearch.file_last_commit_iso(h.repo, h.path) if want_dates else None
        copies.append(Copy(h.repo, h.path, src.decode("utf8", "replace"), date, h.ref, digest[:12]))
    return copies


def marker_absence(copies, fixes):
    rows = []
    for fx in fixes:
        m = fx["marker"]
        absent = [c for c in copies if m not in c.text]
        corrob = None
        if fx.get("fix_date"):
            corrob = sum(1 for c in absent if c.date and c.date[:10] < fx["fix_date"])
        rows.append({"marker": m, "desc": fx.get("desc", ""),
                     "absent": len(absent), "present": len(copies) - len(absent),
                     "absence_rate": round(len(absent) / max(len(copies), 1), 3),
                     "predate_corroboration": corrob})
    return rows


def transplant_precision(copies, patch, marker, compile_sample, workdir, defined=frozenset()):
    results, compiled = [], 0
    for c in copies:
        base = {"repo": c.repo, "blob_sha": c.blob_sha}
        if marker in c.text:
            results.append({**base, "status": "already_fixed"}); continue
        patched, sites, inserted = applyfix.apply_fix(c.text, patch, defined)
        applied = [s for s in sites if s.status == "applied"]
        if not applied:
            results.append({**base, "status": "no_sites_applied"}); continue
        ok, recs = applyfix.audit_placement(patched, inserted, defined)
        wrong_fn = sum(1 for r in recs if (r.get("reason") or "").startswith("wrong function"))
        rec = {**base, "status": "placement_pass" if ok else "placement_fail",
               "sites": len(applied), "inserted": len(recs),
               "misplaced": sum(1 for r in recs if not r["ok"]), "wrong_function": wrong_fn,
               "expected_funcs": sorted({r["expected_func"] for r in recs if r.get("expected_func")})}
        if compiled < compile_sample:
            okb, _ = applyfix.compile_header(c.text, workdir, "b", defined)
            oka, _ = applyfix.compile_header(patched, workdir, "a", defined)
            beh = behavioral.verify(c.text, patched, workdir, marker, defined)
            rec["compiles"] = bool(okb and oka)
            rec["behavioural_fires"] = bool(beh.ran and beh.fires_only_after)
            compiled += 1
        results.append(rec)
    return results


def summarize_transplant(results):
    applicable = [r for r in results if r["status"] in ("placement_pass", "placement_fail")]
    return {
        "already_fixed": sum(1 for r in results if r["status"] == "already_fixed"),
        "no_sites": sum(1 for r in results if r["status"] == "no_sites_applied"),
        "applicable": len(applicable),
        "placement_pass": sum(1 for r in applicable if r["status"] == "placement_pass"),
        "placement_fail": sum(1 for r in applicable if r["status"] == "placement_fail"),
        "wrong_function_insertions": sum(r.get("wrong_function", 0) for r in applicable),
        "compiled": sum(1 for r in results if r.get("compiles")),
        "behavioural_fired": sum(1 for r in results if r.get("behavioural_fires")),
    }


def run(corpus, sample, compile_sample, verbose=lambda *_: None):
    copies = fetch_copies(corpus["discovery_query"], sample, verbose=verbose)
    fixes = corpus["fixes"]
    absence = marker_absence(copies, fixes)

    transplant = None
    patch_fix = next((f for f in fixes if f.get("transplant_patch")), None)
    if patch_fix and copies:
        patch = open(os.path.join(corpus["_dir"], patch_fix["transplant_patch"])).read()
        defined = frozenset(corpus.get("build_defines", []))
        results = transplant_precision(copies, patch, patch_fix["marker"], compile_sample,
                                       tempfile.mkdtemp(), defined)
        transplant = {"marker": patch_fix["marker"], "results": results, "summary": summarize_transplant(results)}

    total = len(copies) * len(fixes)
    total_absent = sum(r["absent"] for r in absence)
    return {
        "library": corpus.get("library", ""),
        "copies_scanned": len(copies), "fixes": len(fixes), "total_judgments": total,
        "total_marker_absent": total_absent,
        "overall_marker_absence_rate": round(total_absent / max(total, 1), 3),
        "copies": [{"repo": c.repo, "path": c.path, "blob_sha": c.blob_sha,
                    "content_hash": c.content_hash, "last_commit": c.date, "ground_truth": None} for c in copies],
        "marker_absence": absence,
        "transplant_precision": transplant,
    }
