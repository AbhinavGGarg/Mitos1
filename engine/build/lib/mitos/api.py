"""Structured, JSON-first status surface — one call a UI can render a dashboard from,
without scraping ANSI terminal output.

Everything here is **read-only over committed artifacts** and does no network I/O, so a
frontend can call `product_state()` (or `python -m mitos state --json`) reliably. The
live flows a UI drives directly:

    mitos.repair.run_repair(recipe_key, work_parent)  -> the exact golden-attested pinned repair (evidence dict)
    mitos.cve.discriminate(fingerprint, ...)          -> discovery: stale-vs-fixed copies in the wild

Both already return plain dataclasses/dicts; this module summarises the *committed* results
so a dashboard has something to show before any live run.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def _load(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def flagship_repair() -> dict | None:
    """The committed, cold-run, exact golden-attested pinned repair (`examples/real_world`).
    Acceptance rests on the golden expected-postimage hash; positional per-hunk checking is an
    experimental cross-check, not a general proof."""
    e = _load(EXAMPLES / "real_world" / "evidence.json")
    if not e:
        return None
    cert, cov, m = e.get("hunk_certification", {}), e.get("coverage", {}), e.get("merge", {})
    up, dn, ga = e.get("upstream", {}), e.get("downstream", {}), e.get("golden_attestation", {})
    return {
        "kind": "exact golden-attested pinned repair (not a general transplant proof)",
        "verdict": e.get("verdict"),
        "reasons": e.get("reasons", []),
        "golden_attestation": {"attested": ga.get("attested"), "merged_match": ga.get("merged_match"),
                               "fix_diff_match": ga.get("fix_diff_match"),
                               "expected_merged_sha256": ga.get("expected_merged_sha256")},
        "target": {"downstream_repo": dn.get("repo"), "path": dn.get("path"), "pinned_sha": dn.get("sha"),
                   "upstream_repo": up.get("repo"), "fix": up.get("fix")},
        "merge": {"returncode": m.get("returncode"), "conflicts": m.get("conflicts"), "clean": m.get("clean"),
                  "marker": m.get("marker"), "marker_before": m.get("marker_before"),
                  "marker_after": m.get("marker_after")},
        "positional_cross_check": {"total": cert.get("upstream_hunks"), "passed": cert.get("verified"),
                                   "experimental": True,
                                   "note": ("the golden expected-postimage hash is the authoritative guarantee; "
                                            "this per-hunk check is an experimental cross-check")},
        "coverage": {"structurally_merged": cov.get("structurally_merged_count"),
                     "reachable_loaders": cov.get("reachable_loaders", []),
                     "behaviourally_verified": cov.get("behaviourally_verified_loaders", [])},
        "builds": {"baseline": (e.get("baseline_build") or {}).get("status"),
                   "patched": (e.get("patched_build") or {}).get("status")},
        "probes": [{"name": p.get("name"), "loader": p.get("loader"), "ok": p.get("ok"),
                    "detail": p.get("detail")} for p in e.get("probes", [])],
        "provenance": {"generator_commit": e.get("generator_commit"), "recipe_digest": e.get("recipe_digest"),
                       "reproduce": e.get("verification_command"), "evidence_sha256": e.get("evidence_sha256")},
        "artifacts": {name: str((EXAMPLES / "real_world" / name).relative_to(ROOT))
                      for name in ("fix.diff", "evidence.json", "PR_BODY.md", "full_command_log.txt")},
    }


def benchmark() -> dict:
    """The frozen benchmark + mined-corpus summary (read-only; never regenerated here)."""
    r = _load(EXAMPLES / "benchmark" / "results.json") or {}
    c = _load(EXAMPLES / "benchmark" / "mined_corpus.json") or {}
    s = c.get("summary", {})
    tp = (r.get("transplant_precision") or {}).get("summary", {})
    return {
        "library": r.get("library"),
        "copies_scanned": r.get("copies_scanned"),
        "marker_absence_rate": r.get("overall_marker_absence_rate"),
        "checks_absent": r.get("total_marker_absent"),
        "checks_total": r.get("total_judgments"),
        "syntactic_placement_pass": tp.get("placement_pass"),
        "syntactic_placement_applicable": tp.get("applicable"),
        "mined": {"candidates_examined": s.get("candidates_examined"),
                  "mechanically_valid": s.get("mechanically_valid_marker_candidates"),
                  "independent_repos": s.get("independent_repos_with_valid"),
                  "unique_patch_ids": s.get("unique_patch_ids")},
        "ground_truth": "null — requires two blinded human reviewers + adjudication; an AI must not assign labels",
    }


def human_gated() -> list:
    """Human-gated items that Mitos deliberately does not automate (not an exhaustive product
    roadmap — building a general transplant engine beyond this exact pinned repair is separate,
    open-ended work)."""
    return [
        {"item": "benchmark ground truth", "status": "pending", "owner": "human",
         "detail": ("Two blinded reviewers label the frozen packets (`mitos bundle` → fill → "
                    "`mitos labels validate/adjudicate`). Precision claims stay unproven until then. "
                    "An AI must not fill any label.")},
        {"item": "external PR to the downstream", "status": "pending", "owner": "human",
         "detail": ("Mitos generates a reviewable PR_BODY.md but opens no external PR. Publishing the "
                    "upstream PR requires the owner's explicit greenlight (repo is private).")},
    ]


def product_state() -> dict:
    """One dashboard payload for a UI: the exact golden-attested pinned repair, the benchmark, and
    what's human-gated."""
    return {
        "product": "Mitos — Dependabot for copied, vendored, and AI-derived code with no manifest",
        "flagship_repair": flagship_repair(),
        "benchmark": benchmark(),
        "human_gated": human_gated(),
        "engine": {
            "verified_repair": "mitos repair",
            "discovery": "mitos cve --repo … --sha … / mitos hunt",
            "benchmark": "mitos bench / mitos mine",
            "labeling": "mitos bundle / mitos labels",
        },
    }
