"""Marker-free staleness detection by function-level similarity.

Marker detection only works when a fix introduces a durable identifier. Many real security
fixes are pure logic changes — an added bounds test, a loop guard, a reordered check — and
introduce no new symbol at all. For those, there is nothing to grep for.

This module decides differently. For each function the upstream fix modified, it holds the
BEFORE and AFTER token shapes. Given a candidate copy, it finds the same function and asks
which shape it resembles more. A copy that matches BEFORE is stale; one that matches AFTER
carries the fix.

Tokens come from `astutils.normalize_tokens`, which collapses identifiers to ID and keeps
structure, so the comparison survives renaming and reformatting.

Deliberate conservatism: when the two sides are too close to separate, the answer is
INDETERMINATE rather than a guess. A false finding is worse than no finding.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import astutils as A

STALE, PATCHED, INDETERMINATE, ABSENT = "STALE", "PATCHED", "INDETERMINATE", "ABSENT"

# The fix must move a function's shape at least this much for the comparison to carry any
# signal at all. Deliberately low: a real CVE fix can be an 8-line guard inside a 3,400-token
# function (miniz tinfl_decompress moves by 0.0087), and a fixed 2% bar discards those.
MIN_FIX_DELTA = 0.002

# How decisive a copy's lean must be, as a FRACTION of how far the fix moved the function.
# An absolute margin cannot work across libraries: the same 0.005 is emphatic for a small
# fix and meaningless for a large one. Scaling to the fix's own delta makes the test
# self-calibrating. Measured on miniz: a correct verdict lands at ~1.0x delta, and versions
# that drifted further still lean the right way at ~0.2x.
MARGIN_FRACTION_OF_DELTA = 0.15

# Floor, so a fix that barely moves anything cannot produce confident verdicts from rounding.
MIN_ABSOLUTE_MARGIN = 0.0005


@dataclass
class ChangedFunc:
    name: str
    before: list          # normalized tokens, pre-fix
    after: list           # normalized tokens, post-fix
    delta: float          # 1 - jaccard(before, after); how much the fix moved this function


@dataclass
class Verdict:
    func: str
    status: str
    sim_before: float
    sim_after: float
    margin: float

    def __str__(self):
        return (f"{self.func:28} {self.status:14} "
                f"before={self.sim_before:.3f} after={self.sim_after:.3f} "
                f"margin={self.margin:+.3f}")


def _tokens_by_name(src: bytes) -> dict:
    out = {}
    for f in A.extract_functions(src):
        # a file may define the same name twice under different #ifdef branches; keep the
        # longest body, which is the one a copy is most likely to carry
        toks = A.normalize_tokens(f.body, f.src)
        if f.name not in out or len(toks) > len(out[f.name]):
            out[f.name] = toks
    return out


def changed_functions(before_src: bytes, after_src: bytes) -> list:
    """Functions whose shape the fix actually moved, most-moved first."""
    b, a = _tokens_by_name(before_src), _tokens_by_name(after_src)
    out = []
    for name in b.keys() & a.keys():
        delta = 1.0 - A.jaccard(b[name], a[name])
        if delta >= MIN_FIX_DELTA:
            out.append(ChangedFunc(name, b[name], a[name], delta))
    return sorted(out, key=lambda c: c.delta, reverse=True)


def classify(copy_src: bytes, changed: list) -> list:
    """Verdict per changed function found in the copy."""
    copy = _tokens_by_name(copy_src)
    verdicts = []
    for cf in changed:
        toks = copy.get(cf.name)
        if toks is None:
            verdicts.append(Verdict(cf.name, ABSENT, 0.0, 0.0, 0.0))
            continue
        sb = A.jaccard(toks, cf.before)
        sa = A.jaccard(toks, cf.after)
        margin = sa - sb
        # required lean scales with how far this particular fix moved the function
        need = max(MIN_ABSOLUTE_MARGIN, MARGIN_FRACTION_OF_DELTA * cf.delta)
        if abs(margin) < need:
            status = INDETERMINATE
        else:
            status = PATCHED if margin > 0 else STALE
        verdicts.append(Verdict(cf.name, status, sb, sa, margin))
    return verdicts


def verdict(copy_src: bytes, changed: list) -> tuple:
    """Whole-file call: (status, evidence).

    STALE if any decidable function matches BEFORE and none matches AFTER.
    PATCHED if any matches AFTER and none matches BEFORE.
    Disagreement or no decidable function yields INDETERMINATE — the copy has drifted
    far enough that similarity cannot separate the two versions honestly.
    """
    vs = classify(copy_src, changed)
    decidable = [v for v in vs if v.status in (STALE, PATCHED)]
    if not decidable:
        return INDETERMINATE, vs
    stale = [v for v in decidable if v.status == STALE]
    patched = [v for v in decidable if v.status == PATCHED]
    if stale and not patched:
        return STALE, vs
    if patched and not stale:
        return PATCHED, vs
    # both — trust the function the fix moved most, since it carries the most signal
    strongest = max(decidable, key=lambda v: abs(v.margin))
    return strongest.status, vs
