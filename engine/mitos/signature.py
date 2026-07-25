"""analyze(): turn an upstream before->after fix into a semantic patch signature.

v0.1 recognises the single most common memory-safety fix class: a missing
bounds check inserted before a copy-like call (CWE-120/787). The signature is
callee- and position-based, NOT text-based, so it survives renaming and
reformatting in descendants. Generalising the edit model beyond this class is
the main roadmap item (see README).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict

from . import astutils as A

COPY_CALLEES = {"memcpy", "memmove", "strncpy", "strcpy", "strcat",
                "strncat", "bcopy", "wmemcpy", "memccpy"}


@dataclass
class PatchSignature:
    kind: str                # "bounds_guard"
    callee: str              # e.g. "memcpy"
    size_arg_index: int      # which argument of the call is the byte count
    dest_arg_index: int      # which argument is the destination buffer
    op: str                  # comparison operator in the guard, e.g. ">"
    error_return: str        # what the guard returns, e.g. "-1"
    upstream_func: str
    upstream_before: str
    upstream_after: str
    label: str = "CWE-120 missing bounds check before copy"

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @staticmethod
    def from_json(s: str) -> "PatchSignature":
        return PatchSignature(**json.loads(s))


class AnalyzeError(Exception):
    pass


def _guard_idents(if_stmt, src):
    """Return (list-of-identifiers-in-condition, operator, return-value-text) or None."""
    cond = if_stmt.child_by_field_name("condition")
    cons = if_stmt.child_by_field_name("consequence")
    if cond is None or cons is None:
        return None
    binexpr = None
    for n in A.walk(cond):
        if n.type == "binary_expression":
            binexpr = n
            break
    if binexpr is None:
        return None
    op_node = binexpr.child_by_field_name("operator")
    op = A.text(op_node, src) if op_node else ">"
    idents = [A.text(n, src) for n in A.walk(binexpr) if n.type == "identifier"]
    ret = None
    for n in A.walk(cons):
        if n.type == "return_statement":
            vals = [A.text(c, src) for c in n.children if c.is_named]
            ret = vals[0] if vals else "-1"
            break
    if ret is None:
        return None
    return idents, op, ret


SIZE_ARG = {"memcpy": 2, "memmove": 2, "memccpy": 3, "strncpy": 2, "strncat": 2,
            "bcopy": 2, "wmemcpy": 2}


def signature_from_vuln(vuln_src) -> PatchSignature:
    """Build a discovery-only signature from a vulnerable function alone (no fix).

    Enough to classify descendants (callee + which arg is the size) and to measure
    lineage; the guard template (op/return) is only needed for transplant, so we
    leave conservative defaults. Used by `mitos hunt`.
    """
    funcs = A.extract_functions(vuln_src)
    if not funcs:
        raise AnalyzeError("could not parse a function from the vulnerable source")
    f = funcs[0]
    call = next((c for c in f.calls() if c.callee in COPY_CALLEES), None)
    if call is None:
        raise AnalyzeError("no copy-like call found in the vulnerable function")
    idx = SIZE_ARG.get(call.callee, len(call.args) - 1)
    return PatchSignature(
        kind="bounds_guard", callee=call.callee, size_arg_index=idx, dest_arg_index=0,
        op=">", error_return="-1", upstream_func=f.name,
        upstream_before=A.text(f.node, f.src), upstream_after="",
    )


def analyze(before_src, after_src) -> PatchSignature:
    fb = A.extract_functions(before_src)
    fa = A.extract_functions(after_src)
    if not fb or not fa:
        raise AnalyzeError("could not parse a function from before/after")
    fb, fa = fb[0], fa[0]

    before_norm = [" ".join(A.normalize_tokens(s, fb.src)) for s in fb.statements()]
    after_stmts = fa.statements()

    # Find statements present in `after` but not in `before` (the inserted fix).
    remaining = list(before_norm)
    inserted = []
    for s in after_stmts:
        key = " ".join(A.normalize_tokens(s, fa.src))
        if key in remaining:
            remaining.remove(key)
        else:
            inserted.append(s)

    guard = next((s for s in inserted if s.type == "if_statement"), None)
    if guard is None:
        raise AnalyzeError("no inserted guard (if-statement) found between before and after")

    g = _guard_idents(guard, fa.src)
    if g is None:
        raise AnalyzeError("inserted if-statement is not a recognisable bounds guard")
    idents, op, ret = g

    # The anchor: the copy call the guard protects.
    call = next((c for c in fa.calls() if c.callee in COPY_CALLEES), None)
    if call is None:
        raise AnalyzeError("no copy-like call found to anchor the guard to")

    size_ident = next((i for i in idents if i in call.args), None)
    if size_ident is None:
        raise AnalyzeError("guard condition does not reference any argument of the copy call")
    size_arg_index = call.args.index(size_ident)

    return PatchSignature(
        kind="bounds_guard",
        callee=call.callee,
        size_arg_index=size_arg_index,
        dest_arg_index=0,     # convention for copy(dst, src, n); refined at transplant time
        op=op,
        error_return=ret,
        upstream_func=fa.name,
        upstream_before=A.text(fb.node, fb.src),
        upstream_after=A.text(fa.node, fa.src),
    )
