"""discover(): given a patch signature, find descendants of the vulnerable code.

For each function in the corpus we ask three questions:
  1. Does it contain the vulnerable call pattern?      (else NO_MATCH)
  2. Is it already guarded before that call?            (then IMMUNE — skip)
  3. How likely is it descended from the upstream code? (lineage score)
Anything vulnerable and un-guarded is STALE and gets a transplant.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from . import astutils as A
from .signature import PatchSignature

STALE, IMMUNE, NO_MATCH = "STALE", "IMMUNE", "NO_MATCH"


@dataclass
class Descendant:
    path: str
    func: A.Func
    call: A.Call | None
    status: str
    lineage: float
    reason: str = ""


_RELATIONAL = {">", ">=", "<", "<="}


def _already_guarded(func: A.Func, call: A.Call, size_ident: str) -> bool:
    """Is there a real bounds guard on `size_ident` before the copy call?

    A guard is an if-statement, before the call, that *relationally* compares the
    size against something and bails out (returns). We specifically reject
    equality fast-paths like `if (len == 0) return 0;`, which mention the size and
    return but are not bounds checks — the bug that made every fast-path look immune.
    """
    stmts = func.statements()
    try:
        call_idx = next(i for i, s in enumerate(stmts) if s.id == call.stmt.id)
    except StopIteration:
        return False
    for s in stmts[:call_idx]:
        if s.type != "if_statement":
            continue
        if not any(n.type == "return_statement" for n in A.walk(s)):
            continue
        for n in A.walk(s):
            if n.type != "binary_expression":
                continue
            op = n.child_by_field_name("operator")
            if op is None or A.text(op, func.src) not in _RELATIONAL:
                continue
            idents = [A.text(k, func.src) for k in A.walk(n) if k.type == "identifier"]
            if size_ident in idents:
                return True
    return False


def classify(func: A.Func, sig: PatchSignature, upstream_tokens: list) -> Descendant:
    lineage = A.jaccard(A.normalize_tokens(func.body, func.src), upstream_tokens)
    calls = func.calls(sig.callee)
    if not calls:
        return Descendant(path="", func=func, call=None, status=NO_MATCH,
                          lineage=lineage, reason=f"no call to {sig.callee}()")
    call = calls[0]
    if sig.size_arg_index >= len(call.args):
        return Descendant(path="", func=func, call=call, status=NO_MATCH,
                          lineage=lineage, reason="call arity does not match signature")
    size_ident = call.args[sig.size_arg_index]
    if _already_guarded(func, call, size_ident):
        return Descendant(path="", func=func, call=call, status=IMMUNE,
                          lineage=lineage, reason="already guarded before copy")
    return Descendant(path="", func=func, call=call, status=STALE,
                      lineage=lineage, reason="unguarded copy — descendant is stale")


def scan_corpus(corpus_dir: str, sig: PatchSignature) -> list:
    upstream_funcs = A.extract_functions(sig.upstream_before)
    upstream_tokens = A.normalize_tokens(upstream_funcs[0].body, upstream_funcs[0].src) if upstream_funcs else []
    out = []
    for root, _, files in os.walk(corpus_dir):
        for fn in sorted(files):
            if not fn.endswith((".c", ".h", ".cc", ".cpp")):
                continue
            path = os.path.join(root, fn)
            with open(path, "rb") as fh:
                src = fh.read()
            for func in A.extract_functions(src):
                d = classify(func, sig, upstream_tokens)
                d.path = path
                out.append(d)
    return out
