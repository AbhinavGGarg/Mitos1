"""transplant(): splice the upstream fix into a descendant, adapted to its context.

The whole point of Mitos over a naive text patch: we resolve the *roles* the
guard needs (the byte-count expression, and the destination's capacity) against
the descendant's own identifiers — so a copy that was renamed and reordered still
gets a correct guard. If we cannot resolve the capacity confidently we emit a
NEEDS_REVIEW conflict rather than a wrong patch (precision over recall).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import astutils as A
from .discover import Descendant
from .signature import PatchSignature

CAP_NAME_HINTS = ("size", "len", "cap", "capacity", "max", "bytes", "avail", "space", "sz", "n")


@dataclass
class Patch:
    path: str
    func_name: str
    original: str
    patched: str
    guard_line: str
    mapping: dict
    confidence: float
    conflict: str | None = None      # None == clean, applies without manual edits


def _resolve_capacity(func: A.Func, dest_name: str, size_name: str):
    """Find the parameter that represents the capacity of the destination buffer.

    Strategy order (each explains itself in the returned reason):
      1. integer param whose name is clearly related to the dest name
      2. integer param whose name looks like a size/capacity word
      3. the sole remaining integer param (after excluding the size arg)
    """
    ints = [p for p in func.params if p.is_int and p.name != size_name]
    if not ints:
        return None, "no candidate capacity parameter"
    base = dest_name.rstrip("_")
    for p in ints:
        if p.name.startswith(base) or base in p.name or p.name.rstrip("_").endswith(base):
            return p.name, f"name-matched destination '{dest_name}'"
    named = [p for p in ints if any(h in p.name.lower() for h in CAP_NAME_HINTS)]
    if len(named) == 1:
        return named[0].name, "sole size/capacity-named parameter"
    if len(ints) == 1:
        return ints[0].name, "sole remaining integer parameter"
    return None, f"ambiguous capacity: {[p.name for p in ints]}"


def _indent_of(func: A.Func, stmt) -> str:
    src = func.src if isinstance(func.src, str) else func.src.decode("utf8", "replace")
    line_start = src.rfind("\n", 0, stmt.start_byte) + 1
    prefix = src[line_start:stmt.start_byte]
    return prefix[:len(prefix) - len(prefix.lstrip())] or "    "


def transplant(desc: Descendant, sig: PatchSignature) -> Patch:
    func = desc.func
    call = desc.call
    src = func.src.decode("utf8", "replace") if isinstance(func.src, bytes) else func.src

    size_expr = call.args[sig.size_arg_index]
    dest_expr = call.args[sig.dest_arg_index] if sig.dest_arg_index < len(call.args) else call.args[0]
    cap_name, reason = _resolve_capacity(func, dest_expr, size_expr)

    indent = _indent_of(func, call.stmt)
    mapping = {"size": size_expr, "dest": dest_expr, "capacity": cap_name,
               "capacity_reason": reason, "callee": sig.callee}

    if cap_name is None:
        # We know it's vulnerable but can't place a correct guard automatically.
        return Patch(path=desc.path, func_name=func.name, original=src, patched=src,
                     guard_line="", mapping=mapping, confidence=0.0,
                     conflict=f"NEEDS_REVIEW: {reason}")

    guard = f"if ({size_expr} {sig.op} {cap_name})\n{indent}    return {sig.error_return};"
    guard_line = f"if ({size_expr} {sig.op} {cap_name}) return {sig.error_return};"

    insert_at = call.stmt.start_byte
    patched = src[:insert_at] + guard + "\n" + indent + src[insert_at:]

    # confidence: lineage-weighted, discounted for weaker capacity resolution
    conf = 0.6 + 0.4 * desc.lineage
    if reason.startswith("name-matched"):
        conf = min(1.0, conf + 0.1)
    elif reason.startswith("sole remaining"):
        conf -= 0.1
    return Patch(path=desc.path, func_name=func.name, original=src, patched=patched,
                 guard_line=guard_line, mapping=mapping, confidence=round(min(conf, 0.99), 2),
                 conflict=None)
