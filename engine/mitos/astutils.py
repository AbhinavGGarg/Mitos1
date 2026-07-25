"""Thin tree-sitter layer for C: parse, extract functions/params/calls, normalize.

Deliberately small. Everything downstream (signature, discover, transplant) speaks
in terms of the dataclasses here so we never touch raw tree-sitter nodes elsewhere.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tree_sitter import Language, Parser
import tree_sitter_c

_C = Language(tree_sitter_c.language())
_PARSER = Parser(_C)

INT_TYPE_HINTS = ("size_t", "ssize_t", "int", "unsigned", "long", "short",
                  "uint", "uintptr", "off_t", "uint8_t", "uint16_t",
                  "uint32_t", "uint64_t", "u32", "u64", "usize")


def parse(src) -> "object":
    if isinstance(src, str):
        src = src.encode()
    return _PARSER.parse(src)


def text(node, src) -> str:
    if isinstance(src, str):
        src = src.encode()
    return src[node.start_byte:node.end_byte].decode("utf8", "replace")


def walk(node):
    """Depth-first over every node in the subtree."""
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def _first_identifier(node):
    for n in walk(node):
        if n.type == "identifier":
            return n
    return None


@dataclass
class Param:
    name: str
    type: str          # e.g. "char *", "const uint8_t *", "size_t"
    pointer: bool
    index: int

    @property
    def is_int(self) -> bool:
        t = self.type.lower()
        return (not self.pointer) and any(h in t for h in INT_TYPE_HINTS)


@dataclass
class Call:
    callee: str
    args: list          # list[str] — argument source texts
    node: object        # call_expression
    stmt: object        # the statement (direct child of the body) containing it


@dataclass
class Func:
    name: str
    src: bytes
    node: object        # function_definition
    body: object        # compound_statement
    params: list        # list[Param]

    def text(self) -> str:
        return text(self.node, self.src)

    def body_text(self) -> str:
        return text(self.body, self.src)

    def statements(self) -> list:
        """Direct child statements/declarations of the function body, in order."""
        out = []
        for c in self.body.children:
            if c.is_named and (c.type.endswith("statement") or c.type.endswith("declaration")):
                out.append(c)
        return out

    def calls(self, callee: str | None = None) -> list:
        out = []
        for n in walk(self.body):
            if n.type != "call_expression":
                continue
            fn = n.child_by_field_name("function")
            if fn is None or fn.type != "identifier":
                continue
            name = text(fn, self.src)
            if callee is not None and name != callee:
                continue
            arglist = n.child_by_field_name("arguments")
            args = [text(a, self.src) for a in arglist.children if a.is_named] if arglist else []
            out.append(Call(callee=name, args=args, node=n, stmt=self._enclosing_stmt(n)))
        return out

    def _enclosing_stmt(self, node):
        """Walk up until the node whose parent is the function body."""
        cur = node
        while cur is not None and cur.parent is not None and cur.parent.id != self.body.id:
            cur = cur.parent
        return cur

    def param_by_name(self, name: str) -> Param | None:
        for p in self.params:
            if p.name == name:
                return p
        return None


def _param_from_decl(decl, src, index: int) -> Param | None:
    """decl is a parameter_declaration node."""
    declarator = decl.child_by_field_name("declarator")
    pointer = False
    name = ""
    if declarator is not None:
        pointer = any(n.type == "pointer_declarator" for n in walk(declarator))
        ident = _first_identifier(declarator)
        name = text(ident, src) if ident else ""
    # Type text = everything in the declaration except the declarator's identifier.
    tnode = decl.child_by_field_name("type")
    parts = []
    for c in decl.children:
        if declarator is not None and c.id == declarator.id:
            if pointer:
                parts.append("*")
            continue
        parts.append(text(c, src))
    type_str = " ".join(p for p in parts if p).replace(" *", " *").strip()
    if not type_str and tnode is not None:
        type_str = text(tnode, src)
    if not name:
        return None
    return Param(name=name, type=type_str, pointer=pointer, index=index)


def extract_functions(src) -> list:
    """All function *definitions* (not prototypes) in the source, top to bottom."""
    if isinstance(src, str):
        src = src.encode()
    tree = parse(src)
    funcs = []
    for n in walk(tree.root_node):
        if n.type != "function_definition":
            continue
        body = n.child_by_field_name("body")
        # find the function_declarator to get name + params
        fdecl = None
        for d in walk(n):
            if d.type == "function_declarator":
                fdecl = d
                break
        if fdecl is None or body is None:
            continue
        ident = fdecl.child_by_field_name("declarator") or _first_identifier(fdecl)
        name = text(ident, src) if ident else "?"
        params = []
        plist = fdecl.child_by_field_name("parameters")
        if plist is not None:
            i = 0
            for c in plist.children:
                if c.type == "parameter_declaration":
                    p = _param_from_decl(c, src, i)
                    if p is not None:
                        params.append(p)
                    i += 1
        funcs.append(Func(name=name, src=src, node=n, body=body, params=params))
    return funcs


def normalize_tokens(node, src) -> list:
    """Structural token stream: identifiers collapsed to ID, everything else literal.

    Used for lineage similarity and 'is this statement the same shape' checks —
    robust to renaming and reformatting.
    """
    toks = []
    for n in walk(node):
        if n.child_count == 0:  # leaf
            if n.type == "identifier":
                toks.append("ID")
            else:
                t = text(n, src).strip()
                if t:
                    toks.append(t)
    return toks


def jaccard(a: list, b: list) -> float:
    from collections import Counter
    ca, cb = Counter(a), Counter(b)
    inter = sum((ca & cb).values())
    union = sum((ca | cb).values())
    return inter / union if union else 0.0
