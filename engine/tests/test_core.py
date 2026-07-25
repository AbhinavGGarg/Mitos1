"""End-to-end + unit checks for the v0.1 transplant core."""
import os
from pathlib import Path

import pytest

from mitos.signature import analyze
from mitos.discover import scan_corpus, STALE, IMMUNE, NO_MATCH
from mitos.transplant import transplant
from mitos.verify import verify

EX = Path(__file__).resolve().parents[1] / "examples" / "memcpy_bounds"
BEFORE = (EX / "upstream_before.c").read_bytes()
AFTER = (EX / "upstream_after.c").read_bytes()


def sig():
    return analyze(BEFORE, AFTER)


def test_signature_extraction():
    s = sig()
    assert s.callee == "memcpy"
    assert s.size_arg_index == 2      # memcpy(buf, data, data_len)
    assert s.op == ">"
    assert s.error_return == "-1"


def test_classification():
    s = sig()
    by_name = {d.func.name: d for d in scan_corpus(str(EX / "corpus"), s)}
    assert by_name["save_blob"].status == STALE
    assert by_name["append_chunk"].status == STALE
    assert by_name["store_thing"].status == IMMUNE      # already guarded
    assert by_name["log_line"].status == NO_MATCH       # no memcpy


def test_transplant_adapts_names():
    s = sig()
    d = {x.func.name: x for x in scan_corpus(str(EX / "corpus"), s)}["append_chunk"]
    p = transplant(d, s)
    assert p.conflict is None
    # capacity must resolve to the drifted local name, not the upstream one
    assert p.mapping["capacity"] == "dstbuf_len"
    assert "chunk_len > dstbuf_len" in p.guard_line


def test_reordered_params_resolve():
    s = sig()
    d = {x.func.name: x for x in scan_corpus(str(EX / "corpus"), s)}["save_blob"]
    p = transplant(d, s)
    assert p.conflict is None
    assert p.mapping["capacity"] == "cap"       # reordered params, still resolved
    assert "n > cap" in p.guard_line


@pytest.mark.parametrize("name", ["save_blob", "append_chunk"])
def test_verified_under_asan(name):
    s = sig()
    d = {x.func.name: x for x in scan_corpus(str(EX / "corpus"), s)}[name]
    p = transplant(d, s)
    ev = verify(d, p, s)
    assert ev.before_overflow, ev.detail
    assert not ev.after_overflow, ev.detail
    assert ev.passed, ev.detail
