"""Offline tests for behavioural verification's decision logic + probe input.

The live probe compiles stb and runs it (exercised by `mitos fix`); here we lock
the pure interpretation so 'guard fires only after the patch' can't silently rot.
"""
import struct

from mitos.behavioral import interpret, oversized_bmp


def test_guard_fires_only_after_when_original_accepts():
    # original accepted the attack; patched rejected it via the dimension guard
    fires, _ = interpret("ACCEPTED|", "REJECTED|too large")
    assert fires is True


def test_not_a_change_if_both_reject_the_same_way():
    fires, _ = interpret("REJECTED|too large", "REJECTED|too large")
    assert fires is False


def test_not_fired_if_after_rejects_for_unrelated_reason():
    # patched rejected, but not via the guard — do not claim behavioural proof
    fires, _ = interpret("ACCEPTED|", "REJECTED|outofmem")
    assert fires is False


def test_still_counts_if_before_rejected_for_a_different_reason():
    # the guard changed *why* it fails: unrelated failure before, guard after
    fires, _ = interpret("REJECTED|corrupt BMP", "REJECTED|too large")
    assert fires is True


def test_probe_declares_oversized_width():
    data = oversized_bmp()
    assert data[:2] == b"BM"
    width = struct.unpack_from("<i", data, 18)[0]
    assert width > (1 << 24)          # exceeds STBI_MAX_DIMENSIONS
    height = struct.unpack_from("<i", data, 22)[0]
    assert width * height * 4 < 2**31  # product doesn't overflow → reaches the guard, not the mul-check
