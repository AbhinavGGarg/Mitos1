"""Behavioural verification: prove a transplanted guard changes behaviour on a
malicious input — not merely that it compiles and sits in executable code.

The audit in applyfix.py proves a guard is *reachable code*. This proves it
*fires*: we feed the copy an input crafted to trip the guard, run it before and
after the patch, and confirm the original accepts the attack while the patched
copy rejects it via the guard.

Probes are (today) hand-written per fix class. We ship one: the stb-image
oversized-dimensions hardening (`STBI_MAX_DIMENSIONS`), driven by a crafted BMP
whose width exceeds the limit. Auto-synthesising adversarial inputs for arbitrary
fixes is future work — so a fix without a registered probe is reported as
placement-verified only, never silently upgraded.
"""
from __future__ import annotations

import os
import struct
import subprocess
from dataclasses import dataclass

_HARNESS = '''#include "hdr.h"
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    if (!f) { printf("OPENFAIL|\\n"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = (unsigned char *) malloc(n);
    if (fread(b, 1, n, f) != (size_t) n) { /* ok for a header-only probe */ }
    fclose(f);
    int x = 0, y = 0, c = 0;
    unsigned char *img = stbi_load_from_memory(b, (int) n, &x, &y, &c, 0);
    const char *r = stbi_failure_reason();
    printf("%s|%s\\n", img ? "ACCEPTED" : "REJECTED", r ? r : "");
    return 0;
}
'''


@dataclass
class BehaviorResult:
    ran: bool
    probe: str
    before: str          # "ACCEPTED|reason" / "REJECTED|reason"
    after: str
    fires_only_after: bool
    detail: str = ""


def oversized_bmp() -> bytes:
    """A 54-byte BMP header claiming width 20,000,000 (> 1<<24) — no pixel data.
    Product w*h*c does not overflow, so it slips past stb's multiply checks and
    reaches the STBI_MAX_DIMENSIONS guard specifically."""
    w, h = 20_000_000, 1
    file_hdr = b"BM" + struct.pack("<I", 54) + struct.pack("<HH", 0, 0) + struct.pack("<I", 54)
    info_hdr = struct.pack("<IiiHHIIIiII", 40, w, h, 1, 24, 0, 0, 0, 0, 0, 0)
    return file_hdr + info_hdr


def interpret(before_out: str, after_out: str):
    """Pure decision: did the guard fire only after the patch? (testable offline)"""
    def parse(s):
        parts = (s or "").split("|")
        return parts[0], (parts[1] if len(parts) > 1 else "")
    b_status, b_reason = parse(before_out)
    a_status, a_reason = parse(after_out)
    after_rejects_via_guard = a_status == "REJECTED" and "too large" in a_reason
    before_rejects_via_guard = b_status == "REJECTED" and "too large" in b_reason
    return after_rejects_via_guard and not before_rejects_via_guard, (b_status, a_status, a_reason)


def _build_and_run(header_text: str, workdir: str, tag: str, input_path: str, defined=frozenset()):
    from .applyfix import clang_define_args
    hp = os.path.join(workdir, "hdr.h")
    cp = os.path.join(workdir, f"{tag}.c")
    bp = os.path.join(workdir, f"{tag}.bin")
    with open(hp, "w") as fh:
        fh.write(header_text)
    with open(cp, "w") as fh:
        fh.write(_HARNESS)
    cc = subprocess.run(["clang", "-w", "-O0", *clang_define_args(defined), cp, "-o", bp],
                        capture_output=True, text=True, timeout=180)
    if cc.returncode != 0:
        return None
    try:
        r = subprocess.run([bp, input_path], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return "TIMEOUT|"
    return (r.stdout or "").strip()


def has_probe(marker: str, after_header: str) -> bool:
    return "STBI_MAX_DIMENSIONS" in (marker or "") or "STBI_MAX_DIMENSIONS" in after_header


def verify(before_header: str, after_header: str, workdir: str, marker: str, defined=frozenset()) -> BehaviorResult:
    if not has_probe(marker, after_header):
        return BehaviorResult(False, "none", "", "", False,
                              "no behavioural probe registered for this fix (placement-verified only)")
    inp = os.path.join(workdir, "oversized.bmp")
    with open(inp, "wb") as fh:
        fh.write(oversized_bmp())
    before = _build_and_run(before_header, workdir, "probe_before", inp, defined)
    after = _build_and_run(after_header, workdir, "probe_after", inp, defined)
    if before is None or after is None:
        return BehaviorResult(False, "stb-oversized-image", before or "BUILD_FAIL", after or "BUILD_FAIL",
                              False, "behavioural probe failed to build")
    fires, (b_status, a_status, a_reason) = interpret(before, after)
    detail = f"crafted 20,000,000x1 BMP: original {b_status}, patched {a_status}" + \
             (f' ("{a_reason}")' if a_reason else "")
    return BehaviorResult(True, "stb-oversized-image (20000000x1 BMP)", before, after, fires, detail)
