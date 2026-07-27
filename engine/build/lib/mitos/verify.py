"""verify(): compile the descendant before/after and prove the patch under ASAN.

This is the leg that makes Mitos sell "a passing patch, not a warning".
We synthesise a tiny harness that drives the function with an overflowing input:
  - BEFORE  -> AddressSanitizer reports a heap-buffer-overflow (vulnerable)
  - AFTER   -> the guard returns the error, clean exit (fixed)
A patch only counts as verified if BEFORE overflows and AFTER does not, and both
compile. No hand edits allowed.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass

from . import astutils as A
from .discover import Descendant
from .signature import PatchSignature
from .transplant import Patch

CC = os.environ.get("MITOS_CC", "clang")
CAP, LEN = 8, 24  # dest capacity vs. bytes we try to copy


@dataclass
class Evidence:
    func_name: str
    compiled_before: bool
    compiled_after: bool
    before_overflow: bool
    after_overflow: bool
    before_exit: int
    after_exit: int
    after_result: str
    passed: bool
    detail: str = ""


def _roles(func: A.Func, patch: Patch):
    """Map each parameter to a role value for the harness call."""
    m = patch.mapping
    dest, src_name, size, cap = m["dest"], None, m["size"], m["capacity"]
    # src = the pointer arg of the copy that isn't the dest
    call_args = None
    for c in func.calls(m["callee"]):
        call_args = c.args
        break
    if call_args:
        for a in call_args:
            if a != dest and func.param_by_name(a) and func.param_by_name(a).pointer:
                src_name = a
                break
    values = []
    for p in func.params:
        if p.name == dest:
            values.append(f"({p.type}) dst")
        elif p.name == src_name:
            values.append(f"({p.type}) src")
        elif p.name == size:
            values.append(str(LEN))
        elif p.name == cap:
            values.append(str(CAP))
        elif p.is_int:
            values.append(str(CAP))
        else:
            values.append("0")
    return values


def _harness(func_src: str, func: A.Func, patch: Patch) -> str:
    args = ", ".join(_roles(func, patch))
    return f"""#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

{func_src}

int main(void) {{
    char *dst = (char *) malloc({CAP});
    char *src = (char *) malloc({LEN});
    memset(src, 'A', {LEN});
    int r = (int) {func.name}({args});
    printf("MITOS_RESULT=%d\\n", r);
    free(dst);
    return 0;
}}
"""


def _compile_run(source: str, workdir: str, tag: str):
    cpath = os.path.join(workdir, f"{tag}.c")
    bpath = os.path.join(workdir, f"{tag}.bin")
    with open(cpath, "w") as fh:
        fh.write(source)
    cc = subprocess.run([CC, "-fsanitize=address", "-g", "-O0", "-w", cpath, "-o", bpath],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        return False, None, "", cc.stderr
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=99")
    run = subprocess.run([bpath], capture_output=True, text=True, env=env, timeout=20)
    out = run.stdout + run.stderr
    overflow = ("AddressSanitizer" in out) or ("buffer-overflow" in out) or run.returncode == 99
    return True, run.returncode, out, ""


def verify(desc: Descendant, patch: Patch, sig: PatchSignature, workdir: str | None = None) -> Evidence:
    func = desc.func
    tmp = workdir or tempfile.mkdtemp(prefix="mitos_")
    os.makedirs(tmp, exist_ok=True)

    cb, eb, ob, errb = _compile_run(_harness(patch.original, func, patch), tmp, f"{func.name}_before")
    ca, ea, oa, erra = _compile_run(_harness(patch.patched, func, patch), tmp, f"{func.name}_after")

    before_overflow = cb and (("AddressSanitizer" in ob) or ("buffer-overflow" in ob) or eb == 99)
    after_overflow = ca and (("AddressSanitizer" in oa) or ("buffer-overflow" in oa) or ea == 99)
    result = ""
    for line in (oa or "").splitlines():
        if line.startswith("MITOS_RESULT="):
            result = line.split("=", 1)[1]

    passed = bool(cb and ca and before_overflow and not after_overflow)
    detail = ""
    if not cb:
        detail = f"before did not compile: {errb.strip()[:200]}"
    elif not ca:
        detail = f"after did not compile: {erra.strip()[:200]}"
    elif not before_overflow:
        detail = "harness did not trigger the vulnerability in the original (inconclusive)"
    elif after_overflow:
        detail = "patch did NOT stop the overflow"
    return Evidence(func_name=func.name, compiled_before=cb, compiled_after=ca,
                    before_overflow=before_overflow, after_overflow=after_overflow,
                    before_exit=eb if eb is not None else -1,
                    after_exit=ea if ea is not None else -1,
                    after_result=result, passed=passed, detail=detail)
