"""Bundled repair recipes beyond the original blurhash flagship.

STB_VORBIS: sphair/ClanLib vendored a renamed copy of nothings/stb `stb_vorbis.c`
(v1.16, 2019-03-04) as `Sources/Sound/SoundProviders/stb_vorbis.h`, adding only a
7-line header-only wrapper. Upstream v1.17 (commit 98fdfc6d) fixed seven CVEs
(CVE-2019-13217..13223, reported by ForAllSecure). The copy never received it.

The probe is a `crash_before_only` sanitizer probe: ClanLib's ACTUAL translation
unit is compiled under AddressSanitizer with a shipped harness, then fed the
public ForAllSecure proof-of-concept Ogg. Pre-fix it aborts with a
stack-buffer-overflow in compute_codewords; post-merge it exits 0.
"""
from __future__ import annotations

import base64
import os

from . import repair

# Offline mirrors (no venue network needed). Canonical URLs are shown in the PR/evidence.
_CACHE = os.environ.get("MITOS_CACHE", '/Users/abhinavgarg/Wizard Hackathon/.mitos-cache')

STB_VORBIS_KEY = "sphair/ClanLib<-nothings/stb@stb_vorbis-v1.17-CVE-2019-132xx"

# ForAllSecure PoC: 278-byte malformed Ogg claiming 16 channels.
# github.com/ForAllSecure/VulnerabilitiesLab  stb-cve-2019-132xx/mayhem/stb-vorbis/poc/crash
_POC_B64 = 'T2dnUwA6Z09nZztPAQAAgGZTQCkAAN/5AAABHgF2b3JiaXMAAAAAEGgAAgD//////78AAAAAAPx2T09nZ1MAOjpnT2dnO08BAACAZlNAKQAA3/kAAAEeAXRvcmJpcwAAAAAQaAACAP//////vwAAAAB2D09nZ1MAOjNPZ2c7VAHM/wkAAAD///+E/wAAAAV2b3JiaXNCQkNWb///////////////////////////MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMjc5NDIzMzM2ODgwNDA5NDQwNnJiaXMAAAAAEGZTQAAAEGgAAgD//////78AAAAAdg9PZ2dTAP//////hP8='

_HARNESS = '/* Mitos behavioural harness for ClanLib\'s copied stb_vorbis.\n   Single TU: -DINCLUDED_FROM_SETUPVORBIS makes ClanLib\'s own wrapper compile the\n   full implementation, exactly as ClanLib builds it. Decodes argv[1] via the same\n   public API ClanLib calls. Built with -fsanitize=address. */\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#define INCLUDED_FROM_SETUPVORBIS\n#include "stb_vorbis.h"\n\nint main(int argc, char **argv) {\n    if (argc < 2) { printf("usage: %s <ogg>\\n", argv[0]); return 2; }\n    FILE *f = fopen(argv[1], "rb");\n    if (!f) { printf("OPENFAIL\\n"); return 2; }\n    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);\n    if (n < 0) { fclose(f); return 2; }\n    unsigned char *buf = (unsigned char *) malloc(n ? (size_t) n : 1);\n    size_t got = fread(buf, 1, (size_t) n, f);\n    fclose(f);\n    int chan = 0, rate = 0; short *out = NULL;\n    int samples = stb_vorbis_decode_memory(buf, (int) got, &chan, &rate, &out);\n    printf("decoded samples=%d chan=%d rate=%d\\n", samples, chan, rate);\n    if (out) free(out);\n    free(buf);\n    return 0;\n}\n'


def _stb_vorbis_recipe() -> repair.Recipe:
    """INTERNAL factory. Every repo/command/probe is defined here; a caller of the public
    run_repair(recipe_key) can never influence what executes."""
    return repair.Recipe(
        key=STB_VORBIS_KEY,
        name="sphair/ClanLib <- nothings/stb  stb_vorbis v1.17 (CVE-2019-13217..13223)",
        upstream_repo="file://" + os.path.join(_CACHE, "stb"),
        upstream_display_url="https://github.com/nothings/stb",
        upstream_fix_sha="98fdfc6df88b1e34a736d5e126e6c8139c8de1a6",
        upstream_parent_sha="c72a95d766b8cbf5514e68d3ddbf6437ac9425b1",
        upstream_path="stb_vorbis.c",
        downstream_repo="file://" + os.path.join(_CACHE, "ClanLib"),
        downstream_display_url="https://github.com/sphair/ClanLib",
        downstream_sha="b7074607ab7853a2cd1f427af0c56f4ad6ffdb6b",
        downstream_path="Sources/Sound/SoundProviders/stb_vorbis.h",
        build_subdir="Sources/Sound/SoundProviders",
        build_cmd=["clang", "-fsanitize=address", "-g", "-O0", "-I.",
                   "vorbis_asan_main.c", "-o", "vorbis_asan"],
        clean_cmd=["rm", "-f", "vorbis_asan"],
        build_artifact="vorbis_asan",
        run_argv=lambda binary, inp: [binary, inp],
        marker="",
        modified_loaders=["lookup1_values", "draw_line", "get_window",
                          "vorbis_finish_frame", "start_decoder"],
        reachable_loaders=["start_decoder", "draw_line", "lookup1_values"],
        coverage_note=(
            "The +22/-6 upstream fix hardens 5 functions, closing CVE-2019-13217..13223. The "
            "ForAllSecure PoC drives stb_vorbis_decode_memory (the exact API ClanLib calls) into a "
            "stack-buffer-overflow in compute_codewords; the fix's start_decoder bounds guard "
            "(current_length >= 32) rejects it. This run behaviourally proves that guard: overflow "
            "before, clean after. Other fix sites are structurally merged or reachable but not yet "
            "exercised."),
        expected_merged_sha256="d7606540ee3975a7e6670c4f82a2739c66b03b1d56d39c91845824b990e0d05b",
        expected_fix_diff_sha256="733dbf95996fc9cce80af5eaba60a34e0159cae94dc2034413e9fc5ca583ebff",
        harness_sources=[("vorbis_asan_main.c", _HARNESS)],
        probes=[
            repair.Probe(
                "crafted Ogg (ForAllSecure PoC, 16-channel)",
                lambda: base64.b64decode(_POC_B64),
                "poc_crash.ogg",
                "crash_before_only",
                loader="start_decoder",
            ),
        ],
    )


repair._REGISTRY[STB_VORBIS_KEY] = _stb_vorbis_recipe
