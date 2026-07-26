"""Measure how many real vendored copies of common single-file C libraries are missing a
published upstream security fix.

Method, and its limits, stated up front:
  * A file counts as a COPY only if it contains implementation-only internals. Files that
    merely call the library, and declaration-only headers, are excluded rather than counted.
  * A copy counts as PATCHED only if it contains a symbol the fix itself introduced. Each
    marker is verified absent in the fix's parent commit and present in the fix.
  * GitHub code search ranking is not stable, so this is a sample, not a census.
"""
import json
import sys
import time

sys.path.insert(0, "/Users/abhinavgarg/Wizard Hackathon/patchdna")
from mitos import cve  # noqa: E402

OUT = "/Users/abhinavgarg/Wizard Hackathon/mitos-data/vendored-scan.json"

LIBS = {
    "stb_image": {
        "queries": ["stbi_load_from_memory language:c",
                    "stbi__parse_png_file language:c",
                    "stbi__jpeg_decode_block language:c",
                    "stbi_load_from_file language:c"],
        "identity": ["stbi__context", "stbi__jpeg_decode_block", "stbi__parse_png_file"],
        "marker": "stbi__addints_valid",
        "fix": "nothings/stb@47164e40 signed integer overflow checks (2022-11-29)",
        "verified": "marker absent in parent 96fe76c2, present in 47164e40 and in HEAD",
    },
    "stb_vorbis": {
        "queries": ["stb_vorbis_get_samples_float language:c",
                    "compute_codewords language:c"],
        "identity": ["compute_codewords", "start_decoder", "vorbis_decode_packet"],
        "marker": "ForAllSecure",
        "fix": "nothings/stb@98fdfc6d CVE-2019-13217..13223 (2019-08-09)",
        "verified": "marker absent in parent c72a95d7, present in 98fdfc6d and in HEAD",
    },
    "lodepng": {
        "queries": ["lodepng_decode32 language:c", "unfilterScanline language:c",
                    "readChunk_PLTE language:c"],
        "identity": ["unfilterScanline", "readChunk_PLTE", "lodepng_inflate"],
        "marker": "lodepng_chunk_type_name_valid",
        "fix": "lvandeve/lodepng@5a2e751 reject invalid chunk type names",
        "verified": "marker absent in parent, present in 5a2e751 and in HEAD; it is a real "
                    "function definition, not a comment",
    },
}


def main():
    out = {}
    for lib, cfg in LIBS.items():
        seen, stale, ok, refs, unread = set(), [], [], 0, 0
        for q in cfg["queries"]:
            try:
                hits = cve.search_code(q, max_results=40, verbose=lambda m: None)
            except Exception as e:
                print(f"{lib}: query failed ({e})", flush=True)
                continue
            for h in hits:
                key = (h.repo, h.path)
                if key in seen:
                    continue
                seen.add(key)
                src = cve.fetch_source(h)
                if src is None:
                    unread += 1
                    continue
                t = src.decode("utf8", "replace")
                if not all(m in t for m in cfg["identity"]):
                    refs += 1
                    continue
                (ok if cfg["marker"] in t else stale).append({"repo": h.repo, "path": h.path})
            print(f"{lib}: '{q[:38]}' -> {len(stale)} unpatched / {len(ok)} patched "
                  f"/ {refs} refs / {unread} unread", flush=True)
            time.sleep(2)

        out[lib] = {
            "fix": cfg["fix"], "marker": cfg["marker"], "marker_verified": cfg["verified"],
            "identity_markers": cfg["identity"],
            "confirmed_copies": len(stale) + len(ok),
            "unpatched": len(stale), "patched": len(ok),
            "references_excluded": refs, "unreadable": unread,
            "unpatched_repos": stale, "patched_repos": ok,
        }

    json.dump(out, open(OUT, "w"), indent=2)
    print("\n=== DATASET ===", flush=True)
    for lib, d in out.items():
        tot = d["confirmed_copies"]
        pct = round(100 * d["unpatched"] / tot) if tot else 0
        print(f"  {lib:12} {d['unpatched']}/{tot} unpatched ({pct}%)  "
              f"· {d['references_excluded']} refs excluded", flush=True)
    print(f"\nwritten -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
