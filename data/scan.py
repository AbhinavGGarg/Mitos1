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
import subprocess
import sys
import time

sys.path.insert(0, "/Users/abhinavgarg/Wizard Hackathon/patchdna")
from mitos import cve, similarity as sim  # noqa: E402

OUT = "/Users/abhinavgarg/Wizard Hackathon/mitos-data/vendored-scan.json"
CACHE = "/Users/abhinavgarg/Wizard Hackathon/.mitos-cache"

# Libraries whose fix introduces no greppable identifier. Classified by comparing the copy's
# version of the patched function against upstream's before/after shapes. Copies that cannot
# be separated are counted as indeterminate, never guessed at.
SIM_LIBS = {
    "miniz": {
        "queries": ["tinfl_decompress language:c", "TINFL_STATUS_DONE language:c"],
        "repo": "miniz", "path": "miniz_tinfl.c", "fix": "384a12d",
        "cve": "CVE-2018-12913 regression (code_len==0 infinite loop)",
    },
    "cgltf": {
        "queries": ["cgltf_parse_json_draco_mesh_compression language:c",
                    "cgltf_parse_json language:c"],
        "repo": "cgltf", "path": "cgltf.h", "fix": "1e40b58",
        "cve": "out-of-bounds read parsing malformed Draco extension",
    },
}


def _blob(repo, ref, path):
    return subprocess.run(["git", "-C", f"{CACHE}/{repo}", "show", f"{ref}:{path}"],
                          capture_output=True).stdout


def scan_similarity(name, cfg):
    parent = subprocess.run(["git", "-C", f"{CACHE}/{cfg['repo']}", "rev-parse", f"{cfg['fix']}~1"],
                            capture_output=True, text=True).stdout.strip()
    changed = sim.changed_functions(_blob(cfg["repo"], parent, cfg["path"]),
                                    _blob(cfg["repo"], cfg["fix"], cfg["path"]))
    if not changed:
        return None
    seen, stale, ok, indet, absent = set(), [], [], 0, 0
    for q in cfg["queries"]:
        try:
            hits = cve.search_code(q, max_results=40, verbose=lambda m: None)
        except Exception as e:
            print(f"{name}: query failed ({e})", flush=True)
            continue
        for h in hits:
            key = (h.repo, h.path)
            if key in seen:
                continue
            seen.add(key)
            src = cve.fetch_source(h)
            if src is None:
                continue
            v, _ = sim.verdict(src, changed)
            if v == sim.STALE:
                stale.append({"repo": h.repo, "path": h.path})
            elif v == sim.PATCHED:
                ok.append({"repo": h.repo, "path": h.path})
            elif v == sim.ABSENT:
                absent += 1
            else:
                indet += 1
        print(f"{name}: '{q[:38]}' -> {len(stale)} unpatched / {len(ok)} patched "
              f"/ {indet} indeterminate", flush=True)
        time.sleep(2)
    return {"method": "similarity", "keyed_on": changed[0].name,
            "fix_delta": round(changed[0].delta, 5), "cve": cfg["cve"],
            "confirmed_copies": len(stale) + len(ok), "unpatched": len(stale),
            "patched": len(ok), "indeterminate": indet, "absent": absent,
            "unpatched_repos": stale, "patched_repos": ok}

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

    for name, cfg in SIM_LIBS.items():
        r = scan_similarity(name, cfg)
        if r:
            out[name] = r

    json.dump(out, open(OUT, "w"), indent=2)
    print("\n=== DATASET ===", flush=True)
    tu = tc = 0
    for lib, d in out.items():
        tot = d["confirmed_copies"]
        pct = round(100 * d["unpatched"] / tot) if tot else 0
        extra = (f"· {d['references_excluded']} refs excluded"
                 if "references_excluded" in d
                 else f"· {d['indeterminate']} indeterminate")
        print(f"  {lib:12} {d['unpatched']:>3}/{tot:<3} unpatched ({pct:>3}%)  {extra}", flush=True)
        tu += d["unpatched"]; tc += tot
    print(f"  {'TOTAL':12} {tu:>3}/{tc:<3} unpatched ({round(100*tu/tc) if tc else 0}%)", flush=True)
    print(f"\nwritten -> {OUT}", flush=True)


if __name__ == "__main__":
    main()
