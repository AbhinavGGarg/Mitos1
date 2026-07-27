"""Serverless audit — the one part of Mitos that can run without a compiler.

Marker-based detection is string matching over bytes we fetch from GitHub, so it needs
no tree-sitter and no clang. The repair path does need both and cannot run here; the
deployed interface says so plainly rather than pretending otherwise.

Requires GITHUB_TOKEN in the environment (GitHub code search rejects anonymous requests).
Without it this returns a configured=false payload and the UI reports that honestly.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

# Same table the local server uses. `identity` markers are implementation internals, so a
# file that merely calls the library, or a declaration-only header, is excluded rather than
# reported. `fix_marker` is a symbol the upstream fix itself introduced, verified absent in
# the fix's parent commit and present at HEAD.
LIBS = [
    {"name": "stb_vorbis", "symbol": "stb_vorbis_get_samples_float", "fix_marker": "ForAllSecure",
     "identity": ["compute_codewords", "start_decoder", "vorbis_decode_packet"],
     "cves": "CVE-2019-13217..13223 (7)", "severity": "high",
     "fix_url": "https://github.com/nothings/stb/commit/98fdfc6df88b1e34a736d5e126e6c8139c8de1a6"},
    {"name": "stb_image", "symbol": "stbi_load_from_memory", "fix_marker": "stbi__addints_valid",
     "identity": ["stbi__context", "stbi__jpeg_decode_block", "stbi__parse_png_file"],
     "cves": "signed integer overflow in decode paths", "severity": "high",
     "fix_url": "https://github.com/nothings/stb/commit/47164e4086c1349ef3042fb04e0f7f7ceaf1fcee"},
    {"name": "lodepng", "symbol": "lodepng_decode32", "fix_marker": "lodepng_chunk_type_name_valid",
     "identity": ["unfilterScanline", "readChunk_PLTE", "lodepng_inflate"],
     "cves": "invalid chunk type names accepted", "severity": "medium",
     "fix_url": "https://github.com/lvandeve/lodepng/commit/5a2e751"},
]


def _get(url, accept="application/vnd.github+json", raw=False):
    req = urllib.request.Request(url, headers={
        "Accept": accept,
        "User-Agent": "mitos-audit",
        **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}),
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read()
    return body if raw else json.loads(body)


def _search(repo, symbol, per_page=4):
    q = urllib.parse.quote(f"repo:{repo} {symbol}")
    data = _get(f"{API}/search/code?q={q}&per_page={per_page}")
    return [(i["repository"]["full_name"], i["path"]) for i in data.get("items", [])]


def _fetch(repo, path, ref="HEAD"):
    url = f"{RAW}/{repo}/{ref}/{urllib.parse.quote(path)}"
    try:
        return _get(url, accept="text/plain", raw=True).decode("utf8", "replace")
    except Exception:
        return None


def audit(repo):
    findings, excluded = [], []
    for lib in LIBS:
        try:
            hits = _search(repo, lib["symbol"])
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise
            continue
        except Exception:
            continue
        for _, path in hits:
            text = _fetch(repo, path)
            if text is None:
                continue
            if not all(m in text for m in lib["identity"]):
                excluded.append(f"{path}: references {lib['name']} but is not a copy of its "
                                f"implementation — excluded")
                continue
            findings.append({
                "lib": lib["name"], "path": path,
                "patched": lib["fix_marker"] in text,
                "cves": lib["cves"], "severity": lib["severity"],
                "fix": lib["fix_url"], "method": "marker",
            })
    return findings, excluded


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        repo = (qs.get("repo") or [""])[0].strip().strip("/")
        if repo.startswith("https://github.com/"):
            repo = repo[len("https://github.com/"):]

        def send(payload, code=200):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        if not TOKEN:
            return send({"configured": False,
                         "error": "GITHUB_TOKEN is not set on this deployment, so GitHub code "
                                  "search is unavailable. The audit runs locally."}, 200)
        if repo.count("/") != 1:
            return send({"error": "expected owner/name"}, 400)
        try:
            findings, excluded = audit(repo)
        except urllib.error.HTTPError as e:
            return send({"error": f"GitHub API returned {e.code}"}, 200)
        except Exception as e:
            return send({"error": f"{type(e).__name__}: {e}"}, 200)
        return send({
            "configured": True, "repo": repo, "findings": findings, "excluded": excluded,
            "vulnerable": len([f for f in findings if not f["patched"]]),
            "checked": len(LIBS),
            "note": "Marker-based detection only. The similarity detector and the repair "
                    "pipeline need tree-sitter and a compiler, which this runtime does not have.",
        })
