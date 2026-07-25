"""Mitos live server — streams REAL engine work to the browser over SSE.

Nothing here is simulated. /api/scan performs live GitHub code search and reads each
copy's actual bytes to classify it. /api/repair runs the real three-way merge, the
golden-postimage hash gate, two sanitizer builds of ClanLib's own translation unit,
and the ForAllSecure proof-of-concept probe.

    python server.py            # http://localhost:8870
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ENGINE = os.environ.get("MITOS_ENGINE", "/Users/abhinavgarg/Wizard Hackathon/patchdna")
sys.path.insert(0, ENGINE)

from mitos import cve, repair  # noqa: E402
from mitos import recipes  # noqa: E402,F401  (registers STB_VORBIS)

PORT = int(os.environ.get("PORT", "8870"))
WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "dist")

# The upstream fix under investigation: nothings/stb v1.17, seven CVEs.
FIX_REPO = "nothings/stb"
FIX_SHA = "98fdfc6df88b1e34a736d5e126e6c8139c8de1a6"
FIX_PATH = "stb_vorbis.c"
CVES = ["CVE-2019-13217", "CVE-2019-13218", "CVE-2019-13219", "CVE-2019-13220",
        "CVE-2019-13221", "CVE-2019-13222", "CVE-2019-13223"]

# Real upstream fixes a judge can pick and scan live. Each is a genuine commit.
TARGETS = [
    {"id": "stb_vorbis", "label": "stb_vorbis v1.17", "repo": "nothings/stb",
     "sha": "98fdfc6df88b1e34a736d5e126e6c8139c8de1a6", "path": "stb_vorbis.c",
     "blurb": "7 CVEs · ForAllSecure · Ogg Vorbis decoder", "cves": 7},
    {"id": "stb_image", "label": "stb_image STBI_MAX_DIMENSIONS", "repo": "nothings/stb",
     "sha": "d60594847ecca4553b18e7607d01328c58d95a42", "path": "stb_image.h",
     "blurb": "decompression-bomb hardening · image loader", "cves": 0},
]

# Commonly-vendored single-file C libraries we can detect INSIDE a given repo.
# `symbol`     — a distinctive identifier that only appears in a copy of that library
# `fix_marker` — a string introduced BY the security fix; absent means the copy predates it.
# Only libraries whose fix marker we have actually verified against the real upstream commit
# are listed here. A false finding would be worse than no finding.
# `identity` — strings that appear ONLY in the library's own implementation. ALL must be present
#   before we call a file a vendored copy. Without this, any file that merely *calls* the library
#   (e.g. SDL_sound_vorbis.c) looks unpatched and we would report a false finding.
VENDOR_MARKERS = [
    {"name": "stb_vorbis", "symbol": "stb_vorbis_get_samples_float", "fix_marker": "ForAllSecure",
     # implementation-only internals: present in a real vendored copy, absent from a
     # declaration-only header and from any file that merely calls the library
     "identity": ["compute_codewords", "start_decoder", "vorbis_decode_packet"],
     "cves": "CVE-2019-13217..13223 (7)", "severity": "high",
     "fix_url": "https://github.com/nothings/stb/commit/98fdfc6df88b1e34a736d5e126e6c8139c8de1a6"},
    {"name": "stb_image", "symbol": "stbi_load_from_memory", "fix_marker": "STBI_MAX_DIMENSIONS",
     "identity": ["stbi__context", "stbi__jpeg_decode_block", "stbi__parse_png_file"],
     "cves": "decompression-bomb hardening", "severity": "medium",
     "fix_url": "https://github.com/nothings/stb/commit/d60594847ecca4553b18e7607d01328c58d95a42"},
]

# What each CVE in the stb_vorbis cluster actually is, and where the fix lands.
CVE_DETAIL = {
    "CVE-2019-13217": ("heap buffer overflow", "start_decoder"),
    "CVE-2019-13218": ("stack buffer overflow", "compute_codewords"),
    "CVE-2019-13219": ("uninitialized memory", "vorbis_decode_packet_rest"),
    "CVE-2019-13220": ("out-of-range read", "draw_line"),
    "CVE-2019-13221": ("large 1D codebooks", "lookup1_values"),
    "CVE-2019-13222": ("unchecked NULL", "get_window"),
    "CVE-2019-13223": ("division by zero", "predict_point"),
}


def _sse(payload: dict) -> bytes:
    return f"data: {json.dumps(payload)}\n\n".encode()


# ---- watchlist: which repos a signed-in user has asked us to monitor -------------------
WATCH_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watchlist.json")
_watch_lock = threading.Lock()


def _load_watch() -> dict:
    try:
        with open(WATCH_DB) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_watch(db: dict):
    with _watch_lock:
        tmp = WATCH_DB + ".tmp"
        with open(tmp, "w") as f:
            json.dump(db, f, indent=2)
        os.replace(tmp, WATCH_DB)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter console during the demo
        pass

    # ---------------- routing ----------------
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/scan":
            return self.stream_scan(parse_qs(u.query))
        if u.path == "/api/repair":
            return self.stream_repair()
        if u.path == "/api/target":
            return self.send_json(self.target_payload())
        if u.path == "/api/evidence":
            return self.send_json(self.evidence_payload())
        if u.path == "/api/source":
            return self.send_json(self.source_payload())
        if u.path == "/api/targets":
            return self.send_json({"targets": TARGETS})
        if u.path == "/api/audit":
            return self.stream_audit(parse_qs(u.query))
        if u.path == "/api/watchlist":
            return self.send_json({"watching": _load_watch().get(
                (parse_qs(u.query).get("user") or ["anon"])[0], [])})
        return self.serve_static(u.path)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/api/watch":
            return self.send_json({"error": "not found"}, 404)
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self.send_json({"error": "bad json"}, 400)
        user = (body.get("user") or "anon")[:120]
        repo = (body.get("repo") or "").strip()[:200]
        if not repo:
            return self.send_json({"error": "repo required"}, 400)
        db = _load_watch()
        entries = db.setdefault(user, [])
        entries = [e for e in entries if e["repo"] != repo]        # replace, don't duplicate
        if not body.get("remove"):
            entries.append({"repo": repo,
                            "findings": body.get("findings") or [],
                            "vulnerable": int(body.get("vulnerable") or 0),
                            "added": body.get("at") or ""})
        db[user] = entries
        _save_watch(db)
        return self.send_json({"watching": entries})

    # ---------------- helpers ----------------
    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def open_sse(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()

    def emit(self, payload):
        self.wfile.write(_sse(payload))
        self.wfile.flush()

    def serve_static(self, path):
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        full = os.path.normpath(os.path.join(WEB, rel))
        if not full.startswith(os.path.realpath(WEB)) or not os.path.isfile(full):
            full = os.path.join(WEB, "index.html")
        if not os.path.isfile(full):
            return self.send_json({"error": "web/dist not built — run: cd web && npm run build"}, 503)
        ctype = ("text/html" if full.endswith(".html") else
                 "text/javascript" if full.endswith(".js") else
                 "text/css" if full.endswith(".css") else
                 "image/svg+xml" if full.endswith(".svg") else "application/octet-stream")
        with open(full, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------------- payloads ----------------
    def target_payload(self):
        r = recipes._stb_vorbis_recipe()
        return {
            "upstream": r.upstream_display_url, "fix": FIX_SHA, "cves": CVES,
            "cve_detail": {k: {"kind": v[0], "fn": v[1]} for k, v in CVE_DETAIL.items()},
            "downstream": r.downstream_display_url, "path": r.downstream_path,
            "downstream_sha": r.downstream_sha,
            "expected_merged_sha256": r.expected_merged_sha256,
            "modified": r.modified_loaders, "reachable": r.reachable_loaders,
        }

    def source_payload(self):
        """ClanLib's ACTUAL vendored file at the pinned commit, plus the regions that matter."""
        import subprocess
        r = recipes._stb_vorbis_recipe()
        cache = r.downstream_repo.replace("file://", "")
        try:
            txt = subprocess.run(
                ["git", "-C", cache, "show", f"{r.downstream_sha}:{r.downstream_path}"],
                capture_output=True, text=True, check=True).stdout
        except Exception as e:
            return {"error": str(e)}
        lines = txt.split("\n")

        def find(pat, start=0):
            for i in range(start, len(lines)):
                if pat in lines[i]:
                    return i + 1
            return None

        return {
            "path": r.downstream_path, "sha": r.downstream_sha,
            "total_lines": len(lines),
            # the 7-line ClanLib wrapper that makes this copy diverge
            "wrapper": lines[:7],
            # the header block where a version WOULD live if this were a package
            "head": lines[:46],
            # the function the proof-of-concept actually overflows
            "vuln_start": find("static int compute_codewords"),
            "vuln": (lambda s: lines[s - 1:s + 22] if s else [])(find("static int compute_codewords")),
            "crash_line": 1065,
            "upstream_crash_line": 1058,
        }

    def evidence_payload(self):
        out = os.path.join(ENGINE, "mitos-out", "real_world")
        try:
            ev = json.load(open(os.path.join(out, "evidence.json")))
            diff = open(os.path.join(out, "fix.diff")).read()
            pr = open(os.path.join(out, "PR_BODY.md")).read()
            return {"evidence": ev, "fix_diff": diff, "pr_body": pr}
        except FileNotFoundError:
            return {"error": "no evidence yet — run a repair first"}

    # ---------------- live scan (real GitHub reads) ----------------
    def stream_scan(self, qs):
        want = int((qs.get("max") or ["24"])[0])
        tid = (qs.get("target") or ["stb_vorbis"])[0]
        tgt = next((t for t in TARGETS if t["id"] == tid), TARGETS[0])
        self.open_sse()
        try:
            self.emit({"type": "phase", "phase": "fingerprint",
                       "text": f"fingerprinting {tgt['repo']}@{tgt['sha'][:10]}"})
            fp = cve.fingerprint_from_commit(tgt["repo"], tgt["sha"], tgt["path"])
            self.emit({"type": "fingerprint", "marker": fp.context_marker,
                       "fix_markers": list(fp.fix_markers), "fix_date": fp.fix_date,
                       "message": fp.message, "cves": CVES})

            self.emit({"type": "phase", "phase": "search",
                       "text": f"GitHub code search: {fp.context_marker}() language:c"})
            hits = cve.search_code(f"{fp.context_marker} language:c", max_results=want,
                                   verbose=lambda m: self.emit({"type": "log", "text": m}))
            self.emit({"type": "total", "count": len(hits)})

            stale = immune = 0
            primary = fp.fix_markers[0] if fp.fix_markers else None
            for i, h in enumerate(hits):
                self.emit({"type": "reading", "repo": h.repo, "path": h.path, "i": i})
                src = cve.fetch_source(h)
                if src is None:
                    self.emit({"type": "hit", "repo": h.repo, "path": h.path,
                               "status": "UNREADABLE", "i": i})
                    continue
                text = src.decode("utf8", "replace")
                has_ctx = fp.context_marker in text
                has_fix = bool(primary and primary in text)
                status = "IMMUNE" if has_fix else ("STALE" if has_ctx else "NO_MATCH")
                date = cve.file_last_commit_iso(h.repo, h.path) if status != "NO_MATCH" else None
                if status == "STALE":
                    stale += 1
                elif status == "IMMUNE":
                    immune += 1
                self.emit({"type": "hit", "repo": h.repo, "path": h.path, "status": status,
                           "date": date, "predates": (date < fp.fix_date) if date else None,
                           "i": i, "stale": stale, "immune": immune})
            self.emit({"type": "done", "stale": stale, "immune": immune,
                       "classified": stale + immune})
        except Exception as e:
            self.emit({"type": "error", "text": f"{type(e).__name__}: {e}"})
            traceback.print_exc()

    # ---------------- audit one repo: what vendored code is hiding in YOUR project ----------
    def stream_audit(self, qs):
        """Search a single named repository for copies of known-vulnerable vendored libraries.
        Real GitHub code search scoped with repo:, then real byte reads of anything found."""
        repo = (qs.get("repo") or [""])[0].strip().strip("/")
        if repo.startswith("https://github.com/"):
            repo = repo[len("https://github.com/"):]
        self.open_sse()
        if not repo or repo.count("/") != 1:
            return self.emit({"type": "error", "text": "expected owner/name"})
        try:
            self.emit({"type": "phase", "text": f"auditing {repo}"})
            findings, checked = [], 0
            for lib in VENDOR_MARKERS:
                self.emit({"type": "checking", "lib": lib["name"], "i": checked})
                checked += 1
                try:
                    hits = cve.search_code(f'repo:{repo} {lib["symbol"]}', max_results=5,
                                           verbose=lambda m: None)
                except Exception as e:
                    self.emit({"type": "log", "text": f"{lib['name']}: search failed ({e})"})
                    continue
                for h in hits:
                    src = cve.fetch_source(h)
                    if src is None:
                        continue
                    text = src.decode("utf8", "replace")
                    # must BE the library, not merely call it — every identity marker required
                    if not all(m in text for m in lib["identity"]):
                        self.emit({"type": "log",
                                   "text": f"{h.path}: references {lib['name']} but is not a copy — skipped"})
                        continue
                    patched = lib["fix_marker"] in text
                    f = {"lib": lib["name"], "path": h.path, "patched": patched,
                         "cves": lib["cves"], "severity": lib["severity"],
                         "fix": lib["fix_url"]}
                    findings.append(f)
                    self.emit({"type": "finding", **f})
            self.emit({"type": "done", "repo": repo, "checked": checked,
                       "findings": len(findings),
                       "vulnerable": len([f for f in findings if not f["patched"]])})
        except Exception as e:
            self.emit({"type": "error", "text": f"{type(e).__name__}: {e}"})
            traceback.print_exc()

    # ---------------- live repair (real merge + builds + sanitizer probe) ----------------
    def stream_repair(self):
        self.open_sse()
        q: "queue.Queue" = queue.Queue()
        result = {}

        def work():
            try:
                res = repair.run_repair(
                    recipes.STB_VORBIS_KEY,
                    os.path.join(ENGINE, "mitos-out", "live-run"),
                    verbose=lambda m: q.put({"type": "log", "text": m}),
                    verification_command="python -m mitos repair --recipe STB_VORBIS")
                out = os.path.join(ENGINE, "mitos-out", "real_world")
                try:
                    repair.write_artifacts(res, out, force=True)
                except Exception:
                    pass
                result["res"] = res
            except Exception as e:
                result["err"] = f"{type(e).__name__}: {e}"
                traceback.print_exc()
            finally:
                q.put(None)

        t = threading.Thread(target=work, daemon=True)
        t.start()
        while True:
            item = q.get()
            if item is None:
                break
            self.emit(item)
        t.join(timeout=5)

        if "err" in result:
            return self.emit({"type": "error", "text": result["err"]})

        r = result["res"]
        self.emit({"type": "result", "verdict": r.verdict, "reasons": r.reasons,
                   "merge": r.merge, "golden": r.golden_attestation,
                   "parent_verified": r.parent_verified,
                   "baseline": {"ok": r.baseline_build["ok"], "status": r.baseline_build["status"],
                                "sha256": r.baseline_build["sha256"][:16]},
                   "patched": {"ok": r.patched_build["ok"], "status": r.patched_build["status"],
                               "sha256": r.patched_build["sha256"][:16]},
                   "probes": r.probes, "coverage": r.coverage,
                   "certification": r.hunk_certification, "hunks": r.hunks,
                   "upstream": r.upstream, "downstream": r.downstream,
                   "generator": r.generator_commit[:10], "recipe_digest": r.recipe_digest[:10]})


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Mitos live  →  http://localhost:{PORT}")
    print(f"engine: {ENGINE}")
    print(f"web:    {WEB}  ({'built' if os.path.isdir(WEB) else 'NOT BUILT — cd web && npm run build'})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
