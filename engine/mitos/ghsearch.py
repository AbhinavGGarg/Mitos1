"""Real descendant discovery over GitHub, via authenticated Code Search (`gh api`).

This is the leg that turns Mitos from a local demo into something that hunts
genuine clones in the wild. Code Search needs auth; we shell out to `gh api` so we
inherit the user's login instead of managing tokens.

Limits we respect: Code Search is 10 req/min and only reaches ~1000 results per
query, indexed on default branches. Raw file bytes come from the CDN (not rate
limited), derived from each hit's blob URL so we read the exact indexed revision.
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from dataclasses import dataclass

MAX_FILE_BYTES = 2_000_000


@dataclass
class Hit:
    repo: str
    path: str
    html_url: str      # https://github.com/OWNER/REPO/blob/REF/PATH

    @property
    def raw_url(self) -> str:
        u = self.html_url.split("#", 1)[0]
        u = u.replace("https://github.com/", "https://raw.githubusercontent.com/")
        return u.replace("/blob/", "/", 1)

    @property
    def ref(self) -> str:
        parts = self.html_url.split("/blob/", 1)
        return parts[1].split("/", 1)[0] if len(parts) == 2 else "HEAD"


class GhError(RuntimeError):
    pass


def _gh_api(args: list, timeout: int = 40, retries: int = 3) -> str:
    last = ""
    for attempt in range(retries):
        try:
            r = subprocess.run(["gh", "api", *args], capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise GhError("`gh` CLI not found — install and `gh auth login`")
        if r.returncode == 0:
            return r.stdout
        last = r.stderr.strip()
        # transient server/abuse errors → back off and retry
        if any(code in last for code in ("HTTP 502", "HTTP 503", "HTTP 504", "rate limit", "secondary rate")):
            time.sleep(2 * (attempt + 1))
            continue
        break
    raise GhError(last[:400] or "gh api failed")


def search_code(query: str, max_results: int = 30, per_page: int = 30, verbose=lambda *_: None) -> list:
    """Return up to max_results Hits for a Code Search query (e.g. 'foo language:c')."""
    hits, page = [], 1
    per_page = min(per_page, 100)
    while len(hits) < max_results:
        out = _gh_api(["-X", "GET", "search/code",
                       "-f", f"q={query}", "-f", f"per_page={per_page}", "-f", f"page={page}",
                       "-H", "Accept: application/vnd.github+json"])
        data = json.loads(out)
        items = data.get("items", [])
        if page == 1:
            verbose(f"code search '{query}' → {data.get('total_count', 0)} total, reading up to {max_results}")
        for it in items:
            hits.append(Hit(repo=it["repository"]["full_name"], path=it["path"], html_url=it["html_url"]))
            if len(hits) >= max_results:
                break
        if len(items) < per_page:
            break
        page += 1
        time.sleep(6.5)   # stay under 10 code searches / minute
    return hits


def fetch_source(hit: Hit) -> bytes | None:
    """Fetch the exact indexed revision via `gh api` (raw). None on failure/too-big.

    We go through gh rather than urllib so we inherit its auth + working TLS —
    the python.org macOS build otherwise can't verify GitHub's cert chain.
    """
    try:
        r = subprocess.run(
            ["gh", "api", "-X", "GET", f"repos/{hit.repo}/contents/{hit.path}",
             "-f", f"ref={hit.ref}", "-H", "Accept: application/vnd.github.raw"],
            capture_output=True, timeout=40)
    except Exception:
        return None
    if r.returncode != 0 or not r.stdout:
        return None
    data = r.stdout
    return data if len(data) <= MAX_FILE_BYTES else None


def file_last_commit_iso(repo: str, path: str) -> str | None:
    """Date of the most recent commit touching this file (staleness signal)."""
    try:
        out = _gh_api(["-X", "GET", f"repos/{repo}/commits",
                       "-f", f"path={path}", "-f", "per_page=1",
                       "--jq", ".[0].commit.committer.date"])
        return out.strip() or None
    except GhError:
        return None
