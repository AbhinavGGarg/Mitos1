"""Queue a repair request.

Repair itself needs clang, AddressSanitizer and a long-running process, none of which
exist in this runtime, and today the engine only runs human-authored recipes pinned to
exact commits. So the honest public surface is: the audit runs for real, and if it finds
a copy missing a published fix you can ask for the repair to be written. A person then
authors the recipe and opens the pull request.

Three properties this endpoint has to hold:

  1. The audit is the spam filter. A request is only accepted if the server re-runs the
     audit itself and sees a real unpatched copy. Nobody can queue a repo we cannot see a
     problem in, and nobody can hand us findings we did not compute.

  2. Contact details never reach a public repository. The queue repo is checked for
     visibility on every request and a public one is refused, because a requester's email
     ending up in a public issue would be our mistake, not theirs.

  3. Submitted text cannot inject anything. Backticks are stripped and the text is fenced,
     which neutralises markdown, raw HTML and @mentions in a single move.

Configuration (the operator sets these; unset means requests are closed and the UI says so):
  MITOS_QUEUE_REPO   owner/name of a PRIVATE repo whose issues form the queue
  MITOS_QUEUE_TOKEN  token with issues:write on it (falls back to GITHUB_TOKEN)
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

from audit import API, RateLimited, TOKEN, audit, normalize_repo

QUEUE_REPO = (os.environ.get("MITOS_QUEUE_REPO") or "").strip().strip("/")
QUEUE_TOKEN = os.environ.get("MITOS_QUEUE_TOKEN") or TOKEN

MAX_CONTACT = 200
MAX_NOTE = 2000
LABEL = "repair-request"


def _api(path, token, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{API}{path}", data=data, method=method, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "mitos-queue",
        "Authorization": f"Bearer {token}",
        **({"Content-Type": "application/json"} if data else {}),
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        body = r.read()
    return json.loads(body) if body else {}


def _clean(text, limit):
    """Strip control characters and backticks, then cap. Fencing does the rest."""
    text = "".join(c for c in (text or "") if c == "\n" or c >= " ")
    return text.replace("`", "").strip()[:limit]


def _fence(text):
    return f"```\n{text}\n```" if text else "_none given_"


def _issue_body(repo, vulnerable, contact, note):
    lines = [
        f"Repair requested for **{repo}** via the website.", "",
        "### What the audit found", "",
        "| library | path | CVEs |", "| --- | --- | --- |",
    ]
    for f in vulnerable:
        lines.append(f"| `{f['lib']}` | `{f['path']}` | {f['cves']} |")
    lines += [
        "", "Each row is an implementation copy missing a symbol the upstream fix introduced.",
        "Re-verified server-side at request time, not taken from the client.", "",
        "### Contact", "", _fence(contact), "",
        "### What they said", "", _fence(note), "",
        "---", "",
        "Next step is human: author a recipe pinning the upstream fix and its parent, run",
        "`mitos repair`, and open the PR with the receipt in the body.",
    ]
    return "\n".join(lines)


def _existing(repo, token):
    """Reuse an open request for the same repository instead of stacking duplicates."""
    try:
        issues = _api(f"/repos/{QUEUE_REPO}/issues?state=open&labels={LABEL}&per_page=100", token)
    except Exception:
        return None
    for i in issues:
        if i.get("title", "").endswith(repo):
            return i.get("html_url")
    return None


def _queue_status():
    """Whether requests can be accepted, and why not when they cannot."""
    if not TOKEN:
        return False, "The audit is not configured on this deployment, so a request cannot be verified."
    if not QUEUE_REPO or not QUEUE_TOKEN:
        return False, "Repair requests are not open yet."
    return True, None


class handler(BaseHTTPRequestHandler):
    def _send(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """Lets the page ask whether the form is worth showing."""
        open_, why = _queue_status()
        self._send({"open": open_, "reason": why})

    def do_POST(self):
        open_, why = _queue_status()
        if not open_:
            return self._send({"error": why}, 503)

        try:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(length, 16384)) or "{}")
        except Exception:
            return self._send({"error": "expected a JSON body"}, 400)

        repo = normalize_repo(body.get("repo"))
        contact = _clean(body.get("contact"), MAX_CONTACT)
        note = _clean(body.get("note"), MAX_NOTE)
        if repo.count("/") != 1:
            return self._send({"error": "expected owner/name"}, 400)
        if not contact:
            return self._send({"error": "leave a way to reach you, or there is nowhere to send "
                                        "the pull request"}, 400)

        # The queue repo must be private before any contact detail is written into it.
        try:
            meta = _api(f"/repos/{QUEUE_REPO}", QUEUE_TOKEN)
        except Exception:
            return self._send({"error": "the request queue is misconfigured"}, 503)
        if not meta.get("private", False):
            return self._send({"error": "the request queue is misconfigured"}, 503)

        # Re-run the audit here. Client-supplied findings are never trusted, and a repo with
        # nothing wrong in it cannot be queued.
        try:
            findings, _ = audit(repo)
        except RateLimited:
            return self._send({"error": "GitHub's search quota is used up for the moment, so the "
                                        "request could not be verified. Try again in a minute."}, 503)
        except Exception:
            return self._send({"error": "the repository could not be read"}, 502)

        vulnerable = [f for f in findings if not f["patched"]]
        if not vulnerable:
            return self._send({"error": "we can only queue a repair for a copy we can see is "
                                        "missing a published fix, and we do not see one in "
                                        f"{repo}."}, 422)

        dupe = _existing(repo, QUEUE_TOKEN)
        if dupe:
            return self._send({"ok": True, "duplicate": True, "url": dupe,
                               "message": f"{repo} is already in the queue."})

        try:
            issue = _api(f"/repos/{QUEUE_REPO}/issues", QUEUE_TOKEN, "POST", {
                "title": f"Repair request: {repo}",
                "body": _issue_body(repo, vulnerable, contact, note),
                "labels": [LABEL],
            })
        except urllib.error.HTTPError:
            return self._send({"error": "the request could not be filed"}, 502)

        return self._send({"ok": True, "url": issue.get("html_url"),
                           "count": len(vulnerable),
                           "message": f"{repo} is in the queue."})
