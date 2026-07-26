"""Find and VERIFY a fix marker for a vendored library.

A usable marker is an identifier introduced by a security fix that:
  1. does not appear in the fix's parent commit
  2. appears in the fix
  3. still appears at HEAD (durable, so old copies stay distinguishable)

Anything failing all three is rejected. A wrong marker produces false findings, which is worse
than no coverage at all.
"""
import re
import subprocess
import sys

CACHE = "/Users/abhinavgarg/Wizard Hackathon/.mitos-cache"


def git(repo, *args):
    r = subprocess.run(["git", "-C", f"{CACHE}/{repo}", *args],
                       capture_output=True, text=True)
    return r.stdout


def blob(repo, ref, path):
    return git(repo, "show", f"{ref}:{path}")


def candidates(repo, sha, path):
    """Identifiers added by this commit, longest first (more distinctive)."""
    diff = git(repo, "show", sha, "--", path)
    added = "\n".join(l[1:] for l in diff.splitlines()
                      if l.startswith("+") and not l.startswith("+++"))
    ids = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{7,}\b", added))
    return sorted(ids, key=len, reverse=True)


def verify(repo, sha, path, marker):
    parent = git(repo, "rev-parse", f"{sha}~1").strip()
    if not parent:
        return None
    p = blob(repo, parent, path).count(marker)
    f = blob(repo, sha, path).count(marker)
    h = blob(repo, "HEAD", path).count(marker)
    return {"marker": marker, "parent": p, "fix": f, "head": h,
            "ok": p == 0 and f > 0 and h > 0}


def search(repo, path, sha, want=3):
    print(f"\n{'='*70}\n{repo}  {path}\n  fix {sha[:12]}  {git(repo,'log','-1','--format=%s',sha).strip()[:56]}")
    found = []
    for c in candidates(repo, sha, path):
        if len(found) >= want:
            break
        v = verify(repo, sha, path, c)
        if v and v["ok"]:
            found.append(v)
            print(f"  ✓ {v['marker']:34} parent={v['parent']} fix={v['fix']} head={v['head']}")
    if not found:
        print("  ✗ no durable marker introduced by this commit")
    return found


if __name__ == "__main__":
    if len(sys.argv) >= 4:
        search(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
