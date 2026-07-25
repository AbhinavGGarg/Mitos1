# Mitos — proof-carrying patches

**Your agents write patches all day. Nobody checks them.**

Mitos finds source code that was copy-pasted out of another project — and therefore lost its
package name and version, making it invisible to Dependabot, Snyk, OSV and every SBOM tool —
works out which security fix it never received, transplants that fix into the modified copy,
rebuilds the downstream project, and **proves the vulnerability is gone** by running a crafted
malicious input under AddressSanitizer.

> ### The compiler decides, not the AI.

**🎥 Demo video:** _<!-- PASTE VIDEO LINK HERE -->_

---

## The problem

A package manager works because your code declares `react@18.2.0`. A scanner matches that string
against a vulnerability database and tells you to upgrade.

Copy a file into your repo instead — rename it, tweak it — and it has **no name and no version.**
There is nothing to match against. It is not that the copy is hard to find; it is *structurally
invisible* to the entire category of tools built for this. Then upstream ships a security fix,
everyone else gets it, and your copy sits there for years.

## What is proven here, live

**[sphair/ClanLib](https://github.com/sphair/ClanLib)** — a real C++ game engine SDK — vendored a
renamed copy of **stb_vorbis v1.16** as `Sources/Sound/SoundProviders/stb_vorbis.h`. The `.c` was
renamed to `.h` and a 7-line wrapper added; the body is otherwise byte-identical to upstream.

Upstream [nothings/stb@98fdfc6d](https://github.com/nothings/stb/commit/98fdfc6df88b1e34a736d5e126e6c8139c8de1a6)
(v1.17) fixed **seven CVEs** — CVE-2019-13217 through CVE-2019-13223, reported by ForAllSecure.
ClanLib's copy never received it.

```
three-way merge     merge_rc=0, 0 conflicts
golden postimage    d7606540ee39…  exact match   (independently reviewed, pinned in the recipe)
baseline build      ok             patched build  ok
behavioural probe   before  rc=-6  AddressSanitizer: stack-buffer-overflow
                                   compute_codewords  stb_vorbis.h:1065
                    after   rc=0   clean
────────────────────  VERIFIED_SCOPED  ────────────────────
```

The crash lands at `stb_vorbis.h:1065`. Upstream crashes at `1058`. **Exactly +7** — ClanLib's
wrapper shifted every line. That offset is why a naive `patch` fails here, and why a three-way
merge is required.

A live scan of GitHub found a **majority of readable copies of this file still missing the fix.**

## Run it

```bash
# 1 · engine deps
cd engine && python3 -m venv .venv && ./.venv/bin/pip install tree-sitter tree-sitter-c

# 2 · the repair, on the command line
PYTHONPATH=. ./.venv/bin/python -m mitos repair --recipe STB_VORBIS --force

# 3 · the live interface
cd ../web && npm install && npm run build
cd .. && engine/.venv/bin/python server.py        # → http://localhost:8870
```

Requires `clang` with AddressSanitizer, `git`, and `gh` authenticated for the live GitHub scans.

## What the interface does

| Section | What it actually does |
|---|---|
| **Audit a repo** | Type any public GitHub repo. Scoped code search, then reads the bytes of every candidate to decide whether the fix is present. |
| **The hunt** | Pick a real upstream fix. Live GitHub search; every card is a repository whose bytes were just read. |
| **The target** | ClanLib's real file at the pinned commit — the 7-line wrapper, the header with no version, and the vulnerable function with the crash line highlighted. |
| **The repair** | The three-way merge, the golden postimage hash gate, the full `fix.diff`, and all 11 hunks. |
| **The proof** | An agent asserting it fixed the bug, beside a receipt proving it: crash before, clean after. |
| **Evidence** | The real `PR_BODY.md`, `fix.diff` and `evidence.json` the run wrote to disk. |

**Nothing in this repository replays a recording or fabricates a result.** There is no `setTimeout`
progress animation and no fixture data. If the engine is not running, the interface shows empty
states rather than fake ones.

## How trust is earned

The AI has exactly two jobs: recognise what a file is, and judge whether a fix applies.
Everything that *decides* is deterministic:

| Step | Decided by |
|---|---|
| the merge | `git merge-file --diff3` |
| correctness of the result | sha256 against an independently-reviewed golden postimage |
| does it still build | `clang` |
| is the bug actually gone | AddressSanitizer + the ForAllSecure proof-of-concept |

If the merge produces anything other than the exact expected bytes, the run is `NEEDS_REVIEW`.

## What this does **not** claim

- Behavioural coverage is **scoped**: 1 of 3 reachable fix sites was exercised. Hence
  `VERIFIED_SCOPED`, never bare `VERIFIED`.
- We are **not** claiming a remote exploit of the shipped ClanLib application. We prove the
  memory-safety bug in ClanLib's actual compiled translation unit.
- The repair recipe was written by a human. Fully autonomous discovery is the open problem.
- 2 of 11 hunks are advisory under the positional cross-check — `draw_line` contains two
  identical `inverse_db_table[y&255]` edits that no positional heuristic can tell apart. The
  golden postimage certifies both byte-exact.
- The repo audit checks a small set of commonly-copied C libraries whose fix signatures we have
  verified. Absence of a finding is not proof of absence.

## Provenance

`engine/` is the **Mitos engine** — pre-existing open-source work
([AbhinavGGarg/Mitos](https://github.com/AbhinavGGarg/Mitos)), included here so the repository is
self-contained and runnable. It is a disclosed dependency, not work claimed as new.

**Built during the hackathon window:** the `STB_VORBIS` recipe (`engine/mitos/recipes.py`), the
AddressSanitizer harness, the `crash_before_only` probe capability, the `harness_sources` build
capability, the golden-postimage authority change, the live SSE server (`server.py`), and the
entire interface (`web/`).

## Attribution

- [nothings/stb](https://github.com/nothings/stb) — stb_vorbis, public domain
- [sphair/ClanLib](https://github.com/sphair/ClanLib) — the downstream copy under study
- [ForAllSecure/VulnerabilitiesLab](https://github.com/ForAllSecure/VulnerabilitiesLab) — the
  proof-of-concept input and the harness shape
