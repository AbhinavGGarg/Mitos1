# Real-world close-the-loop: an exact, golden-attested pinned repair

Mitos run against real GitHub, end to end — the **one exact, pinned** stb→blurhash repair. A real
upstream fix is applied to a real vendored copy with a **three-way merge**, gated against an
**independently-reviewed golden hash of the exact expected postimage** (`merged` sha256
`d3b5c868…`, `fix.diff` sha256 `9af88203…`), positionally cross-checked per hunk (experimental), and checked through
**the downstream repo's own build and binary**. This closes PM1 around *this exact repair* — it is
**not** a claim of general transplant correctness; generic positional verification beyond this
golden-attested recipe is **experimental**. Reproduce with `mitos repair`; the files here
([`fix.diff`](fix.diff), [`evidence.json`](evidence.json), [`commands.log`](commands.log),
[`full_command_log.txt`](full_command_log.txt), [`PR_BODY.md`](PR_BODY.md)) are exactly what a
**cold run** (fresh clones) emitted. Provenance — generator commit, recipe digest and the exact
reproduction command — is recorded in `evidence.json` and the PR body.

**Upstream fix:** [`nothings/stb@d6059484`](https://github.com/nothings/stb/commit/d60594847ecc) —
*"Reject images that are too large."* Introduces `STBI_MAX_DIMENSIONS` (default `1<<24`) and guards
every image loader. **Parent taken from the raw commit object** (not `rev-parse fix^`, which honours
grafts/replace refs): `98ca24b8`.

**Stale copy:** [`woltapp/blurhash`](https://github.com/woltapp/blurhash) vendored `stb_image.h` into
`C/`, pinned at `712a47f9` — an older, drifted stb (7,177 lines vs. the parent's 7,693) with no
`STBI_MAX_DIMENSIONS`.

## Merge

`git diff 98ca24b8 d6059484 -- stb_image.h` applied via `git merge-file -p --diff3 current base other`.
**`merge_rc == 0`, 0 conflicts**; marker `STBI_MAX_DIMENSIONS` **0 → 21**. Parsed hunk count equals
the patch's actual hunk count. A non-zero `merge_rc`, any conflict, or a hunk-count mismatch forces
`NEEDS_REVIEW`.

## Golden postimage — the authoritative acceptance guarantee

PM1's acceptance rests on the **exact expected postimage**, not on generic verification: the merged
file and `fix.diff` must hash to the independently-reviewed constants pinned in the recipe (`merged`
`d3b5c868…`, `fix.diff` `9af88203…`). A clean but wrongly-positioned merge whose bytes differ is
`NEEDS_REVIEW` through this hard gate. The gate compares the run's computed sha to the hardcoded
constants — it never learns the expected value from the run being certified.

## Positional hunk cross-check (experimental)

Alongside the golden gate, Mitos also cross-checks each hunk's placement. Each hunk's target scope is
the enclosing function of **its own coordinates in the upstream child** (tree-sitter) — not git's
`@@` funcname. Function hunks are diffed body-vs-merge (the change must be exactly the hunk's
additions/removals, one region, pinned to a unique surviving context anchor — this tolerates
line-level drift, e.g. the copy's TGA loader drifted its local variables yet the guard is located in
`stbi__tga_load`); file-scope macros require a unique block bracketed by both preprocessor anchors.

This is an **experimental cross-check that rejects the covered regression cases** — guard-after-return,
an edit on the wrong one of two identical calls, a macro under the wrong `#if` branch, and an obsolete
line left beside its replacement (see `tests/test_repair.py`). It is **not** a general proof that every
mislocated or ambiguous mapping is caught; the golden postimage above is the authoritative guarantee.
For this pinned repair the cross-check agrees with the golden gate (11/11), and `decide()` still
rejects the run if any hunk is unverified.

## Build + behaviour (constrained host execution)

Build order is provenance-checked: **clean → write + hash the intended header → delete the expected
artifact → build → verify the header hash is unchanged → require a newly-created regular, non-symlink
artifact inside the worktree → hash + copy.** So a clean step that creates the artifact, or a build
that overwrites the certified source, cannot be certified; a missing fresh artifact is
`stale_artifact`. Both binaries' sha256 are recorded (`encoder_before` ≠ `encoder_after`).

Builds and probes run their **own process group** (killed as a group on timeout) with a scrubbed
no-credentials env, CPU/file-size/core resource limits, wall timeouts, and bounded output. A rejection
counts **only** on the exact allowed exit code **and** the expected diagnostic; signals, crashes and
timeouts always fail.

| gate | result |
|---|---|
| baseline build (fresh artifact) | ✅ ok |
| patched build (fresh artifact) | ✅ ok |
| **normal 4×4 BMP** | ✅ identical blurhash before/after |
| **oversized BMP** (20,000,000×1) | ✅ accepted before (`rc=0`), rejected after (`rc=1` **and** "Failed to load") |
| **oversized PNM** (P6 20,000,000×1) | ✅ accepted before, rejected after (`rc=1` + diagnostic) |

## Verdict: VERIFIED_SCOPED (honest)

The verdict is **VERIFIED_SCOPED**, not bare `VERIFIED`, and the reachable-loader set is encoded in
the gate:

- **Structurally merged loaders (9):** JPEG, PNG, BMP, TGA, PSD, PIC, GIF, HDR, PNM.
- **Reachable loaders (5):** BMP, PNG, PSD, HDR, PNM — a crafted oversized input can reach their guard
  at the default `1<<24` limit (BMP/PSD 32-bit, PNG 31-bit, HDR/PNM ASCII). **JPEG, GIF, TGA and PIC
  read 16-bit dimensions** (≤ 65535 `<` `1<<24`), so their guard is **unreachable** by any input —
  structurally merged, defence-in-depth only.
- **Behaviourally verified (2):** BMP, PNM.

The verdict gate enforces **behavioural ⊆ reachable ⊆ modified**. Because only 2 of the 5 reachable
loaders were exercised, the run is `VERIFIED_SCOPED`; bare `VERIFIED` requires exercising **every**
reachable loader, and a passing unrelated probe never counts. (Note: PNG already rejected dimensions
> `1<<24` before this fix via its own check, so the fix's *newly-introduced* default behavioural paths
are BMP, PSD, HDR, PNM — of which BMP and PNM are exercised, 2/4.)

## Git / host boundary

Git runs from a **from-scratch whitelisted environment** (no inherited `GIT_*`, isolated `HOME`,
`GIT_CONFIG_GLOBAL=/dev/null`, replacement objects/hooks/attributes disabled) into a **fresh
Mitos-owned 0700 clone** that is validated: origin URL, and no grafts, replacement refs, checkout
filters, or `url.insteadOf`. Merge inputs and outputs are created `O_EXCL | O_NOFOLLOW`; the copy path
is checked for symlink/path escape. There is **no network/PID/memory namespace isolation** on this
host, so `mitos repair` runs only an **internal allowlisted, pinned recipe** — arbitrary untrusted
repositories require a real no-network sandbox. Regression tests drive the full `run_repair` over
local repos and defeat a hostile `GIT_CONFIG_COUNT` / `url.insteadOf` injection, a clean-created stale
artifact, and a build that overwrites the source.

## Honest scope

- ✅ Real fix, real drifted copy, content-based three-way merge with 0 conflicts matching the
  independently-reviewed **golden postimage** (the authoritative guarantee), fresh builds,
  exact-code+diagnostic probes. Positional per-hunk placement is an experimental cross-check.
- ⚠️ `VERIFIED_SCOPED`: 2 of 5 reachable loaders behaviourally exercised. One fix class; a drop-in
  header; blurhash ships no C-encoder unit suite, so "own tests" means its build + binary here.
  Generic positional verification beyond this golden-attested recipe is experimental — this is one
  exact pinned repair, not a proof of general transplant correctness.
- ❌ **No external PR opened.** A generated, reviewable artifact only.
