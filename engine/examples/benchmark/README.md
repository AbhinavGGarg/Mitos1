# Benchmark: real fixes × real copies

`mitos bench` measures precision on real data, not fixtures — over a live, **content-hash
de-duplicated** sample of real GitHub copies of `stb_image.h`. Two stages:

1. **Marker-absence rate** — for each real hardening fix (a distinctive symbol it introduced),
   what fraction of copies *lack* that symbol, judged from each copy's own bytes. This is a
   marker-absence measurement, **not** a precision or exploitability claim.
2. **Syntactic placement pass** — transplant one fix (`STBI_MAX_DIMENSIONS`) into every applicable
   copy and run the static placement audit: every inserted line must be **live code** (not comment,
   not `#if 0`/`#elif 0` dead, not an unresolved `#if`, with `#ifdef`s resolved against the build's
   declared macros) **and inside the function the upstream hunk targeted**. It is a *static* pass —
   not behavioural proof.

Run: `python -m mitos bench --sample 25` · full data + per-copy metadata in [`results.json`](results.json).

## Pilot result (25 deduped live copies)

| | |
|---|---|
| **Marker-absence, overall** | 92 / 225 checks absent — **40%** of copies lack a given hardening marker |
| Newest fixes (`STBI_MAX_DIMENSIONS`, `stbi__addints_valid`, `stbi__mul2shorts_valid`) | **96%** absent (14/24 predate the fix) |
| Older fixes (`stbi__mad{2,3,4}sizes_valid`, `stbi__malloc_mad*`) | 12–16% absent (only the oldest copies) |
| **Syntactic placement pass** | **24 / 24** applicable copies — every inserted line live & in the expected function |
| Wrong-function insertions detected | **0** (in this sample; the check itself is exercised by a unit test) |
| Compile sample | 3 / 4 compiled — one real copy fails to build standalone (the build-rate wall, live) |
| Behavioural sample | 2 / 4 fire the guard — site-specific (see caveats) |

## What changed after review (benchmark-integrity pass)

An earlier version reported "24/24 zero wrong-function," but the audit only checked "in *a*
function," never the *right* one. Fixed:

- **Exact-line tracking.** `apply_fix` returns the precise lines each hunk inserted; the audit
  checks *those* lines, not any line containing the marker.
- **Right-function check.** The audit extracts the upstream hunk's enclosing function and requires
  the target insertion to land in the matching function. A patch meant for `intended()` that lands
  in `wrong()` now **fails** (`tests/test_precision.py::test_wrong_function_insertion_is_rejected`).
- **Preprocessor honesty.** `#if (0)` and `#elif 0` are dead; `#ifdef`/`#ifndef` resolve against the
  build's declared macros (closed-world for the verification build we control); genuinely unevaluable
  `#if <expr>` is **unresolved → unverified**, never assumed-live.
- **De-dup + provenance.** Copies are de-duplicated by SHA-256 of content; each is recorded with
  repo, path, **blob SHA**, content hash, and a `ground_truth` field (null — reserved for manual labels).
- **Honest metric names.** "stale" → *marker-absence rate*; "placement OK" → *syntactic placement pass*.
  The "zero wrong-function" claim is removed; the number reported is "wrong-function insertions
  **detected**," which is only as strong as the check that now backs it.

## Mining + mechanically validating candidate markers (`mitos mine`)

`mitos mine` clones widely-copied C libraries locally (no GitHub commit API, which is flaky for
large repos), **checks out each pinned upstream commit**, walks the target file's **complete**
history, extracts the distinctive symbol each fix-keyworded commit introduced, and mechanically
validates every row. Rows are **candidate markers, not validated fixes** — a real fix is a
ground-truth judgement. Seed list: [`libs.json`](libs.json) (with `pinned_head` per library);
frozen corpus in [`mined_corpus.json`](mined_corpus.json); blinded review packets in
[`review_packets.json`](review_packets.json).

A **mechanically valid marker candidate** must (a) be **absent from every parent** (merge commits
have >1 parent — checked against all of them), (b) be **introduced in real code** (not comment/
string), (c) be **not a hex/numeric fragment** (incl. `xff000000`-style), and (d) have clang
**`preprocess_status = ok`** and **`active_in_declared_config = true`** under the **actual clang
preprocessor** with the declared `-D` defines. The enclosing function comes from **tree-sitter**
on the child (not git's `@@` context). `conditional_context` records which kind of `#if` gates the
marker — `include_guard` / `implementation_gate` / `feature_gate` / `compiler_gate`.

```
── corpus-integrity report ──
  candidates examined                    : 129
  mechanically valid marker candidates   : 44    (absent from ALL parents + in code + not hex + clang ok/active)
  all survive preprocessing (active)     : 44
  conditional context of the valid:
    · include_guard only                 : 15    (public-API declarations, guarded only by the include guard)
    · include_guard + compiler           : 1
    · implementation/feature gated       : 28
  model: security/correctness            : (model_label, NOT ground truth)
  model: fix-identifying markers         : (model_label, NOT ground truth)
  independent repos / files with valid   : 4 / 8
  unique patch ids (of valid)            : 44
  frozen: generator <sha> · clang <ver> <target> · corpus_hash <sha256> · packets_hash <sha256>
```

**All 44 survive preprocessing; none is unconditionally live.** Every single-file library wraps its
body in an include guard and/or an `#ifdef <LIB>_IMPLEMENTATION` gate, so nothing compiles at
truly unconditional scope. The 15 `include_guard`-only markers are **code/declarations gated only by the include guard**
(the header's declaration section); the 28 are implementation/feature gated; 1 is under an include
guard plus a compiler condition. (The count is **44, not 45** — the
new all-parents check removed one candidate whose marker was inherited from a non-first merge
parent, not introduced.)

### Freeze & reproduce
Generation is a two-commit process: the **generator code** is committed first, then the artifact is
generated (recording that `generator_commit`) and committed. Each library pins an upstream HEAD
(`pinned_head`), so a re-run mines the identical history. `mitos mine --verify mined_corpus.json`
regenerates from the pins and checks the `corpus_hash` matches. The corpus records `toolchain`
(clang version + target), and each row records parent SHAs, upstream HEAD, patch-id, child/parent
paths + lines.

`conditional_context` is a **static** classification of the enclosing `#if` directives (it retains
the actual expressions and if/elif/else branch) — separate from the clang `preprocess` result.
Only the canonical outer file guard counts as `include_guard`; nested `#ifndef X / #define X`
config defaults do not.

### Human review (not started)
[`review_packets.json`](review_packets.json) holds **blinded** packets — full untruncated commit
message, the **complete commit diff** (all files) and a separate **target-file diff**, a changed-file
manifest, **all changed test-file diffs**, the selected hunk, before/after context taken from the
**hunk coordinates**, every marker occurrence with its surrounding context and enclosing function,
merge parents, and linked issues/tests — **with `model_label` removed**. Each carries a
`label_template` rubric for a human to fill.

[`review_protocol.md`](review_protocol.md) defines the controlled values (every field allows
`unknown`) with examples. `mitos bundle --packets review_packets.json --reviewer <id> --seed <n>`
produces a **blinded, randomized, packet-only** bundle plus a **separate empty label file** keyed by
`packet_id` and `packets_hash` — the frozen packets are never mutated. **Two blinded reviewers +
adjudication → ground_truth; one reviewer → single-reviewer labels.** `ground_truth` is null
everywhere; an AI must not fill any label.

## Caveats (the point of a benchmark)

- **Pilot, not 100 fixes.** The 9 markers are ~4–5 *independent* fix-events (the `mad*` family shipped
  together, so they correlate). A true 100 needs the git-clone miner across many libraries.
- **Syntactic ≠ behavioural.** Placement pass proves live + right-function *statically*. Behavioural
  coverage is site-specific: a copy where the BMP site didn't apply won't fire the BMP probe.
- **Marker-absence ≠ exploitable.** A missing hardening marker means a defence-in-depth check is
  absent; it is not proof of a reachable exploit.
- **Ground truth is not yet established.** Precision claims require manually-verified labels; the
  `ground_truth` field is recorded but null.
