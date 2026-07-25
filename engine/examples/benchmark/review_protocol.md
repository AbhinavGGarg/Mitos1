# Review protocol — candidate fix markers

The mined corpus contains **mechanically valid marker candidates**, not fixes. A "fix" is a
ground-truth judgement made by a **human reviewer**, not by the generator and not by an AI. This
document defines how to label them.

- Never mutate the frozen packets. Labels live in **separate reviewer files** keyed by `packet_id`
  and the `source_packets_hash` they were made against.
- Reviewers see **blinded, randomized, packet-only bundles** (`mitos bundle`): evidence only, no
  `model_label`, no validity verdict, shuffled order.
- **Two blinded reviewers**, then adjudicate disagreements → defensible **ground_truth**. With a
  **single reviewer**, the output is **"single-reviewer labels"**, not ground truth.

## Rubric — controlled values (every field allows `unknown`)

| field | allowed values | meaning |
|---|---|---|
| `is_actual_fix` | `yes` \| `no` \| `unknown` | Does this commit fix a real defect (not a rename/typo/build/feature)? |
| `fix_class` | `security` \| `correctness` \| `robustness` \| `cosmetic` \| `refactor` \| `feature` \| `other` \| `unknown` | Category of the change. |
| `marker_necessary` | `yes` \| `no` \| `unknown` | Is the marker's presence **necessary** to detect this fix (would its absence reliably indicate the fix is missing)? |
| `marker_sufficient` | `yes` \| `no` \| `unknown` | Is the marker's presence **sufficient** to identify this fix (could it appear coincidentally without the fix)? |
| `logical_family_id` | free string \| `null` | Reviewer-assigned id grouping markers/commits that are one logical fix (e.g. a fix split across files/commits). |
| `evidence` | free text | Cite the hunk, line numbers, issue, or test that supports the judgement. |
| `confidence` | `high` \| `medium` \| `low` | Reviewer confidence. |
| `reviewer` | free string | Reviewer id (also stored at file level). |

## Examples (synthetic — these markers do NOT appear in the 44 packets)

- `wdgt_checked_add` (a made-up commit *"guard integer add against overflow"*): `is_actual_fix=yes`,
  `fix_class=security`, `marker_necessary=yes`, `marker_sufficient=yes` (a distinctive new helper),
  `confidence=high`, `evidence="new bounds guard invoked before the copy"`.
- `wdgt_export_v2` (a made-up public API *rename/add*): `is_actual_fix=no` (feature/rename, not a
  defect fix), `fix_class=feature`, `marker_sufficient=yes`, `marker_necessary=no`.
- `tmp_len` (a made-up generic local touched by a correctness fix): `is_actual_fix=yes`,
  `fix_class=correctness`, `marker_sufficient=no` (a common name that can appear without the fix),
  `marker_necessary=unknown`, `confidence=low`.
- A candidate you cannot judge from the packet: leave any field `unknown` and note why in `evidence`.

(These names are illustrative only. Never copy a value from an example onto a real packet.)

## Adjudication (two reviewers)

For each `packet_id`, compare the two label files. Agreement on `is_actual_fix` **and** `fix_class`
→ accept as `ground_truth`. Disagreement → a third adjudicator resolves it, or the field is recorded
as `unknown` with both opinions retained. Store the adjudicated result in a new file; leave the
per-reviewer files immutable.

> AI note: an automated agent MAY generate bundles, schemas, and adjudication tooling, but MUST NOT
> populate any label value itself. All values in this repo's label files are entered by humans.
