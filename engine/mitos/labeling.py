"""Labeling system (infrastructure only — an AI must NOT assign label values).

Turns a frozen `review_packets.json` into blinded, randomized, **evidence-only** reviewer
bundles (no `label_template`), with a **separate** empty label file keyed by `packet_id` and
`packets_hash`. Validates human-entered label files against the controlled vocabulary, and
adjudicates two reviewers' decisions. The frozen packets are never mutated; disagreements are
never auto-resolved. See review_protocol.md.
"""
from __future__ import annotations

import hashlib
import json
import random

# rubric fields (mirrors miner.RUBRIC); decision fields are the four adjudicated ones
RUBRIC_FIELDS = ["is_actual_fix", "fix_class", "marker_necessary", "marker_sufficient",
                 "logical_family_id", "evidence", "confidence", "reviewer"]
DECISION_FIELDS = ["is_actual_fix", "fix_class", "marker_necessary", "marker_sufficient"]

ALLOWED = {
    "is_actual_fix": ["yes", "no", "unknown"],
    "fix_class": ["security", "correctness", "robustness", "cosmetic", "refactor", "feature", "other", "unknown"],
    "marker_necessary": ["yes", "no", "unknown"],
    "marker_sufficient": ["yes", "no", "unknown"],
    "confidence": ["high", "medium", "low", "unknown"],
}
_FORBIDDEN_IN_PACKET = ("model_label", "ground_truth", "validity", "conditional_context", "preprocess")


def _sha(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def packets_hash(packets) -> str:
    return _sha(packets)


def bundle_hash(bundle: dict) -> str:
    return _sha(bundle)


def verify_packet_doc(doc: dict) -> list:
    """Structural integrity of a frozen packet doc before we bundle it: packets_hash must
    match, packet_ids unique, and no packet may carry a verdict field or a prefilled label."""
    errs, packets = [], doc.get("packets", [])
    ids = [p.get("packet_id") for p in packets]
    if len(ids) != len(set(ids)):
        errs.append("duplicate packet_ids")
    if any(i is None for i in ids):
        errs.append("packet missing packet_id")
    recomputed = packets_hash(packets)
    if doc.get("packets_hash") and recomputed != doc["packets_hash"]:
        errs.append(f"packets_hash mismatch: recorded {doc['packets_hash'][:12]}, recomputed {recomputed[:12]}")
    for p in packets:
        for f in _FORBIDDEN_IN_PACKET:
            if f in p:
                errs.append(f"packet {p.get('packet_id')} carries forbidden field {f!r}")
        lt = p.get("label_template")
        if isinstance(lt, dict) and any(v is not None for v in lt.values()):
            errs.append(f"packet {p.get('packet_id')} has prefilled label_template values")
    return errs


def build_bundle(packet_doc: dict, seed: int, reviewer: str):
    """(bundle, empty_label_file). Bundle is evidence-only (label_template stripped),
    shuffled deterministically by seed; the label file is separate and keyed by packet_id."""
    errs = verify_packet_doc(packet_doc)
    if errs:
        raise ValueError("packet doc failed integrity checks: " + "; ".join(errs))
    packets, ph = packet_doc["packets"], packet_doc["packets_hash"]
    evidence = [{k: v for k, v in p.items() if k != "label_template"} for p in packets]   # evidence-only
    shuffled = evidence[:]
    random.Random(seed).shuffle(shuffled)
    bundle = {"kind": "reviewer_bundle", "reviewer": reviewer, "seed": seed,
              "source_packets_hash": ph, "rubric_fields": RUBRIC_FIELDS,
              "packet_order": [p["packet_id"] for p in shuffled], "packets": shuffled}
    labels = {"kind": "reviewer_labels", "reviewer": reviewer, "source_packets_hash": ph,
              "note": "human-entered per review_protocol.md; every field may be 'unknown'. AI must not fill these.",
              "labels": {p["packet_id"]: {f: None for f in RUBRIC_FIELDS} for p in packets}}
    return bundle, labels


def validate_label_file(label_file: dict, packet_ids=None, source_packets_hash=None, final=False) -> list:
    """Verify kind, reviewer, source hash, exact packet-ID set, exact fields, controlled values,
    free-field types, and reviewer consistency. `final=True` additionally requires every decision
    field populated (a value or explicit 'unknown'); WIP mode allows nulls."""
    errs = []
    if label_file.get("kind") != "reviewer_labels":
        errs.append("kind is not 'reviewer_labels'")
    reviewer = label_file.get("reviewer")
    if not reviewer:
        errs.append("missing reviewer")
    if source_packets_hash and label_file.get("source_packets_hash") != source_packets_hash:
        errs.append("source_packets_hash does not match the packets")
    labels = label_file.get("labels", {})
    if packet_ids is not None:
        got, want = set(labels), set(packet_ids)
        errs += [f"missing label for packet {m}" for m in sorted(want - got)]
        errs += [f"label for unknown packet {e}" for e in sorted(got - want)]
    for pid, lab in labels.items():
        if set(lab) != set(RUBRIC_FIELDS):
            errs.append(f"{pid}: fields {sorted(set(lab) ^ set(RUBRIC_FIELDS))} differ from the rubric")
        for field, allowed in ALLOWED.items():
            v = lab.get(field)
            if v is not None and v not in allowed:
                errs.append(f"{pid}.{field}={v!r} not a controlled value {allowed}")
        for free in ("evidence", "logical_family_id"):
            if lab.get(free) is not None and not isinstance(lab[free], str):
                errs.append(f"{pid}.{free} must be a string or null")
        if lab.get("reviewer") is not None and lab["reviewer"] != reviewer:
            errs.append(f"{pid}.reviewer {lab['reviewer']!r} != file reviewer {reviewer!r}")
        if final:
            for df in DECISION_FIELDS:
                if lab.get(df) in (None, ""):
                    errs.append(f"{pid}.{df} unpopulated (final mode requires a value or 'unknown')")
    return errs


def adjudicate(labels_a: dict, labels_b: dict) -> dict:
    """Compare the four DECISION fields for two reviewers. Agreement resolves; any disagreement
    stays `needs_adjudication` with `resolved=null` (a human decides — never auto-resolved).
    logical_family_id is intentionally NOT compared here — it is a separate second pass."""
    la, lb = labels_a.get("labels", {}), labels_b.get("labels", {})
    shared = sorted(set(la) & set(lb))
    decisions, disagreements = {}, 0
    for pid in shared:
        d = {}
        for f in DECISION_FIELDS:
            va, vb = la[pid].get(f), lb[pid].get(f)
            agree = va is not None and va == vb
            d[f] = {"a": va, "b": vb, "agreed": bool(agree),
                    "resolved": va if agree else None,
                    "status": "agreed" if agree else "needs_adjudication"}
            if not agree:
                disagreements += 1
        decisions[pid] = d
    return {"kind": "adjudication", "reviewers": [labels_a.get("reviewer"), labels_b.get("reviewer")],
            "source_packets_hash": labels_a.get("source_packets_hash"),
            "note": "resolved fields on agreement only; disagreements need a human adjudicator. "
                    "logical_family_id grouping is a separate second pass. AI must not resolve.",
            "shared_packets": len(shared), "disagreement_count": disagreements,
            "only_in_a": sorted(set(la) - set(lb)), "only_in_b": sorted(set(lb) - set(la)),
            "decisions": decisions}


def family_groups(label_file: dict) -> dict:
    """Second-pass aggregation of the human-entered logical_family_id values into groups.
    Purely mechanical grouping of what a human wrote; assigns nothing."""
    groups = {}
    for pid, lab in label_file.get("labels", {}).items():
        fid = lab.get("logical_family_id")
        if fid:
            groups.setdefault(fid, []).append(pid)
    return {"kind": "logical_family_grouping", "reviewer": label_file.get("reviewer"),
            "source_packets_hash": label_file.get("source_packets_hash"),
            "groups": {k: sorted(v) for k, v in sorted(groups.items())}}
