"""Labeling-integrity tests: tamper/hash-mismatch detection, duplicate/forbidden/prefilled
rejection, blinded evidence-only bundles, label-file validation (WIP + final), adjudication
(no auto-resolve), family second pass, and CLI overwrite protection."""
import argparse
import json
import os
import tempfile

import pytest

from mitos import labeling, cli


def _doc(n=4):
    packets = [{"packet_id": f"p{i}", "marker": f"m{i}", "full_commit_message": "msg",
                "complete_commit_diff": "d", "label_template": {f: None for f in labeling.RUBRIC_FIELDS}}
               for i in range(n)]
    return {"packets_hash": labeling.packets_hash(packets), "rubric_fields": labeling.RUBRIC_FIELDS,
            "packets": packets}


def _labels(doc, reviewer="alice", fill=None, source_hash=None):
    lab = {p["packet_id"]: {f: None for f in labeling.RUBRIC_FIELDS} for p in doc["packets"]}
    for pid, vals in (fill or {}).items():
        lab[pid].update(vals)
    return {"kind": "reviewer_labels", "reviewer": reviewer,
            "source_packets_hash": source_hash or doc["packets_hash"], "labels": lab}


# ---- integrity of the packet doc before bundling ----------------------------
def test_verify_clean_doc_and_bundle_is_evidence_only():
    doc = _doc()
    assert labeling.verify_packet_doc(doc) == []
    bundle, labels = labeling.build_bundle(doc, seed=3, reviewer="alice")
    assert all("label_template" not in p for p in bundle["packets"])         # evidence-only
    assert all("model_label" not in p for p in bundle["packets"])
    assert set(bundle["packet_order"]) == {f"p{i}" for i in range(4)}
    assert set(labels["labels"]) == {f"p{i}" for i in range(4)}
    assert all(v is None for v in labels["labels"]["p0"].values())           # AI fills nothing
    assert labeling.build_bundle(doc, 3, "alice")[0]["packet_order"] == bundle["packet_order"]  # seed determinism


def test_verify_detects_tampering_and_hash_mismatch():
    doc = _doc()
    doc["packets"][0]["marker"] = "TAMPERED"                                  # content changed, hash not updated
    errs = labeling.verify_packet_doc(doc)
    assert any("packets_hash mismatch" in e for e in errs)
    with pytest.raises(ValueError):
        labeling.build_bundle(doc, 1, "alice")


def test_verify_rejects_duplicate_ids():
    doc = _doc()
    doc["packets"][1]["packet_id"] = "p0"
    doc["packets_hash"] = labeling.packets_hash(doc["packets"])
    assert any("duplicate packet_ids" in e for e in labeling.verify_packet_doc(doc))


def test_verify_rejects_forbidden_and_prefilled_fields():
    doc = _doc()
    doc["packets"][0]["model_label"] = {"fix_class": "security"}
    doc["packets"][1]["validity"] = {"mechanically_valid": True}
    doc["packets"][2]["label_template"]["is_actual_fix"] = "yes"              # prefilled
    doc["packets_hash"] = labeling.packets_hash(doc["packets"])
    errs = labeling.verify_packet_doc(doc)
    assert any("forbidden field 'model_label'" in e for e in errs)
    assert any("forbidden field 'validity'" in e for e in errs)
    assert any("prefilled label_template" in e for e in errs)


# ---- label-file validation ---------------------------------------------------
def test_validate_wip_ok_but_final_requires_decisions():
    doc = _doc()
    lf = _labels(doc)
    ids = [p["packet_id"] for p in doc["packets"]]
    assert labeling.validate_label_file(lf, packet_ids=ids, source_packets_hash=doc["packets_hash"]) == []
    final_errs = labeling.validate_label_file(lf, packet_ids=ids, final=True)
    assert final_errs and all("unpopulated" in e for e in final_errs)         # all decision fields null
    lf2 = _labels(doc, fill={pid: {"is_actual_fix": "unknown", "fix_class": "unknown",
                                   "marker_necessary": "unknown", "marker_sufficient": "unknown"} for pid in ids})
    assert labeling.validate_label_file(lf2, packet_ids=ids, final=True) == []  # 'unknown' counts as populated


def test_validate_missing_extra_ids_and_source_hash():
    doc = _doc()
    lf = _labels(doc)
    del lf["labels"]["p0"]
    lf["labels"]["pX"] = {f: None for f in labeling.RUBRIC_FIELDS}
    errs = labeling.validate_label_file(lf, packet_ids=[p["packet_id"] for p in doc["packets"]],
                                        source_packets_hash="OTHERHASH")
    assert any("missing label for packet p0" in e for e in errs)
    assert any("unknown packet pX" in e for e in errs)
    assert any("source_packets_hash" in e for e in errs)


def test_validate_controlled_values_types_and_reviewer():
    doc = _doc()
    lf = _labels(doc, fill={"p0": {"is_actual_fix": "maybe"}, "p1": {"evidence": 123}, "p2": {"reviewer": "bob"}})
    errs = labeling.validate_label_file(lf)
    assert any("p0.is_actual_fix='maybe' not a controlled value" in e for e in errs)
    assert any("p1.evidence must be a string" in e for e in errs)
    assert any("p2.reviewer" in e and "file reviewer" in e for e in errs)


# ---- adjudication (never auto-resolves) -------------------------------------
def test_adjudicate_agreement_and_disagreement():
    doc = _doc(2)
    a = _labels(doc, "alice", {"p0": {"is_actual_fix": "yes", "fix_class": "security"},
                               "p1": {"is_actual_fix": "yes"}})
    b = _labels(doc, "bob", {"p0": {"is_actual_fix": "yes", "fix_class": "security"},
                             "p1": {"is_actual_fix": "no"}})
    adj = labeling.adjudicate(a, b)
    assert adj["decisions"]["p0"]["is_actual_fix"]["status"] == "agreed"
    assert adj["decisions"]["p0"]["is_actual_fix"]["resolved"] == "yes"
    assert adj["decisions"]["p1"]["is_actual_fix"]["status"] == "needs_adjudication"
    assert adj["decisions"]["p1"]["is_actual_fix"]["resolved"] is None        # disagreement never auto-resolved
    assert adj["disagreement_count"] >= 1


def test_family_groups_is_a_separate_pass():
    doc = _doc(3)
    lf = _labels(doc, fill={"p0": {"logical_family_id": "F1"}, "p1": {"logical_family_id": "F1"},
                            "p2": {"logical_family_id": "F2"}})
    fg = labeling.family_groups(lf)
    assert fg["groups"] == {"F1": ["p0", "p1"], "F2": ["p2"]}


# ---- CLI overwrite protection -----------------------------------------------
def test_cli_bundle_refuses_overwrite_without_force():
    d = tempfile.mkdtemp()
    ppath = os.path.join(d, "review_packets.json")
    with open(ppath, "w") as fh:
        json.dump(_doc(), fh)
    ns = argparse.Namespace(packets=ppath, reviewer="alice", seed=1, out=d, force=False)
    cli.cmd_bundle(ns)                                                        # first time: writes
    assert os.path.exists(os.path.join(d, "bundle_alice.json"))
    with pytest.raises(SystemExit) as e:
        cli.cmd_bundle(ns)                                                    # second time: refuse
    assert e.value.code == 2
    ns.force = True
    cli.cmd_bundle(ns)                                                        # --force: allowed
