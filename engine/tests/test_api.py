"""The JSON status surface a UI consumes: read-only, offline, JSON-serialisable, and honest
about what is human-gated."""
import json

from mitos import api


def test_product_state_is_json_serialisable_and_shaped():
    st = api.product_state()
    json.dumps(st)                                            # must serialise for a UI
    assert set(st) >= {"product", "flagship_repair", "benchmark", "human_gated", "engine"}
    assert "Mitos" in st["product"]


def test_flagship_repair_reflects_committed_verified_scoped_run():
    fr = api.product_state()["flagship_repair"]
    assert fr and fr["verdict"] == "VERIFIED_SCOPED"
    assert "golden-attested pinned repair" in fr["kind"] and fr["golden_attestation"]["merged_match"] is True
    assert fr["merge"]["returncode"] == 0 and fr["merge"]["conflicts"] == 0
    pcc = fr["positional_cross_check"]                              # experimental cross-check, not the guarantee
    assert pcc["experimental"] is True and pcc["passed"] == pcc["total"] and pcc["total"] >= 1
    # scoped: behavioural coverage is a strict subset of reachable
    beh, reach = fr["coverage"]["behaviourally_verified"], fr["coverage"]["reachable_loaders"]
    assert beh and set(beh) < set(reach)
    assert fr["provenance"]["generator_commit"] and fr["provenance"]["recipe_digest"]
    assert all(p["ok"] for p in fr["probes"])


def test_benchmark_summary_present_and_ground_truth_flagged_null():
    bm = api.product_state()["benchmark"]
    assert bm["copies_scanned"] and bm["mined"]["mechanically_valid"]
    assert "null" in bm["ground_truth"] and "must not" in bm["ground_truth"]


def test_human_gated_items_are_owned_by_a_human():
    hg = api.product_state()["human_gated"]
    assert len(hg) == 2 and all(h["owner"] == "human" and h["status"] == "pending" for h in hg)
    assert any("ground truth" in h["item"] for h in hg) and any("PR" in h["item"] for h in hg)
