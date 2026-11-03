import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.run_framework.core import FrameworkError, canonical, digest, load_config
from runtime.candidate.run_framework.incremental import CampaignV2
from test_reusable_run_framework import fixture_config


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _campaign(tmp_path):
    config_path = tmp_path / "config.json"
    if not config_path.exists():
        config_path, cfg = fixture_config(tmp_path)
        root = Path(cfg["code_root"]).parent
        source = root / "input.json"
        evidence = root / "adapter.json"
        contract = root / "contract.json"
        dataset = root / "dataset.json"
        contract.write_bytes(canonical({"producers": {"fixture-producer": {"identity_status": "DECLARED"}}}))
        dataset.write_bytes(canonical({
            "units": [{"unit_id": unit, "source_id": "fixture-source", "source_sha256": _sha(source),
                       "evidence_references": [{"path": str(evidence), "sha256": _sha(evidence)}]}
                      for unit in cfg["expected_units"]],
        }))
        cfg["contract_sha256"] = _sha(contract)
        cfg["input_manifest_sha256"] = _sha(dataset)
        cfg["checkpoint_policy"] = {"interval": 2, "schema": "pgop1.reusable-run-checkpoint.v2"}
        config_path.write_bytes(canonical(cfg))
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    root = Path(cfg["code_root"]).parent
    output = root / cfg["run_id"] / "attempts" / cfg["campaign_attempt_id"]
    campaign = load_config(config_path, [root], output, [root], [root])
    # The caller's v2 selector constructs this subclass; the base load_config
    # remains v1 until the coordinator routes it.
    c = CampaignV2(campaign.config, campaign.config_sha256, campaign.config_path,
                   campaign.config_roots, campaign.output, campaign.output_roots)
    c.preflight()
    return c


def _envelope(c, unit):
    source = Path(c.config["input_bindings"][0]["path"])
    evidence = Path(c.config["adapter_registry"]["path"])
    result_payload = {"status": "synthetic-only", "unit": unit}
    return {
        "schema": "pgop1.run-result-envelope.v2", "run_id": c.run_id,
        "campaign_attempt_id": c.config["campaign_attempt_id"],
        "campaign_id": c.config["campaign_id"], "unit_id": unit,
        "source_id": "fixture-source", "source_sha256": _sha(source),
        "contract_sha256": c.config["contract_sha256"],
        "candidate_commit": c.config["candidate_commit"], "candidate_tree": c.config["candidate_tree"],
        "producer_id": "fixture-producer", "producer_identity_status": "DECLARED",
        "result_id": "result-" + unit, "result_type": "synthetic-test",
        "evidence_references": [{"path": str(evidence), "sha256": _sha(evidence)}],
        "result_payload_sha256": digest(canonical(result_payload)), "result_payload": result_payload,
    }


def test_v2_manifest_delta_checkpoint_and_fresh_process_read_recovery(tmp_path):
    c = _campaign(tmp_path)
    c.begin_unit("u1", {"note": "synthetic start"})
    c.complete_unit("u1", "DISPOSITION_RECORDED", _envelope(c, "u1"))
    c2 = _campaign(tmp_path)
    state = c2.recover()
    assert state["completed"] == {"u1"}
    assert state["pending"] == {"u2"}
    assert state["inflight"] == set()
    assert len(state["checkpoints"]) == 1
    assert c2.report()["execution_completeness"] == "NOT_CERTIFIED"
    with pytest.raises(FrameworkError, match="read-only"):
        c2.begin_unit("u2", {})


def test_result_rejection_is_preserved_and_never_admitted(tmp_path):
    c = _campaign(tmp_path)
    c.begin_unit("u1", {})
    bad = _envelope(c, "u1")
    bad["source_id"] = "substituted-source"
    raw = canonical(bad)
    with pytest.raises(FrameworkError, match="RESULT_PROVENANCE_MISMATCH"):
        c.complete_unit("u1", "DONE", bad)
    rejected = list((c.output / "rejected").glob("*.json"))
    assert len(rejected) == 1 and rejected[0].read_bytes() == raw
    state = _campaign(tmp_path).recover()
    assert state["inflight"] == {"u1"}
    assert state["completed"] == set()


@pytest.mark.parametrize("tamper", ["delta", "manifest", "checkpoint"])
def test_v2_tampering_blocks_read_recovery(tmp_path, tamper):
    c = _campaign(tmp_path)
    c.begin_unit("u1", {})
    c.complete_unit("u1", "DONE", _envelope(c, "u1"))
    if tamper == "delta":
        p = next((c.output / "deltas").glob("*.json"))
    elif tamper == "manifest":
        p = next((c.output / "manifest").glob("*.json"))
    else:
        p = next((c.output / "checkpoints").glob("*.json"))
    p.write_bytes(p.read_bytes() + b" ")
    with pytest.raises(FrameworkError):
        _campaign(tmp_path).recover()


def test_v2_orphan_delta_and_truncation_block_recovery(tmp_path):
    c = _campaign(tmp_path)
    c.begin_unit("u1", {})
    (c.output / "deltas" / ("00000099-" + "a" * 64 + ".json")).write_bytes(b"{}")
    with pytest.raises(FrameworkError):
        _campaign(tmp_path).recover()


def test_interrupted_tail_exposes_last_verified_checkpoint_without_repair(tmp_path):
    c = _campaign(tmp_path)
    c.begin_unit("u1", {})
    c.complete_unit("u1", "DONE", _envelope(c, "u1"))
    c.begin_unit("u2", {})
    tail = sorted((c.output / "deltas").glob("*.json"))[-1]
    tail.write_bytes(tail.read_bytes() + b" ")
    recovered = _campaign(tmp_path).recover_valid_prefix()
    assert recovered["recovery_status"] == "INCOMPLETE_READ_ONLY"
    assert recovered["verified_prefix_sequence"] == 2
    assert recovered["completed"] == {"u1"}
    assert recovered["pending"] == {"u2"}
    assert tail.read_bytes().endswith(b" ")


def test_v2_configuration_is_recursively_immutable_in_memory(tmp_path):
    c = _campaign(tmp_path)
    with pytest.raises(FrameworkError, match="configuration is immutable"):
        c.config["resource_budget"]["max_units"] = 999
    with pytest.raises(FrameworkError, match="configuration is immutable"):
        c.config["expected_units"].append("substituted")


def test_v2_manifest_and_selection_are_bound_to_frozen_config(tmp_path):
    c = _campaign(tmp_path)
    c.begin_unit("u1", {})
    config_path = c.config_path
    cfg = json.loads(config_path.read_text(encoding="utf-8"))
    cfg["expected_units"] = ["u1"]
    config_path.write_bytes(canonical(cfg))
    with pytest.raises(FrameworkError):
        _campaign(tmp_path).recover()

