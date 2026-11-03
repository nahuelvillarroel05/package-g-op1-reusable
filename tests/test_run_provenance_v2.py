import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime.candidate.run_framework import FrameworkError
from runtime.candidate.run_framework.provenance import RESULT_SCHEMA, validate_result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "synthetic-source.json"
    source.write_text('{"kind":"synthetic inert fixture","unit":"u1"}', encoding="utf-8")
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"fixture_evidence":true}', encoding="utf-8")
    source_bytes, evidence_bytes = source.read_bytes(), evidence.read_bytes()
    unit = {"unit_id": "u1", "source_id": "fixture-source-u1", "source_sha256": sha(source_bytes),
            "evidence_references": [{"path": str(evidence), "sha256": sha(evidence_bytes)}]}
    manifest = {"units": [unit]}
    contract = {"producers": {"fixture-producer": {"identity_status": "DECLARED"}}}
    manifest_path, contract_path = tmp_path / "dataset.json", tmp_path / "contract.json"
    manifest_path.write_bytes(canonical(manifest))
    contract_path.write_bytes(canonical(contract))
    config = {
        "run_id": "run-v2", "campaign_attempt_id": "attempt-v2", "campaign_id": "campaign-v2",
        "dataset_manifest_path": str(manifest_path), "input_manifest_sha256": sha(manifest_path.read_bytes()),
        "contract_path": str(contract_path), "contract_sha256": sha(contract_path.read_bytes()),
        "input_bindings": [{"path": str(source), "sha256": sha(source_bytes)}],
        "allowlisted_roots": [str(tmp_path)], "expected_units": ["u1"],
        "candidate_commit": "a" * 40, "candidate_tree": "b" * 40,
    }
    campaign = SimpleNamespace(config=config)
    result_payload = {"disposition": "recorded", "score": 1}
    envelope = {
        "schema": RESULT_SCHEMA, "run_id": config["run_id"],
        "campaign_attempt_id": config["campaign_attempt_id"], "campaign_id": config["campaign_id"],
        "unit_id": "u1", "source_id": unit["source_id"], "source_sha256": unit["source_sha256"],
        "contract_sha256": config["contract_sha256"], "candidate_commit": config["candidate_commit"],
        "candidate_tree": config["candidate_tree"], "producer_id": "fixture-producer",
        "producer_identity_status": "DECLARED", "result_id": "result-u1", "result_type": "disposition",
        "evidence_references": [{"path": str(evidence), "sha256": sha(evidence_bytes)}],
        "result_payload_sha256": sha(canonical(result_payload)), "result_payload": result_payload,
    }
    return campaign, envelope, source, evidence


def test_admits_structural_provenance_without_certifying_execution(tmp_path):
    campaign, envelope, _, _ = fixture(tmp_path)
    metadata = validate_result(campaign, "u1", envelope)
    assert metadata["admission_status"] == "STRUCTURALLY_ADMITTED"
    assert metadata["execution_certification"] == "NOT_EXECUTION_CERTIFIED"
    assert metadata["producer_identity_status"] == "DECLARED"


@pytest.mark.parametrize("field,value,reason", [
    ("campaign_attempt_id", "attempt-from-another-campaign", "RESULT_FROM_ANOTHER_CAMPAIGN"),
    ("unit_id", "other-unit", "RESULT_UNIT_MISMATCH"),
    ("source_sha256", "0" * 64, "RESULT_PROVENANCE_MISMATCH:source_sha256"),
    ("candidate_commit", "f" * 40, "RESULT_PROVENANCE_MISMATCH:candidate_commit"),
    ("contract_sha256", "0" * 64, "RESULT_PROVENANCE_MISMATCH:contract_sha256"),
    ("producer_id", "undeclared-producer", "RESULT_PRODUCER_UNKNOWN"),
    ("producer_identity_status", "AUTHENTICATED", "RESULT_PRODUCER_NOT_AUTHENTICATED"),
    ("result_payload_sha256", "0" * 64, "RESULT_PAYLOAD_HASH_MISMATCH"),
])
def test_rejects_forged_or_cross_bound_envelopes(tmp_path, field, value, reason):
    campaign, envelope, _, _ = fixture(tmp_path)
    envelope[field] = value
    with pytest.raises(FrameworkError, match=reason):
        validate_result(campaign, "u1", envelope)


def test_rejects_missing_provenance_and_unlisted_evidence(tmp_path):
    campaign, envelope, _, evidence = fixture(tmp_path)
    with pytest.raises(FrameworkError, match="RESULT_WITHOUT_PROVENANCE"):
        validate_result(campaign, "u1", {"result_payload": {"ok": True}})
    envelope["evidence_references"] = [{"path": str(evidence), "sha256": "c" * 64}]
    with pytest.raises(FrameworkError, match="RESULT_EVIDENCE_NOT_IN_MANIFEST"):
        validate_result(campaign, "u1", envelope)


def test_rejects_evidence_whose_current_bytes_differ_from_manifest(tmp_path):
    campaign, envelope, _, evidence = fixture(tmp_path)
    evidence.write_text('{"fixture_evidence":false}', encoding="utf-8")
    with pytest.raises(FrameworkError, match="result evidence byte hash mismatch"):
        validate_result(campaign, "u1", envelope)


def test_rejects_evidence_authorized_for_a_different_unit(tmp_path):
    campaign, envelope, _, _ = fixture(tmp_path)
    other_source = tmp_path / "synthetic-source-u2.json"
    other_source.write_text('{"kind":"synthetic inert fixture","unit":"u2"}', encoding="utf-8")
    other_evidence = tmp_path / "evidence-u2.json"
    other_evidence.write_text('{"fixture_evidence":"u2"}', encoding="utf-8")
    dataset_path = Path(campaign.config["dataset_manifest_path"])
    manifest = json.loads(dataset_path.read_text(encoding="utf-8"))
    manifest["units"].append({
        "unit_id": "u2", "source_id": "fixture-source-u2", "source_sha256": sha(other_source.read_bytes()),
        "evidence_references": [{"path": str(other_evidence), "sha256": sha(other_evidence.read_bytes())}],
    })
    dataset_path.write_bytes(canonical(manifest))
    campaign.config["input_manifest_sha256"] = sha(dataset_path.read_bytes())
    campaign.config["input_bindings"].append({"path": str(other_source), "sha256": sha(other_source.read_bytes())})
    campaign.config["expected_units"] = ["u1", "u2"]
    envelope["evidence_references"] = manifest["units"][1]["evidence_references"]
    with pytest.raises(FrameworkError, match="RESULT_EVIDENCE_NOT_IN_MANIFEST"):
        validate_result(campaign, "u1", envelope)


def test_rejects_source_without_bytes_binding_and_source_mutation(tmp_path):
    campaign, envelope, source, _ = fixture(tmp_path)
    campaign.config["input_bindings"] = []
    with pytest.raises(FrameworkError, match="dataset source has no uniquely bound source bytes"):
        validate_result(campaign, "u1", envelope)

    campaign, envelope, source, _ = fixture(tmp_path / "second")
    validate_result(campaign, "u1", envelope)
    source.write_text("tampered source", encoding="utf-8")
    with pytest.raises(FrameworkError, match="dataset source byte hash mismatch"):
        validate_result(campaign, "u1", envelope)
