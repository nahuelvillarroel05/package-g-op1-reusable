"""Synthetic read-only controls for the prospective rev004 sidecar verifier."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from runtime.candidate.run_framework.core import canonical
from runtime.candidate.run_framework.revision004_sidecar import (
    INDEX_V1,
    INDEX_V2,
    INDEX_V3,
    SidecarVerificationError,
    project_v2_receipt_payload,
    verify_revision004_sidecar,
)
from runtime.candidate.run_framework.revision004_wire import (
    canonical_payload,
    validate_unit_payload,
    validated_checkpoint_context,
)
from test_run_checkpoint_v2 import _campaign, _envelope
from test_convergence_caller import fixture as typed_fixture
from runtime.candidate.run_framework.caller import GenericCaller
from runtime.candidate.run_framework.revision004_profile import project_unit_metadata


SHA = "a" * 64


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _snapshot(root):
    return {path.relative_to(root).as_posix(): path.read_bytes()
            for path in sorted(root.rglob("*")) if path.is_file() and not path.is_symlink()}


def _v2_campaign(tmp_path):
    campaign = _campaign(tmp_path)
    for unit_id in campaign.config["expected_units"]:
        campaign.begin_unit(unit_id, {"synthetic": "sidecar-test"})
        if unit_id == "u1":
            audit_disposition = "AUDITED"
            audit_result = {"decision": "SUPPORTED", "reason": "authored scalar fixture"}
        else:
            audit_disposition = "ABSTAIN"
            audit_result = {"schema": "pgop1.predicate-evidence.v1",
                            "predicate_results": [{"predicate_id": "P1", "decision": "ABSTAIN",
                                                   "reason": "authored per-predicate fixture"}],
                            "abstentions": [{"predicate_id": "P1", "reason": "authored per-predicate fixture"}]}
        envelope = _envelope(campaign, unit_id)
        result_payload = {
            "schema": "pgop1.modality-a-payload.v1", "benchmark_id": "synthetic",
            "benchmark_version": "1", "adapter_id": "synthetic.adapter", "adapter_version": "1",
            "predicate_contract": {"contract_id": "SYNTHETIC", "version": "1", "sha256": SHA},
            "supporting_source_references": [], "normative_companion_references": [],
            "producer_provenance_status": "DECLARED", "processing_disposition": "AGENT_OUTPUT_AUDITED",
            "audit_disposition": audit_disposition, "audit_result": audit_result,
            "result_sha256": _hash(canonical(audit_result)),
        }
        envelope["result_type"] = "pgop1.modality-a-payload.v1"
        envelope["result_payload"] = result_payload
        envelope["result_payload_sha256"] = _hash(canonical(result_payload))
        campaign.complete_unit(unit_id, "AGENT_OUTPUT_AUDITED", envelope)
    campaign.recover()
    return campaign


def _typed_campaign(tmp_path):
    campaign = typed_fixture(tmp_path)
    def adapter(unit, refs):
        return {"definition": True}
    def auditor(unit, adapted):
        return {"audit_result": adapted, "processing_disposition": "TASK_DEFINITION_PROCESSED",
                "audit_disposition": "NOT_AUDITED_MISSING_AGENT_OUTPUT"}
    caller = GenericCaller(campaign, {("inert", "1"): adapter}, auditor, producer_id="fixture-producer")
    for unit in campaign.config["expected_units"]:
        caller.execute(unit)
    return campaign


def _make_sidecar(campaign, *, profile=INDEX_V2, attempt_mutator=None,
                  foreign_campaign=False, verdict=None, config_sha256=None,
                  checkpoint_limit=None, metadata_mutator=None):
    root = Path(campaign.output.parent) / "REV004_WIRE"
    (root / "receipts").mkdir(parents=True)
    (root / "checkpoints").mkdir()
    state = campaign.recover()
    selected = sorted(campaign.config["expected_units"])
    sidecar_config_sha = config_sha256 or campaign.config_sha256
    receipt_rows, payloads, hashes = [], [], []
    checkpoints = []
    context = None
    started, terminal = set(), set()
    for position, v2_summary in enumerate(state["receipts"], 1):
        v2_receipt = json.loads((campaign.output / v2_summary["path"]).read_text(encoding="utf-8"))
        phase = v2_receipt["phase"].upper()
        unit_id = v2_receipt["unit_id"]
        attempt_id = v2_receipt["attempt_id"]
        if attempt_mutator is not None:
            attempt_id = attempt_mutator(unit_id, phase, attempt_id)
        campaign_id = "FOREIGN-CAMPAIGN" if foreign_campaign else campaign.config["campaign_id"]
        projection = project_v2_receipt_payload(v2_receipt)
        payload = {
            "schema": "pgop1.run004.unit-receipt-payload.rev004",
            "campaign_id": campaign_id,
            "campaign_attempt_id": campaign.config["campaign_attempt_id"],
            "unit_id": unit_id, "logical_id": unit_id, "benchmark": "synthetic-v2",
            "version": "1", "revision": "1", "split": "development", "locale": "en",
            "modality": "A", "source_uri": f"synthetic://{unit_id}", "source_sha256": SHA,
            "integrity_status": "VERIFIED_SYNTHETIC", "available_evidence": [], "missing_evidence": [],
            "authentic_agent_output_status": "NOT_PRESENT", "producer_provenance": "DECLARED_SYNTHETIC",
            "contract_id": "SYNTHETIC-CONTRACT", "contract_sha256": campaign.config["contract_sha256"],
            "predicate_version": "synthetic-v1", "processing_started_at_unix_ns": 1000 + position * 10,
            "processing_ended_at_unix_ns": 1000 + position * 10 + (0 if phase == "START" else 5),
            "processing_duration_ns": 0 if phase == "START" else 5,
            **projection,
            "verdict": verdict if verdict is not None else projection["verdict"],
            "error": None, "blocker": None,
            "recovery_status": "INFLIGHT" if phase == "START" else "TERMINAL_RECORDED",
            "phase": phase, "parent_receipt_sha256": hashes[-1] if hashes else None,
            "attempt_id": attempt_id, "sequence": position,
            "bindings": {"source_sha256": SHA, "contract_sha256": campaign.config["contract_sha256"],
                         "config_sha256": sidecar_config_sha},
        }
        if profile == INDEX_V3:
            payload.update(project_unit_metadata(campaign, unit_id))
            payload["campaign_id"] = campaign_id
            payload["bindings"]["config_sha256"] = sidecar_config_sha
        if metadata_mutator is not None:
            metadata_mutator(payload)
        raw = validate_unit_payload(payload)
        digest = _hash(raw)
        name = f"{position:08d}-{digest}.json"
        (root / "receipts" / name).write_bytes(raw)
        receipt_rows.append({"sequence": position, "path": f"receipts/{name}", "sha256": digest,
                             "unit_id": unit_id, "phase": phase})
        payloads.append(payload); hashes.append(digest)
        if phase == "START": started.add(unit_id)
        else: terminal.add(unit_id)
        if profile == INDEX_V1:
            should_checkpoint = position == len(state["receipts"])
        else:
            should_checkpoint = position % 2 == 0
        if checkpoint_limit is not None and len(checkpoints) >= checkpoint_limit:
            should_checkpoint = False
        if should_checkpoint:
            checkpoint_payload = {
                "schema": "pgop1.run004.checkpoint-payload.rev004",
                "campaign_id": campaign_id,
                "campaign_attempt_id": campaign.config["campaign_attempt_id"],
                "parent_checkpoint_sha256": context.payload_sha256 if context else None,
                "ordered_receipt_payload_sha256": list(hashes),
                "completed_units": sorted(terminal),
                "pending_units": sorted(set(selected) - started),
                "inflight_units": sorted(started - terminal),
                "bindings": {"candidate_sha256": SHA, "config_sha256": sidecar_config_sha,
                             "contract_sha256": campaign.config["contract_sha256"]},
            }
            context = validated_checkpoint_context(checkpoint_payload, selected, payloads, context)
            checkpoint_raw = canonical_payload(checkpoint_payload)
            checkpoint_hash = _hash(checkpoint_raw)
            checkpoint_sequence = len(checkpoints) + 1
            checkpoint_name = f"{checkpoint_sequence:08d}-{checkpoint_hash}.json"
            (root / "checkpoints" / checkpoint_name).write_bytes(checkpoint_raw)
            checkpoints.append({"sequence": checkpoint_sequence,
                                "path": f"checkpoints/{checkpoint_name}", "sha256": checkpoint_hash})
    if not checkpoints:  # Authored no-event state: empty genesis, all units pending.
        checkpoint_payload = {
            "schema": "pgop1.run004.checkpoint-payload.rev004",
            "campaign_id": campaign.config["campaign_id"],
            "campaign_attempt_id": campaign.config["campaign_attempt_id"],
            "parent_checkpoint_sha256": None, "ordered_receipt_payload_sha256": [],
            "completed_units": [], "pending_units": selected, "inflight_units": [],
            "bindings": {"candidate_sha256": SHA, "config_sha256": campaign.config_sha256,
                         "contract_sha256": campaign.config["contract_sha256"]},
        }
        context = validated_checkpoint_context(checkpoint_payload, selected, [])
        raw = canonical_payload(checkpoint_payload); digest = _hash(raw)
        name = f"00000001-{digest}.json"
        (root / "checkpoints" / name).write_bytes(raw)
        checkpoints.append({"sequence": 1, "path": f"checkpoints/{name}", "sha256": digest})
    if profile == INDEX_V1:
        index = {"schema": INDEX_V1, "receipts": receipt_rows, "checkpoint": checkpoints[-1]}
    elif profile == INDEX_V2:
        index = {"schema": INDEX_V2, "receipts": receipt_rows, "checkpoints": checkpoints}
    else:
        from runtime.candidate.run_framework.core import canonical
        index = {"schema": INDEX_V3, "receipt_index": "VERIFIED_CAMPAIGN_V2_JOURNAL",
                 "run_id": campaign.run_id, "campaign_id": campaign.config["campaign_id"],
                 "campaign_attempt_id": campaign.config["campaign_attempt_id"],
                 "config_sha256": campaign.config_sha256,
                 "contract_sha256": campaign.config["contract_sha256"],
                 "expected_units_sha256": _hash(canonical(sorted(campaign.config["expected_units"]))) }
    (root / "INDEX.json").write_bytes(canonical_payload(index))
    return root


def test_clean_index_v2_chain_matches_same_object_v2_and_is_read_only(tmp_path):
    campaign = _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign)
    before = _snapshot(sidecar)
    result = verify_revision004_sidecar(sidecar, campaign)
    assert result["status"] == "READ_ONLY_SIDECAR_MATCHES_SAME_OBJECT_V2_RECOVERY"
    assert result["receipt_count"] == 4 and result["checkpoint_count"] == 2
    assert result["completed_units"] == ["u1", "u2"]
    terminal_payloads = [json.loads((sidecar / row["path"]).read_text(encoding="utf-8"))
                         for row in json.loads((sidecar / "INDEX.json").read_text(encoding="utf-8"))["receipts"]
                         if row["phase"] == "TERMINAL"]
    assert terminal_payloads[0]["verdict"] == "SUPPORTED"
    assert terminal_payloads[0]["audit_status"] == "PERFORMED"
    assert terminal_payloads[1]["verdict"] == "UNKNOWN"
    assert terminal_payloads[1]["verdict_scope_reason"] == "PREDICATE_RESULTS_HAVE_NO_SINGLE_GLOBAL_VERDICT"
    assert terminal_payloads[1]["audit_status"] == "PERFORMED"
    assert _snapshot(sidecar) == before


def test_index_v3_header_derives_receipts_and_checkpoints_from_same_v2_context(tmp_path):
    campaign = _typed_campaign(tmp_path); sidecar = _make_sidecar(campaign, profile=INDEX_V3)
    index = json.loads((sidecar / "INDEX.json").read_text(encoding="utf-8"))
    assert set(index) == {"schema", "receipt_index", "run_id", "campaign_id", "campaign_attempt_id",
                          "config_sha256", "contract_sha256", "expected_units_sha256"}
    before = _snapshot(sidecar)
    result = verify_revision004_sidecar(sidecar, campaign)
    assert result["index_profile"] == INDEX_V3
    assert result["receipt_count"] == 4 and result["checkpoint_count"] == 2
    assert "unit/phase/attempt crosswalk and typed result projection" in result["verified_scope"]
    assert "source_sha256" not in result["unverified_crosswalk_fields"]
    assert result["unit_metadata_verification"] == "FROZEN_TYPED_UNIT_AND_EVIDENCE_BYTES"
    assert result["external_custody_established"] is False
    assert result["independent_antirollback_established"] is False
    assert _snapshot(sidecar) == before


def test_index_v3_empty_genesis_covers_only_pending_units(tmp_path):
    campaign = _campaign(tmp_path)
    sidecar = _make_sidecar(campaign, profile=INDEX_V3)
    result = verify_revision004_sidecar(sidecar, campaign)
    assert result["receipt_count"] == 0
    assert result["checkpoint_count"] == 1
    assert result["completed_units"] == []
    assert result["pending_units"] == ["u1", "u2"]


def test_index_v3_header_binding_mismatch_is_rejected(tmp_path):
    campaign = _typed_campaign(tmp_path); sidecar = _make_sidecar(campaign, profile=INDEX_V3)
    index_path = sidecar / "INDEX.json"
    index = json.loads(index_path.read_text(encoding="utf-8")); index["expected_units_sha256"] = "b" * 64
    index_path.write_bytes(canonical_payload(index))
    with pytest.raises(SidecarVerificationError, match="INDEX_V3_CONTROL_HEADER_BINDING_MISMATCH"):
        verify_revision004_sidecar(sidecar, campaign)


@pytest.mark.parametrize('field,value', [
    ('benchmark', 'invented-benchmark'), ('logical_id', 'invented-logical-id'),
    ('source_uri', 'synthetic://foreign-source'), ('source_sha256', '0'*64),
    ('authentic_agent_output_status', 'AUTHENTIC_AND_AUTHENTICATED'),
    ('available_evidence', []), ('predicate_version', 'invented-version'),
])
def test_v3_rehashed_false_unit_metadata_is_rejected(tmp_path, field, value):
    campaign = _typed_campaign(tmp_path)
    def mutate(payload):
        payload[field] = value
        if field == 'source_sha256':
            payload['bindings']['source_sha256'] = value
    sidecar = _make_sidecar(campaign, profile=INDEX_V3, metadata_mutator=mutate)
    with pytest.raises(SidecarVerificationError, match='AUTHORITATIVE_UNIT_METADATA_MISMATCH'):
        verify_revision004_sidecar(sidecar, campaign)


def test_index_v3_uncheckpointed_receipt_tail_blocks(tmp_path):
    campaign = _typed_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, profile=INDEX_V3, checkpoint_limit=1)
    with pytest.raises(SidecarVerificationError, match="SIDECAR_RECEIPTS_NOT_COVERED_BY_FINAL_CHECKPOINT"):
        verify_revision004_sidecar(sidecar, campaign)


def test_v2_projection_maps_not_performed_with_exact_audit_disposition_reason():
    audit_result = {"schema": "pgop1.predicate-evidence.v1",
                    "predicate_results": [{"predicate_id": "P1", "decision": "NOT_EVALUATED",
                                           "reason": "No authentic output is bound"}]}
    result = {"schema": "pgop1.modality-a-payload.v1", "benchmark_id": "synthetic",
              "benchmark_version": "1", "adapter_id": "synthetic.adapter", "adapter_version": "1",
              "predicate_contract": {"contract_id": "SYNTHETIC", "version": "1", "sha256": SHA},
              "supporting_source_references": [], "normative_companion_references": [],
              "producer_provenance_status": "DECLARED", "processing_disposition": "TASK_DEFINITION_PROCESSED",
              "audit_disposition": "NOT_AUDITED_MISSING_AGENT_OUTPUT", "audit_result": audit_result,
              "result_sha256": _hash(canonical(audit_result))}
    v2_payload = {"result_type": "pgop1.modality-a-payload.v1", "result_payload": result,
                  "result_payload_sha256": _hash(canonical(result))}
    projected = project_v2_receipt_payload({"phase": "terminal", "disposition": "TASK_DEFINITION_PROCESSED",
                                             "payload": v2_payload})
    assert projected["audit_status"] == "NOT_PERFORMED"
    assert projected["audit_reason"] == "NOT_AUDITED_MISSING_AGENT_OUTPUT"
    assert projected["verdict"] == "UNKNOWN"
    assert projected["verdict_scope_reason"] == "AUDIT_NOT_PERFORMED"


def test_v2_projection_binds_definition_metadata_without_interpreting_it():
    metadata = {"definition": True, "source": "authored synthetic metadata"}
    result = {"schema": "pgop1.modality-a-payload.v1", "benchmark_id": "synthetic",
              "benchmark_version": "1", "adapter_id": "synthetic.adapter", "adapter_version": "1",
              "predicate_contract": {"contract_id": "SYNTHETIC", "version": "1", "sha256": SHA},
              "supporting_source_references": [], "normative_companion_references": [],
              "producer_provenance_status": "DECLARED", "processing_disposition": "TASK_DEFINITION_PROCESSED",
              "audit_disposition": "NOT_AUDITED_MISSING_AGENT_OUTPUT", "audit_result": metadata,
              "result_sha256": _hash(canonical(metadata))}
    v2_payload = {"result_type": "pgop1.modality-a-payload.v1", "result_payload": result,
                  "result_payload_sha256": _hash(canonical(result))}
    projected = project_v2_receipt_payload({"phase": "terminal", "disposition": "TASK_DEFINITION_PROCESSED",
                                             "payload": v2_payload})
    assert projected["processing_result"] == "TASK_DEFINITION_PROCESSED"
    assert projected["audit_status"] == "NOT_PERFORMED"
    assert projected["audit_reason"] == "NOT_AUDITED_MISSING_AGENT_OUTPUT"
    assert projected["verdict"] == "UNKNOWN"
    assert projected["verdict_scope_reason"] == "AUDIT_NOT_PERFORMED"
    assert projected["audit_result_sha256"] == _hash(canonical(metadata))


def test_v2_projection_rejects_mixed_predicate_and_global_scalar_claims():
    audit_result = {"schema": "pgop1.predicate-evidence.v1",
                    "predicate_results": [{"predicate_id": "P1", "decision": "CONTRADICTED"}],
                    "decision": "SUPPORTED", "reason": "authored conflicting summary"}
    result = {"schema": "pgop1.modality-a-payload.v1", "benchmark_id": "synthetic",
              "benchmark_version": "1", "adapter_id": "synthetic.adapter", "adapter_version": "1",
              "predicate_contract": {"contract_id": "SYNTHETIC", "version": "1", "sha256": SHA},
              "supporting_source_references": [], "normative_companion_references": [],
              "producer_provenance_status": "DECLARED", "processing_disposition": "AGENT_OUTPUT_AUDITED",
              "audit_disposition": "AUDITED", "audit_result": audit_result,
              "result_sha256": _hash(canonical(audit_result))}
    v2_payload = {"result_type": "pgop1.modality-a-payload.v1", "result_payload": result,
                  "result_payload_sha256": _hash(canonical(result))}
    with pytest.raises(SidecarVerificationError, match="V2_AUDIT_RESULT_PROFILE_AMBIGUOUS"):
        project_v2_receipt_payload({"phase": "terminal", "disposition": "AGENT_OUTPUT_AUDITED",
                                    "payload": v2_payload})


def test_exact_legacy_index_is_supported_for_one_genesis_checkpoint(tmp_path):
    campaign = _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, profile=INDEX_V1)
    assert verify_revision004_sidecar(sidecar, campaign)["index_profile"] == INDEX_V1


def test_empty_legacy_genesis_matches_v2_initial_pending_state(tmp_path):
    campaign = _campaign(tmp_path)
    sidecar = _make_sidecar(campaign, profile=INDEX_V1)
    result = verify_revision004_sidecar(sidecar, campaign)
    assert result["receipt_count"] == 0
    assert result["pending_units"] == ["u1", "u2"]


def test_orphan_receipt_is_rejected_even_when_indexed_data_is_valid(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    (sidecar / "receipts" / ("00000099-" + "f" * 64 + ".json")).write_bytes(b"orphan")
    with pytest.raises(SidecarVerificationError, match="ORPHAN_SIDECAR_RECEIPT"):
        verify_revision004_sidecar(sidecar, campaign)


@pytest.mark.parametrize("profile", [INDEX_V2, INDEX_V3])
def test_v3_and_v2_orphan_receipts_are_rejected(tmp_path, profile):
    campaign = _typed_campaign(tmp_path) if profile == INDEX_V3 else _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, profile=profile)
    (sidecar / "receipts" / ("00000099-" + "f" * 64 + ".json")).write_bytes(b"orphan")
    with pytest.raises(SidecarVerificationError, match="ORPHAN_SIDECAR_RECEIPT"):
        verify_revision004_sidecar(sidecar, campaign)


def test_missing_indexed_receipt_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    index = json.loads((sidecar / "INDEX.json").read_text(encoding="utf-8"))
    (sidecar / index["receipts"][0]["path"]).unlink()
    with pytest.raises(SidecarVerificationError, match="MISSING_SIDECAR_RECEIPT"):
        verify_revision004_sidecar(sidecar, campaign)


@pytest.mark.parametrize("profile", [INDEX_V2, INDEX_V3])
def test_v3_and_v2_missing_receipts_are_rejected(tmp_path, profile):
    campaign = _typed_campaign(tmp_path) if profile == INDEX_V3 else _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, profile=profile)
    target = next((sidecar / "receipts").iterdir()); target.unlink()
    with pytest.raises(SidecarVerificationError, match="MISSING_SIDECAR_RECEIPT"):
        verify_revision004_sidecar(sidecar, campaign)


def test_truncated_indexed_receipt_is_rejected_without_repair(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    index = json.loads((sidecar / "INDEX.json").read_text(encoding="utf-8"))
    target = sidecar / index["receipts"][0]["path"]
    target.write_bytes(b"{\"partial\":")
    before = target.read_bytes()
    with pytest.raises(SidecarVerificationError, match="SIDECAR_RECEIPT_HASH_MISMATCH"):
        verify_revision004_sidecar(sidecar, campaign)
    assert target.read_bytes() == before


def test_orphan_checkpoint_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    (sidecar / "checkpoints" / ("00000099-" + "f" * 64 + ".json")).write_bytes(b"orphan")
    with pytest.raises(SidecarVerificationError, match="ORPHAN_SIDECAR_CHECKPOINT"):
        verify_revision004_sidecar(sidecar, campaign)


def test_v3_orphan_checkpoint_is_rejected(tmp_path):
    campaign = _typed_campaign(tmp_path); sidecar = _make_sidecar(campaign, profile=INDEX_V3)
    (sidecar / "checkpoints" / ("00000099-" + "f" * 64 + ".json")).write_bytes(b"orphan")
    with pytest.raises(SidecarVerificationError, match="ORPHAN_SIDECAR_CHECKPOINT"):
        verify_revision004_sidecar(sidecar, campaign)


def test_missing_indexed_checkpoint_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    index = json.loads((sidecar / "INDEX.json").read_text(encoding="utf-8"))
    (sidecar / index["checkpoints"][0]["path"]).unlink()
    with pytest.raises(SidecarVerificationError, match="MISSING_SIDECAR_CHECKPOINT"):
        verify_revision004_sidecar(sidecar, campaign)


def test_truncated_or_noncanonical_index_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    (sidecar / "INDEX.json").write_bytes(b"{\"truncated\":")
    with pytest.raises(SidecarVerificationError, match="SIDECAR_NONCANONICAL_OR_TRUNCATED:INDEX.json"):
        verify_revision004_sidecar(sidecar, campaign)


def test_index_path_traversal_and_duplicate_order_are_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    index_path = sidecar / "INDEX.json"
    original_index = index_path.read_bytes()
    index = json.loads(original_index.decode("utf-8"))
    index["receipts"][0]["path"] = "receipts/../outside.json"
    index_path.write_bytes(canonical_payload(index))
    with pytest.raises(SidecarVerificationError, match="SIDECAR_RECEIPT_PATH_UNSAFE"):
        verify_revision004_sidecar(sidecar, campaign)

    index_path.write_bytes(original_index)
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["receipts"][0], index["receipts"][1] = index["receipts"][1], index["receipts"][0]
    index_path.write_bytes(canonical_payload(index))
    with pytest.raises(SidecarVerificationError, match="SIDECAR_RECEIPT_INDEX_SEQUENCE_INVALID"):
        verify_revision004_sidecar(sidecar, campaign)


def test_symlinked_receipt_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path); sidecar = _make_sidecar(campaign)
    index = json.loads((sidecar / "INDEX.json").read_text(encoding="utf-8"))
    target = sidecar / index["receipts"][0]["path"]
    original = target.with_suffix(".original")
    target.rename(original)
    try:
        target.symlink_to(original)
    except (OSError, NotImplementedError) as exc:
        original.rename(target)
        pytest.skip(f"symlink creation unavailable: {exc}")
    with pytest.raises(SidecarVerificationError, match="SIDECAR_REPARSE_TRAVERSAL"):
        verify_revision004_sidecar(sidecar, campaign)


def test_v2_crosswalk_rejects_foreign_attempt_id(tmp_path):
    campaign = _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, attempt_mutator=lambda _unit, _phase, _attempt: "FOREIGN-ATTEMPT")
    with pytest.raises(SidecarVerificationError, match="V2_SIDECAR_RECEIPT_CROSSWALK_MISMATCH"):
        verify_revision004_sidecar(sidecar, campaign)


def test_sidecar_campaign_mismatch_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, foreign_campaign=True)
    with pytest.raises(SidecarVerificationError, match="SIDECAR_RECEIPT_IDENTITY_OR_CHAIN_MISMATCH"):
        verify_revision004_sidecar(sidecar, campaign)


def test_sidecar_config_mismatch_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, config_sha256="b" * 64)
    with pytest.raises(SidecarVerificationError, match="SIDECAR_RECEIPT_IDENTITY_OR_CHAIN_MISMATCH"):
        verify_revision004_sidecar(sidecar, campaign)


def test_sidecar_positive_verdict_that_disagrees_with_v2_is_rejected(tmp_path):
    campaign = _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, verdict="SUPPORTED")
    with pytest.raises(SidecarVerificationError, match="SIDECAR_SEMANTIC_CLAIM_MISMATCH"):
        verify_revision004_sidecar(sidecar, campaign)


@pytest.mark.parametrize("profile", [INDEX_V2, INDEX_V3])
def test_subprocess_interruption_leaves_orphan_and_fails_closed(tmp_path, profile):
    campaign = _typed_campaign(tmp_path) if profile == INDEX_V3 else _v2_campaign(tmp_path)
    sidecar = _make_sidecar(campaign, profile=profile)
    partial = sidecar / "receipts" / ("00000099-" + "e" * 64 + ".json")
    child = "import os,sys; p=sys.argv[1]; fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY); os.write(fd,b'{\\\"partial\\\":'); os._exit(73)"
    result = subprocess.run([sys.executable, "-c", child, str(partial)], capture_output=True)
    assert result.returncode == 73
    before = partial.read_bytes()
    with pytest.raises(SidecarVerificationError, match="ORPHAN_SIDECAR_RECEIPT"):
        verify_revision004_sidecar(sidecar, campaign)
    assert partial.read_bytes() == before
