"""Focused contract-wire controls for rev004; authored synthetic payloads only."""
import hashlib

import pytest

from runtime.candidate.run_framework.revision004_wire import (
    Rev004WireError, canonical_payload, decode_payload,
    validate_checkpoint_payload, validate_unit_payload, observe_callback,
)

SHA = "a" * 64


def unit():
    return {"schema": "pgop1.run004.unit-receipt-payload.rev004", "campaign_id": "DEV-CAMPAIGN",
            "campaign_attempt_id": "DEV-ATTEMPT", "unit_id": "u1", "logical_id": "task-1",
            "benchmark": "synthetic", "version": "1", "revision": "1", "split": "development",
            "locale": "en", "modality": "A", "source_uri": "synthetic://source", "source_sha256": SHA,
            "integrity_status": "VERIFIED_SYNTHETIC", "available_evidence": [], "missing_evidence": [],
            "authentic_agent_output_status": "NOT_PRESENT", "producer_provenance": "DECLARED",
            "contract_id": "DEV-CONTRACT", "contract_sha256": SHA, "predicate_version": "development-1",
            "processing_started_at_unix_ns": 100, "processing_ended_at_unix_ns": 110,
            "processing_duration_ns": 10, "processing_result": "NOT_EVALUABLE_WITH_CURRENT_EVIDENCE",
            "audit_status": "NOT_PERFORMED", "audit_reason": "No authentic output in synthetic fixture",
            "verdict": "UNKNOWN", "abstention_reason": "NO_AUTHENTIC_OUTPUT",
            "error": None, "blocker": None, "recovery_status": "PENDING",
            "phase": "START", "parent_receipt_sha256": None,
            "attempt_id": "DEV-ATTEMPT-1", "sequence": 1,
            "bindings": {"source_sha256": SHA, "contract_sha256": SHA, "config_sha256": SHA},
            "result": "NOT_EVALUABLE_WITH_CURRENT_EVIDENCE"}


def receipt_pair():
    import copy
    start = unit()
    start_raw = validate_unit_payload(start)
    start_sha = hashlib.sha256(start_raw).hexdigest()
    terminal = copy.deepcopy(start)
    terminal.update(phase="TERMINAL", parent_receipt_sha256=start_sha, sequence=2,
                    processing_ended_at_unix_ns=120, processing_duration_ns=20,
                    processing_result="TASK_DEFINITION_PROCESSED", recovery_status="TERMINAL_RECORDED")
    terminal_raw = validate_unit_payload(terminal)
    terminal_sha = hashlib.sha256(terminal_raw).hexdigest()
    return [start, terminal], [start_sha, terminal_sha]


def checkpoint(receipt_hashes):
    return {"schema": "pgop1.run004.checkpoint-payload.rev004", "campaign_id": "DEV-CAMPAIGN",
            "campaign_attempt_id": "DEV-ATTEMPT", "parent_checkpoint_sha256": None,
            "ordered_receipt_payload_sha256": receipt_hashes, "completed_units": ["u1"],
            "pending_units": ["u2"], "inflight_units": [],
            "bindings": {"candidate_sha256": SHA, "config_sha256": SHA, "contract_sha256": SHA}}


def test_rev004_unit_payload_is_detached_canonical_utf8_and_roundtrips():
    payload = unit(); payload["result"] = "desarrollo-é"
    raw = validate_unit_payload(payload)
    assert not raw.startswith(b"\xef\xbb\xbf") and not raw.endswith(b"\n")
    assert decode_payload(raw, hashlib.sha256(raw).hexdigest()) == payload


def test_rev004_rejects_noncanonical_duplicate_float_and_wrong_digest():
    payload = unit(); raw = canonical_payload(payload)
    with pytest.raises(Rev004WireError, match="canonical"):
        decode_payload(raw + b"\n", hashlib.sha256(raw + b"\n").hexdigest())
    with pytest.raises(Rev004WireError, match="duplicate"):
        decode_payload(b'{"a":1,"a":1}', hashlib.sha256(b'{"a":1,"a":1}').hexdigest())
    bad = unit(); bad["unsupported"] = 1.25
    with pytest.raises(Rev004WireError, match="floating"):
        validate_unit_payload(bad)
    with pytest.raises(Rev004WireError, match="digest"):
        decode_payload(raw, "0" * 64)


def test_rev004_checkpoint_requires_exact_disjoint_sets_and_bindings():
    receipts, hashes = receipt_pair()
    value = checkpoint(hashes)
    assert validate_checkpoint_payload(value, ["u1", "u2"], receipts)
    bad = checkpoint(hashes); bad["inflight_units"] = ["u1"]
    with pytest.raises(Rev004WireError, match="disjoint"):
        validate_checkpoint_payload(bad, ["u1", "u2"], receipts)
    bad = checkpoint(hashes); bad["pending_units"] = []
    with pytest.raises(Rev004WireError, match="reconcile"):
        validate_checkpoint_payload(bad, ["u1", "u2"], receipts)
    bad = checkpoint(hashes); bad["completed_units"] = ["u1", "u1"]
    with pytest.raises(Rev004WireError, match="sorted unique"):
        validate_checkpoint_payload(bad, ["u1", "u2"], receipts)


def test_callback_timing_is_observation_not_isolation():
    ticks = iter((10, 20))
    walls = iter((100, 200))
    result, timing = observe_callback(lambda x: x + 1, 4, clock_ns=lambda: next(ticks), wall_ns=lambda: next(walls))
    assert result == 5
    assert (timing.started_unix_ns, timing.ended_unix_ns, timing.duration_ns) == (100, 200, 10)


def test_compact_framework_v2_checkpoint_is_not_renamed_as_rev004():
    from runtime.candidate.run_framework.revision004_wire import assess_compact_checkpoint_v2
    existing = {"schema": "pgop1.reusable-run-checkpoint.v2", "sequence": 2,
                "manifest_sha256": SHA, "head_delta_sha256": SHA,
                "parent_checkpoint_sha256": None, "state_sha256": SHA}
    result = assess_compact_checkpoint_v2(existing)
    assert result["status"] == "INCOMPATIBLE"
    assert set(result["missing_rev004_fields"]) == {
        "ordered_receipt_payload_sha256", "completed_units", "pending_units", "inflight_units", "bindings"}
    assert result["mapping_performed"] is False and result["normative_amendment_required"] is True
    assert result["compatibility"] == "NOT_ESTABLISHED"


def test_rev004_receipt_requires_parent_sequence_and_top_level_binding_equality():
    receipt = unit()
    receipt["sequence"] = 2
    with pytest.raises(Rev004WireError, match="parent linkage"):
        validate_unit_payload(receipt)
    receipt["parent_receipt_sha256"] = SHA
    receipt["source_sha256"] = "b" * 64
    with pytest.raises(Rev004WireError, match="differ from binding"):
        validate_unit_payload(receipt)


def test_checkpoint_requires_actual_start_terminal_membership():
    import copy
    receipts, _hashes = receipt_pair()
    first = copy.deepcopy(receipts[1]); first.update(sequence=1, parent_receipt_sha256=None)
    first_sha = hashlib.sha256(validate_unit_payload(first)).hexdigest()
    second = copy.deepcopy(receipts[1]); second.update(sequence=2, parent_receipt_sha256=first_sha)
    second_sha = hashlib.sha256(validate_unit_payload(second)).hexdigest()
    bad = checkpoint([first_sha, second_sha])
    with pytest.raises(Rev004WireError, match="matching start"):
        validate_checkpoint_payload(bad, ["u1", "u2"], [first, second])


@pytest.mark.parametrize("mutation,expected", [
    ("foreign_campaign", "campaign/config/contract bindings change"),
    ("changed_config", "campaign/config/contract bindings change"),
    ("checkpoint_config", "checkpoint campaign/config/contract identity differs"),
    ("checkpoint_contract", "checkpoint campaign/config/contract identity differs"),
])
def test_checkpoint_rejects_cross_receipt_and_checkpoint_identity_substitution(mutation, expected):
    import copy
    receipts, _ = receipt_pair()
    receipts = copy.deepcopy(receipts)
    checkpoint_payload = None
    if mutation == "foreign_campaign":
        receipts[1]["campaign_id"] = "FOREIGN-CAMPAIGN"
    elif mutation == "changed_config":
        receipts[1]["bindings"]["config_sha256"] = "b" * 64
    hashes = [hashlib.sha256(validate_unit_payload(r)).hexdigest() for r in receipts]
    receipts[1]["parent_receipt_sha256"] = hashes[0]
    hashes[1] = hashlib.sha256(validate_unit_payload(receipts[1])).hexdigest()
    checkpoint_payload = checkpoint(hashes)
    if mutation == "checkpoint_contract":
        checkpoint_payload["bindings"]["contract_sha256"] = "b" * 64
    elif mutation == "checkpoint_config":
        checkpoint_payload["bindings"]["config_sha256"] = "b" * 64
    with pytest.raises(Rev004WireError, match=expected):
        validate_checkpoint_payload(checkpoint_payload, ["u1", "u2"], receipts)
