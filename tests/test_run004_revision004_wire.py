"""Focused contract-wire controls for rev004; authored synthetic payloads only."""
import hashlib

import pytest

from runtime.candidate.run_framework.revision004_wire import (
    Rev004WireError, canonical_payload, decode_payload,
    validate_checkpoint_payload, validated_checkpoint_context,
    validate_unit_payload, observe_callback,
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


def progressed_chain(first_receipts, first_hashes):
    import copy
    start = copy.deepcopy(unit())
    start.update(unit_id="u2", logical_id="task-2", attempt_id="DEV-ATTEMPT-2",
                 sequence=3, parent_receipt_sha256=first_hashes[-1])
    start_hash = hashlib.sha256(validate_unit_payload(start)).hexdigest()
    terminal = copy.deepcopy(start)
    terminal.update(phase="TERMINAL", sequence=4, parent_receipt_sha256=start_hash,
                    processing_ended_at_unix_ns=120, processing_duration_ns=20,
                    processing_result="TASK_DEFINITION_PROCESSED", recovery_status="TERMINAL_RECORDED")
    terminal_hash = hashlib.sha256(validate_unit_payload(terminal)).hexdigest()
    receipts = [*copy.deepcopy(first_receipts), start, terminal]
    hashes = [*first_hashes, start_hash, terminal_hash]
    return receipts, hashes


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


def test_checkpoint_genesis_requires_null_parent_and_child_requires_validated_context():
    receipts, hashes = receipt_pair()
    genesis = checkpoint(hashes)
    context = validated_checkpoint_context(genesis, ["u1", "u2"], receipts)
    with pytest.raises(Rev004WireError, match="genesis checkpoint cannot have a predecessor"):
        validate_checkpoint_payload(genesis, ["u1", "u2"], receipts, context)
    child_receipts, child_hashes = progressed_chain(receipts, hashes)
    child = checkpoint(child_hashes)
    child.update(parent_checkpoint_sha256=context.payload_sha256,
                 completed_units=["u1", "u2"], pending_units=[])
    assert validate_checkpoint_payload(child, ["u1", "u2"], child_receipts, context)


def test_checkpoint_parent_digest_without_context_is_not_trusted():
    receipts, hashes = receipt_pair()
    child = checkpoint(hashes)
    child["parent_checkpoint_sha256"] = "b" * 64
    with pytest.raises(Rev004WireError, match="requires validated predecessor context"):
        validate_checkpoint_payload(child, ["u1", "u2"], receipts)


def test_empty_genesis_checkpoint_is_declared_state_only_and_accepts_first_start_child():
    empty = {"schema": "pgop1.run004.checkpoint-payload.rev004", "campaign_id": "DEV-CAMPAIGN",
             "campaign_attempt_id": "DEV-ATTEMPT", "parent_checkpoint_sha256": None,
             "ordered_receipt_payload_sha256": [], "completed_units": [],
             "pending_units": ["u1", "u2"], "inflight_units": [],
             "bindings": {"candidate_sha256": SHA, "config_sha256": SHA, "contract_sha256": SHA}}
    context = validated_checkpoint_context(empty, ["u1", "u2"], [])
    assert context.ordered_receipt_payload_sha256 == ()

    start = unit()
    start_raw = validate_unit_payload(start)
    start_sha = hashlib.sha256(start_raw).hexdigest()
    child = {**empty, "parent_checkpoint_sha256": context.payload_sha256,
             "ordered_receipt_payload_sha256": [start_sha], "pending_units": ["u2"],
             "inflight_units": ["u1"]}
    validated_checkpoint_context(child, ["u1", "u2"], [start], context)


def test_checkpoint_rejects_mismatched_and_foreign_predecessor_context():
    receipts, hashes = receipt_pair()
    context = validated_checkpoint_context(checkpoint(hashes), ["u1", "u2"], receipts)
    child_receipts, child_hashes = progressed_chain(receipts, hashes)

    mismatched = checkpoint(child_hashes)
    mismatched.update(parent_checkpoint_sha256="b" * 64,
                      completed_units=["u1", "u2"], pending_units=[])
    with pytest.raises(Rev004WireError, match="parent digest does not match"):
        validate_checkpoint_payload(mismatched, ["u1", "u2"], child_receipts, context)

    foreign_receipts, foreign_hashes = receipt_pair()
    for row in foreign_receipts:
        row["campaign_id"] = "FOREIGN-CAMPAIGN"
    foreign_hashes = [hashlib.sha256(validate_unit_payload(row)).hexdigest() for row in foreign_receipts]
    foreign_receipts[1]["parent_receipt_sha256"] = foreign_hashes[0]
    foreign_hashes[1] = hashlib.sha256(validate_unit_payload(foreign_receipts[1])).hexdigest()
    foreign_checkpoint = checkpoint(foreign_hashes)
    foreign_checkpoint["campaign_id"] = "FOREIGN-CAMPAIGN"
    foreign_context = validated_checkpoint_context(foreign_checkpoint, ["u1", "u2"], foreign_receipts)
    child = checkpoint(child_hashes)
    child.update(parent_checkpoint_sha256=foreign_context.payload_sha256,
                 completed_units=["u1", "u2"], pending_units=[])
    with pytest.raises(Rev004WireError, match="different campaign or binding context"):
        validate_checkpoint_payload(child, ["u1", "u2"], child_receipts, foreign_context)


def test_checkpoint_rejects_mutated_predecessor_context_metadata():
    from dataclasses import replace
    receipts, hashes = receipt_pair()
    context = validated_checkpoint_context(checkpoint(hashes), ["u1", "u2"], receipts)
    changed = replace(context, completed_units=())
    child_receipts, child_hashes = progressed_chain(receipts, hashes)
    child = checkpoint(child_hashes)
    child.update(parent_checkpoint_sha256=context.payload_sha256,
                 completed_units=["u1", "u2"], pending_units=[])
    with pytest.raises(Rev004WireError, match="unissued or has been modified"):
        validate_checkpoint_payload(child, ["u1", "u2"], child_receipts, changed)


@pytest.mark.parametrize("mutation", ["schema", "unvalidated_parent", "receipt_state"])
def test_checkpoint_rejects_replaced_or_forged_predecessor_context(mutation):
    from dataclasses import replace
    receipts, hashes = receipt_pair()
    context = validated_checkpoint_context(checkpoint(hashes), ["u1", "u2"], receipts)
    forged_payload = decode_payload(context.payload_bytes, context.payload_sha256)
    changes = {}
    if mutation == "schema":
        forged_payload["schema"] = "pgop1.run004.forged-checkpoint"
    elif mutation == "unvalidated_parent":
        forged_payload["parent_checkpoint_sha256"] = "f" * 64
    else:
        forged_payload.update(completed_units=[], pending_units=["u1", "u2"])
        changes.update(completed_units=(), pending_units=("u1", "u2"))
    raw = canonical_payload(forged_payload)
    forged = replace(context, payload_bytes=raw, payload_sha256=hashlib.sha256(raw).hexdigest(), **changes)
    child_receipts, child_hashes = progressed_chain(receipts, hashes)
    child = checkpoint(child_hashes)
    child.update(parent_checkpoint_sha256=forged.payload_sha256,
                 completed_units=["u1", "u2"], pending_units=[])
    with pytest.raises(Rev004WireError, match="unissued or has been modified"):
        validate_checkpoint_payload(child, ["u1", "u2"], child_receipts, forged)


@pytest.mark.parametrize("selected", ["u1", b"u1", ["u1", "u1"], ["u1", 2], [""]])
def test_checkpoint_selected_units_reject_scalar_invalid_or_duplicate_input(selected):
    empty = {"schema": "pgop1.run004.checkpoint-payload.rev004", "campaign_id": "DEV-CAMPAIGN",
             "campaign_attempt_id": "DEV-ATTEMPT", "parent_checkpoint_sha256": None,
             "ordered_receipt_payload_sha256": [], "completed_units": [],
             "pending_units": ["u1", "u2"], "inflight_units": [],
             "bindings": {"candidate_sha256": SHA, "config_sha256": SHA, "contract_sha256": SHA}}
    with pytest.raises(Rev004WireError, match="selected units"):
        validate_checkpoint_payload(empty, selected, [])


@pytest.mark.parametrize("field", ["config_sha256", "contract_sha256"])
def test_checkpoint_rejects_predecessor_binding_change(field):
    import copy
    receipts, hashes = receipt_pair()
    context = validated_checkpoint_context(checkpoint(hashes), ["u1", "u2"], receipts)
    child_receipts, child_hashes = progressed_chain(receipts, hashes)
    child_receipts = copy.deepcopy(child_receipts)
    for row in child_receipts:
        row["bindings"][field] = "b" * 64
        if field == "contract_sha256":
            row["contract_sha256"] = "b" * 64
    child_hashes = [hashlib.sha256(validate_unit_payload(row)).hexdigest() for row in child_receipts]
    for index in range(1, len(child_receipts)):
        child_receipts[index]["parent_receipt_sha256"] = child_hashes[index - 1]
        child_hashes[index] = hashlib.sha256(validate_unit_payload(child_receipts[index])).hexdigest()
    child = checkpoint(child_hashes)
    child["bindings"][field] = "b" * 64
    child.update(parent_checkpoint_sha256=context.payload_sha256,
                 completed_units=["u1", "u2"], pending_units=[])
    with pytest.raises(Rev004WireError, match="different campaign or binding context"):
        validate_checkpoint_payload(child, ["u1", "u2"], child_receipts, context)


def test_checkpoint_rejects_receipt_history_rollback():
    receipts, hashes = receipt_pair()
    genesis = checkpoint(hashes)
    genesis_context = validated_checkpoint_context(genesis, ["u1", "u2"], receipts)
    child_receipts, child_hashes = progressed_chain(receipts, hashes)
    progressed = checkpoint(child_hashes)
    progressed.update(parent_checkpoint_sha256=genesis_context.payload_sha256,
                      completed_units=["u1", "u2"], pending_units=[])
    progressed_context = validated_checkpoint_context(progressed, ["u1", "u2"], child_receipts,
                                                       genesis_context)

    rollback = checkpoint(hashes)
    rollback["parent_checkpoint_sha256"] = progressed_context.payload_sha256
    with pytest.raises(Rev004WireError, match="history rollback or non-advancing"):
        validate_checkpoint_payload(rollback, ["u1", "u2"], receipts, progressed_context)
