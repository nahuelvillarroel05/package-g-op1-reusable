"""Tests for explicitly committed, but unauthenticated, transcript role exports."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import audit_evidence, audit_file
from runtime.candidate.swebench_claim_audit.predicate_evidence import (
    ReferenceError, evaluate_reference_cases,
)

RUN = "run-dev-002"
INSTANCE = "sharkdp__bat-562"
PARSER = "pgop1.swebench.transcript.role_export.v1"
MINISWE_ATTRIBUTION = "pgop1.swebench.trajectory.miniswe_role_attribution.v1"


def _commit(data: bytes) -> dict[str, object]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def _json_file(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    data = json.dumps(value, separators=(",", ":")).encode()
    (root / name).write_bytes(data)
    return {"path": name, **_commit(data), "role": role, "parser_id": parser_id}


def _export(root: Path, *, text: str = "assistant says resolved", speaker: str = "assistant",
            run_id: str = RUN, instance_id: str = INSTANCE, scope: str = "task",
            timestamp: str = "2026-10-28T12:00:00Z") -> dict[str, object]:
    encoded = text.encode("utf-8")
    message = {"message_id": "m-1", "speaker": speaker, "byte_start": 0,
               "byte_end": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}
    doc = {"schema": "pgop1.swebench.transcript-role-export.v1", "run_id": run_id,
           "instance_id": instance_id, "scope": scope, "timestamp": timestamp,
           "source": {"text": text, **_commit(encoded)}, "messages": [message]}
    data = json.dumps(doc, separators=(",", ":")).encode()
    path = root / "role-export.json"
    path.write_bytes(data)
    return {"path": path.name, **_commit(data), "role": "ROLE_EXPORT", "parser_id": PARSER,
            "instance_id": instance_id, "scope": scope, "timestamp": timestamp}


def test_role_export_emits_declared_unverified_attribution_and_no_claims(tmp_path: Path) -> None:
    descriptor = _export(tmp_path)
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "SUPPORTED"
    attribution = parsed["observations"][0]
    assert attribution["kind"] == "transcript_attribution"
    assert attribution["value"]["attribution_status"] == "SOURCE_DECLARED_UNVERIFIED"
    assert attribution["attribution"] == "SOURCE_DECLARED_NOT_AUTHENTICATED"
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": INSTANCE,
                                       "evidence": [descriptor]})
    assert result["AGENT_STATEMENT"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_miniswe_role_attribution_is_top_level_declared_and_claim_free(tmp_path: Path) -> None:
    trajectory = {"instance_id": INSTANCE, "agent_id": "unrelated-agent",
                  "messages": [
                      {"role": "assistant", "content": "    I have resolved the task."},
                      {"role": "user", "content": "user body",
                       "extra": {"response": {"choices": [{"message": {
                           "role": "assistant", "content": "I have resolved the task."}}]}}},
                  ]}
    data = json.dumps(trajectory, separators=(",", ":")).encode()
    path = tmp_path / "native.json"
    path.write_bytes(data)
    descriptor = {"path": path.name, **_commit(data), "role": "AGENT_TRAJECTORY",
                  "parser_id": MINISWE_ATTRIBUTION, "instance_id": INSTANCE,
                  "scope": "task", "timestamp": "2026-10-28T12:00:00Z"}
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "SUPPORTED"
    assert [o["value"]["declared_speaker"] for o in parsed["observations"]] == ["assistant", "user"]
    assert all(o["value"]["attribution_status"] == "SOURCE_DECLARED_UNVERIFIED"
               for o in parsed["observations"])
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": INSTANCE,
                                       "evidence": [descriptor]})
    assert result["AGENT_STATEMENT"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_miniswe_role_attribution_rejects_conflicting_embedded_run(tmp_path: Path) -> None:
    data = json.dumps({"instance_id": INSTANCE, "run_id": "other-run", "messages": []}).encode()
    (tmp_path / "native.json").write_bytes(data)
    descriptor = {"path": "native.json", **_commit(data), "role": "AGENT_TRAJECTORY",
                  "parser_id": MINISWE_ATTRIBUTION, "instance_id": INSTANCE,
                  "scope": "task", "timestamp": "2026-10-28T12:00:00Z"}
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "ERROR"
    assert "WRONG_RUN_BINDING" in parsed["reason_codes"]


def test_miniswe_role_attribution_retains_nontext_content_records(tmp_path: Path) -> None:
    descriptor = _json_file(tmp_path, "native.json", {
        "instance_id": INSTANCE,
        "messages": [
            {"role": "assistant", "content": None},
            {"role": "tool", "content": [{"type": "tool_call", "name": "run"}]},
            {"role": "system"},
        ],
    }, "AGENT_TRAJECTORY", MINISWE_ATTRIBUTION)
    descriptor.update({"instance_id": INSTANCE, "scope": "task",
                       "timestamp": "2026-10-28T12:00:00Z"})
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "SUPPORTED"
    assert len(parsed["observations"]) == 3
    assert [o["value"]["content_status"] for o in parsed["observations"]] == [
        "NON_TEXT_UNSUPPORTED", "NON_TEXT_UNSUPPORTED", "CONTENT_MISSING"]
    assert [o["value"]["declared_speaker"] for o in parsed["observations"]] == [
        "assistant", "tool", "system"]
    assert all(o["value"]["speaker_role"] == "UNKNOWN" for o in parsed["observations"])


def test_miniswe_role_attribution_rejects_nonobject_message_rows(tmp_path: Path) -> None:
    descriptor = _json_file(tmp_path, "native.json", {
        "instance_id": INSTANCE, "messages": [{"role": "assistant", "content": "ok"}, None],
    }, "AGENT_TRAJECTORY", MINISWE_ATTRIBUTION)
    descriptor.update({"instance_id": INSTANCE, "scope": "task",
                       "timestamp": "2026-10-28T12:00:00Z"})
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "ERROR"
    assert "MALFORMED_TRAJECTORY" in parsed["reason_codes"]


@pytest.mark.parametrize("trajectory", [
    {"instance_id": INSTANCE, "messages": [{"role": "assistant",
     "content": "    I have resolved the task."}]},
    {"instance_id": INSTANCE, "messages": [{"role": "user", "content": "outer",
     "extra": {"response": {"choices": [{"message": {
         "role": "assistant", "content": "I have resolved the task."}}]}}}]},
    {"instance_id": INSTANCE, "agent_id": "unrelated-agent", "messages": [
     {"role": "assistant", "content": "I have resolved the task."}]},
    {"instance_id": INSTANCE, "messages": [{"role": "assistant", "agent_id": "subagent-7",
     "content": "I have resolved the task."}]},
    {"instance_id": INSTANCE, "messages": [{"role": "assistant", "content": "   "}]},
])
def test_legacy_miniswe_fails_closed_on_code_nested_payload_unscoped_agent_and_empty(
        tmp_path: Path, trajectory: dict[str, object]) -> None:
    descriptor = _json_file(tmp_path, "legacy.json", trajectory,
                            "AGENT_TRAJECTORY", "pgop1.swebench.trajectory.miniswe_json.v1")
    descriptor["instance_id"] = INSTANCE
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "SUPPORTED"
    assert parsed["source_ref"]["parser_version"] == "1.1.0"
    assert parsed["normalization_schema"] == "pgop1.swebench.source-bound-normalization.v2"
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": INSTANCE,
                                       "evidence": [descriptor]})
    assert result["AGENT_STATEMENT"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_legacy_miniswe_rejects_conflicting_embedded_run_id(tmp_path: Path) -> None:
    descriptor = _json_file(tmp_path, "legacy.json", {
        "instance_id": INSTANCE, "run_id": "another-run",
        "messages": [{"role": "assistant", "content": "I have resolved the task."}],
    }, "AGENT_TRAJECTORY", "pgop1.swebench.trajectory.miniswe_json.v1")
    descriptor["instance_id"] = INSTANCE
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "ERROR"
    assert "WRONG_RUN_BINDING" in parsed["reason_codes"]


@pytest.mark.parametrize("kwargs,reason", [
    ({"run_id": "other-run"}, "WRONG_INSTANCE_BINDING"),
    ({"instance_id": "other-instance"}, "WRONG_INSTANCE_BINDING"),
    ({"scope": ""}, "ROLE_EXPORT_SCOPE_INVALID"),
    ({"timestamp": "2026-10-28T12:00:00"}, "ROLE_EXPORT_TIME_INVALID"),
])
def test_role_export_requires_identity_scope_and_time_bindings(
        tmp_path: Path, kwargs: dict[str, str], reason: str) -> None:
    descriptor = _export(tmp_path, **kwargs)
    if "instance_id" in kwargs:
        descriptor["instance_id"] = INSTANCE
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "ERROR"
    assert reason in parsed["reason_codes"]


def test_role_export_checks_source_span_hash(tmp_path: Path) -> None:
    descriptor = _export(tmp_path)
    data = json.loads((tmp_path / "role-export.json").read_text())
    data["messages"][0]["sha256"] = "0" * 64
    raw = json.dumps(data, separators=(",", ":")).encode()
    (tmp_path / "role-export.json").write_bytes(raw)
    descriptor.update(_commit(raw))
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "ERROR"
    assert "ROLE_EXPORT_SPAN_HASH_MISMATCH" in parsed["reason_codes"]


def test_role_export_rejects_bool_source_byte_count(tmp_path: Path) -> None:
    descriptor = _export(tmp_path, text="x")
    path = tmp_path / str(descriptor["path"])
    doc = json.loads(path.read_text())
    doc["source"]["bytes"] = True
    raw = json.dumps(doc, separators=(",", ":")).encode()
    path.write_bytes(raw)
    descriptor.update(_commit(raw))
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "ERROR"
    assert "ROLE_EXPORT_SOURCE_COMMITMENT_INVALID" in parsed["reason_codes"]


@pytest.mark.parametrize("defect,reason", [
    ("duplicate", "ROLE_EXPORT_DUPLICATE_MESSAGE_ID"),
    ("overlap", "ROLE_EXPORT_OVERLAPPING_SPANS"),
    ("whitespace_id", "ROLE_EXPORT_MESSAGE_INVALID"),
])
def test_role_export_rejects_duplicate_or_overlapping_message_spans(
        tmp_path: Path, defect: str, reason: str) -> None:
    descriptor = _export(tmp_path, text="abcdefghij")
    path = tmp_path / str(descriptor["path"])
    doc = json.loads(path.read_text())
    message = dict(doc["messages"][0])
    if defect == "duplicate":
        doc["messages"].append(message)
    elif defect == "overlap":
        message.update({"message_id": "m-2", "byte_start": 5, "byte_end": 10,
                        "sha256": hashlib.sha256(b"fghij").hexdigest()})
        doc["messages"].append(message)
    else:
        doc["messages"][0]["message_id"] = "   "
    raw = json.dumps(doc, separators=(",", ":")).encode()
    path.write_bytes(raw)
    descriptor.update(_commit(raw))
    parsed = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert parsed["status"] == "ERROR"
    assert reason in parsed["reason_codes"]


def _reference(reference_id: str, polarity: bool | None, adjudication: str = "DECIDED") -> dict[str, object]:
    return {"reference_id": reference_id, "run_id": RUN, "instance_id": INSTANCE,
            "scope": "task", "timestamp": "2026-10-28T12:00:00Z",
            "source_sha256": "a" * 64, "source_bytes": 64, "message_id": "m-" + reference_id,
            "span_start": 0, "span_end": 10, "predicate": "TASK_RESOLVED",
            "polarity": polarity, "adjudication": adjudication,
            "evidence_commitment": "b" * 64,
            "rationale": "Independent adjudication record."}


def _prediction(reference: dict[str, object], verdict: str) -> dict[str, object]:
    fields = ("reference_id", "run_id", "instance_id", "scope", "timestamp",
              "source_sha256", "source_bytes", "message_id", "span_start", "span_end", "predicate")
    return {**{key: reference[key] for key in fields}, "verdict": verdict}


def test_reference_evaluator_counts_metrics_abstentions_misses_and_unknowns() -> None:
    refs = [_reference("p", True), _reference("n", False),
            _reference("u", None, "UNKNOWN"), _reference("miss", True)]
    preds = [_prediction(refs[0], "SUPPORTED"), _prediction(refs[1], "SUPPORTED"),
             _prediction(refs[2], "SUPPORTED")]
    result = evaluate_reference_cases(preds, refs)
    assert result["counts"] == {"TP": 1, "FP": 1, "TN": 0, "FN": 0,
                                "positive_abstentions": 0, "negative_abstentions": 0,
                                "missed_extractions": 1, "missed_positive_reference_claims": 1,
                                "missed_negative_reference_claims": 0, "unknown_reference_rows": 1,
                                "INTEGRITY_FAILURE": 0, "VERIFICATION_ERROR": 0,
                                "positive_error_outcomes": 0, "negative_error_outcomes": 0}
    assert result["metrics"] == {"precision": 0.5, "recall": 0.5,
                                 "decided_accuracy": 0.5, "coverage": 2 / 3}
    assert result["excluded_unknown_reference_ids"] == ["u"]


def test_reference_evaluator_reports_abstentions_and_empty_metrics() -> None:
    ref = _reference("p", True)
    result = evaluate_reference_cases([_prediction(ref, "INSUFFICIENT_EVIDENCE")], [ref])
    assert result["counts"]["positive_abstentions"] == 1
    assert result["metrics"]["precision"] is None
    assert result["metrics"]["recall"] == 0
    empty = evaluate_reference_cases([], [])
    assert empty["status"] == "NOT_COMPUTABLE"
    assert empty["metrics"] == {"precision": None, "recall": None,
                                 "decided_accuracy": None, "coverage": None}


def test_reference_evaluator_reports_audit_errors_separately_without_recall_inflation() -> None:
    ref = _reference("p", True)
    result = evaluate_reference_cases([_prediction(ref, "INTEGRITY_FAILURE")], [ref])
    assert result["counts"]["INTEGRITY_FAILURE"] == 1
    assert result["counts"]["positive_error_outcomes"] == 1
    assert result["counts"]["TP"] == result["counts"]["FN"] == 0
    assert result["metrics"]["recall"] == 0
    assert result["metrics"]["coverage"] == 0


def test_predicate_verifier_requires_exact_identity_and_registered_contract() -> None:
    from runtime.candidate.swebench_claim_audit.predicate_evidence import verify_predicate_claim

    claim = _reference("c", True)
    claim["asserted_value"] = True
    evidence = {**claim, "contract": "pgop1.swebench.task-resolved-boolean.v1",
                "observed_value": True}
    assert verify_predicate_claim(claim, evidence)["verdict"] == "SUPPORTED"
    evidence["observed_value"] = False
    assert verify_predicate_claim(claim, evidence)["verdict"] == "CONTRADICTED"
    evidence["source_sha256"] = "c" * 64
    assert verify_predicate_claim(claim, evidence)["verdict"] == "INSUFFICIENT_EVIDENCE"
    evidence["source_sha256"] = claim["source_sha256"]
    evidence["contract"] = "unregistered"
    assert verify_predicate_claim(claim, evidence)["verdict"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("mutation,error", [
    ("duplicate", "DUPLICATE_REFERENCE_ID"),
    ("identity", "PREDICTION_REFERENCE_IDENTITY_MISMATCH"),
    ("unknown_label", "REFERENCE_ADJUDICATION_INVALID"),
    ("unknown_polarity", "UNKNOWN_REFERENCE_HAS_POLARITY"),
    ("null_run", "RUN_ID_INVALID"),
    ("bool_bytes", "SOURCE_BYTES_INVALID"),
    ("bool_span", "MESSAGE_SPAN_INVALID"),
])
def test_reference_evaluator_rejects_ambiguous_or_mismatched_inputs(mutation: str, error: str) -> None:
    ref = _reference("one", True)
    pred = _prediction(ref, "SUPPORTED")
    refs = [ref]
    if mutation == "duplicate":
        refs = [ref, dict(ref)]
    elif mutation == "identity":
        pred["run_id"] = "other-run"
    elif mutation == "unknown_label":
        ref["adjudication"] = "MAYBE"
    elif mutation == "unknown_polarity":
        ref["adjudication"], ref["polarity"] = "UNKNOWN", False
    elif mutation == "null_run":
        ref["run_id"] = None
    elif mutation == "bool_bytes":
        ref["source_bytes"] = True
    elif mutation == "bool_span":
        ref["span_start"] = False
    with pytest.raises(ReferenceError, match=error):
        evaluate_reference_cases([pred], refs)
