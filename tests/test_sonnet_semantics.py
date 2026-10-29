"""Focused regressions for prospective generalized claim semantics."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import (
    _stable,
    audit_evidence,
    audit_file,
)

RUN = "sonnet-semantics-001"
INSTANCE = "owner__repo-1"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"
CATALOG = "pgop1.swebench.catalog.per_instance_details_json.v1"


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _trajectory(root: Path, messages: list[dict[str, object]], **extra: object) -> dict[str, object]:
    return _put(root, "traj.json", {"instance_id": INSTANCE, "messages": messages, **extra},
                 "AGENT_TRAJECTORY", TRAJECTORY)


def _report(root: Path, resolved: bool = True) -> dict[str, object]:
    return _put(root, "report.json", {INSTANCE: {"resolved": resolved}}, "EVALUATOR_REPORT", REPORT)


def _request(*descriptors: dict[str, object]) -> dict[str, object]:
    return {"run_id": RUN, "instance_id": INSTANCE, "evidence": list(descriptors)}


def test_invalid_unhashable_path_returns_audit_error(tmp_path: Path) -> None:
    result = audit_evidence(tmp_path, _request({
        "path": [], "sha256": "0" * 64, "bytes": 0, "role": "AGENT_TRAJECTORY",
        "parser_id": TRAJECTORY,
    }))
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["reason_codes"] == ["PATH_INVALID"]


def test_question_in_later_sentence_does_not_drop_assertion(tmp_path: Path) -> None:
    result = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content":
                                "I have resolved the task. Is the deployment stable?"}]),
        _report(tmp_path),
    ))
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert len(result["AGENT_STATEMENT"]) == 1
    assert result["CLAIM_REJECTIONS"] == []


def test_question_form_claims_are_rejected(tmp_path: Path) -> None:
    for content in ("I have resolved the task?", "I resolved the task?", "Have I resolved the task?"):
        result = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            _report(tmp_path),
        ))
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert not [c for c in result["AGENT_STATEMENT"] if c["asserted_value"] is True]


def test_unambiguous_clausal_tails_are_parsed_and_task_subscopes_are_rejected(tmp_path: Path) -> None:
    for tail in ("and added regression tests", "by correcting the parser",
                 "with a targeted fix", "after fixing the validation path"):
        trajectory = _trajectory(tmp_path, [{"role": "assistant", "content":
                                             "I have resolved the task " + tail + "."}])
        parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
        assert len([o for o in parsed["observations"] if o["kind"] == "agent_statement"]) == 1
    for text in ("I have resolved the task queue issue.",
                 "I have resolved the task description formatting."):
        trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": text}])
        parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
        assert not [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert any("NONCOMPARABLE_TASK_SCOPE" in o["value"]["reason_codes"]
                   for o in parsed["observations"] if o["kind"] == "claim_rejection")


def test_unrelated_later_retraction_does_not_suppress_assertion(tmp_path: Path) -> None:
    result = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content":
                                "I have resolved the task. I was wrong about the unrelated schedule."}]),
        _report(tmp_path),
    ))
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert len(result["AGENT_STATEMENT"]) == 1


def test_correction_about_unrelated_or_other_predicate_does_not_retract(tmp_path: Path) -> None:
    for first, later in (
        ("I have resolved the task.", "Actually, the schedule is incomplete."),
        ("I have resolved the task.", "Actually, the task summary was sent, but the schedule is incomplete."),
        ("I have resolved the task.", "Actually, the task summary was sent, but deployment remains broken."),
        ("I have resolved the task.", "I was wrong; the task summary was sent, but deployment remains broken."),
        ("I have resolved the task.", "Actually, the issue remains unresolved."),
        ("I have resolved the issue.", "Correction: the task remains unresolved."),
    ):
        result = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": first + " " + later}]),
            _report(tmp_path),
        ))
        earlier = next(c for c in result["AGENT_STATEMENT"] if c["asserted_value"] is True)
        assert "superseded_by" not in earlier


def test_claim_segmentation_unicode_quotes_and_rejection_spans(tmp_path: Path) -> None:
    content = ("After careful review, I have resolved the task, and the dashboard is not loading. "
               "I\u2019ve successfully fixed the issue. \u201cI resolved the task.\u201d I have resolved the task.")
    trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": content}])
    parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
    accepted = [o["value"] for o in parsed["observations"] if o["kind"] == "agent_statement"]
    rejected = [o["value"] for o in parsed["observations"] if o["kind"] == "claim_rejection"]
    assert parsed["status"] == "SUPPORTED"
    assert len(accepted) == 3
    assert accepted[-1]["match_span"][0] < accepted[-1]["byte_span"][0]
    assert accepted[-1]["span_unit"] == "MESSAGE_RELATIVE_UTF8_BYTES"
    assert any("QUOTED_CLAIM" in item["reason_codes"] for item in rejected)


def test_single_quoted_claim_and_example_prefix_are_rejected_but_contraction_is_safe(tmp_path: Path) -> None:
    for content, expected_reason in (("'I have resolved the task.'", "QUOTED_CLAIM"),
                                     ("Example: I have resolved the task.", "REPORTED_CLAIM")):
        trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": content}])
        parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
        assert not [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
        rejected = [o["value"] for o in parsed["observations"] if o["kind"] == "claim_rejection"]
        assert any(expected_reason in item["reason_codes"] for item in rejected)
    contraction = _trajectory(tmp_path, [{"role": "assistant", "content": "I’ve resolved the task."}])
    parsed = audit_file(tmp_path, {**contraction, "run_id": RUN, "instance_id": INSTANCE})
    assert len([o for o in parsed["observations"] if o["kind"] == "agent_statement"]) == 1


def test_adjacent_explicit_retraction_still_rejects_claim(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [{"role": "assistant", "content":
                                         "I resolved the issue. I was wrong; it remains broken."}])
    parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
    assert parsed["status"] == "SUPPORTED"
    assert not [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
    assert any("EXPLICIT_CORRECTION" in o["value"]["reason_codes"]
               for o in parsed["observations"] if o["kind"] == "claim_rejection")


def test_opposite_predicates_do_not_supersede_each_other(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [
        {"role": "assistant", "content": "I have resolved the task."},
        {"role": "assistant", "content": "The issue remains unresolved."},
    ])
    result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path)))
    task_claim = next(c for c in result["AGENT_STATEMENT"] if c["predicate"] == "TASK_RESOLVED")
    assert task_claim["AUDIT_VERDICT"] == "SUPPORTED"
    assert "superseded_by" not in task_claim


def test_later_opposite_assertion_requires_explicit_same_predicate_correction(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [
        {"role": "assistant", "content": "I have resolved the task."},
        {"role": "assistant", "content": "Correction: The original task remains unresolved."},
    ])
    result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path, False)))
    earlier = next(c for c in result["AGENT_STATEMENT"] if c["asserted_value"] is True)
    assert earlier["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert earlier["reason_codes"] == ["SUPERSEDED_BY_LATER_OPPOSITE_ASSERTION"]


def test_same_predicate_opposition_without_correction_remains_a_contradiction(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [
        {"role": "assistant", "content": "I have resolved the task."},
        {"role": "assistant", "content": "The original task remains unresolved."},
    ])
    result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path, False)))
    earlier = next(c for c in result["AGENT_STATEMENT"] if c["asserted_value"] is True)
    assert earlier["AUDIT_VERDICT"] == "CONTRADICTED"
    assert "superseded_by" not in earlier


def test_correction_marker_in_an_unrelated_clause_does_not_supersede(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [
        {"role": "assistant", "content": "I have resolved the task."},
        {"role": "assistant", "content":
         "Actually, the schedule is incomplete. The task remains unresolved."},
    ])
    result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path, False)))
    earlier = next(c for c in result["AGENT_STATEMENT"] if c["asserted_value"] is True)
    later = next(c for c in result["AGENT_STATEMENT"] if c["asserted_value"] is False)
    assert earlier["AUDIT_VERDICT"] == "CONTRADICTED"
    assert later["AUDIT_VERDICT"] == "SUPPORTED"
    assert "superseded_by" not in earlier
    assert earlier["claim_state"] == "ACTIVE_CONTRADICTED"
    assert earlier["claim_id"] in result["CLAIM_AGGREGATION"]["active_contradicted_claim_ids"]
    assert "ACTIVE_CONTRADICTED_CLAIM_PRESENT" in result["reason_codes"]


def test_unrelated_hedged_clause_does_not_drop_assertion_but_self_doubt_does(tmp_path: Path) -> None:
    for tail, expected_count in (("but maybe the dashboard is broken", 1),
                                 ("but I may be wrong", 0)):
        trajectory = _trajectory(tmp_path, [{"role": "assistant", "content":
                                             "I have resolved the task, " + tail + "."}])
        parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
        accepted = [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert len(accepted) == expected_count
        if not expected_count:
            assert any("HEDGED_CLAUSE" in o["value"]["reason_codes"]
                       for o in parsed["observations"] if o["kind"] == "claim_rejection")


def test_actor_metadata_rejects_only_its_message_and_preserves_reason(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [
        {"role": "assistant", "content": "I have resolved the task."},
        {"role": "assistant", "agent_id": "worker-7", "content": "I have not resolved the task."},
        {"role": "assistant", "content": [{"type": "text", "text": "I have resolved the task."}]},
    ])
    parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
    claims = [o["value"] for o in parsed["observations"] if o["kind"] == "agent_statement"]
    rejected = [o["value"] for o in parsed["observations"] if o["kind"] == "claim_rejection"]
    assert len(claims) == 1
    assert any("MESSAGE_ACTOR_SCOPE_UNVERIFIED" in x["reason_codes"] for x in rejected)
    assert any("STRUCTURED_CONTENT_UNSUPPORTED" in x["reason_codes"] for x in rejected)


def test_root_actor_metadata_retains_explicit_scope_rejection(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [
        {"role": "assistant", "content": "I have resolved the task."},
    ], speaker_id="worker-7")
    parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
    assert not [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
    rejected = [o["value"] for o in parsed["observations"] if o["kind"] == "claim_rejection"]
    assert len(rejected) == 1
    assert rejected[0]["reason_codes"] == ["ROOT_ACTOR_SCOPE_UNVERIFIED"]


def test_windows_superscript_device_aliases_are_rejected(tmp_path: Path) -> None:
    for name in ("COM\u00b9.txt", "LPT\u00b2.log", "COM\u00b3.json"):
        parsed = audit_file(tmp_path, {
            "path": name, "sha256": "0" * 64, "bytes": 0,
            "role": "AGENT_TRAJECTORY", "parser_id": TRAJECTORY,
            "run_id": RUN, "instance_id": INSTANCE,
        })
        assert parsed["status"] == "ERROR"
        assert parsed["reason_codes"] == ["PATH_TRAVERSAL"]


def test_catalog_malformed_non_target_row_is_not_silently_omitted(tmp_path: Path) -> None:
    catalog = _put(tmp_path, "catalog.json", {
        INSTANCE: {"resolved": True}, "other__repo-2": {"resolved": "false"},
    }, "EVALUATOR_CATALOG", CATALOG)
    parsed = audit_file(tmp_path, {**catalog, "run_id": RUN, "instance_id": INSTANCE})
    assert parsed["status"] == "ERROR"
    assert parsed["reason_codes"] == ["MALFORMED_EVALUATOR_CATALOG"]
    assert parsed["observations"] == []


def test_final_error_does_not_overwrite_computed_claim_verdict(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": "I have resolved the task."}])
    report = _report(tmp_path)
    missing = {"path": "missing.log", "sha256": "0" * 64, "bytes": 1,
               "role": "EXECUTION_LOG", "parser_id": "pgop1.swebench.log.text_unattributed.v1"}
    result = audit_evidence(tmp_path, _request(trajectory, report, missing))
    assert result["FINAL_ERROR"] == "VERIFICATION_ERROR"
    assert result["COMPUTED_VERDICT"] == "SUPPORTED"
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["AGENT_STATEMENT"][0]["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["AGENT_STATEMENT"][0]["COMPUTED_VERDICT"] == "SUPPORTED"
    assert result["AGENT_STATEMENT"][0]["FINAL_ERROR"] == "VERIFICATION_ERROR"
    assert result["FINAL_ERROR_CODES"] == ["EVIDENCE_MISSING"]
    assert len(result["relationships"]) == 1


def test_source_availability_error_is_distinct_from_semantic_abstention(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": "I have resolved the task."}])
    abstention = audit_evidence(tmp_path, _request(trajectory))
    assert abstention["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert abstention["FINAL_ERROR"] is None
    missing = {"path": "missing.log", "sha256": "0" * 64, "bytes": 1,
               "role": "EXECUTION_LOG", "parser_id": "pgop1.swebench.log.text_unattributed.v1"}
    error = audit_evidence(tmp_path, _request(missing))
    assert error["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert error["FINAL_ERROR_CODES"] == ["EVIDENCE_MISSING"]
    unavailable = audit_evidence(tmp_path / "absent-root", _request(trajectory))
    assert unavailable["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert unavailable["COMPUTED_VERDICT"] is None
    assert unavailable["FINAL_ERROR_CODES"] == ["ROOT_UNAVAILABLE"]


def test_unsupported_shape_retains_actual_final_error_code(tmp_path: Path) -> None:
    raw = b"a:\n  b: c\n"
    (tmp_path / "bad.yaml").write_bytes(raw)
    descriptor = {"path": "bad.yaml", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                  "role": "RUN_METADATA", "parser_id": "pgop1.swebench.metadata.yaml.v1"}
    result = audit_evidence(tmp_path, _request(descriptor))
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["FINAL_ERROR_CODES"] == ["UNSUPPORTED_YAML_SHAPE"]


def test_observation_id_binds_frozen_final_value_and_source_hash(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": "I have resolved the task."}])
    result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path)))
    claim = result["AGENT_STATEMENT"][0]
    observation = next(o for o in result["observations"] if o.get("claim_id") == claim["claim_id"])
    source_hash = observation["source_ref"]["sha256"]
    value = json.dumps(observation["value"], sort_keys=True, ensure_ascii=False)
    expected = _stable("observation", RUN, INSTANCE, observation["source_ref"]["path"],
                       source_hash, observation["source_ref"]["pointer"], observation["kind"],
                       observation["predicate"], value)
    assert observation["value"] is not claim
    assert "AUDIT_VERDICT" not in observation["value"]
    assert observation["observation_id"] == expected


def test_logical_support_keeps_evaluator_authentication_unknown(tmp_path: Path) -> None:
    trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": "The task remains unresolved."}])
    result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path, False)))
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["COMPUTED_VERDICT"] == "SUPPORTED"
    assert result["EVALUATOR_RESULT"][0]["evaluator_identity_status"] == "UNKNOWN"
    assert result["EVALUATOR_RESULT"][0]["authentication_status"] == "UNAUTHENTICATED"
    assert result["SOURCE_PROVENANCE"]["evaluator_authentication"] == "UNAUTHENTICATED"
    assert result["semantic_derivation_schema"] == "pgop1.swebench.audit-derivation.v1"
