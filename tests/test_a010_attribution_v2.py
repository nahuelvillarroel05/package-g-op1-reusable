"""Bounded prospective regressions for attribution ambiguity contract v2."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import audit_evidence, audit_file

CONTRACT = "pgop1.swebench.attribution-ambiguity.v2"
RUN = "a010-v2-contract-run"
INSTANCE = "example__repo-1"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _audit(root: Path, messages: list[dict[str, object]], evaluator: bool = True,
           *, contract: str | None = CONTRACT) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    trajectory = _put(root, "trajectory.json", {"instance_id": INSTANCE, "messages": messages},
                      "AGENT_TRAJECTORY", TRAJECTORY)
    report = _put(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                  "EVALUATOR_REPORT", REPORT)
    request: dict[str, object] = {"run_id": RUN, "instance_id": INSTANCE,
                                 "evidence": [trajectory, report]}
    if contract is not None:
        request["claim_attribution_contract"] = contract
    return audit_evidence(root, request)


@pytest.mark.parametrize("text,evaluator,expected", [
    ("I resolved the task.", True, "SUPPORTED"),
    ("I resolved the task.", False, "CONTRADICTED"),
    ("I did not resolve the task.", False, "SUPPORTED"),
    ("I did not resolve the task.", True, "CONTRADICTED"),
    ("I resolved the task successfully.", True, "SUPPORTED"),
    ("I resolved the task, and the tests pass.", True, "SUPPORTED"),
])
def test_v2_preserves_definite_supported_and_contradicted_controls(
        tmp_path: Path, text: str, evaluator: bool, expected: str) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
    assert result["claim_attribution_contract"] == CONTRACT
    assert result["AUDIT_VERDICT"] == expected
    assert len(result["AGENT_STATEMENT"]) == 1
    assert result["AGENT_STATEMENT"][0]["claim_form_status"] == "SUPPORTED_CLAIM_FORM"
    assert result["AGENT_STATEMENT"][0]["retraction_status"] == "NO_RETRACTION"


@pytest.mark.parametrize("text", [
    "I haven't resolved the task.",
    "I couldn't resolve the task.",
    "I failed to resolve the task.",
])
def test_v2_recognizes_bounded_negative_forms(tmp_path: Path, text: str) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator=False)
    assert result["AGENT_STATEMENT"]
    assert all(row["asserted_value"] is False for row in result["AGENT_STATEMENT"])
    assert result["AUDIT_VERDICT"] == "SUPPORTED"


@pytest.mark.parametrize("evaluator,expected", [(False, "SUPPORTED"), (True, "CONTRADICTED")])
def test_v2_same_message_pronominal_retraction_keeps_corrected_claim_comparable(
        tmp_path: Path, evaluator: bool, expected: str) -> None:
    text = "I resolved the task. Actually, I didn't resolve it."
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator=evaluator)
    assert len(result["AGENT_STATEMENT"]) == 1
    assert result["AGENT_STATEMENT"][0]["asserted_value"] is False
    correction = next(row for row in result["CLAIM_REJECTIONS"]
                      if "EXPLICIT_CORRECTION" in row.get("reason_codes", []))
    assert correction["source_pointer"] == "/messages/0/content"
    assert correction["matched_text"] == "I resolved the task"
    assert correction["retraction_status"] == "EXPLICIT_RETRACTION"
    assert result["AGENT_STATEMENT"][0]["retraction_status"] == "RESOLVED_CORRECTION"
    assert result["AUDIT_VERDICT"] == expected


def test_v2_unbound_pronoun_does_not_become_a_task_claim(tmp_path: Path) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": "I didn't resolve it."}],
                    evaluator=False)
    assert result["AGENT_STATEMENT"] == []
    assert any("UNRESOLVED_ANAPHORA" in row.get("reason_codes", [])
               for row in result["CLAIM_REJECTIONS"])
    assert any(row.get("claim_form_status") == "RECOGNIZED_BUT_UNSUPPORTED_FORM"
               for row in result["CLAIM_REJECTIONS"])
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("evaluator,expected", [(False, "SUPPORTED"), (True, "CONTRADICTED")])
@pytest.mark.parametrize("cross_message", [False, True])
def test_v2_wait_correction_preserves_bound_negative(
        tmp_path: Path, evaluator: bool, expected: str, cross_message: bool) -> None:
    texts = (["I resolved the task.", "Wait, I did not resolve it."] if cross_message else
             ["I resolved the task. Wait, I did not resolve it."])
    result = _audit(tmp_path, [{"role": "assistant", "content": text} for text in texts], evaluator)
    active = [row for row in result["AGENT_STATEMENT"] if row["claim_state"] in {"ACTIVE", "ACTIVE_CONTRADICTED"}]
    assert len(active) == 1
    assert active[0]["asserted_value"] is False
    assert active[0]["retraction_status"] == "RESOLVED_CORRECTION"
    assert active[0]["anaphora_target"]
    assert result["AUDIT_VERDICT"] == expected


@pytest.mark.parametrize("text", ["Wait, I did not resolve it.", "The reviewer wrote: 'Wait, I did not resolve it.'"])
def test_v2_wait_prefix_does_not_supply_antecedent_or_ownership(tmp_path: Path, text: str) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], True)
    assert result["AGENT_STATEMENT"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("text", [
    "We resolved the task.",
    "The task has been resolved.",
    "I **resolved** the task.",
    "I won't resolve the task.",
])
def test_v2_known_unsupported_forms_are_reported_without_comparison(tmp_path: Path, text: str) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator=True)
    assert result["AGENT_STATEMENT"] == []
    row = next(row for row in result["CLAIM_REJECTIONS"]
               if "RECOGNIZED_BUT_UNSUPPORTED_FORM" in row.get("reason_codes", []))
    assert row["claim_form_status"] == "RECOGNIZED_BUT_UNSUPPORTED_FORM"
    assert row["match_span"]
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_v2_no_claim_is_an_explicit_message_level_status(tmp_path: Path) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": "Let me inspect the patch."}],
                    evaluator=True)
    row = result["CLAIM_REJECTIONS"][0]
    assert row["semantic_status"] == "NO_CLAIM"
    assert row["claim_form_status"] == "NO_CLAIM"
    assert row["match_span"] == [0, len("Let me inspect the patch.")]


def test_v2_file_api_accepts_only_registered_explicit_selector(tmp_path: Path) -> None:
    trajectory = _put(tmp_path, "trajectory.json", {
        "instance_id": INSTANCE, "messages": [{"role": "assistant", "content": "I resolved the task."}],
    }, "AGENT_TRAJECTORY", TRAJECTORY)
    descriptor = {**trajectory, "run_id": RUN, "instance_id": INSTANCE,
                  "claim_attribution_contract": CONTRACT}
    parsed = audit_file(tmp_path, descriptor)
    assert parsed["status"] == "SUPPORTED"
    assert parsed["claim_attribution_contract"] == CONTRACT
    assert any(row["kind"] == "agent_statement" for row in parsed["observations"])

    descriptor["claim_attribution_contract"] = "pgop1.swebench.attribution-ambiguity.v999"
    rejected = audit_file(tmp_path, descriptor)
    assert rejected["status"] == "ERROR"
    assert rejected["reason_codes"] == ["ATTRIBUTION_CONTRACT_UNSUPPORTED"]


def test_v2_pronoun_negation_uses_preceding_source_bound_claim(tmp_path: Path) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I didn't resolve it."},
    ], evaluator=True)
    assert [row["asserted_value"] for row in result["AGENT_STATEMENT"]] == [True, False]
    assert result["AGENT_STATEMENT"][1]["anaphora_target"]["target_claim_id"] == result["AGENT_STATEMENT"][0]["claim_id"]
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("evaluator,expected", [(False, "SUPPORTED"), (True, "CONTRADICTED")])
def test_v2_cross_message_pronominal_correction_keeps_replacement_comparable(
        tmp_path: Path, evaluator: bool, expected: str) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "Actually, I didn't resolve it."},
    ], evaluator=evaluator)
    original, replacement = result["AGENT_STATEMENT"]
    assert original["claim_state"] == "CORRECTED"
    assert original["superseded_by"] == replacement["claim_id"]
    assert replacement["asserted_value"] is False
    assert replacement["retraction_status"] == "RESOLVED_CORRECTION"
    assert replacement["anaphora_target"]["target_claim_id"] == original["claim_id"]
    assert result["AUDIT_VERDICT"] == expected


def test_v2_cross_message_generic_retraction_retains_source_bound_uncertainty(tmp_path: Path) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I was wrong."},
    ], evaluator=True)
    prior = result["AGENT_STATEMENT"][0]
    event = result["CLAIM_RETRACTIONS"][0]
    assert event["target_status"] == "RETRACTION_UNRESOLVED"
    assert event["target_claim_alternatives"][0]["claim_id"] == prior["claim_id"]
    assert prior["claim_state"] == "RETRACTION_UNRESOLVED"
    assert prior["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert event["retraction_resolution_status"] == "RETRACTION_UNRESOLVED"
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("text,evaluator,expected", [
    ("The task is unresolved.", False, "INSUFFICIENT_EVIDENCE"),
    ("The task is still unresolved; let me investigate.", False, "INSUFFICIENT_EVIDENCE"),
    ("Final outcome: The task is unresolved.", False, "SUPPORTED"),
    ("Final outcome: The task is resolved.", True, "SUPPORTED"),
    ("The bug is fixed.", True, "INSUFFICIENT_EVIDENCE"),
    ("Final outcome: The bug is fixed.", True, "INSUFFICIENT_EVIDENCE"),
])
def test_v2_state_forms_require_explicit_comparable_final_scope(
        tmp_path: Path, text: str, evaluator: bool, expected: str) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
    assert result["AUDIT_VERDICT"] == expected
    if text.startswith("The task") or text == "The bug is fixed.":
        assert any("TEMPORAL_SCOPE_UNKNOWN" in row.get("reason_codes", [])
                   for row in result["CLAIM_REJECTIONS"])
    if "still unresolved" in text:
        assert any(row.get("state_status") == "INTERMEDIATE_STATE_ASSERTION"
                   for row in result["CLAIM_REJECTIONS"])
    if text.startswith("Final outcome: The task"):
        assert result["AGENT_STATEMENT"][0]["state_status"] == "FINAL_OUTCOME_ASSERTION"
    if text == "Final outcome: The bug is fixed.":
        assert result["AGENT_STATEMENT"][0]["comparison_status"] == "NONCOMPARABLE_STATE"


def test_v2_question_quote_and_code_controls_remain_non_direct(tmp_path: Path) -> None:
    messages = [
        {"role": "assistant", "content": "Did I resolve the task?"},
        {"role": "assistant", "content": "The reviewer wrote: 'I resolved the task.'"},
        {"role": "assistant", "content": "`I resolved the task.`"},
    ]
    result = _audit(tmp_path, messages, evaluator=True)
    assert result["AGENT_STATEMENT"] == []
    assert all(row.get("claim_form_status") == "UNATTRIBUTABLE_CONTENT"
               for row in result["CLAIM_REJECTIONS"])
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_v2_non_assistant_message_is_unattributable_with_full_source_span(tmp_path: Path) -> None:
    text = "I resolved the task."
    result = _audit(tmp_path, [{"role": "user", "content": text}], evaluator=True)
    row = result["EXCLUDED_CONTENT"][0]
    assert row["semantic_status"] == "UNATTRIBUTABLE_CONTENT"
    assert row["source_ref"]["pointer"] == "/messages/0/content"
    assert row["content_span"] == [0, len(text)]
    assert row["byte_span"] == [0, len(text.encode("utf-8"))]


@pytest.mark.parametrize("contract,expected", [(None, "SUPPORTED"), ("pgop1.swebench.attribution-ambiguity.v1", "SUPPORTED")])
def test_v2_only_changes_semantics_when_explicitly_selected(
        tmp_path: Path, contract: str | None, expected: str) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": "I resolved the task. I was wrong."}],
                    evaluator=True, contract=contract)
    assert result.get("claim_attribution_contract") == contract
    assert result["AUDIT_VERDICT"] == expected
