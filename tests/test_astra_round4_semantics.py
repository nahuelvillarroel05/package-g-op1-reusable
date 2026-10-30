"""Prospective round-004 quote-boundary regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import PARSER_VERSIONS, audit_evidence

RUN = "astra-remediation-round-004"
INSTANCE = "public__astra-99"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _audit(root: Path, messages: list[dict[str, object]], evaluator: bool) -> dict[str, object]:
    trajectory = _put(root, "trajectory.json", {"instance_id": INSTANCE, "messages": messages},
                      "AGENT_TRAJECTORY", TRAJECTORY)
    report = _put(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                  "EVALUATOR_REPORT", REPORT)
    return audit_evidence(root, {"run_id": RUN, "instance_id": INSTANCE,
                                 "evidence": [trajectory, report]})


ABSTAINING_REPORTS = [
    "The reviewer wrote: 'The students'**assignments** are complete; I resolved the task.'",
    "The reviewer wrote: 'The students'`assignments` are complete; I resolved the task.'",
    "The reviewer wrote: 'The students'.NET assignments are complete; I resolved the task.'",
    "The reviewer wrote: 'The students'(assignments) are complete; I resolved the task.'",
    "The reviewer wrote: 'The students' **assignments** are complete; I resolved the task.'",
    "The reviewer wrote: 'The students' .NET assignments are complete; I resolved the task.'",
    "The reviewer wrote: " + chr(0x2018) + "The students" + chr(0x2019)
    + "**assignments** are complete; I resolved the task." + chr(0x2019),
    'The reviewer wrote: "The students\'**assignments** are complete; I resolved the task."',
    "The reviewer wrote: 'The students'<assignments> are complete; I resolved the task.'",
    "The reviewer wrote: 'The students'... assignments are complete; I resolved the task.'",
]


@pytest.mark.parametrize("text", ABSTAINING_REPORTS,
                         ids=["adjacent-bold", "adjacent-code", "adjacent-dotnet", "adjacent-parenthesis",
                              "spaced-bold", "spaced-dotnet", "curly-adjacent-bold", "double-quote-control",
                              "adjacent-unknown-wrapper", "adjacent-ellipsis"])
def test_adjacent_plural_possessive_continuations_remain_reported(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejection = next(row for row in result["CLAIM_REJECTIONS"]
                         if row.get("predicate") == "TASK_RESOLVED")
        assert "QUOTED_CLAIM" in rejection["reason_codes"]
        start, end = rejection["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == rejection["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == rejection["byte_span"][1]
        assert any(source["role"] == "AGENT_TRAJECTORY"
                   and source["parser_id"] == TRAJECTORY
                   for source in result["SOURCE_PROVENANCE"]["evidence_references"])
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_semicolon_after_real_quote_close_keeps_outside_claim(tmp_path: Path) -> None:
    text = "The reviewer wrote: 'The students'; I resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["asserted_value"] is True
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claim["source_pointer"] == "/messages/0/content"
        start, end = claim["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == claim["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == claim["byte_span"][1]
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_single_full_stop_after_quote_is_an_external_close(tmp_path: Path) -> None:
    text = "The reviewer wrote: 'The students'\n. I resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        assert result["AGENT_STATEMENT"][0]["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_separate_own_claim_after_report_remains_supported_control(tmp_path: Path) -> None:
    messages = [
        {"role": "assistant", "content": "The reviewer wrote: 'The students' **assignments** are complete; I resolved the task.'"},
        {"role": "assistant", "content": "I resolved the task."},
    ]
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["asserted_value"] is True
        assert claim["source_pointer"] == "/messages/1/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


@pytest.mark.parametrize("reported", [
    "The reviewer wrote: 'The students'**assignments** are complete. Correction: I resolved the task.'",
    "The reviewer wrote: 'The students' **assignments** are complete. Correction: I resolved the task.'",
], ids=["adjacent-markdown", "spaced-markdown"])
def test_reported_correction_does_not_supersede_earlier_own_negative(
        tmp_path: Path, reported: str) -> None:
    messages = [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": reported},
    ]
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 1
        claim = claims[0]
        assert claim["asserted_value"] is False
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claim["source_pointer"] == "/messages/0/content"
        assert claim["claim_state"] != "CORRECTED"
        assert "superseded_by" not in claim
        rejected = next(row for row in result["CLAIM_REJECTIONS"]
                        if row.get("predicate") == "TASK_RESOLVED")
        assert rejected["matched_text"] == "I resolved the task"
        assert "QUOTED_CLAIM" in rejected["reason_codes"]
        assert result["AUDIT_VERDICT"] == ("CONTRADICTED" if evaluator else "SUPPORTED")


def test_later_direct_own_correction_still_supersedes_prior_negative(tmp_path: Path) -> None:
    messages = [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "Correction: I resolved the task."},
    ]
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2
        assert claims[0]["asserted_value"] is False
        assert claims[0]["claim_state"] == "CORRECTED"
        assert claims[0]["superseded_by"] == claims[1]["claim_id"]
        assert claims[1]["asserted_value"] is True
        assert claims[1]["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claims[1]["source_pointer"] == "/messages/1/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_trajectory_parser_version_is_bumped_for_round004_quote_scope() -> None:
    assert PARSER_VERSIONS[TRAJECTORY] == "1.7.0"


NUMERIC_QUOTE_AMBIGUITIES = [
    "The reviewer wrote: 'The fence is 5' high; I resolved the task.'",
    "The reviewer wrote: 'The fence is 5'**high**; I resolved the task.'",
    'The reviewer wrote: "The fence is 5" high; I resolved the task."',
    "The reviewer wrote: 'In the '90s, the build changed; I resolved the task.'",
    "The reviewer wrote: 'The student\u017f'**assignments** are complete; I resolved the task.'",
    "The reviewer wrote: \u2018In the \u201990s, the build changed; I resolved the task.\u2019",
    "The reviewer wrote: 'The fence is 5\u00bd' high; I resolved the task.'",
    'The reviewer wrote: "The fence is 5\u00bd" high; I resolved the task."',
]


@pytest.mark.parametrize("text", NUMERIC_QUOTE_AMBIGUITIES,
                         ids=["single-unit-spaced", "single-unit-adjacent-markup",
                              "double-unit-spaced", "decade-apostrophe", "unicode-case-equivalent-s",
                              "curly-decade", "unicode-number-single-unit", "unicode-number-double-unit"])
def test_numeric_quote_and_decade_marks_do_not_close_reported_frames(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejection = next(row for row in result["CLAIM_REJECTIONS"]
                         if row.get("predicate") == "TASK_RESOLVED")
        assert rejection["matched_text"] == "I resolved the task"
        assert "QUOTED_CLAIM" in rejection["reason_codes"]
        start, end = rejection["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == rejection["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == rejection["byte_span"][1]
        assert any(source["role"] == "AGENT_TRAJECTORY"
                   and source["parser_id"] == TRAJECTORY
                   for source in result["SOURCE_PROVENANCE"]["evidence_references"])
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("text", [
    "The reviewer wrote: 'The fence is 5'; I resolved the task.",
    'The reviewer wrote: "The fence is 5"; I resolved the task.',
], ids=["single-mark-close", "double-mark-close"])
def test_punctuation_proves_numeric_quote_close(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 1
        assert claims[0]["matched_text"] == "I resolved the task"
        assert claims[0]["asserted_value"] is True
        assert claims[0]["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claims[0]["source_pointer"] == "/messages/0/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_ordinary_double_quote_after_s_closes_without_possessive_inference(tmp_path: Path) -> None:
    text = "\"status\"\nI resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 1
        assert claims[0]["matched_text"] == "I resolved the task"
        assert claims[0]["source_pointer"] == "/messages/0/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")
