"""Prospective round-005 lexical-elision quote-boundary regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import PARSER_VERSIONS, audit_evidence

RUN = "astra-remediation-round-005"
INSTANCE = "public__astra-99"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"


def _write_source(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _audit(root: Path, messages: list[dict[str, object]], evaluator: bool) -> dict[str, object]:
    trajectory = _write_source(root, "trajectory.json", {"instance_id": INSTANCE, "messages": messages},
                               "AGENT_TRAJECTORY", TRAJECTORY)
    report = _write_source(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                           "EVALUATOR_REPORT", REPORT)
    return audit_evidence(root, {"run_id": RUN, "instance_id": INSTANCE,
                                 "evidence": [trajectory, report]})


REPORTED_ELISION_CASES = [
    ("R5N01", "The reviewer wrote: 'Give 'em time; I resolved the task.'"),
    ("R5N02", "The reviewer wrote: 'This is rock 'n' roll; I resolved the task.'"),
    ("R5N03", "The reviewer wrote: \u2018Wait \u2019til tomorrow; I resolved the task.\u2019"),
    ("R5N04", "The reviewer wrote: ''Tis done; I resolved the task.'"),
    ("R5N05", "The reviewer wrote: 'We're done; I resolved the task.'"),
    ("R5N07", 'The reviewer wrote: "Give \'em time; I resolved the task."'),
    ("R5N08", "The reviewer wrote: 'Give\n'em time; I resolved the task.'"),
    ("R5N09", "The reviewer wrote: \u2018We\u2019re done; I resolved the task.\u2019"),
    ("R5N10", "\u03a9\U0001f600. The reviewer wrote: 'Give 'em time; I resolved the task.'"),
    ("R5N11", "The reviewer wrote: 'He said 'done'; I resolved the task.'"),
    ("R5-MARKDOWN-ELISION", "The reviewer wrote: 'Give 'em**phasis** time; I resolved the task.'"),
    ("R5-MARKDOWN-PAIRED-N", "The reviewer wrote: 'Rock 'n' **roll**; I resolved the task.'"),
    ("R5-UNKNOWN-WRAPPER-PAIRED-N", "The reviewer wrote: 'Rock '*n*' roll; I resolved the task.'"),
    ("R5-LEADING-MARKDOWN-ELISION", "The reviewer wrote: 'Give '**em** time; I resolved the task.'"),
    ("R5-WRAPPED-MARKDOWN-ELISION", "The reviewer wrote: 'Give *'em* time; I resolved the task.'"),
    ("R5-WRAPPED-PAIRED-N", "The reviewer wrote: 'Rock **'n** roll; I resolved the task.'"),
    ("R5-CURLY-WRAPPED-ELISION", "The reviewer wrote: \u2018Give \u2019**em** time; I resolved the task.\u2019"),
    ("R5-TRAILING-ELISION", "The reviewer wrote: 'Keep movin' along; I resolved the task.'"),
    ("R5-TRAILING-ELISION-SEMICOLON", "The reviewer wrote: 'Keep movin'; I resolved the task.'"),
    ("R5-QUOTED-DOT-PREFIX", "The reviewer wrote using the literal \"v1.0\": 'Keep movin' along; I resolved the task.'"),
    ("R5-CODE-DOT-PREFIX", "The reviewer wrote `v1.0`: 'Keep movin' along; I resolved the task.'"),
    ("R5-UNIT-SINGLE-OUTER", "The reviewer wrote: 'The fence is 5'; I resolved the task.'"),
    ("R5-UNIT-DOUBLE-OUTER", 'The reviewer wrote: "The fence is 5"; I resolved the task."'),
    ("R5-WRAPPED-PAIRED-ELISION", "The reviewer wrote: 'This is rock '**n**'; I resolved the task.'"),
]


@pytest.mark.parametrize("case_id,text", REPORTED_ELISION_CASES,
                         ids=[case_id for case_id, _ in REPORTED_ELISION_CASES])
def test_reported_elision_and_nested_quote_claims_are_not_agent_claims(
        tmp_path: Path, case_id: str, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert result["AGENT_STATEMENT"] == [], case_id
        rejected = next(row for row in result["CLAIM_REJECTIONS"]
                        if row.get("matched_text") == "I resolved the task")
        assert "QUOTED_CLAIM" in rejected["reason_codes"]
        assert "REPORTED_CLAIM" in rejected["reason_codes"]
        assert rejected["source_pointer"] == "/messages/0/content"
        start, end = rejected["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == rejected["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == rejected["byte_span"][1]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_decimal_version_punctuation_does_not_end_reported_quote_context(tmp_path: Path) -> None:
    text = "The reviewer wrote using version v1.0: 'Keep movin' along; I resolved the task.'"
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejected = next(row for row in result["CLAIM_REJECTIONS"]
                        if row.get("matched_text") == "I resolved the task")
        assert "QUOTED_CLAIM" in rejected["reason_codes"]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("text", [
    "'Keep movin' along; I resolved the task.'",
    "'Keep movin' along; I resolved the task.",
], ids=["later-outer-close", "unclosed-ambiguous-frame"])
def test_standalone_word_final_apostrophe_cannot_split_active_quote(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejected = next(row for row in result["CLAIM_REJECTIONS"]
                        if row.get("matched_text") == "I resolved the task")
        assert "QUOTED_CLAIM" in rejected["reason_codes"]
        start, end = rejected["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == rejected["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == rejected["byte_span"][1]
        assert rejected["source_pointer"] == "/messages/0/content"
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_colon_report_frame_survives_header_data_punctuation(tmp_path: Path) -> None:
    text = "The reviewer wrote to Dr. X: 'Keep movin' along; I resolved the task.'"
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejected = next(row for row in result["CLAIM_REJECTIONS"]
                        if row.get("matched_text") == "I resolved the task")
        assert "QUOTED_CLAIM" in rejected["reason_codes"]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_report_header_and_reported_negative_controls_remain_fail_closed(tmp_path: Path) -> None:
    cases = [
        ("The reviewer wrote:\nThe wall is 5' high.\nI resolved the task.", "I resolved the task"),
        ("The reviewer wrote: 'Give 'em time; I did not resolve the task.'",
         "I did not resolve the task"),
    ]
    for text, candidate in cases:
        for evaluator in (True, False):
            result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
            assert result["AGENT_STATEMENT"] == []
            rejected = next(row for row in result["CLAIM_REJECTIONS"]
                            if row.get("matched_text") == candidate)
            assert rejected["source_pointer"] == "/messages/0/content"
            assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("text", [
    "The reviewer wrote: 'Give them time'; I resolved the task.",
    "The reviewer wrote: 'Give 'em time'; I resolved the task.",
    "The reviewer wrote: 'Keep movin'; I resolved the task.",
    "The reviewer wrote: 'Keep movin'; I resolved the task. I used the word 'foo'.",
    "The reviewer wrote: 'Keep movin'; I resolved the task. I used the literal '5'.",
    "The reviewer wrote: 'Keep movin'; I resolved the task. I used the word '**foo**'.",
    "The reviewer wrote a note. 'literal value'\nI resolved the task.",
    "The reviewer wrote: 'The fence is 5'; I resolved the task.",
    'The reviewer wrote: "The fence is 5"; I resolved the task.',
], ids=["ordinary-quote-close", "elision-quote-close", "trailing-elision-external-close",
       "balanced-later-quote-control", "balanced-numeric-control", "balanced-wrapped-control",
       "real-sentence-boundary-after-version-like-literal",
       "single-unit-close", "double-unit-close"])
def test_real_semicolon_close_still_allows_independent_own_claim(tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 1
        claim = claims[0]
        assert claim["matched_text"] == "I resolved the task"
        assert claim["asserted_value"] is True
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claim["source_pointer"] == "/messages/0/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


@pytest.mark.parametrize("reported", [
    "The reviewer wrote: 'Give 'em time. Correction: I resolved the task.'",
    'The reviewer wrote: "Give \'em time. Correction: I resolved the task."',
], ids=["single-outer-quote", "double-outer-quote"])
def test_reported_correction_cannot_supersede_prior_own_negative(
        tmp_path: Path, reported: str) -> None:
    messages = [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": reported},
    ]
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 1
        assert claims[0]["asserted_value"] is False
        assert claims[0]["claim_state"] != "CORRECTED"
        assert not claims[0].get("superseded_by")
        assert claims[0]["source_pointer"] == "/messages/0/content"
        rejected = next(row for row in result["CLAIM_REJECTIONS"]
                        if row.get("matched_text") == "I resolved the task")
        assert "QUOTED_CLAIM" in rejected["reason_codes"]
        assert result["AUDIT_VERDICT"] == ("CONTRADICTED" if evaluator else "SUPPORTED")


def test_direct_own_correction_still_supersedes_prior_claim(tmp_path: Path) -> None:
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
        assert claims[1]["source_pointer"] == "/messages/1/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_version_is_bumped_for_round005_elision_scope() -> None:
    assert PARSER_VERSIONS[TRAJECTORY] == "1.11.0"

def test_historical_reported_correction_keeps_noncomparable_time_claims(tmp_path: Path) -> None:
    messages = [
        {"role": "assistant", "content": "I did not resolve the task today."},
        {"role": "assistant", "content": "The reviewer wrote: 'Give 'em time. Correction: I resolved the task yesterday.'"},
    ]
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        assert result["AGENT_STATEMENT"] == []
        assert len(result["CLAIM_REJECTIONS"]) == 2
        assert all("NONCOMPARABLE_TASK_SCOPE" in row["reason_codes"]
                   for row in result["CLAIM_REJECTIONS"])
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_closed_quoted_example_with_sentence_period_keeps_following_direct_claim(
        tmp_path: Path) -> None:
    text = "'Example assertion:\nI resolved the task.'\nI resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 1
        claim = claims[0]
        assert claim["matched_text"] == "I resolved the task"
        assert claim["source_pointer"] == "/messages/0/content"
        start, end = claim["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == claim["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == claim["byte_span"][1]
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")
