"""Prospective round-002 structural semantic regressions (Astra NEW cases)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import PARSER_VERSIONS, audit_evidence

RUN = "astra-remediation-round-002"
INSTANCE = "public__astra-99"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"
NL = chr(10)


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _audit(root: Path, messages: list[dict[str, object]], evaluator: bool = True) -> dict[str, object]:
    trajectory = _put(root, "trajectory.json", {"instance_id": INSTANCE, "messages": messages},
                       "AGENT_TRAJECTORY", TRAJECTORY)
    report = _put(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                  "EVALUATOR_REPORT", REPORT)
    return audit_evidence(root, {"run_id": RUN, "instance_id": INSTANCE,
                                 "evidence": [trajectory, report]})


def _assert_no_supported_claim(result: dict[str, object], text: str, reason: str) -> None:
    assert result["AGENT_STATEMENT"] == []
    rejected = [row for row in result["CLAIM_REJECTIONS"]
                if row.get("predicate") == "TASK_RESOLVED"]
    assert rejected
    assert any(reason in row["reason_codes"] for row in rejected)
    row = rejected[0]
    start, end = row["match_span"]
    assert text[start:end] == "I resolved the task"
    assert row["source_pointer"] == "/messages/0/content"
    assert any(ref["role"] == "AGENT_TRAJECTORY" and ref["parser_id"] == TRAJECTORY
               for ref in result["SOURCE_PROVENANCE"]["evidence_references"])
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("first,second", [
    ("Yesterday, honestly, I did not resolve the task.",
     "Actually, today, honestly, I resolved the task."),
    ("Today, indeed, I did not resolve the task.",
     "Actually, yesterday, honestly, I resolved the task."),
], ids=["neutral-adverbs-preserve-day", "reverse-explicit-days"])
def test_neutral_prefix_words_do_not_erase_different_day_scope(
        tmp_path: Path, first: str, second: str) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": first},
        {"role": "assistant", "content": second},
    ], True)
    claims = result["AGENT_STATEMENT"]
    assert len(claims) == 2
    assert [claim["asserted_value"] for claim in claims] == [False, True]
    assert all(claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT" for claim in claims)
    assert all("superseded_by" not in claim for claim in claims)
    assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
    assert result["AUDIT_VERDICT"] != "SUPPORTED"


def test_multiple_explicit_days_are_ambiguous_and_same_day_correction_still_works(tmp_path: Path) -> None:
    ambiguous = _audit(tmp_path, [
        {"role": "assistant", "content": "Yesterday, I did not resolve the task."},
        {"role": "assistant", "content": "Actually, yesterday, today, honestly, I resolved the task."},
    ], True)
    assert len(ambiguous["AGENT_STATEMENT"]) == 2
    assert all("superseded_by" not in claim for claim in ambiguous["AGENT_STATEMENT"])
    assert ambiguous["AUDIT_VERDICT"] != "SUPPORTED"

    same_day = _audit(tmp_path, [
        {"role": "assistant", "content": "Today, I did not resolve the task."},
        {"role": "assistant", "content": "Actually, today, honestly, I resolved the task."},
    ], True)
    claims = same_day["AGENT_STATEMENT"]
    assert claims[0]["claim_state"] == "CORRECTED"
    assert claims[0]["superseded_by"] == claims[1]["claim_id"]
    assert same_day["AUDIT_VERDICT"] == "SUPPORTED"


@pytest.mark.parametrize("text", [
    "``" + NL + "I resolved the task." + NL + "``",
    "`" + NL + "I resolved the task." + NL + "`",
], ids=["double-backtick-multiline", "single-backtick-multiline"])
def test_matching_multiline_backtick_run_is_quoted(tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        _assert_no_supported_claim(_audit(tmp_path, [{"role": "assistant", "content": text}], evaluator),
                                   text, "QUOTED_CLAIM")


@pytest.mark.parametrize("quoted", [
    '"I did not resolve the task"',
    '"I did not resolve the task."',
    chr(0x2018) + "the task is not resolved" + chr(0x2019),
    chr(0x201c) + "the task is not resolved." + chr(0x201d),
], ids=["ascii-negative", "ascii-terminal-period", "curly-negative", "curly-terminal-period"])
def test_quoted_target_result_cannot_be_reclassified_as_unrelated_output(
        tmp_path: Path, quoted: str) -> None:
    text = f"I resolved the task, but the output says {quoted}."
    for evaluator in (True, False):
        _assert_no_supported_claim(_audit(tmp_path, [{"role": "assistant", "content": text}], evaluator),
                                   text, "EMBEDDED_CLAIM_CONTEXT")


@pytest.mark.parametrize("text", [
    'I resolved the task, but the output says "deployment failed".',
    "I resolved the task, but the output says " + chr(0x201c) + "why?" + chr(0x201d) + ".",
    "`literal value`." + NL + "I resolved the task.",
    "I" + chr(0x2019) + "ve resolved the task.",
], ids=["unrelated-quoted-deployment", "quoted-question-output", "claim-after-inline-code", "curly-apostrophe-contraction"])
def test_unrelated_quotes_and_outside_direct_claim_remain_extractable(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claim["source_pointer"] == "/messages/0/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


@pytest.mark.parametrize("text,reason", [
    ("I deny that" + NL + "I resolved the task.", "DENIED_CLAIM"),
    ("I doubt that" + NL + "I resolved the task.", "HEDGED_CLAUSE"),
    ("The reviewer said that" + NL + "I resolved the task.", "REPORTED_CLAIM"),
    ("If checks pass," + NL + "I resolved the task.", "CONDITIONAL_CLAUSE"),
    ("I doubt that" + NL + NL + "I resolved the task.", "HEDGED_CLAUSE"),
    ("The tool output says:" + NL + "Build complete." + NL + "I resolved the task.", "REPORTED_CLAIM"),
], ids=["denial-soft-wrap", "doubt-soft-wrap", "report-soft-wrap", "conditional-soft-wrap",
       "doubt-blank-line", "report-continuation"])
def test_operator_frames_survive_soft_wrap_until_explicit_termination(
        tmp_path: Path, text: str, reason: str) -> None:
    for evaluator in (True, False):
        _assert_no_supported_claim(_audit(tmp_path, [{"role": "assistant", "content": text}], evaluator),
                                   text, reason)


def test_explicitly_terminated_operator_and_closed_frames_allow_later_claim(tmp_path: Path) -> None:
    for text in (
        "If checks fail, halt." + NL + "I resolved the task.",
        "I deny that other assertion." + NL + "I resolved the task.",
        chr(0x22) + "Example assertion:" + NL + "I resolved the task." + chr(0x22)
        + NL + "I resolved the task.",
        "I did not resolve the task." + NL + "Actually, I resolved the task.",
    ):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], True)
        claims = result["AGENT_STATEMENT"]
        if text.startswith("I did not"):
            assert len(claims) == 2
            assert claims[0]["claim_state"] == "CORRECTED"
            assert claims[1]["AUDIT_VERDICT"] == "SUPPORTED"
        else:
            assert len(claims) == 1
            assert claims[0]["asserted_value"] is True
            assert claims[0]["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"


def test_trajectory_parser_version_is_bumped_for_round002_semantics() -> None:
    assert PARSER_VERSIONS[TRAJECTORY] == "1.11.0"


@pytest.mark.parametrize("text,reason", [
    ("If the test prints " + chr(0x22) + "PASS" + chr(0x22) + NL + "I resolved the task.",
     "CONDITIONAL_CLAUSE"),
    ("I doubt that the result is " + chr(0x22) + "complete" + chr(0x22) + NL + "I resolved the task.",
     "HEDGED_CLAUSE"),
    ("I doubt that the result is complete:" + NL + "```text" + NL + "details" + NL
     + "```" + NL + "I resolved the task.", "HEDGED_CLAUSE"),
], ids=["outer-conditional-survives-embedded-quote", "outer-doubt-survives-embedded-quote",
       "outer-doubt-survives-closed-fence"])
def test_closing_embedded_quote_does_not_end_open_outer_operator(
        tmp_path: Path, text: str, reason: str) -> None:
    for evaluator in (True, False):
        _assert_no_supported_claim(_audit(tmp_path, [{"role": "assistant", "content": text}], evaluator),
                                   text, reason)


@pytest.mark.parametrize("second", [
    "Today," + NL + "Actually, honestly, I resolved the task.",
    "Today," + NL + "Correction: honestly, I resolved the task.",
], ids=["actually-after-softwrap", "correction-after-softwrap"])
def test_temporal_scope_uses_full_accepted_multiline_clause_prefix(
        tmp_path: Path, second: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [
            {"role": "assistant", "content": "Yesterday," + NL + "honestly, I did not resolve the task."},
            {"role": "assistant", "content": second},
        ], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2
        assert all(claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT" for claim in claims)
        assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
        assert all("superseded_by" not in claim for claim in claims)
        assert result["AUDIT_VERDICT"] != "SUPPORTED"


def test_softwrapped_same_day_correction_still_supersedes(tmp_path: Path) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "Today," + NL + "honestly, I did not resolve the task."},
        {"role": "assistant", "content": "Today," + NL + "Actually, honestly, I resolved the task."},
    ], True)
    claims = result["AGENT_STATEMENT"]
    assert len(claims) == 2
    assert claims[0]["claim_state"] == "CORRECTED"
    assert claims[0]["superseded_by"] == claims[1]["claim_id"]
    assert result["AUDIT_VERDICT"] == "SUPPORTED"


@pytest.mark.parametrize("quote", [
    '"I did not resolve the task at all"',
    '"the task is not resolved (yet)"',
    chr(0x2018) + "the task is not resolved (yet)" + chr(0x2019),
], ids=["negative-action-extra-modifier", "state-extra-parenthetical", "curly-state-extra-parenthetical"])
def test_any_quoted_reference_to_audited_task_blocks_unrelated_quote_exception(
        tmp_path: Path, quote: str) -> None:
    text = "I resolved the task, but the output says " + quote + "."
    for evaluator in (True, False):
        _assert_no_supported_claim(_audit(tmp_path, [{"role": "assistant", "content": text}], evaluator),
                                   text, "EMBEDDED_CLAIM_CONTEXT")


@pytest.mark.parametrize("text", [
    "The reviewer said: 'It's done; I resolved the task.'",
    "The reviewer said: " + chr(0x2018) + "I" + chr(0x2019)
    + "m done; I resolved the task." + chr(0x2019),
    "The reviewer said: 'The students' assignments are complete; I resolved the task.'",
], ids=["ascii-contraction-does-not-close-report-quote", "curly-contraction-does-not-close-report-quote",
       "plural-possessive-does-not-close-report-quote"])
def test_contractions_do_not_terminate_quoted_report_before_semicolon(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        _assert_no_supported_claim(_audit(tmp_path, [{"role": "assistant", "content": text}], evaluator),
                                   text, "QUOTED_CLAIM")


def test_triple_backtick_inline_span_at_line_start_is_not_a_fence(tmp_path: Path) -> None:
    text = "```literal```." + NL + "I resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claim["source_pointer"] == "/messages/0/content"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


@pytest.mark.parametrize("operator", ["and", "but"], ids=["and", "but"])
def test_temporal_correction_after_coordination_keeps_local_historical_scope(
        tmp_path: Path, operator: str) -> None:
    text = f"I did not resolve the task, {operator} Actually, yesterday, I resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2
        assert [claim["asserted_value"] for claim in claims] == [False, True]
        assert all(claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT" for claim in claims)
        assert all(claim["source_pointer"] == "/messages/0/content" for claim in claims)
        for claim in claims:
            start, end = claim["match_span"]
            assert text[start:end] == claim["matched_text"]
            byte_start, byte_end = claim["byte_span"]
            assert len(text[:start].encode("utf-8")) == byte_start
            assert len(text[:end].encode("utf-8")) == byte_end
        assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
        assert all("superseded_by" not in claim for claim in claims)
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_same_historical_scope_correction_after_coordination_still_supersedes(tmp_path: Path) -> None:
    text = "Yesterday, I did not resolve the task, and Actually, yesterday, I resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2
        assert claims[0]["claim_state"] == "CORRECTED"
        assert claims[0]["superseded_by"] == claims[1]["claim_id"]
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


@pytest.mark.parametrize("first,later", [
    ("The word 'yesterday' appears before I did not resolve the task.",
     "Actually, yesterday, I resolved the task."),
    ('The literal "today" appears, and I did not resolve the task.',
     "Actually, today, I resolved the task."),
], ids=["quoted-word-is-not-a-time-label", "quoted-literal-is-not-a-time-label"])
def test_quoted_date_metadata_cannot_scope_a_claim_or_enable_supersession(
        tmp_path: Path, first: str, later: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [
            {"role": "assistant", "content": first},
            {"role": "assistant", "content": later},
        ], evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2
        assert [claim["asserted_value"] for claim in claims] == [False, True]
        assert all(claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT" for claim in claims)
        assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
        assert all("superseded_by" not in claim for claim in claims)
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
