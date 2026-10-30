"""Prospective round-003 quote and soft-wrap semantic regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import PARSER_VERSIONS, audit_evidence

RUN = "astra-remediation-round-003"
INSTANCE = "public__astra-99"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _audit(root: Path, text: str, evaluator: bool = True) -> dict[str, object]:
    trajectory = _put(root, "trajectory.json", {"instance_id": INSTANCE,
                                                   "messages": [{"role": "assistant", "content": text}]},
                      "AGENT_TRAJECTORY", TRAJECTORY)
    report = _put(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                  "EVALUATOR_REPORT", REPORT)
    return audit_evidence(root, {"run_id": RUN, "instance_id": INSTANCE,
                                 "evidence": [trajectory, report]})


@pytest.mark.parametrize("separator", [" ", "\t", "\n", "\r\n", "\r",
                                      chr(0x2028), chr(0x2029)],
                         ids=["space", "tab", "lf", "crlf", "cr",
                              "unicode-line-separator", "unicode-paragraph-separator"])
@pytest.mark.parametrize("prefix,continuation", [
    ("The reviewer wrote: 'The students'", "assignments are complete; I resolved the task.'"),
    ("The user wrote: 'The users'", "requests are complete; I resolved the task.'"),
])
def test_plural_possessive_quote_remains_open_across_softwrap(
        tmp_path: Path, separator: str, prefix: str, continuation: str) -> None:
    text = prefix + separator + continuation
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejected = [row for row in result["CLAIM_REJECTIONS"]
                    if row.get("predicate") == "TASK_RESOLVED"
                    and "QUOTED_CLAIM" in row.get("reason_codes", [])]
        assert len(rejected) == 1
        row = rejected[0]
        start, end = row["match_span"]
        assert text[start:end] == "I resolved the task"
        byte_start, byte_end = row["byte_span"]
        assert len(text[:start].encode("utf-8")) == byte_start
        assert len(text[:end].encode("utf-8")) == byte_end
        sources = result["SOURCE_PROVENANCE"]["evidence_references"]
        assert any(source["role"] == "AGENT_TRAJECTORY"
                   and source["parser_id"] == TRAJECTORY for source in sources)
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_closed_quote_does_not_hide_following_direct_claim(tmp_path: Path) -> None:
    text = (chr(0x22) + "Example assertion:" + "\n" + "I resolved the task."
            + chr(0x22) + "\n" + "I resolved the task.")
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["asserted_value"] is True
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claim["source_pointer"] == "/messages/0/content"
        start, end = claim["match_span"]
        assert text[start:end] == "I resolved the task"
        byte_start, byte_end = claim["byte_span"]
        assert len(text[:start].encode("utf-8")) == byte_start
        assert len(text[:end].encode("utf-8")) == byte_end
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")
        assert result["COMPUTED_VERDICT"] == result["AUDIT_VERDICT"]


@pytest.mark.parametrize("gap,continuation", [
    ("\n\n", "assignments are complete; I resolved the task."),
    ("\r\n\r\n", "assignments are complete; I resolved the task."),
    ("\n \n", "assignments are complete; I resolved the task."),
    ("\n", "*assignments* are complete; I resolved the task."),
    ("\n", "**assignments** are complete; I resolved the task."),
    ("\n", "_assignments_ are complete; I resolved the task."),
    ("\n", "[assignments] are complete; I resolved the task."),
    ("\n", "(assignments) are complete; I resolved the task."),
], ids=["paragraph-lf", "paragraph-crlf", "paragraph-spaces", "emphasis-star",
       "bold-star", "emphasis-underscore", "bracket", "parenthesis"])
def test_possessive_quote_survives_paragraph_and_markdown_continuation(
        tmp_path: Path, gap: str, continuation: str) -> None:
    text = "The reviewer wrote: 'The students'" + gap + continuation + "'"
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert result["AGENT_STATEMENT"] == []
        row = next(row for row in result["CLAIM_REJECTIONS"]
                   if row.get("predicate") == "TASK_RESOLVED")
        assert "QUOTED_CLAIM" in row["reason_codes"]
        start, end = row["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == row["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == row["byte_span"][1]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("text", [
    "The reviewer wrote: " + chr(0x2018) + "The students" + chr(0x2019)
    + "\nassignments are complete; I resolved the task." + chr(0x2019),
    chr(0x03a9) + chr(0x1f600)
    + ". The reviewer wrote: 'The students'\nassignments are complete; I resolved the task.'",
    "The reviewer wrote: 'The students'\n`assignments` are complete; I resolved the task.'",
], ids=["curly-possessive-softwrap-R3N23", "unicode-prefix-R3N27",
       "inline-code-continuation-R3N29"])
def test_astra_a007_quote_variants_remain_reported_across_softwrap(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejected = [row for row in result["CLAIM_REJECTIONS"]
                    if row.get("predicate") == "TASK_RESOLVED"
                    and "QUOTED_CLAIM" in row.get("reason_codes", [])]
        assert len(rejected) == 1
        row = rejected[0]
        start, end = row["match_span"]
        assert text[start:end] == "I resolved the task"
        byte_start, byte_end = row["byte_span"]
        assert len(text[:start].encode("utf-8")) == byte_start
        assert len(text[:end].encode("utf-8")) == byte_end
        assert any(source["role"] == "AGENT_TRAJECTORY"
                   and source["parser_id"] == TRAJECTORY
                   for source in result["SOURCE_PROVENANCE"]["evidence_references"])
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("text", [
    'The reviewer wrote: "The delimiter is clear". I resolved the task.',
    "The reviewer wrote: 'The students are ready'; I resolved the task.",
    'I resolved the task, but the output says "the students\' assignments are ready".',
], ids=["closed-report-R3N25", "closed-report-R3N26", "unrelated-quoted-output-R3N28"])
def test_astra_a007_closed_quote_and_unrelated_output_controls_remain_positive(
        tmp_path: Path, text: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["asserted_value"] is True
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert claim["source_pointer"] == "/messages/0/content"
        start, end = claim["match_span"]
        assert text[start:end] == "I resolved the task"
        byte_start, byte_end = claim["byte_span"]
        assert len(text[:start].encode("utf-8")) == byte_start
        assert len(text[:end].encode("utf-8")) == byte_end
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")
        assert result["COMPUTED_VERDICT"] == result["AUDIT_VERDICT"]


@pytest.mark.parametrize("continuation", [
    "**_assignments_** are complete; I resolved the task.",
    "**`assignments`** are complete; I resolved the task.",
    "(**assignments**) are complete; I resolved the task.",
    "[*assignments*] are complete; I resolved the task.",
    "` .NET assignments` are complete; I resolved the task.",
    "**.NET assignments** are complete; I resolved the task.",
    ".NET assignments are complete; I resolved the task.",
    ".**NET** assignments are complete; I resolved the task.",
    ".`word` assignments are complete; I resolved the task.",
    "... assignments are complete; I resolved the task.",
    "<assignments> are complete; I resolved the task.",
], ids=["nested-emphasis", "nested-inline-code", "nested-parenthesis",
       "nested-bracket", "inline-code-leading-punctuation", "bold-leading-punctuation",
       "plain-leading-period-is-lexical", "formatted-dot-is-lexical",
       "inline-after-dot-is-lexical", "ellipsis-is-ambiguous",
       "unknown-markup-stays-ambiguous"])
def test_nested_or_unknown_markdown_continuation_keeps_report_quote_open(
        tmp_path: Path, continuation: str) -> None:
    text = "The reviewer wrote: 'The students'\n" + continuation + "'"
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert result["AGENT_STATEMENT"] == []
        row = next(row for row in result["CLAIM_REJECTIONS"]
                   if row.get("predicate") == "TASK_RESOLVED")
        assert "QUOTED_CLAIM" in row["reason_codes"]
        start, end = row["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == row["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == row["byte_span"][1]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_curly_plural_possessive_quote_survives_blank_line(tmp_path: Path) -> None:
    text = ("The reviewer wrote: " + chr(0x2018) + "The students" + chr(0x2019)
            + "\n\nassignments are complete; I resolved the task." + chr(0x2019))
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert result["AGENT_STATEMENT"] == []
        row = next(row for row in result["CLAIM_REJECTIONS"]
                   if row.get("predicate") == "TASK_RESOLVED")
        assert "QUOTED_CLAIM" in row["reason_codes"]
        start, end = row["match_span"]
        assert text[start:end] == "I resolved the task"
        assert len(text[:start].encode("utf-8")) == row["byte_span"][0]
        assert len(text[:end].encode("utf-8")) == row["byte_span"][1]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_single_external_full_stop_after_plural_quote_allows_direct_claim(tmp_path: Path) -> None:
    text = "The reviewer wrote: 'The students'\n. I resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["asserted_value"] is True
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_punctuation_terminated_plural_quote_allows_following_direct_claim(tmp_path: Path) -> None:
    text = "The reviewer wrote: 'The students'; I resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
        assert len(result["AGENT_STATEMENT"]) == 1
        claim = result["AGENT_STATEMENT"][0]
        assert claim["asserted_value"] is True
        assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_closed_single_quoted_literal_allows_following_direct_claim(tmp_path: Path) -> None:
    text = "'literal value'\nI resolved the task."
    for evaluator in (True, False):
        result = _audit(tmp_path, text, evaluator)
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


def test_trajectory_parser_version_is_bumped_for_quote_scope_change() -> None:
    assert PARSER_VERSIONS[TRAJECTORY] == "1.11.0"
