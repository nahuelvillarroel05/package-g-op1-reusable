"""Bounded regression controls mapped to Astra round-001 findings."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import (
    PARSER_VERSIONS,
    audit_evidence,
    audit_file,
)

RUN = "astra-remediation-round-001"
INSTANCE = "public__astra-99"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _request(root: Path, messages: list[dict[str, object]], evaluator: bool = True) -> dict[str, object]:
    trajectory = _put(root, "trajectory.json", {"instance_id": INSTANCE, "messages": messages},
                       "AGENT_TRAJECTORY", TRAJECTORY)
    report = _put(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                  "EVALUATOR_REPORT", REPORT)
    return {"run_id": RUN, "instance_id": INSTANCE, "evidence": [trajectory, report]}


CASES = (
    ("A-002/A01", "If and only if the final checks pass:\nI resolved the task.", "CONDITIONAL_CLAUSE"),
    ("A-002/A02", 'The reviewer wrote: "\nI resolved the task.\n"', "QUOTED_CLAIM"),
    ("A-001/A03", "I resolved the task, but this assertion is false according to the tests.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/A05", "I resolved the task, but only its documentation part.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-002/A07", "The tool output says:\nI resolved the task.", "REPORTED_CLAIM"),
    ("A-002/continuation-1", "The tool output says:\nBuild complete.\nI resolved the task.",
     "REPORTED_CLAIM"),
    ("A-002/continuation-2", "The reviewer wrote:\nChecks are complete.\nI resolved the task.",
     "REPORTED_CLAIM"),
    ("A-002/continuation-3", "If all checks pass:\nProceed with review.\nI resolved the task.",
     "CONDITIONAL_CLAUSE"),
    ("A-002/report-correction-frame", "The tool output says:\nCorrection: I resolved the task.",
     "REPORTED_CLAIM"),
    ("A-002/example-correction-frame", "Example assertion:\nActually, I resolved the task.",
     "REPORTED_CLAIM"),
    ("A-002/unknown-colon-frame", "Context:\nReview is complete.\nI resolved the task.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-002/example-blank-boundary", "Example assertion:\n\nI resolved the task.",
     "REPORTED_CLAIM"),
    ("A-002/report-blank-body", "The tool output says:\nBuild complete.\n\nI resolved the task.",
     "REPORTED_CLAIM"),
    ("A-001/A08", "I resolved the task, but only for the build tests.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/A10", "I resolved the task, but the tests prove that I did not.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-002/A18", "Example assertion:\nI resolved the task.", "REPORTED_CLAIM"),
    ("A-001/outer-assertion-1", "I resolved the task, but my assertion is false.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/outer-assertion-2", "I resolved the task, but my statement was incorrect.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/outer-assertion-3", "I resolved the task, but the preceding assertion was untrue.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/quoted-self-reference", 'I resolved the task, but my assertion is "false".',
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/self-referential-action", "I resolved the task, but I retract my claim.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/subscope-embedded-1",
     "I resolved the task, but my remark is false because the task queue remains incomplete.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/subscope-embedded-2",
     "I resolved the task, but the above result is incorrect because the work remains incomplete.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/partial-target-1", "I resolved the task, but the documentation is all I resolved.",
     "EMBEDDED_CLAIM_CONTEXT"),
    ("A-001/partial-target-2", "I resolved the task, but the documentation is the sole part I fixed.",
     "EMBEDDED_CLAIM_CONTEXT"),
)


@pytest.mark.parametrize("case_id,text,reason", CASES, ids=[case[0] for case in CASES])
@pytest.mark.parametrize("evaluator", [True, False], ids=["evaluator-true", "evaluator-false"])
def test_astra_nonassertive_context_abstains_across_evaluator_polarities(
        tmp_path: Path, case_id: str, text: str, reason: str, evaluator: bool) -> None:
    result = audit_evidence(tmp_path, _request(
        tmp_path, [{"role": "assistant", "content": text}], evaluator))

    # Extraction: no target claim is emitted; the exact candidate span remains
    # in the source-bound rejection ledger.
    assert result["AGENT_STATEMENT"] == [], case_id
    rejected = [row for row in result["CLAIM_REJECTIONS"] if row.get("predicate") == "TASK_RESOLVED"]
    assert rejected, case_id
    assert any(reason in row["reason_codes"] for row in rejected), (case_id, rejected)
    row = rejected[0]
    start, end = row["match_span"]
    assert text[start:end] == "I resolved the task", case_id
    assert row["source_pointer"] == "/messages/0/content", case_id

    # Attribution: source role is the assistant trajectory content, while the
    # rejected content itself carries no authenticated speaker identity.
    assert any(ref["role"] == "AGENT_TRAJECTORY" and ref["parser_id"] == TRAJECTORY
               for ref in result["SOURCE_PROVENANCE"]["evidence_references"]), case_id
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE", case_id
    assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE", case_id


@pytest.mark.parametrize("fence", ["```", "~~~"], ids=["backtick-fence", "tilde-fence"])
def test_nonclosing_fence_like_line_does_not_escape_markdown_code(tmp_path: Path, fence: str) -> None:
    text = f"{fence}text\n{fence}not-a-closing-fence\nI resolved the task.\n{fence}"
    parsed = audit_file(tmp_path, {
        **_put(tmp_path, "trajectory.json", {
            "instance_id": INSTANCE,
            "messages": [{"role": "assistant", "content": text}],
        }, "AGENT_TRAJECTORY", TRAJECTORY),
        "run_id": RUN, "instance_id": INSTANCE,
    })
    assert parsed["schema"] == "pgop1.swebench.generalized-audit-file.v1"
    assert parsed["status"] == "SUPPORTED"  # Source format parsed; this is not a claim verdict.
    assert not [row for row in parsed["observations"] if row["kind"] == "agent_statement"]
    rejection = next(row["value"] for row in parsed["observations"]
                     if row["kind"] == "claim_rejection")
    assert "MARKDOWN_CODE" in rejection["reason_codes"]
    a, b = rejection["match_span"]
    assert text[a:b] == "I resolved the task"
    for evaluator in (True, False):
        audited = audit_evidence(tmp_path, _request(
            tmp_path, [{"role": "assistant", "content": text}], evaluator))
        assert audited["AGENT_STATEMENT"] == []
        assert audited["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert audited["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_tilde_fence_with_horizontal_whitespace_closes_before_direct_claim(tmp_path: Path) -> None:
    text = "~~~text\ncode\n~~~ \t\nI resolved the task."
    result = audit_evidence(tmp_path, _request(
        tmp_path, [{"role": "assistant", "content": text}], True))
    assert len(result["AGENT_STATEMENT"]) == 1
    assert result["AGENT_STATEMENT"][0]["asserted_value"] is True
    assert result["COMPUTED_VERDICT"] == "SUPPORTED"
    for evaluator in (True, False):
        audited = audit_evidence(tmp_path, _request(
            tmp_path, [{"role": "assistant", "content": text}], evaluator))
        assert len(audited["AGENT_STATEMENT"]) == 1
        assert audited["COMPUTED_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


@pytest.mark.parametrize("first_day,second_day", [
    ("Today", "yesterday"), ("yesterday", "Today"),
    ("yesterday", ""), ("", "yesterday"),
], ids=["today-to-yesterday", "yesterday-to-today", "explicit-to-unknown", "unknown-to-explicit"])
def test_different_or_unknown_temporal_scope_is_not_superseded(
        tmp_path: Path, first_day: str, second_day: str) -> None:
    earlier = f"{first_day + ', ' if first_day else ''}I did not resolve the task."
    later = f"Actually, {second_day + ', ' if second_day else ''}I resolved the task."
    result = audit_evidence(tmp_path, _request(tmp_path, [
        {"role": "assistant", "content": earlier},
        {"role": "assistant", "content": later},
    ], evaluator=True))
    claims = result["AGENT_STATEMENT"]
    assert len(claims) == 2
    assert all("superseded_by" not in claim for claim in claims)
    assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
    assert result["AUDIT_VERDICT"] != "SUPPORTED"


def test_postfix_temporal_labels_and_same_message_correction_keep_incompatible_claims_active(
        tmp_path: Path) -> None:
    for earlier, later in (
        ("I did not resolve the task, today.", "Correction: I resolved the task, yesterday."),
        ("I resolved the task, yesterday.", "Correction: I did not resolve the task, today."),
    ):
        result = audit_evidence(tmp_path, _request(tmp_path, [
            {"role": "assistant", "content": earlier},
            {"role": "assistant", "content": later},
        ], evaluator=True))
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2
        assert all("superseded_by" not in claim for claim in claims)
        assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
        assert result["AUDIT_VERDICT"] != "SUPPORTED"

    same_message = audit_evidence(tmp_path, _request(tmp_path, [{
        "role": "assistant",
        "content": "Today, I resolved the task. Correction: Yesterday, the task remains unresolved.",
    }], evaluator=False))
    claims = same_message["AGENT_STATEMENT"]
    assert len(claims) == 2
    assert all("superseded_by" not in claim for claim in claims)
    assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
    assert same_message["AUDIT_VERDICT"] != "SUPPORTED"

    unqualified_same_message = audit_evidence(tmp_path, _request(tmp_path, [{
        "role": "assistant",
        "content": "I resolved the task. Correction: Yesterday, the task remains unresolved.",
    }], evaluator=False))
    claims = unqualified_same_message["AGENT_STATEMENT"]
    assert len(claims) == 2
    assert all("superseded_by" not in claim for claim in claims)
    assert all(claim["claim_state"] != "CORRECTED" for claim in claims)
    assert unqualified_same_message["AUDIT_VERDICT"] != "SUPPORTED"

    long_prefix = "Today," + (" " * 160) + "I did not resolve the task."
    long_context = audit_evidence(tmp_path, _request(tmp_path, [
        {"role": "assistant", "content": long_prefix},
        {"role": "assistant", "content": "Correction: Yesterday, I resolved the task."},
    ], evaluator=True))
    assert len(long_context["AGENT_STATEMENT"]) == 2
    assert all("superseded_by" not in claim for claim in long_context["AGENT_STATEMENT"])
    assert long_context["AUDIT_VERDICT"] != "SUPPORTED"


@pytest.mark.parametrize("earlier,later", [
    ("Today, I did not resolve the task.", "Correction: Today, I have now resolved the task."),
    ("I did not resolve the task.", "Correction: I have now resolved the task."),
])
def test_explicit_compatible_scope_correction_still_supersedes(
        tmp_path: Path, earlier: str, later: str) -> None:
    result = audit_evidence(tmp_path, _request(tmp_path, [
        {"role": "assistant", "content": earlier},
        {"role": "assistant", "content": later},
    ], evaluator=True))
    claims = result["AGENT_STATEMENT"]
    assert len(claims) == 2
    assert claims[0].get("superseded_by") == claims[1]["claim_id"]
    assert claims[0]["claim_state"] == "CORRECTED"
    assert claims[1]["AUDIT_VERDICT"] == "SUPPORTED"


@pytest.mark.parametrize("text", [
    "If checks fail, halt.\nI resolved the task.",
    "After review, I resolved the task, but the deployment failed.",
    "I resolved the task.",
])
def test_independent_assertion_controls_remain_extractable(tmp_path: Path, text: str) -> None:
    result = audit_evidence(tmp_path, _request(
        tmp_path, [{"role": "assistant", "content": text}], True))
    assert any(claim["predicate"] == "TASK_RESOLVED" and claim["asserted_value"] is True
               for claim in result["AGENT_STATEMENT"])


@pytest.mark.parametrize("text", [
    "I resolved the task, and I did not resolve the task.",
    "I did not resolve the task, and I resolved the task.",
    "I resolved the task; I did not resolve the task.",
    "I resolved the task, and I completed the task.",
])
def test_direct_compound_assertions_keep_each_clause_and_active_scope(
        tmp_path: Path, text: str) -> None:
    result = audit_evidence(tmp_path, _request(
        tmp_path, [{"role": "assistant", "content": text}], True))
    claims = result["AGENT_STATEMENT"]
    assert len(claims) == 2
    assert all("ACTIVE" in claim["claim_state"] for claim in claims)
    if "and I did not" in text or "and I resolved" in text or "; I did not" in text:
        assert {claim["asserted_value"] for claim in claims} == {True, False}
        assert result["AUDIT_VERDICT"] != "SUPPORTED"
    else:
        assert {claim["predicate"] for claim in claims} == {"TASK_RESOLVED", "TASK_COMPLETED"}


@pytest.mark.parametrize("text", [
    "The user said I resolved the task, and I did not resolve the task.",
    "If checks pass and I resolved the task, proceed.",
])
def test_and_does_not_close_report_or_conditional_scope(tmp_path: Path, text: str) -> None:
    result = audit_evidence(tmp_path, _request(
        tmp_path, [{"role": "assistant", "content": text}], True))
    assert result["AGENT_STATEMENT"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_correction_word_does_not_terminate_an_unclosed_example_frame(tmp_path: Path) -> None:
    text = ("Example assertion:\nI resolved the task.\n"
            "Correction: I never resolved the task.")
    result = audit_evidence(tmp_path, _request(
        tmp_path, [{"role": "assistant", "content": text}], False))
    assert result["AGENT_STATEMENT"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert sum("REPORTED_CLAIM" in row["reason_codes"]
               for row in result["CLAIM_REJECTIONS"]) == 2


def test_multiline_utf8_quote_rejection_preserves_character_and_byte_spans(tmp_path: Path) -> None:
    text = 'Reviewer wrote: “\nI resolved the task.\n” — revisión.'
    parsed = audit_file(tmp_path, {
        **_put(tmp_path, "trajectory.json", {
            "instance_id": INSTANCE,
            "messages": [{"role": "assistant", "content": text}],
        }, "AGENT_TRAJECTORY", TRAJECTORY),
        "run_id": RUN, "instance_id": INSTANCE,
    })
    rejection = next(row["value"] for row in parsed["observations"]
                     if row["kind"] == "claim_rejection")
    start, end = rejection["match_span"]
    byte_start, byte_end = rejection["byte_span"]
    assert text[start:end] == "I resolved the task"
    assert len(text[:start].encode("utf-8")) == byte_start
    assert len(text[:end].encode("utf-8")) == byte_end
    assert PARSER_VERSIONS[TRAJECTORY] == "1.5.0"
