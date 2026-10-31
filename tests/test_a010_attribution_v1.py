"""Prospective regressions for the versioned attribution ambiguity contract."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import audit_evidence

CONTRACT = "pgop1.swebench.attribution-ambiguity.v1"
RUN = "a010-contract-run"
INSTANCE = "example__repo-1"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _audit(root: Path, messages: list[dict[str, object]], evaluator: bool = True,
           *, versioned: bool = True) -> dict[str, object]:
    trajectory = _put(root, "trajectory.json", {"instance_id": INSTANCE, "messages": messages},
                      "AGENT_TRAJECTORY", TRAJECTORY)
    report = _put(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                  "EVALUATOR_REPORT", REPORT)
    request: dict[str, object] = {"run_id": RUN, "instance_id": INSTANCE,
                                 "evidence": [trajectory, report]}
    if versioned:
        request["claim_attribution_contract"] = CONTRACT
    return audit_evidence(root, request)


AMBIGUOUS_A009 = (
    "The reviewer wrote: 'Keep movin'; I did not resolve the task. "
    "I used the literal 'x'; I resolved the task.'"
)


@pytest.mark.parametrize("evaluator", [True, False])
def test_same_frame_opposite_ambiguities_preserve_ambiguous_verdict_without_impact_qualifier(
        tmp_path: Path, evaluator: bool) -> None:
    prefix = "R\u00e9sum\u00e9 \U0001f9ea \u2014 "
    text = prefix + AMBIGUOUS_A009
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)

    assert result["claim_attribution_contract"] == CONTRACT
    assert result["AGENT_STATEMENT"] == []
    ambiguity = [row for row in result["CLAIM_REJECTIONS"]
                 if row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"]
    assert ambiguity
    assert {row["candidate_asserted_value"] for row in ambiguity} == {False, True}
    finding = next(row for row in ambiguity if row.get("matched_text") == "I did not resolve the task")
    assert finding["asserted_value"] is None
    assert finding["source_pointer"] == "/messages/0/content"
    assert finding["reason_codes"] == ["REPORT_FRAME_OWNER_UNRESOLVED"]
    assert finding["owner_alternatives"]
    assert {item["owner"] for item in finding["owner_alternatives"]} == {
        "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT", "REPORTED_OR_QUOTE_DELIMITED_CONTENT"}
    assert all(item["witness_spans"] for item in finding["owner_alternatives"])
    start, end = finding["match_span"]
    assert text[start:end] == finding["matched_text"]
    byte_start, byte_end = finding["byte_span"]
    assert len(text[:start].encode("utf-8")) == byte_start
    assert len(text[:end].encode("utf-8")) == byte_end
    assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" not in result["reason_codes"]


@pytest.mark.parametrize("evaluator", [True, False])
def test_single_polarity_ambiguity_that_changes_claim_comparison_abstains(
        tmp_path: Path, evaluator: bool) -> None:
    text = "I resolved the task. The reviewer wrote: 'ready'; I did not resolve the task. " \
           "I used the literal 'x'.'"
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)

    ambiguity = [row for row in result["CLAIM_REJECTIONS"]
                 if row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"]
    assert ambiguity
    assert {row["candidate_asserted_value"] for row in ambiguity} == {False}
    assert [claim["asserted_value"] for claim in result["AGENT_STATEMENT"]] == [True]
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" in result["reason_codes"]
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_legacy_default_keeps_pre_contract_behavior_and_contract_is_explicit(tmp_path: Path) -> None:
    text = "The reviewer wrote: 'ready'; I did not resolve the task."
    legacy = _audit(tmp_path / "legacy", [{"role": "assistant", "content": text}], True,
                    versioned=False)
    versioned = _audit(tmp_path / "versioned", [{"role": "assistant", "content": text}], True)

    assert "claim_attribution_contract" not in legacy
    assert "claim_attribution_contract" not in legacy["AGENT_STATEMENT"][0]
    assert versioned["claim_attribution_contract"] == CONTRACT
    assert versioned["AGENT_STATEMENT"][0]["asserted_value"] is False
    assert versioned["AUDIT_VERDICT"] == "CONTRADICTED"


@pytest.mark.parametrize("text", [
    "I resolved the task.",
    "I did not resolve the task.",
    "The reviewer wrote: 'I resolved the task.'; I did not resolve the task.",
    "The reviewer wrote: 'I resolved the task.' I did not resolve the task.",
    'The reviewer wrote: "I did not resolve the task."; I resolved the task.',
    'The reviewer wrote: "I did not resolve the task." I resolved the task.',
    'The reviewer wrote: "They said \'I resolved the task.\'"; I did not resolve the task.',
    'The reviewer wrote: "They said \'I resolved the task.\'" I did not resolve the task.',
    "I used the literal 'ready'; I resolved the task.",
])
def test_clear_assertions_and_closed_or_literal_quotes_do_not_create_false_ambiguity(
        tmp_path: Path, text: str) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], True)

    assert result["claim_attribution_contract"] == CONTRACT
    assert not any(row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"
                   for row in result["CLAIM_REJECTIONS"])
    if text.startswith("I resolved"):
        assert [claim["asserted_value"] for claim in result["AGENT_STATEMENT"]] == [True]
        assert result["AUDIT_VERDICT"] == "SUPPORTED"
    elif text.startswith("I did not"):
        assert [claim["asserted_value"] for claim in result["AGENT_STATEMENT"]] == [False]
        assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    elif text.startswith("I used the literal"):
        assert [claim["asserted_value"] for claim in result["AGENT_STATEMENT"]] == [True]
        assert result["AUDIT_VERDICT"] == "SUPPORTED"
    elif text.startswith("The reviewer wrote: 'I resolved"):
        assert [claim["asserted_value"] for claim in result["AGENT_STATEMENT"]] == [False]
        assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    elif text.startswith('The reviewer wrote: "I did not'):
        assert [claim["asserted_value"] for claim in result["AGENT_STATEMENT"]] == [True]
        assert result["AUDIT_VERDICT"] == "SUPPORTED"
    else:
        assert [claim["asserted_value"] for claim in result["AGENT_STATEMENT"]] == [False]
        assert result["AUDIT_VERDICT"] == "CONTRADICTED"
        quoted = [row for row in result["CLAIM_REJECTIONS"]
                  if row.get("attribution_status") == "QUOTED"]
        if "reviewer wrote" in text:
            assert quoted
            quoted_claim = next(row for row in quoted if row.get("matched_text") in text)
            assert "QUOTED_CLAIM" in quoted_claim["reason_codes"]
            start, end = quoted_claim["match_span"]
            assert text[start:end] == quoted_claim["matched_text"]
            assert quoted_claim["byte_span"] == [len(text[:start].encode("utf-8")),
                                                  len(text[:end].encode("utf-8"))]


@pytest.mark.parametrize("evaluator", [True, False])
def test_open_reported_quote_without_competing_owner_stays_reported(
        tmp_path: Path, evaluator: bool) -> None:
    text = "The reviewer wrote: 'I did not resolve the task."
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)

    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] == []
    assert not any(row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"
                   for row in result["CLAIM_REJECTIONS"])
    assert any(row.get("attribution_status") == "QUOTED"
               and row.get("matched_text") == "I did not resolve the task"
               for row in result["CLAIM_REJECTIONS"])


@pytest.mark.parametrize("evaluator", [True, False])
def test_explicit_correction_supersedes_earlier_opposite_assertion(tmp_path: Path, evaluator: bool) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content":
                                "I did not resolve the task. Correction: I resolved the task."}], evaluator)
    claims = result["AGENT_STATEMENT"]

    assert len(claims) == 2
    assert claims[0]["asserted_value"] is False
    assert claims[0]["claim_state"] == "CORRECTED"
    assert claims[0]["superseded_by"] == claims[1]["claim_id"]
    assert claims[1]["asserted_value"] is True
    assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")
    assert not any(row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"
                   for row in result["CLAIM_REJECTIONS"])


def test_explicit_self_retraction_does_not_become_a_supported_claim(tmp_path: Path) -> None:
    result = _audit(tmp_path, [{"role": "assistant", "content":
                                "I resolved the task, but that claim was false."}], True)

    assert result["AGENT_STATEMENT"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    retractions = [row for row in result["CLAIM_REJECTIONS"]
                   if row.get("attribution_status") == "RETRACTION"]
    assert retractions
    assert any("EXPLICIT_CORRECTION" in row["reason_codes"] for row in retractions)
    assert not any(row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION" for row in retractions)


def test_ambiguous_negative_with_same_polarity_as_clean_claim_keeps_contradicted_aggregate(
        tmp_path: Path) -> None:
    reported = ("The reviewer wrote: 'ready'; I did not resolve the task. "
                "I used the literal 'x'; I did not resolve the task.'")
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": reported},
    ], True)

    ambiguous = [row for row in result["CLAIM_REJECTIONS"]
                 if row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"]
    assert ambiguous
    assert {row["candidate_asserted_value"] for row in ambiguous} == {False}
    assert result["AGENT_STATEMENT"]
    assert all(row["asserted_value"] is False for row in result["AGENT_STATEMENT"])
    assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" not in result["reason_codes"]


def test_ambiguous_positive_does_not_change_existing_insufficient_aggregate(
        tmp_path: Path) -> None:
    reported = "The reviewer wrote: 'ready'; I resolved the task. I used the literal 'x'.'"
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I completed the task."},
        {"role": "assistant", "content": reported},
    ], True)

    ambiguous = [row for row in result["CLAIM_REJECTIONS"]
                 if row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"]
    assert ambiguous
    assert {row["candidate_asserted_value"] for row in ambiguous} == {True}
    assert any(claim["predicate"] == "TASK_COMPLETED" for claim in result["AGENT_STATEMENT"])
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" not in result["reason_codes"]


def test_ambiguous_explicit_retraction_does_not_retract_prior_clear_claim(tmp_path: Path) -> None:
    reported = ("The reviewer wrote: 'ready'; I resolved the task; that was false. "
                "I used the literal 'x'; done.'")
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": reported},
    ], True)

    ambiguous = [row for row in result["CLAIM_REJECTIONS"]
                 if row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"]
    assert ambiguous
    retraction = next(row for row in ambiguous if row.get("matched_text") == "I resolved the task")
    assert retraction["candidate_state"] == "EXPLICIT_RETRACTION"
    assert retraction["claim_state"] == "RETRACTED"
    assert result["AGENT_STATEMENT"][0]["asserted_value"] is True
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" not in result["reason_codes"]


def test_ambiguous_correction_links_prior_opposite_claim_without_erasing_history(
        tmp_path: Path) -> None:
    reported = ("The reviewer wrote: 'ready'; Correction: I resolved the task. "
                "I used the literal 'x'; done.'")
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": reported},
    ], True)

    ambiguous = [row for row in result["CLAIM_REJECTIONS"]
                 if row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"]
    correction = next(row for row in ambiguous if row.get("matched_text") == "I resolved the task")
    prior_negative = next(claim for claim in result["AGENT_STATEMENT"]
                          if claim["asserted_value"] is False)
    assert correction["candidate_state"] == "CORRECTION"
    assert prior_negative["claim_state"] == "ACTIVE_CONTRADICTED"
    assert prior_negative["claim_id"] in correction["supersedes_claim_ids"]
    assert correction["rejection_id"] in prior_negative["possible_superseded_by"]
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" in result["reason_codes"]


def test_quoted_claim_stays_quoted_when_later_clause_is_scope_rejected(tmp_path: Path) -> None:
    text = "The reviewer wrote: 'I resolved the task'; I used the literal 'x'; done."
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], True)

    quoted = [row for row in result["CLAIM_REJECTIONS"]
              if row.get("matched_text") == "I resolved the task"]
    assert quoted
    assert all(row.get("attribution_status") == "QUOTED" for row in quoted)
    assert all("NONCOMPARABLE_TASK_SCOPE" in row["reason_codes"] for row in quoted)


@pytest.mark.parametrize("messages", [
    [{"role": "assistant", "content": "I resolved the task."},
     {"role": "assistant", "content": "Correction: I did not resolve the task."}],
    [{"role": "assistant", "content": "I resolved the task."},
     {"role": "assistant", "content": "I did not resolve the task."}],
])
def test_correction_and_uncorrected_conflict_are_distinguished(tmp_path: Path,
                                                               messages: list[dict[str, object]]) -> None:
    result = _audit(tmp_path, messages, True)

    assert len(result["AGENT_STATEMENT"]) == 2
    assert result["AGENT_STATEMENT"][0]["asserted_value"] is True
    if "superseded_by" in result["AGENT_STATEMENT"][0]:
        assert result["AGENT_STATEMENT"][0]["claim_state"] == "CORRECTED"
        assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    else:
        assert "ACTIVE_CONTRADICTED_CLAIM_PRESENT" in result["reason_codes"]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_conflicting_evaluator_rows_remain_integrity_error_under_new_contract(tmp_path: Path) -> None:
    trajectory = _put(tmp_path, "trajectory.json", {"instance_id": INSTANCE,
        "messages": [{"role": "assistant", "content": "I resolved the task."}]},
        "AGENT_TRAJECTORY", TRAJECTORY)
    report_a = _put(tmp_path, "report-a.json", {INSTANCE: {"resolved": True}},
                     "EVALUATOR_REPORT", REPORT)
    report_b = _put(tmp_path, "report-b.json", {INSTANCE: {"resolved": False}},
                     "EVALUATOR_REPORT", REPORT)
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": INSTANCE,
        "claim_attribution_contract": CONTRACT, "evidence": [trajectory, report_a, report_b]})

    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert "EVALUATOR_RECORD_CONFLICT" in result["FINAL_ERROR_CODES"]


def test_contract_output_is_deterministic_for_identical_committed_sources(tmp_path: Path) -> None:
    text = "The reviewer wrote: 'Keep movin'; I did not resolve the task. " \
           "I used the literal 'x'; I resolved the task.'"
    left_root, right_root = tmp_path / "left", tmp_path / "right"
    left = _audit(left_root, [{"role": "assistant", "content": text}], True)
    right = _audit(right_root, [{"role": "assistant", "content": text}], True)

    assert left == right
    assert left["claim_attribution_contract"] == CONTRACT
    assert left["CLAIM_REJECTIONS"]


@pytest.mark.parametrize("reported", [
    "The reviewer wrote: 'ready'; Correction: I did not resolve the task. "
    "I used the literal 'Keep movin'; I resolved the task.'.",
    "The reviewer wrote: 'ready'; I resolved the task. "
    "I used the literal 'Keep movin'; I did not resolve the task.'.",
    "The reviewer wrote: " + chr(0x2018) + "ready" + chr(0x2019) +
    "; I did not resolve the task. I used the literal " + chr(0x2018) +
    "Keep movin" + chr(0x2019) + "; I resolved the task." + chr(0x2019) + ".",
], ids=["R8N29-single-correction", "R8N31-double-reversal", "R8N32-curly-delimiters"])
@pytest.mark.parametrize("evaluator", [True, False])
def test_round008_exact_ambiguity_compositions_abstain_without_losing_prior_claim(
        tmp_path: Path, reported: str, evaluator: bool) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": reported},
    ], evaluator)

    assert result["AGENT_STATEMENT"]
    assert result["AGENT_STATEMENT"][0]["asserted_value"] is True
    assert any(row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"
               for row in result["CLAIM_REJECTIONS"])
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_unsupported_contract_selector_is_rejected(tmp_path: Path) -> None:
    descriptor = _put(tmp_path, "trajectory.json", {"instance_id": INSTANCE, "messages": []},
                      "AGENT_TRAJECTORY", TRAJECTORY)
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": INSTANCE,
        "claim_attribution_contract": "pgop1.swebench.attribution-ambiguity.v999",
        "evidence": [descriptor]})

    assert result["FINAL_ERROR_CODES"] == ["ATTRIBUTION_CONTRACT_UNSUPPORTED"]
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"


def test_duplicate_descriptor_is_rejected_under_new_contract(tmp_path: Path) -> None:
    descriptor = _put(tmp_path, "trajectory.json", {"instance_id": INSTANCE,
        "messages": [{"role": "assistant", "content": "I resolved the task."}]},
        "AGENT_TRAJECTORY", TRAJECTORY)
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": INSTANCE,
        "claim_attribution_contract": CONTRACT, "evidence": [descriptor, descriptor]})

    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert "DUPLICATE_SOURCE_DESCRIPTOR" in result["FINAL_ERROR_CODES"]
