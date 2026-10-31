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


@pytest.mark.parametrize("evaluator", [True, False])
def test_b05_standalone_same_source_retraction_links_and_deactivates_prior_claim(
        tmp_path: Path, evaluator: bool) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I retract my previous claim."},
    ], evaluator)

    assert len(result["AGENT_STATEMENT"]) == 1
    prior = result["AGENT_STATEMENT"][0]
    assert prior["asserted_value"] is True
    assert prior["claim_state"] == "RETRACTED"
    events = result["CLAIM_RETRACTIONS"]
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "STANDALONE_CLAIM_RETRACTION"
    assert event["target_status"] == "LINKED"
    assert event["target_claim_id"] == prior["claim_id"]
    assert event["source_pointer"] == "/messages/1/content"
    assert event["source_message_id"] == "UNKNOWN"
    assert event["attribution_status"] == "SOURCE_DECLARED_UNVERIFIED"
    assert event["speaker_identity_status"] == "UNKNOWN"
    event_observation = next(row for row in result["observations"]
                             if row["kind"] == "claim_retraction")
    trajectory_ref = next(ref for ref in result["SOURCE_PROVENANCE"]["evidence_references"]
                          if ref["path"] == "trajectory.json")
    assert event_observation["value"] == event
    assert event_observation["source_ref"]["path"] == "trajectory.json"
    assert event_observation["source_ref"]["sha256"] == trajectory_ref["sha256"]
    assert event["event_id"] in prior["retracted_by"]
    assert event["target_source_ref"] == prior["source_ref"]
    assert event["target_source_pointer"] == prior["source_pointer"]
    assert event["target_match_span"] == prior["match_span"]
    assert event["speaker_scope"] == "SAME_TRAJECTORY_DECLARED_ASSISTANT_ROLE"
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" not in result["reason_codes"]


@pytest.mark.parametrize("evaluator,expected", [(True, "SUPPORTED"), (False, "CONTRADICTED")])
def test_b05_standalone_retraction_keeps_legacy_default_unchanged(
        tmp_path: Path, evaluator: bool, expected: str) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I retract my previous claim."},
    ], evaluator, versioned=False)

    assert "claim_attribution_contract" not in result
    assert "CLAIM_RETRACTIONS" not in result
    assert len(result["AGENT_STATEMENT"]) == 1
    assert result["AGENT_STATEMENT"][0]["asserted_value"] is True
    assert set(result["CLAIM_AGGREGATION"]) == {
        "policy", "corrected_claim_ids", "active_contradicted_claim_ids",
        "active_noncomparable_claim_ids", "retracted_candidate_count",
    }
    assert result["AUDIT_VERDICT"] == expected


@pytest.mark.parametrize("evaluator", [True, False])
def test_quoted_or_conditional_retraction_does_not_deactivate_prior_claim(
        tmp_path: Path, evaluator: bool) -> None:
    cases = [
        "The reviewer wrote: 'I retract my previous claim.'",
        "If I retract my previous claim, the task status would change.",
    ]
    for text in cases:
        result = _audit(tmp_path / str(len(text)), [
            {"role": "assistant", "content": "I resolved the task."},
            {"role": "assistant", "content": text},
        ], evaluator)

        assert len(result["AGENT_STATEMENT"]) == 1
        prior = result["AGENT_STATEMENT"][0]
        expected_state = "ACTIVE" if evaluator else "ACTIVE_CONTRADICTED"
        assert prior["claim_state"] == expected_state and "retracted_by" not in prior
        assert result["CLAIM_RETRACTIONS"] == []
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


@pytest.mark.parametrize("evaluator", [True, False])
def test_question_form_standalone_retraction_is_not_an_event(
        tmp_path: Path, evaluator: bool) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I retract my previous claim?"},
    ], evaluator)

    prior = result["AGENT_STATEMENT"][0]
    assert prior["claim_state"] == ("ACTIVE" if evaluator else "ACTIVE_CONTRADICTED")
    assert "retracted_by" not in prior
    assert result["CLAIM_RETRACTIONS"] == []
    assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_correction_then_standalone_retraction_targets_corrected_claim(tmp_path: Path) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "Correction: I resolved the task."},
        {"role": "assistant", "content": "I retract my previous claim."},
    ], True)

    negative, positive = result["AGENT_STATEMENT"]
    assert negative["claim_state"] == "CORRECTED"
    assert positive["claim_state"] == "RETRACTED"
    event = result["CLAIM_RETRACTIONS"][0]
    assert event["target_claim_id"] == positive["claim_id"]
    assert event["event_id"] in positive["retracted_by"]
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("evaluator,expected", [(True, "CONTRADICTED"), (False, "SUPPORTED")])
def test_standalone_retraction_then_correction_uses_event_time_active_claim(
        tmp_path: Path, evaluator: bool, expected: str) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I retract my previous claim."},
        {"role": "assistant", "content": "Correction: I did not resolve the task."},
    ], evaluator)

    original, later_negative = result["AGENT_STATEMENT"]
    event = result["CLAIM_RETRACTIONS"][0]
    assert event["target_claim_id"] == original["claim_id"]
    assert event["target_source_ref"] == original["source_ref"]
    assert event["target_source_pointer"] == original["source_pointer"]
    assert event["target_match_span"] == original["match_span"]
    assert event["event_id"] in original["retracted_by"]
    assert original["claim_state"] == "RETRACTED"
    assert later_negative["asserted_value"] is False
    assert later_negative["claim_state"] == (
        "ACTIVE_CONTRADICTED" if evaluator else "ACTIVE")
    assert result["AUDIT_VERDICT"] == expected


@pytest.mark.parametrize("evaluator", [True, False])
def test_retraction_target_ambiguity_preserves_source_bound_clear_and_candidate_alternatives(
        tmp_path: Path, evaluator: bool) -> None:
    ambiguous_text = "The reviewer wrote: 'ready'; I did not resolve the task. " \
                     "I used the literal 'x'; done.'"
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": ambiguous_text},
        {"role": "assistant", "content": "I retract my previous claim."},
    ], evaluator)

    clear_negative, clear_positive = result["AGENT_STATEMENT"]
    assert clear_positive["asserted_value"] is True
    assert clear_positive["claim_state"] == (
        "ACTIVE" if evaluator else "ACTIVE_CONTRADICTED")
    assert "retracted_by" not in clear_positive
    event = result["CLAIM_RETRACTIONS"][0]
    assert event["source_pointer"] == "/messages/3/content"
    assert event["target_status"] == "AMBIGUOUS_TARGET"
    assert event["target_claim_id"] is None
    assert event["event_id"] in clear_positive["possible_retracted_by"]

    candidate = next(row for row in result["CLAIM_REJECTIONS"]
                     if row.get("attribution_status") == "AMBIGUOUS_ATTRIBUTION"
                     and row.get("matched_text") == "I did not resolve the task")
    assert candidate["source_pointer"] == "/messages/2/content"
    assert candidate["candidate_predicate"] == "TASK_RESOLVED"
    assert candidate["candidate_asserted_value"] is False
    assert candidate["asserted_value"] is None
    start, end = candidate["match_span"]
    assert ambiguous_text[start:end] == candidate["matched_text"]
    assert candidate["byte_span"] == [start, end]

    alternatives = event["target_claim_alternatives"]
    assert {row["target_kind"] for row in alternatives} == {
        "CLEAR_CLAIM", "AMBIGUOUS_CLAIM"}
    clear_alternative = next(row for row in alternatives if row["target_kind"] == "CLEAR_CLAIM")
    candidate_alternative = next(row for row in alternatives
                                 if row["target_kind"] == "AMBIGUOUS_CLAIM")
    assert clear_alternative["claim_id"] == clear_positive["claim_id"]
    assert clear_alternative["source_ref"] == clear_positive["source_ref"]
    assert clear_alternative["source_pointer"] == clear_positive["source_pointer"]
    assert clear_alternative["match_span"] == clear_positive["match_span"]
    assert candidate_alternative["claim_id"] == candidate["rejection_id"]
    assert candidate_alternative["ambiguity_group_id"] == candidate["ambiguity_group_id"]
    assert candidate_alternative["source_ref"]["path"] == "trajectory.json"
    assert candidate_alternative["source_pointer"] == candidate["source_pointer"]
    assert candidate_alternative["match_span"] == candidate["match_span"]
    assert clear_negative["asserted_value"] is False
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert "ATTRIBUTION_AMBIGUITY_AFFECTS_COMPARISON" in result["reason_codes"]


@pytest.mark.parametrize("evaluator,expected", [(True, "SUPPORTED"), (False, "CONTRADICTED")])
def test_retraction_in_user_speaker_scope_cannot_withdraw_assistant_claim(
        tmp_path: Path, evaluator: bool, expected: str) -> None:
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "user", "content": "I retract my previous claim."},
    ], evaluator)

    expected_state = "ACTIVE" if evaluator else "ACTIVE_CONTRADICTED"
    assert [claim["claim_state"] for claim in result["AGENT_STATEMENT"]] == [expected_state]
    assert result["CLAIM_RETRACTIONS"] == []
    assert result["AUDIT_VERDICT"] == expected


@pytest.mark.parametrize("evaluator,expected", [(True, "SUPPORTED"), (False, "CONTRADICTED")])
def test_retraction_in_another_source_cannot_withdraw_prior_source_claim(
        tmp_path: Path, evaluator: bool, expected: str) -> None:
    first = _put(tmp_path, "trajectory-a.json", {"instance_id": INSTANCE,
        "messages": [{"role": "assistant", "content": "I resolved the task."}]},
        "AGENT_TRAJECTORY", TRAJECTORY)
    second = _put(tmp_path, "trajectory-b.json", {"instance_id": INSTANCE,
        "messages": [{"role": "assistant", "content": "I retract my previous claim."}]},
        "AGENT_TRAJECTORY", TRAJECTORY)
    report = _put(tmp_path, "report.json", {INSTANCE: {"resolved": evaluator}},
                  "EVALUATOR_REPORT", REPORT)
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": INSTANCE,
        "claim_attribution_contract": CONTRACT, "evidence": [first, second, report]})

    expected_state = "ACTIVE" if evaluator else "ACTIVE_CONTRADICTED"
    assert [claim["claim_state"] for claim in result["AGENT_STATEMENT"]] == [expected_state]
    event = result["CLAIM_RETRACTIONS"][0]
    assert event["target_status"] == "UNKNOWN_NO_PRIOR_COMPATIBLE_ACTIVE_CLAIM"
    assert event["target_claim_id"] is None
    assert not any(row.get("target_status") == "LINKED"
                   for row in result["CLAIM_RETRACTIONS"])
    assert result["AUDIT_VERDICT"] == expected


@pytest.mark.parametrize("evaluator,expected", [(False, "SUPPORTED"), (True, "CONTRADICTED")])
def test_b12_blank_line_closes_markdown_quote_and_preserves_own_negative(
        tmp_path: Path, evaluator: bool, expected: str) -> None:
    text = "> I resolved the task.\n\nI did not resolve the task."
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)

    assert len(result["AGENT_STATEMENT"]) == 1
    claim = result["AGENT_STATEMENT"][0]
    assert claim["asserted_value"] is False
    assert claim["match_span"] == [24, 50]
    assert claim["byte_span"] == [24, 50]
    assert text[24:50] == "I did not resolve the task"
    quoted = next(row for row in result["CLAIM_REJECTIONS"]
                  if row.get("matched_text") == "I resolved the task")
    assert quoted["attribution_status"] == "QUOTED"
    assert "MARKDOWN_QUOTE" in quoted["reason_codes"]
    assert result["AUDIT_VERDICT"] == expected


def test_b13_unicode_prefix_remains_disclosed_scope_mismatch_with_correct_offsets(tmp_path: Path) -> None:
    text = (chr(0x1f9ea) + " café e" + chr(0x301) + " — I did not resolve the task.")
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], True)

    assert result["AGENT_STATEMENT"] == []
    rejected = next(row for row in result["CLAIM_REJECTIONS"]
                    if row.get("matched_text") == "I did not resolve the task")
    assert "EMBEDDED_CLAIM_CONTEXT" in rejected["reason_codes"]
    assert rejected["match_span"] == [12, 38]
    assert rejected["byte_span"] == [19, 45]


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
