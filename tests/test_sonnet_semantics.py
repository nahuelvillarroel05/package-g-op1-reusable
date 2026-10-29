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


def test_conditional_claims_are_rejected_across_conjunctions(tmp_path: Path) -> None:
    conditional = (
        "If the deployment succeeds and I resolved the task, we can ship.",
        "Unless the tests fail and I resolved the task, we should wait.",
        "Assuming the tests pass and I resolved the task, we can ship.",
        "If the deployment succeeds or I resolved the task, we can ship.",
    )
    for content in conditional:
        for evaluator_value in (True, False):
            trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": content}])
            result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path, evaluator_value)))
            assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
            assert result["AGENT_STATEMENT"] == []
            rejection = next(item for item in result["CLAIM_REJECTIONS"]
                             if "CONDITIONAL_CLAUSE" in item["reason_codes"])
            assert content[rejection["match_span"][0]:rejection["match_span"][1]] == "I resolved the task"
            assert rejection["byte_span"] == rejection["match_span"]


def test_conditionals_end_before_independent_claims_and_quoted_if_is_not_a_condition(tmp_path: Path) -> None:
    safe = (
        "If the deployment succeeds, we can ship; I resolved the task.",
        "If the deployment succeeds, we can ship. I resolved the task.",
        "The word 'if' appears, and I resolved the task.",
        "The word 'if' appears before I resolved the task.",
        "Perhaps the deployment is delayed, but I resolved the task.",
    )
    for content in safe:
        result = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            _report(tmp_path, True),
        ))
        assert result["COMPUTED_VERDICT"] == "SUPPORTED"
        assert len(result["AGENT_STATEMENT"]) == 1
        assert result["AGENT_STATEMENT"][0]["predicate"] == "TASK_RESOLVED"
        assert "CONDITIONAL_CLAUSE" not in result["AGENT_STATEMENT"][0]["reason_codes"]


def test_inline_and_trailing_conditionals_are_rejected_for_each_supported_predicate(tmp_path: Path) -> None:
    inline_claims = (
        "I resolved the task", "I did not resolve the task",
        "I have completed the task", "the task remains incomplete",
        "I resolved the issue", "the issue remains unresolved",
    )
    for marker in ("if", "unless", "assuming"):
        for claim in inline_claims:
            content = f"We can proceed {marker} deployment succeeds and {claim}."
            for evaluator_value in (True, False):
                result = audit_evidence(tmp_path, _request(
                    _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
                    _report(tmp_path, evaluator_value),
                ))
                assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
                assert result["AGENT_STATEMENT"] == []
                assert any("CONDITIONAL_CLAUSE" in item["reason_codes"]
                           for item in result["CLAIM_REJECTIONS"])

    trailing_claims = (
        "I resolved the task", "I have completed the task", "I resolved the issue",
    )
    for marker in ("if", "unless", "assuming"):
        for claim in trailing_claims:
            content = f"{claim}, {marker} deployment succeeds."
            for evaluator_value in (True, False):
                result = audit_evidence(tmp_path, _request(
                    _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
                    _report(tmp_path, evaluator_value),
                ))
                assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
                assert result["AGENT_STATEMENT"] == []
                assert any("CONDITIONAL_CLAUSE" in item["reason_codes"]
                           for item in result["CLAIM_REJECTIONS"])


def test_conditional_scope_ignores_quoted_punctuation_and_finds_noninitial_operators(tmp_path: Path) -> None:
    conditional = (
        'If the log contains "version 1.0" and I resolved the task, we can ship.',
        "Only if the deployment succeeds and I resolved the task, we can ship.",
        "For this check, assuming deployment succeeds and I resolved the task, we can ship.",
    )
    for content in conditional:
        result = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            _report(tmp_path, True),
        ))
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["AGENT_STATEMENT"] == []
        assert any("CONDITIONAL_CLAUSE" in item["reason_codes"]
                   for item in result["CLAIM_REJECTIONS"])

    for content in (
        'The literal "if version 1.0" appears, but I resolved the task.',
        'The configuration uses "if" and I resolved the task.',
        "If the deployment succeeds, we can ship; I resolved the task.",
        "If the deployment succeeds. I resolved the task.",
        "Perhaps deployment is delayed, but I resolved the task.",
        "I resolved the task, but if deployment succeeds we can ship.",
    ):
        result = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            _report(tmp_path, True),
        ))
        assert result["COMPUTED_VERDICT"] == "SUPPORTED"
        assert len(result["AGENT_STATEMENT"]) == 1
        assert "CONDITIONAL_CLAUSE" not in result["AGENT_STATEMENT"][0]["reason_codes"]


def test_conditional_boundaries_keep_absolute_offsets_after_multiple_buts(tmp_path: Path) -> None:
    content = ("Deployment is ready, but tests fail, but if deployment succeeds "
               "and I resolved the task, we can ship.")
    result = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
        _report(tmp_path, True),
    ))
    assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] == []
    rejection = next(item for item in result["CLAIM_REJECTIONS"]
                     if item["predicate"] == "TASK_RESOLVED")
    assert "CONDITIONAL_CLAUSE" in rejection["reason_codes"]
    assert content[rejection["match_span"][0]:rejection["match_span"][1]] == "I resolved the task"


def test_quoted_question_punctuation_does_not_make_an_assertion_interrogative(tmp_path: Path) -> None:
    result = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content":
                                'I resolved the task, and the output is "why?".'}]),
        _report(tmp_path, True),
    ))
    assert result["COMPUTED_VERDICT"] == "SUPPORTED"
    assert len(result["AGENT_STATEMENT"]) == 1
    assert "INTERROGATIVE_CLAUSE" not in result["AGENT_STATEMENT"][0]["reason_codes"]

    for content in (
        "I resolved the task?",
        'I resolved the task, and the output is "why?"?',
    ):
        result = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            _report(tmp_path, True),
        ))
        assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
        assert result["AGENT_STATEMENT"] == []
        assert any("INTERROGATIVE_CLAUSE" in item["reason_codes"]
                   for item in result["CLAIM_REJECTIONS"])

    outer_conditional = 'If the log prints "ok?" and I resolved the task, we ship.'
    result = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content": outer_conditional}]),
        _report(tmp_path, True),
    ))
    assert result["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] == []
    assert any("CONDITIONAL_CLAUSE" in item["reason_codes"]
               for item in result["CLAIM_REJECTIONS"])


def test_report_and_denial_prefixes_stop_at_semicolon_or_contrast_but(tmp_path: Path) -> None:
    positive = (
        "The report claimed deployment was ready; I resolved the task.",
        "I did not claim deployment was ready; I resolved the task.",
        "The report claimed deployment was ready, but I resolved the task.",
        "I did not claim deployment was ready, but I resolved the task.",
    )
    for content in positive:
        for evaluator_value, expected_verdict in ((True, "SUPPORTED"), (False, "CONTRADICTED")):
            result = audit_evidence(tmp_path, _request(
                _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
                _report(tmp_path, evaluator_value),
            ))
            assert len(result["AGENT_STATEMENT"]) == 1
            assert result["AGENT_STATEMENT"][0]["predicate"] == "TASK_RESOLVED"
            assert result["COMPUTED_VERDICT"] == expected_verdict

    reported = audit_file(tmp_path, {
        **_trajectory(tmp_path, [{"role": "assistant", "content": "The report claimed I resolved the task."}]),
        "run_id": RUN, "instance_id": INSTANCE,
    })
    denied = audit_file(tmp_path, {
        **_trajectory(tmp_path, [{"role": "assistant", "content": "I did not claim that I resolved the task."}]),
        "run_id": RUN, "instance_id": INSTANCE,
    })
    for parsed, reason in ((reported, "REPORTED_CLAIM"), (denied, "DENIED_CLAIM")):
        assert not [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert any(reason in o["value"]["reason_codes"]
                   for o in parsed["observations"] if o["kind"] == "claim_rejection")

    for content, reason in (
        ("The report claimed deployment was ready and I resolved the task.", "REPORTED_CLAIM"),
        ("I did not claim deployment was ready and I resolved the task.", "DENIED_CLAIM"),
        ("The report claimed 'I resolved the task.'", "REPORTED_CLAIM"),
    ):
        parsed = audit_file(tmp_path, {
            **_trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            "run_id": RUN, "instance_id": INSTANCE,
        })
        assert not [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert any(reason in o["value"]["reason_codes"]
                   for o in parsed["observations"] if o["kind"] == "claim_rejection")


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
    for content, predicate in (
        ("I\u2019ve resolved the task.", "TASK_RESOLVED"),
        ("I\u2019ve fixed the issue.", "ISSUE_RESOLVED"),
        ("I\u2019ve completed the task.", "TASK_COMPLETED"),
        ("I\u2019d resolved the task.", "TASK_RESOLVED"),
    ):
        trajectory = _trajectory(tmp_path, [{"role": "assistant", "content": content}])
        parsed = audit_file(tmp_path, {**trajectory, "run_id": RUN, "instance_id": INSTANCE})
        claims = [o["value"] for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert len(claims) == 1
        assert claims[0]["predicate"] == predicate


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


def test_astra_unrelated_actions_and_other_predicate_hedges_do_not_suppress_task(tmp_path: Path) -> None:
    texts = (
        "I resolved the task. Actually I did not update the documentation.",
        "Perhaps the deployment is delayed, but I resolved the task.",
        "I resolved the task, but the issue might remain unresolved.",
    )
    for content in texts:
        result = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            _report(tmp_path, True),
        ))
        assert result["COMPUTED_VERDICT"] == "SUPPORTED"
        assert result["AUDIT_VERDICT"] == "SUPPORTED"
        assert len(result["AGENT_STATEMENT"]) == 1
        assert result["AGENT_STATEMENT"][0]["predicate"] == "TASK_RESOLVED"
        assert result["AGENT_STATEMENT"][0]["asserted_value"] is True


def test_astra_same_predicate_correction_and_hedge_controls_remain_conservative(tmp_path: Path) -> None:
    corrected = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content":
                                "I resolved the task. Actually, I did not resolve the task."}]),
        _report(tmp_path, False),
    ))
    assert corrected["COMPUTED_VERDICT"] == "SUPPORTED"
    assert len(corrected["AGENT_STATEMENT"]) == 1
    assert corrected["AGENT_STATEMENT"][0]["predicate"] == "TASK_RESOLVED"
    assert corrected["AGENT_STATEMENT"][0]["asserted_value"] is False
    assert any("EXPLICIT_CORRECTION" in rejection["reason_codes"]
               for rejection in corrected["CLAIM_REJECTIONS"])

    for content in ("Perhaps I resolved the task.",
                    "I resolved the task, but the task might remain unresolved.",
                    "I resolved the task, but I may be wrong."):
        parsed = audit_file(tmp_path, {
            **_trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            "run_id": RUN, "instance_id": INSTANCE,
        })
        assert not [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert any("HEDGED_CLAUSE" in o["value"]["reason_codes"]
                   for o in parsed["observations"] if o["kind"] == "claim_rejection")


def test_qualifier_scope_tracks_task_predicate_and_ignores_other_topics(tmp_path: Path) -> None:
    positive_cases = (
        ("I resolved the task, but I might not update the documentation.", "TASK_RESOLVED", None),
        ("I resolved the task, but the claim about deployment might be false.", "TASK_RESOLVED", None),
        ("I resolved the task, but maybe the task queue remains unresolved.", "TASK_RESOLVED", None),
        ("I resolved the task, but maybe the documentation task remains incomplete.", "TASK_RESOLVED", None),
        ("I resolved the task, but maybe the issue remains unresolved.", "TASK_RESOLVED", "ISSUE_RESOLVED"),
        ("I resolved the task, but I might not have completed the task.", "TASK_RESOLVED", "TASK_COMPLETED"),
        ("I have completed the task, but I might not have resolved the task.", "TASK_COMPLETED", "TASK_RESOLVED"),
        ("I resolved the task, but the task might remain unfinished.", "TASK_RESOLVED", "TASK_COMPLETED"),
        ("I resolved the task, but perhaps the task remains unfinished.", "TASK_RESOLVED", "TASK_COMPLETED"),
        ("I have completed the task, but the task might remain unresolved.", "TASK_COMPLETED", "TASK_RESOLVED"),
        ("I resolved the task, but I might not have completed the work.", "TASK_RESOLVED", "TASK_COMPLETED"),
    )
    for content, expected_predicate, expected_rejected_predicate in positive_cases:
        parsed = audit_file(tmp_path, {
            **_trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            "run_id": RUN, "instance_id": INSTANCE,
        })
        claims = [o["value"] for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert any(claim["predicate"] == expected_predicate and claim["asserted_value"] is True
                   for claim in claims)
        if expected_rejected_predicate:
            rejected = [o["value"] for o in parsed["observations"]
                        if o["kind"] == "claim_rejection"]
            assert any(item["predicate"] == expected_rejected_predicate
                       and item["asserted_value"] is False
                       and "HEDGED_CLAUSE" in item["reason_codes"] for item in rejected)

    uncertain_texts = (
        "I resolved the task, but maybe the task remains unresolved.",
        "I resolved the task, but maybe the task remains still unresolved.",
        "I resolved the task, but the task may remain currently unresolved.",
        "I resolved the task, but the task might still be unresolved.",
        "I have completed the task, but maybe the task remains still unfinished.",
        "I have completed the task, but maybe the original task remains incomplete.",
        "I have completed the task, but perhaps the assigned task remains unfinished.",
        "I have completed the task, but perhaps the SWE-bench task remains unfinished.",
        "I have completed the task, but maybe the task might still be incomplete.",
        "I resolved the issue, but maybe the issue remains unresolved.",
        "I resolved the issue, but maybe the issue remains still unresolved.",
        "I resolved the task, but maybe I did not resolve it.",
        "I resolved the task, but maybe it remains unresolved.",
        "I have completed the task, but perhaps the task remains incomplete.",
        "I resolved the task, but maybe I am wrong.",
        "I resolved the task, but I might not have resolved the task.",
        "I have completed the task, but I might not have completed it.",
        "I have completed the work, but I might not have completed the work.",
        "I have completed the implementation, but I might not have completed the implementation.",
        "I have completed the requested change, but I might not have completed the requested change.",
    )
    for content in uncertain_texts:
        parsed = audit_file(tmp_path, {
            **_trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            "run_id": RUN, "instance_id": INSTANCE,
        })
        claims = [o for o in parsed["observations"] if o["kind"] == "agent_statement"]
        rejected = [o["value"] for o in parsed["observations"] if o["kind"] == "claim_rejection"]
        assert not [o for o in claims if o["value"]["asserted_value"] is True]
        assert any("HEDGED_CLAUSE" in item["reason_codes"] for item in rejected)

    preclaim = audit_file(tmp_path, {
        **_trajectory(tmp_path, [{"role": "assistant", "content": "Maybe I resolved the task."}]),
        "run_id": RUN, "instance_id": INSTANCE,
    })
    assert not [o for o in preclaim["observations"] if o["kind"] == "agent_statement"]
    assert any("HEDGED_CLAUSE" in o["value"]["reason_codes"]
               for o in preclaim["observations"] if o["kind"] == "claim_rejection")

    for content in ("The task remains unfinished.", "The task is incomplete.", "Task incomplete."):
        parsed = audit_file(tmp_path, {
            **_trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            "run_id": RUN, "instance_id": INSTANCE,
        })
        claims = [o["value"] for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert [(claim["predicate"], claim["asserted_value"]) for claim in claims] == [
            ("TASK_COMPLETED", False)]

    audited = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content":
                                "I resolved the task, but maybe the task remains unfinished."}]),
        _report(tmp_path, False),
    ))
    resolved_claim = next(c for c in audited["AGENT_STATEMENT"]
                          if c["predicate"] == "TASK_RESOLVED")
    completion_rejection = next(r for r in audited["CLAIM_REJECTIONS"]
                                if r["predicate"] == "TASK_COMPLETED")
    assert resolved_claim["asserted_value"] is True
    assert resolved_claim["AUDIT_VERDICT"] == "CONTRADICTED"
    assert "HEDGED_CLAUSE" in completion_rejection["reason_codes"]
    assert audited["COMPUTED_VERDICT"] == "CONTRADICTED"

    for evaluator_value in (True, False):
        uncompleted = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": "The task remains unfinished."}]),
            _report(tmp_path, evaluator_value),
        ))
        assert len(uncompleted["AGENT_STATEMENT"]) == 1
        assert uncompleted["AGENT_STATEMENT"][0]["predicate"] == "TASK_COMPLETED"
        assert uncompleted["AGENT_STATEMENT"][0]["asserted_value"] is False
        assert uncompleted["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"

    for content in ("The task remains unresolved.", "The task is not resolved.", "Task not resolved."):
        unresolved = audit_evidence(tmp_path, _request(
            _trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            _report(tmp_path, False),
        ))
        assert unresolved["AGENT_STATEMENT"][0]["predicate"] == "TASK_RESOLVED"
        assert unresolved["AGENT_STATEMENT"][0]["AUDIT_VERDICT"] == "SUPPORTED"

    for content, expected_predicate in (
        ("I resolved the task. Actually I did not complete the task.", "TASK_RESOLVED"),
        ("I completed the task. Actually I did not resolve the task.", "TASK_COMPLETED"),
    ):
        corrected = audit_file(tmp_path, {
            **_trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            "run_id": RUN, "instance_id": INSTANCE,
        })
        claims = [o["value"] for o in corrected["observations"] if o["kind"] == "agent_statement"]
        assert any(c["predicate"] == expected_predicate and c["asserted_value"] is True
                   for c in claims)
        assert not any("EXPLICIT_CORRECTION" in o["value"]["reason_codes"]
                       for o in corrected["observations"] if o["kind"] == "claim_rejection")

def test_task_queue_negative_actions_are_noncomparable_and_do_not_retract_task(tmp_path: Path) -> None:
    cases = (
        ("I resolved the task, but I might not have resolved the task queue.", "TASK_RESOLVED"),
        ("I resolved the task. Actually I did not resolve the task queue.", "TASK_RESOLVED"),
        ("I have completed the task, but I might not have completed the task queue.", "TASK_COMPLETED"),
        ("I have completed the task. Actually I did not complete the task queue.", "TASK_COMPLETED"),
    )
    for content, expected_predicate in cases:
        parsed = audit_file(tmp_path, {
            **_trajectory(tmp_path, [{"role": "assistant", "content": content}]),
            "run_id": RUN, "instance_id": INSTANCE,
        })
        claims = [o["value"] for o in parsed["observations"] if o["kind"] == "agent_statement"]
        assert any(c["predicate"] == expected_predicate and c["asserted_value"] is True
                   for c in claims)
        rejected = [o["value"] for o in parsed["observations"] if o["kind"] == "claim_rejection"]
        assert any(r.get("candidate_predicate") == expected_predicate
                   and r["asserted_value"] is False
                   and r["reason_codes"] == ["NONCOMPARABLE_TASK_SCOPE"] for r in rejected)
        assert not any("EXPLICIT_CORRECTION" in r["reason_codes"] for r in rejected)

    direct = audit_file(tmp_path, {
        **_trajectory(tmp_path, [{"role": "assistant", "content": "I did not resolve the task queue."}]),
        "run_id": RUN, "instance_id": INSTANCE,
    })
    assert not [o for o in direct["observations"] if o["kind"] == "agent_statement"]
    direct_rejections = [o["value"] for o in direct["observations"] if o["kind"] == "claim_rejection"]
    assert len(direct_rejections) == 1
    assert direct_rejections[0]["reason_codes"] == ["NONCOMPARABLE_TASK_SCOPE"]

    audited = audit_evidence(tmp_path, _request(
        _trajectory(tmp_path, [{"role": "assistant", "content": "I did not resolve the task queue."}]),
        _report(tmp_path, False),
    ))
    assert audited["AGENT_STATEMENT"] == []
    assert audited["COMPUTED_VERDICT"] == "INSUFFICIENT_EVIDENCE"


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
