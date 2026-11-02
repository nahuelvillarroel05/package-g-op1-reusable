"""Prospective regressions from independently rejected C003; expectations retained."""
import pytest

from test_a010_attribution_v2 import _audit
from runtime.candidate.swebench_claim_audit.generalized_bridge import bind_generalized_audit, recover_generalized_audit


@pytest.mark.parametrize("cross_message", [False, True])
@pytest.mark.parametrize("observed,expected", [(True, "SUPPORTED"), (False, "CONTRADICTED")])
def test_affirmative_wait_correction_remains_decisive(tmp_path, cross_message, observed, expected):
    texts = (["I did not resolve the task.", "Wait, I did resolve it."] if cross_message else
             ["I did not resolve the task. Wait, I did resolve it."])
    result = _audit(tmp_path, [{"role": "assistant", "content": text} for text in texts], observed)
    assert result["AUDIT_VERDICT"] == expected
    active = [row for row in result["AGENT_STATEMENT"] if row["claim_state"] in {"ACTIVE", "ACTIVE_CONTRADICTED"}]
    assert len(active) == 1 and active[0]["asserted_value"] is True


@pytest.mark.parametrize("cue", ["I retract that?", "I take that back?", "That is false?", "I was wrong?"])
@pytest.mark.parametrize("cross_message", [False, True])
@pytest.mark.parametrize("observed,expected", [(True, "SUPPORTED"), (False, "CONTRADICTED")])
def test_question_does_not_perform_retraction(tmp_path, cue, cross_message, observed, expected):
    texts = (["I resolved the task.", cue] if cross_message else ["I resolved the task. " + cue])
    result = _audit(tmp_path, [{"role": "assistant", "content": text} for text in texts], observed)
    assert result["AUDIT_VERDICT"] == expected
    assert not result["CLAIM_RETRACTIONS"]
    assert result["AGENT_STATEMENT"][0]["asserted_value"] is True


@pytest.mark.parametrize("cross_message", [False, True])
@pytest.mark.parametrize("observed", [True, False])
def test_competing_resolution_subjects_do_not_bind_it_to_task(tmp_path, cross_message, observed):
    texts = (["I resolved the task. I have fixed the issue.", "Actually, I didn't resolve it."] if cross_message else
             ["I resolved the task. I have fixed the issue. Actually, I didn't resolve it."])
    result = _audit(tmp_path, [{"role": "assistant", "content": text} for text in texts], observed)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    rows = [row for row in result["CLAIM_REJECTIONS"] if "UNRESOLVED_ANAPHORA_TARGET" in row["reason_codes"]]
    assert rows and rows[0]["retraction_status"] == "RETRACTION_UNRESOLVED"
    assert {row["predicate"] for row in rows[0]["target_claim_alternatives"]} == {"TASK_RESOLVED", "ISSUE_RESOLVED"}
    assert all(row["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE" for row in result["AGENT_STATEMENT"]
               if row["predicate"] == "TASK_RESOLVED")


@pytest.mark.parametrize("cue", ["I retract that if the tests fail.", "I was wrong about the other issue."])
def test_qualified_cue_does_not_withdraw_unrelated_clear_claim(tmp_path, cue):
    result = _audit(tmp_path, [{"role": "assistant", "content": "I resolved the task. " + cue}], True)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"


def test_actor_unscoped_rejection_has_explicit_status(tmp_path):
    result = _audit(tmp_path, [{"role": "assistant", "speaker_id": "other", "content": "I resolved the task."}], True)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["CLAIM_REJECTIONS"][0]["semantic_status"] == "UNATTRIBUTABLE_CONTENT"


@pytest.mark.parametrize("observed,expected", [(True, "SUPPORTED"), (False, "CONTRADICTED")])
def test_unresolved_single_target_event_preserves_unanimous_comparison(tmp_path, observed, expected):
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I was wrong."},
    ], observed)
    assert result["CLAIM_RETRACTIONS"][0]["target_status"] == "RETRACTION_UNRESOLVED"
    assert result["AGENT_STATEMENT"][0]["AUDIT_VERDICT"] == expected
    assert result["AGENT_STATEMENT"][1]["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AUDIT_VERDICT"] == expected


@pytest.mark.parametrize("observed", [True, False])
def test_unresolved_retraction_must_compare_retained_and_withdrawn_alternatives(tmp_path, observed):
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "I was wrong."},
    ], observed)
    assert result["CLAIM_RETRACTIONS"][0]["target_status"] == "RETRACTION_UNRESOLVED"
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("texts", [
    ["The task is unresolved."],
    ["Final outcome: The task is unresolved."],
    ["I resolved the task.", "I did not resolve the task.", "I was wrong."],
    ["I resolved the task. I have fixed the issue. Actually, I didn't resolve it."],
])
def test_new_semantic_records_survive_real_fresh_process_recovery(tmp_path, texts):
    data = tmp_path / "data"
    audit = _audit(data, [{"role": "assistant", "content": text} for text in texts], True)
    bound = bind_generalized_audit(audit, data, tmp_path / "context")
    assert bound["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert bound["context_engine"]["fresh_process_readback"]["status"] == "PASS"
    for p in data.iterdir():
        p.unlink()
    recovered = recover_generalized_audit(tmp_path / "context")
    assert recovered["status"] == "PASS"
    assert recovered["derivation"]["status"] == "DERIVATION_VERIFIED"


@pytest.mark.parametrize("form", ["We resolved the task.", "The task has been resolved.",
    "I **resolved** the task.", "The task is resolved."])
@pytest.mark.parametrize("observed", [True, False])
def test_omitted_possible_positive_must_not_make_negative_definitive(tmp_path, form, observed):
    result = _audit(tmp_path, [{"role": "assistant", "content": "I did not resolve the task."},
                             {"role": "assistant", "content": form}], observed)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("form", ["We resolved the task.", "The task has been resolved.",
    "I **resolved** the task.", "The task is resolved."])
@pytest.mark.parametrize("observed,expected", [(True, "SUPPORTED"), (False, "CONTRADICTED")])
def test_possible_same_polarity_form_preserves_unanimous_result(tmp_path, form, observed, expected):
    result = _audit(tmp_path, [{"role": "assistant", "content": "I resolved the task."},
                             {"role": "assistant", "content": form}], observed)
    assert result["AUDIT_VERDICT"] == expected


@pytest.mark.parametrize("form", ["We resolved the task?", "The reviewer said: 'We resolved the task.'",
    "```text\nWe resolved the task.\n```", "If this were true, We resolved the task."])
def test_nonassertive_unsupported_content_does_not_disturb_clear_claim(tmp_path, form):
    result = _audit(tmp_path, [{"role": "assistant", "content": "I did not resolve the task."},
                             {"role": "assistant", "content": form}], False)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"


@pytest.mark.parametrize("reversed_order", [False, True])
@pytest.mark.parametrize("observed", [True, False])
def test_same_message_generic_cue_keeps_retained_interpretation(tmp_path, reversed_order, observed):
    texts = ["I resolved the task.", "I did not resolve the task."]
    if reversed_order:
        texts.reverse()
    result = _audit(tmp_path, [{"role": "assistant", "content": " ".join(texts) + " I was wrong."}], observed)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    uncertain = [row for row in result["CLAIM_REJECTIONS"] if row.get("retraction_cue")]
    assert uncertain and uncertain[0]["target_claim_alternatives"]
    assert len(result["AGENT_STATEMENT"]) == 2


@pytest.mark.parametrize("cue", ["I retract that: it was premature.", "I retract that, it was premature."])
@pytest.mark.parametrize("cross_message", [False, True])
@pytest.mark.parametrize("observed", [True, False])
def test_qualified_retraction_is_not_silently_ignored(tmp_path, cue, cross_message, observed):
    texts = (["I resolved the task.", cue] if cross_message else ["I resolved the task. " + cue])
    result = _audit(tmp_path, [{"role": "assistant", "content": text} for text in texts], observed)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("observed", [True, False])
def test_temporal_marker_does_not_leak_from_previous_sentence(tmp_path, observed):
    text = "I did not resolve the task. I am still examining logs. The task is resolved."
    result = _audit(tmp_path, [{"role": "assistant", "content": text}], observed)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    state = next(row for row in result["CLAIM_REJECTIONS"] if row["matched_text"] == "The task is resolved")
    assert state["state_status"] == "TEMPORAL_SCOPE_UNKNOWN"


@pytest.mark.parametrize("state,prior", [
    ("The task is currently unresolved.", "I resolved the task."),
    ("The task is currently resolved.", "I did not resolve the task."),
])
@pytest.mark.parametrize("observed", [True, False])
def test_current_state_is_not_an_accredited_final_outcome(tmp_path, state, prior, observed):
    result = _audit(tmp_path, [{"role": "assistant", "content": prior + " " + state}], observed)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_explicit_task_correction_does_not_retract_nearer_issue(tmp_path):
    result = _audit(tmp_path, [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "I have fixed the issue."},
        {"role": "assistant", "content": "Actually, I did not resolve the task."},
    ], True)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    issue = next(row for row in result["AGENT_STATEMENT"] if row["predicate"] == "ISSUE_RESOLVED")
    assert not issue.get("retracted_by")
    assert issue["claim_state"] == "ACTIVE_NONCOMPARABLE"


@pytest.mark.parametrize("cross_message", [False, True])
@pytest.mark.parametrize("final_value", [False, True])
@pytest.mark.parametrize("observed", [False, True])
def test_own_clause_still_state_does_not_conflict_with_explicit_final(
        tmp_path, cross_message, final_value, observed):
    previous = "The task is still " + ("unresolved." if final_value else "resolved.")
    final = "Final outcome: The task is " + ("resolved." if final_value else "unresolved.")
    texts = [previous, final] if cross_message else [previous + " " + final]
    result = _audit(tmp_path, [{"role": "assistant", "content": text} for text in texts], observed)
    assert result["AUDIT_VERDICT"] == ("SUPPORTED" if final_value == observed else "CONTRADICTED")
    intermediate = next(row for row in result["CLAIM_REJECTIONS"] if row["matched_text"].startswith("The task is still"))
    assert intermediate["state_status"] == "INTERMEDIATE_STATE_ASSERTION"
