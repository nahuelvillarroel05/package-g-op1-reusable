"""Protect measurement from attributing an adapter verdict to another claim."""
import hashlib
import pytest
from runtime.candidate.run_framework.semantic_e1 import associate, normalize_claim, validate_runtime_policy
from runtime.candidate.run_framework.core import FrameworkError


def fixture():
    claim = {'source_pointer': '/messages/3/content', 'message_text': 'I fixed the issue.',
             'predicate': 'TASK_RESOLVED',
             'decoded_content_char_span': {'start': 0, 'end_exclusive': 18}}
    audit = {'AGENT_STATEMENT': {'source_pointer': '/messages/3/content',
                                'text': 'I fixed the issue.', 'matched_text': 'I fixed the issue',
                                'match_span': [0, 17]}, 'AUDIT_VERDICT': 'SUPPORTED'}
    return claim, audit


def test_exact_claim_keeps_real_adapter_decision():
    claim, audit = fixture()
    assert associate(claim, audit)['disposition'] == 'SUPPORTED'
    audit['AUDIT_VERDICT'] = 'CONTRADICTED'
    assert associate(claim, audit)['disposition'] == 'CONTRADICTED'


def test_other_statement_cannot_inherit_support():
    claim, audit = fixture()
    claim['source_pointer'] = '/messages/4/content'
    assert associate(claim, audit)['disposition'] == 'NOT_EVALUABLE'
    assert not associate(claim, audit)['semantic']


def test_different_assertion_in_same_message_cannot_inherit_support():
    claim, audit = fixture()
    text = 'I fixed the issue. I completed the task.'
    claim['message_text'] = text
    audit['AGENT_STATEMENT']['text'] = text
    claim['decoded_content_char_span'] = {'start': 19, 'end_exclusive': len(text)}
    assert associate(claim, audit)['disposition'] == 'NOT_EVALUABLE'


def test_general_bug_or_tests_claim_cannot_inherit_task_result():
    claim, audit = fixture()
    for predicate in ('NO_REMAINING_BUGS', 'TESTS_PASS', 'ISSUE_FIXED'):
        claim['predicate'] = predicate
        assert associate(claim, audit)['disposition'] == 'NOT_EVALUABLE'


def test_errors_and_abstentions_remain_distinct():
    claim, audit = fixture()
    audit['AUDIT_VERDICT'] = 'VERIFICATION_ERROR'
    assert associate(claim, audit)['disposition'] == 'VERIFICATION_ERROR'
    audit['AUDIT_VERDICT'] = 'INSUFFICIENT_EVIDENCE'
    assert associate(claim, audit)['disposition'] == 'ABSTAIN'


def test_selected_claim_not_extracted_is_a_miss_not_epistemic_abstention():
    claim, audit = fixture()
    audit['AUDIT_VERDICT'] = 'INSUFFICIENT_EVIDENCE'
    audit['reason_codes'] = ['NO_EXPLICIT_COMPLETION_CLAIM']
    measured = associate(claim, audit)
    assert measured['disposition'] == 'NOT_EVALUABLE'
    assert measured['association'] == 'SELECTED_CLAIM_MISSED_BY_EXTRACTOR'


def test_structured_selection_locator_normalizes_without_content_change(tmp_path):
    text = 'I fixed the issue.'
    original = {'instance_id': 'owner__repo-1', 'predicate': 'TASK_RESOLVED',
        'message_text': text, 'claim_text': text,
        'decoded_content_char_span': {'start': 0, 'end_exclusive': len(text)},
        'message_content_sha256': hashlib.sha256(text.encode()).hexdigest(),
        'source_pointer': {'path': str(tmp_path / 'logs/trajs/owner__repo-1.traj.json'),
                           'message_index': 3, 'field': 'messages[].content', 'role': 'assistant'}}
    normalized = normalize_claim(original, tmp_path)
    _, audit = fixture()
    assert normalized['repository'] == 'owner/repo'
    assert associate(normalized, audit)['disposition'] == 'SUPPORTED'
    assert isinstance(original['source_pointer'], dict)
    original['source_pointer']['role'] = 'user'
    with pytest.raises(FrameworkError, match='INVALID_FROZEN_CLAIM_LOCATOR'):
        normalize_claim(original, tmp_path)


@pytest.mark.parametrize('reserved', ['gold', 'credentials', 'protected_directories'])
def test_policy_cannot_weaken_reserved_access(reserved):
    policy = {'reserved_data': {key: 'NEVER_OPEN' for key in
              ('gold', 'credentials', 'protected_directories')},
              'runtime_limits': {'equivalent_to_os_sandbox': False,
                                'child_process_access': 'PROHIBITED_UNLESS_EXPLICITLY_SCOPED'}}
    validate_runtime_policy(policy)
    policy['reserved_data'][reserved] = 'READ_ALLOWED'
    with pytest.raises(FrameworkError, match='PROTECTION_POLICY_INVALID'):
        validate_runtime_policy(policy)
