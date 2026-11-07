"""Protect measurement from attributing an adapter verdict to another claim."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from runtime.candidate.run_framework import semantic_e1
from runtime.candidate.run_framework.semantic_e1 import (
    associate, normalize_claim, validate_runtime_policy, _stop_after_audit,
)
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


def test_integrity_failure_is_preserved_and_stops_later_dispatch():
    claim, audit = fixture()
    audit['AUDIT_VERDICT'] = 'INTEGRITY_FAILURE'
    measured = associate(claim, audit)
    assert measured['disposition'] == 'VERIFICATION_ERROR'
    assert measured['auditor_verdict'] == 'INTEGRITY_FAILURE'
    assert not measured['semantic']
    assert _stop_after_audit(audit)

    audit['AUDIT_VERDICT'] = 'VERIFICATION_ERROR'
    assert not _stop_after_audit(audit)


def test_execute_stops_after_first_integrity_failure_and_records_remaining_units(tmp_path, monkeypatch):
    data_root = tmp_path / 'data'
    claims, refs = [], []
    for index in (1, 2):
        instance = f'owner__repo-{index}'
        trajectory_path = data_root / 'logs' / 'trajs' / f'{instance}.traj.json'
        trajectory_path.parent.mkdir(parents=True, exist_ok=True)
        trajectory = {'instance_id': instance, 'messages': [
            {'role': 'assistant', 'content': 'I resolved the issue.'}]}
        raw = json.dumps(trajectory).encode()
        trajectory_path.write_bytes(raw)
        refs.append({'path': str(trajectory_path), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'bytes': len(raw)})
        claims.append({'claim_id': f'claim-{index}', 'instance_id': instance,
                       'source_pointer': '/messages/0/content', 'predicate': 'TASK_RESOLVED',
                       'message_text': 'I resolved the issue.',
                       'decoded_content_char_span': {'start': 0, 'end_exclusive': 20},
                       'original_source_locator': {'message_index': 0}})

    class Campaign:
        config = {'expected_units': ['claim-1', 'claim-2'], 'dataset_manifest_path': 'selection.json',
                  'candidate_commit': 'commit', 'candidate_tree': 'tree', 'run_id': 'run',
                  'campaign_attempt_id': 'attempt'}
        config_sha256 = 'config-hash'

        def begin_unit(self, *_args):
            pass

        def complete_unit(self, unit_id, _disposition, _payload):
            return {'receipt_sha256': 'receipt-' + unit_id}

    class Engine:
        def __init__(self, root): self.root = Path(root)
        def admit_source(self, *_args, **_kwargs): return {'source_id': 'source'}
        def ingest(self, *_args, **_kwargs): return 'manifest'

    campaign = Campaign()
    scope = {'source_references': refs, 'allowed_sources': [ref['path'] for ref in refs],
             'protected_roots': []}
    monkeypatch.setattr(semantic_e1, 'bootstrap', lambda _args: (scope, SimpleNamespace(denied_events=[]), campaign))
    monkeypatch.setattr(semantic_e1, 'Engine', Engine)
    monkeypatch.setattr(semantic_e1, 'require_read_scope', lambda *_args: None)
    original_read = semantic_e1._read
    def read(path):
        if str(path) == 'selection.json': return {'claims': claims}
        if str(path) == 'launch.json':
            return {'status': 'OWNER_AUTHORIZED', 'config_sha256': 'config-hash',
                    'scope_sha256': 'scope-hash', 'candidate_commit': 'commit', 'candidate_tree': 'tree'}
        return original_read(path)
    monkeypatch.setattr(semantic_e1, '_read', read)
    invocations = []
    def audit(_root, instance_id, **_kwargs):
        invocations.append(instance_id)
        return {'AUDIT_VERDICT': 'INTEGRITY_FAILURE', 'reason_codes': ['PATH_TRAVERSAL'],
                'AGENT_STATEMENT': None, 'schema': 'pgop1.swebench.selected-claim-audit.v3'}
    monkeypatch.setattr(semantic_e1, 'audit_instance', audit)
    output = tmp_path / 'output' / 'attempt' / 'results'
    args = SimpleNamespace(scope='scope.json', scope_sha256='scope-hash', config='config.json',
                           workspace=str(tmp_path), output=str(output), data_root=str(data_root),
                           output_root=str(tmp_path / 'output'), launch='launch.json')
    with pytest.raises(FrameworkError, match='INTEGRITY_FAILURE_STOP_NO_FURTHER_DISPATCH'):
        semantic_e1.execute(args)
    ledger = json.loads((output / 'LEDGER.json').read_text(encoding='utf-8'))
    assert invocations == ['owner__repo-1']
    assert ledger['selected_claim_count'] == 2 and ledger['attempted_claim_count'] == 1
    assert ledger['remaining_claim_ids'] == ['claim-2']
    assert ledger['execution_status'] == 'STOPPED_ON_INTEGRITY_FAILURE'
    capsule = json.loads(Path(ledger['rows'][0]['capsule_path']).read_text(encoding='utf-8'))
    assert capsule['audit']['AUDIT_VERDICT'] == 'INTEGRITY_FAILURE'
    assert capsule['disposition'] == 'VERIFICATION_ERROR'


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
