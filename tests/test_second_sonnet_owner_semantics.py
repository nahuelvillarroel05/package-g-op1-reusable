"""Owner examples: extraction, attribution and logical verdict checked separately."""
import hashlib
import json

import pytest

from runtime.candidate.swebench_claim_audit.generalized import audit_evidence, audit_file

INSTANCE = 'public__owner-1'


def put(root, name, value, role, parser):
    raw = json.dumps(value, ensure_ascii=False).encode('utf-8')
    (root / name).write_bytes(raw)
    return dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                role=role, parser_id=parser)


@pytest.mark.parametrize('content,polarity,verdict', [
    ('I doubt I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('I deny that I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('Nobody said I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('Suppose I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('There is no evidence that I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('I have not resolved the task.', False, 'CONTRADICTED'),
    ('I resolved the task.', True, 'SUPPORTED'),
    ('I have successfully resolved the task.', True, 'SUPPORTED'),
    ('Actually, I resolved the task. Ω', True, 'SUPPORTED'),
    ('If the tests pass, I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('Did I resolve the task?', None, 'INSUFFICIENT_EVIDENCE'),
    ('The user said I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('> I resolved the task.', None, 'INSUFFICIENT_EVIDENCE'),
    ('````text\nI resolved the task.\n````', None, 'INSUFFICIENT_EVIDENCE'),
    ('“I resolved the task.”', None, 'INSUFFICIENT_EVIDENCE'),
])
def test_owner_examples_layers(tmp_path, content, polarity, verdict):
    trajectory = put(tmp_path, 'trajectory.json', {
        'instance_id': INSTANCE, 'messages': [{'role': 'assistant', 'content': content}],
    }, 'AGENT_TRAJECTORY', 'pgop1.swebench.trajectory.miniswe_json.v1')
    report = put(tmp_path, 'report.json', {INSTANCE: {'resolved': True}},
                 'EVALUATOR_REPORT', 'pgop1.swebench.evaluator_report.resolved_map_json.v1')
    # Extraction checks original source identity, predicate, polarity and offsets.
    parsed = audit_file(tmp_path, {**trajectory, 'run_id': 'owner-cases', 'instance_id': INSTANCE})
    assert parsed['status'] == 'SUPPORTED'  # Parser-format support, separate from logical verdict.
    observations = [o for o in parsed['observations'] if o['kind'] == 'agent_statement']
    assert len(observations) == (0 if polarity is None else 1)
    for o in observations:
        claim = o['value']
        assert claim['predicate'] == 'TASK_RESOLVED'
        assert claim['asserted_value'] is polarity
        start, end = claim['match_span']
        assert content[start:end] == claim['matched_text']
        assert content.encode()[claim['byte_span'][0]:claim['byte_span'][1]].decode() == claim['matched_text']
        # Attribution is a source-declared role, with no authenticated identity.
        assert o['source_ref']['sha256'] == trajectory['sha256']
        assert o['source_ref']['pointer'] == '/messages/0/content'
        assert claim['attribution'] == 'ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT'
        assert claim['speaker_identity_status'] == 'UNKNOWN'
        assert claim['authentication_status'] == 'UNAUTHENTICATED'
    result = audit_evidence(tmp_path, {'run_id': 'owner-cases', 'instance_id': INSTANCE,
                                      'evidence': [trajectory, report]})
    assert len(result['AGENT_STATEMENT']) == len(observations)
    assert result['AUDIT_VERDICT'] == verdict
    assert result['verification_qualifiers']['logical_verdict'] == verdict
    if polarity is None:
        assert 'NO_ATTRIBUTABLE_CLAIM' in result['reason_codes']
    else:
        assert result['AGENT_STATEMENT'][0]['AUDIT_VERDICT'] == verdict


def test_structured_content_has_unknown_attribution_and_no_logical_claim(tmp_path):
    trajectory = put(tmp_path, 'structured.json', {'instance_id': INSTANCE, 'messages': [
        {'role': 'assistant', 'content': [{'text': 'I resolved the task.'}]},
    ]}, 'AGENT_TRAJECTORY', 'pgop1.swebench.trajectory.miniswe_json.v1')
    result = audit_evidence(tmp_path, {'run_id': 'structured-owner', 'instance_id': INSTANCE,
                                      'evidence': [trajectory]})
    assert result['AGENT_STATEMENT'] == []
    assert result['EXCLUDED_CONTENT'][0]['attribution_status'] == 'UNKNOWN'
    assert result['EXCLUDED_CONTENT'][0]['source_ref']['pointer'] == '/messages/0/content'
    assert result['AUDIT_VERDICT'] == 'INSUFFICIENT_EVIDENCE'
