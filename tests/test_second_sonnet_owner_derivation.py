"""Exact Owner adversary: false source, forged support, removed schema marker."""
import hashlib
import json

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.generalized import audit_evidence
from runtime.candidate.swebench_claim_audit.generalized_bridge import bind_generalized_audit


@pytest.mark.parametrize('remove', ['derivation', 'both', 'neither'])
def test_false_source_forged_supported_is_never_new_audit_approved(tmp_path, remove):
    instance = 'public__derivation-1'
    descriptors = []
    for name, doc, role, parser in [
        ('trajectory.json', {'instance_id': instance, 'messages': [
            {'role': 'assistant', 'content': 'I resolved the task.'}]},
         'AGENT_TRAJECTORY', 'pgop1.swebench.trajectory.miniswe_json.v1'),
        ('evaluator.json', {instance: {'resolved': False}}, 'EVALUATOR_REPORT',
         'pgop1.swebench.evaluator_report.resolved_map_json.v1'),
    ]:
        raw = json.dumps(doc, separators=(',', ':')).encode()
        (tmp_path / name).write_bytes(raw)
        descriptors.append(dict(path=name, sha256=hashlib.sha256(raw).hexdigest(),
                                bytes=len(raw), role=role, parser_id=parser))
    result = audit_evidence(tmp_path, {'run_id': 'owner-adversarial-derivation',
        'instance_id': instance, 'evidence': descriptors})
    assert result['AUDIT_VERDICT'] == 'CONTRADICTED'
    assert result['AGENT_STATEMENT'][0]['AUDIT_VERDICT'] == 'CONTRADICTED'
    result['AUDIT_VERDICT'] = result['COMPUTED_VERDICT'] = 'SUPPORTED'
    result['verification_qualifiers']['logical_verdict'] = 'SUPPORTED'
    for claim in result['AGENT_STATEMENT']:
        claim['AUDIT_VERDICT'] = claim['COMPUTED_VERDICT'] = 'SUPPORTED'
        claim['verification_qualifiers']['logical_verdict'] = 'SUPPORTED'
    if remove != 'neither':
        result.pop('semantic_derivation_schema')
    if remove == 'both':
        result.pop('audit_contract_version')
    with pytest.raises(AuditError) as refused:
        bind_generalized_audit(result, tmp_path, tmp_path / 'context')
    if remove == 'neither':
        assert refused.value.code == 'BRIDGE_SEMANTIC_DERIVATION_MISMATCH'
    else:
        assert refused.value.code == 'BRIDGE_AUDIT_CONTRACT_INVALID'
