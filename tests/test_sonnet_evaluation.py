"""Prospective metrics and canonical identity regressions; synthetic labels only."""
import copy
import pytest
from runtime.candidate.swebench_claim_audit.predicate_evidence import (
    evaluate_reference_cases, evaluate_reference_cases_v2, ReferenceError,
)

def reference(i, polarity=True):
    return dict(reference_id=str(i), run_id='probe', instance_id='case-1', scope='task',
        timestamp='2026-10-28T12:00:00Z', source_sha256='a'*64, source_bytes=64,
        message_id='m-'+str(i), span_start=0, span_end=10, predicate='TASK_RESOLVED',
        polarity=polarity, adjudication='DECIDED', evidence_commitment='b'*64,
        rationale='Synthetic development reference.', span_unit='UTF8_BYTES_SOURCE_RELATIVE')

def test_false_abstentions_are_not_perfect_false_detection():
    refs=[reference(i,i<10) for i in range(20)]
    preds=[dict(r,verdict='SUPPORTED' if r['polarity'] else 'INSUFFICIENT_EVIDENCE') for r in refs]
    assert evaluate_reference_cases(preds,refs)['metrics']['decided_accuracy']==1
    result=evaluate_reference_cases_v2(preds,refs)
    assert result['metrics']['false_claim_detection']==dict(numerator=0,denominator=10,value=0)
    assert result['metrics']['true_claim_detection']['value']==1
    assert result['metrics']['decision_coverage']['value']==0.5
    assert result['counts']['negative_abstentions']==10

def test_canonical_equivalent_timestamp_preserves_original_and_v1():
    ref=reference(1)
    pred=dict(ref,verdict='SUPPORTED',timestamp='2026-10-28T09:00:00-03:00')
    original=copy.deepcopy((ref,pred))
    with pytest.raises(ReferenceError,match='IDENTITY_MISMATCH'):
        evaluate_reference_cases([pred],[ref])
    result=evaluate_reference_cases_v2([pred],[ref])
    assert result['counts']['TP']==1
    assert (ref,pred)==original
    assert result['normalized_reference_identities'][0]['original_timestamp'].endswith('Z')

@pytest.mark.parametrize('field,value', [('span_start',1),('source_sha256','c'*64),
    ('message_id','other'),('instance_id','other'),('timestamp','2026-10-28T12:00:01Z')])
def test_v2_does_not_fuzz_identity(field,value):
    ref=reference(1)
    pred=dict(ref,verdict='SUPPORTED',**{field:value})
    with pytest.raises(ReferenceError,match='IDENTITY_MISMATCH'):
        evaluate_reference_cases_v2([pred],[ref])

def test_unknown_labels_and_missing_span_units_remain_unqualified():
    ref=reference(1,None)
    ref['adjudication']='UNKNOWN'
    result=evaluate_reference_cases_v2([], [ref])
    assert result['status']=='NOT_COMPUTABLE'
    assert all(m['value'] is None for m in result['metrics'].values())
    ref.pop('span_unit')
    with pytest.raises(ReferenceError,match='SPAN_UNIT_REQUIRED'):
        evaluate_reference_cases_v2([], [ref])

def test_false_misses_errors_and_false_positives_keep_denominators():
    refs=[reference(i,False) for i in range(4)]
    preds=[dict(refs[0],verdict='SUPPORTED'), dict(refs[1],verdict='VERIFICATION_ERROR'),
           dict(refs[2],verdict='CONTRADICTED')]
    result=evaluate_reference_cases_v2(preds,refs)
    assert result['counts']['FP']==1
    assert result['counts']['missed_negative_reference_claims']==1
    assert result['counts']['negative_error_outcomes']==1
    assert result['metrics']['false_claim_detection']['value']==0.25
    assert result['metrics']['claim_extraction']['value']==0.75
