"""Prospective campaign naming/review gates; all inputs synthetic development."""
import hashlib
import pytest
from runtime.candidate.swebench_claim_audit.campaign import run_campaign, POST_SONNET_CAMPAIGN
from runtime.candidate.swebench_claim_audit.adapter import AuditError

def plan(root):
    (root/'source.txt').write_bytes(b'Unattributed synthetic log.\n')
    raw=(root/'source.txt').read_bytes()
    return dict(schema='pgop1.swebench.campaign-plan.v1',campaign_id=POST_SONNET_CAMPAIGN,
        code_commit='SYNTHETIC', sources=[dict(source_id='one',path='source.txt',
        sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),role='EXECUTION_LOG',
        parser_id='pgop1.swebench.log.text_unattributed.v1')],requests=[])

def test_post_sonnet_plan_requires_exact_review_even_in_development(tmp_path):
    data=tmp_path/'data'; data.mkdir(); p=plan(data)
    with pytest.raises(AuditError,match='Astra approval'):
        run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0)
    p['independent_review']=dict(decision='PASS_WITH_EXACT_SCOPE',candidate_commit='OTHER',
        model='gpt-6-astra',audit_sha256='a'*64)
    with pytest.raises(AuditError,match='Astra approval'):
        run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0)

def test_synthetic_prospective_campaign_reports_own_id_and_recovers(tmp_path):
    data=tmp_path/'data'; data.mkdir(); p=plan(data)
    p['independent_review']=dict(decision='PASS_WITH_EXACT_SCOPE',candidate_commit='SYNTHETIC',
        model='gpt-6-astra',audit_sha256='a'*64)
    first=run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0)
    replay=run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0,resume=True)
    assert first['campaign_id']==POST_SONNET_CAMPAIGN
    assert first['executed']==1
    assert replay['recovered']==1 and replay['executed']==0

def test_unknown_campaign_id_is_not_silently_run001(tmp_path):
    data=tmp_path/'data'; data.mkdir(); p=plan(data); p['campaign_id']='RUN_002'
    with pytest.raises(AuditError):
        run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0)

def test_interrupted_start_preserves_result_and_blocks_redispatch(tmp_path):
    data=tmp_path/'data'; data.mkdir(); p=plan(data)
    p['campaign_id']='PGOP1_RUN_001'
    out=tmp_path/'out'
    run_campaign(data,p,out,development=True,min_free_bytes=0)
    journal=out/'attempts.jsonl'
    first=journal.read_bytes().splitlines()[0]+b'\n'
    journal.write_bytes(first)
    result=next(out.glob('file-*.json'))
    original=result.read_bytes()
    with pytest.raises(AuditError) as error:
        run_campaign(data,p,out,development=True,min_free_bytes=0,resume=True)
    assert error.value.code=='CAMPAIGN_AMBIGUOUS_ATTEMPT'
    assert journal.read_bytes()==first and result.read_bytes()==original

def test_orphan_result_without_start_blocks_redispatch(tmp_path):
    data=tmp_path/'data'; data.mkdir(); p=plan(data)
    p['campaign_id']='PGOP1_RUN_001'; out=tmp_path/'out'
    run_campaign(data,p,out,development=True,min_free_bytes=0)
    (out/'file-99-uncommitted.json').write_bytes(b'{}')
    with pytest.raises(AuditError) as error:
        run_campaign(data,p,out,development=True,min_free_bytes=0,resume=True)
    assert error.value.code=='CAMPAIGN_ORPHAN_RESULT'
