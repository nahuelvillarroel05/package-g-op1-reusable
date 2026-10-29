"""Prospective campaign naming/review gates; all inputs synthetic development."""
import hashlib
import json
import pytest
from runtime.candidate.swebench_claim_audit.campaign import run_campaign, POST_SONNET_CAMPAIGN, _alive, _acquire_campaign_writer_lock, _release_campaign_writer_lock
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
        model='gpt-6-astra',audit_sha256='a'*64,
        invocation_audit=dict(declared_model='gpt-6-astra',observed_model='gpt-6-astra',
            evidence_sha256='b'*64,metadata_evidence='metadata-only runtime evidence',
            identity_attestation_status='NOT_CRYPTOGRAPHICALLY_AUTHENTICATED'))
    with pytest.raises(AuditError,match='Astra approval'):
        run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0)

def test_synthetic_prospective_campaign_reports_own_id_and_recovers(tmp_path):
    data=tmp_path/'data'; data.mkdir(); p=plan(data)
    p['independent_review']=dict(decision='PASS_WITH_EXACT_SCOPE',candidate_commit='SYNTHETIC',
        model='gpt-6-astra',audit_sha256='a'*64,
        invocation_audit=dict(declared_model='gpt-6-astra',observed_model='gpt-6-astra',
            evidence_sha256='b'*64,metadata_evidence='metadata-only runtime evidence',
            identity_attestation_status='NOT_CRYPTOGRAPHICALLY_AUTHENTICATED'))
    first=run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0)
    replay=run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0,resume=True)
    assert first['campaign_id']==POST_SONNET_CAMPAIGN
    assert first['executed']==1
    assert first['review_invocation_assessment']=='CALLER_SUPPLIED_METADATA_AUDIT_ONLY'
    assert first['review_identity_authentication']=='NOT_CRYPTOGRAPHICALLY_AUTHENTICATED'
    assert first['review_metadata_verification']=='NOT_INDEPENDENTLY_VERIFIED'
    assert replay['recovered']==1 and replay['executed']==0

def test_self_declared_model_without_invocation_audit_is_rejected(tmp_path):
    data=tmp_path/'data'; data.mkdir(); p=plan(data)
    p['independent_review']=dict(decision='PASS_WITH_EXACT_SCOPE',candidate_commit='SYNTHETIC',
        model='gpt-6-astra',audit_sha256='a'*64)
    with pytest.raises(AuditError,match='metadata-only invocation audit'):
        run_campaign(data,p,tmp_path/'out',development=True,min_free_bytes=0)

@pytest.mark.parametrize('pid',[True,False,0,-1,0x100000000,'4',None])
def test_windows_pid_validation_precedes_platform_probe(pid):
    with pytest.raises(ValueError,match='DWORD range'):
        _alive(pid)

def test_empty_interrupted_writer_lock_fails_closed_and_is_preserved(tmp_path):
    lock=tmp_path/'writer.json'; lock.touch()
    with pytest.raises(AuditError) as error:
        _acquire_campaign_writer_lock(lock,resume=True)
    assert error.value.code=='CAMPAIGN_WRITER_LOCK_EMPTY'
    assert lock.read_bytes()==b''

def test_malformed_writer_pid_fails_as_structured_lock_error(tmp_path):
    lock=tmp_path/'writer.json'; lock.write_text('{"pid":4294967296}')
    with pytest.raises(AuditError) as error:
        _acquire_campaign_writer_lock(lock,resume=True)
    assert error.value.code=='CAMPAIGN_WRITER_LOCK_INVALID'
    assert json.loads(lock.read_text())=={'pid':4294967296}

def test_writer_lock_is_retained_with_released_owner_for_resume(tmp_path):
    lock=tmp_path/'writer.json'
    stream=_acquire_campaign_writer_lock(lock,resume=False)
    _release_campaign_writer_lock(stream)
    record=json.loads(lock.read_text())
    assert record['state']=='RELEASED'
    resumed=_acquire_campaign_writer_lock(lock,resume=True)
    _release_campaign_writer_lock(resumed)

def test_writer_lock_excludes_a_concurrent_process(tmp_path):
    import subprocess, sys
    lock=tmp_path/'writer.json'
    stream=_acquire_campaign_writer_lock(lock,resume=False)
    code=("from pathlib import Path; from runtime.candidate.swebench_claim_audit.campaign "
          "import _acquire_campaign_writer_lock; "
          f"_acquire_campaign_writer_lock(Path({str(lock)!r}), resume=True)")
    try:
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True)
        assert result.returncode != 0
        assert 'CAMPAIGN_WRITER_PRESENT' in result.stderr
    finally:
        _release_campaign_writer_lock(stream)

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
