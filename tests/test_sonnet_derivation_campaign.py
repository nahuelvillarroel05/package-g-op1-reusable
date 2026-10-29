"""Exercise the full-run derivation stage using one synthetic instance only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import pytest
from runtime.candidate.swebench_claim_audit.generalized import audit_evidence

def test_instance_derivation_stage_binds_and_recovers_exact_committed_audit(tmp_path):
    script=Path(__file__).resolve().parents[1]/'tools/claim-audit/post_sonnet_engineering.py'
    spec=importlib.util.spec_from_file_location('post_sonnet_engineering',script)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    data=tmp_path/'data'; data.mkdir(); out=tmp_path/'out'; (out/'campaign').mkdir(parents=True)
    iid='synthetic__case-1'; descriptors=[]
    for name,doc,role,parser in [
        ('trajectory.json',{'instance_id':iid,'messages':[{'role':'assistant','content':'I have resolved the task.'}]},
         'AGENT_TRAJECTORY','trajectory.miniswe_json.v1'),
        ('report.json',{iid:{'resolved':False}},'EVALUATOR_REPORT','evaluator_report.resolved_map_json.v1')]:
        raw=json.dumps(doc).encode(); (data/name).write_bytes(raw)
        descriptors.append(dict(path=name,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),
            role=role,parser_id='pgop1.swebench.'+parser))
    audit=audit_evidence(data,dict(run_id='synthetic',instance_id=iid,evidence=descriptors))
    assert audit['AUDIT_VERDICT']=='CONTRADICTED'
    raw=json.dumps(audit).encode(); (out/'campaign'/'audit-0-test.json').write_bytes(raw)
    event=dict(event='COMPLETE',unit='audit-0',result_path='audit-0-test.json',sha256=hashlib.sha256(raw).hexdigest())
    (out/'campaign'/'attempts.jsonl').write_text(json.dumps(event)+'\n',encoding='utf-8')
    first=module.verify_instance_derivations(data,out)
    replay=module.verify_instance_derivations(data,out)
    assert first==replay
    assert first['verified']==1 and first['failures']==0 and first['not_verified']==0
    # A valid context for A cannot verify different campaign result B just
    # because the mutable progress receipt claims B's file hash.
    changed=json.dumps({iid:{'resolved':True}}).encode()
    (data/'report.json').write_bytes(changed)
    descriptors[1].update(sha256=hashlib.sha256(changed).hexdigest(),bytes=len(changed))
    other=audit_evidence(data,dict(run_id='synthetic',instance_id=iid,evidence=descriptors))
    assert other['AUDIT_VERDICT']=='SUPPORTED'
    other_raw=json.dumps(other).encode(); (out/'campaign'/'audit-0-test.json').write_bytes(other_raw)
    event['sha256']=hashlib.sha256(other_raw).hexdigest()
    (out/'campaign'/'attempts.jsonl').write_text(json.dumps(event)+'\n',encoding='utf-8')
    saved_path=out/'instance-derivation'/'audit-0-verification.json'
    saved=json.loads(saved_path.read_bytes()); saved['audit_result_sha256']=event['sha256']
    saved_path.write_text(json.dumps(saved),encoding='utf-8')
    with pytest.raises(RuntimeError,match='DERIVATION_CAMPAIGN_AUDIT_MISMATCH'):
        module.verify_instance_derivations(data,out)

def test_recovery_receipt_preserves_initial_execution_counters(tmp_path):
    script=Path(__file__).resolve().parents[1]/'tools/claim-audit/post_sonnet_engineering.py'
    spec=importlib.util.spec_from_file_location('post_sonnet_receipt_test',script)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    initial=dict(campaign_id='synthetic',code_commit='a'*40,plan_sha256='b'*64,
                 files=1,audits=0,status='COMPLETED_PLAN_UNITS',executed=1,recovered=0)
    module.record_campaign_execution(tmp_path,initial)
    original=(tmp_path/'CAMPAIGN_EXECUTION.json').read_bytes()
    replay=dict(initial,executed=0,recovered=1)
    module.record_campaign_execution(tmp_path,replay)
    assert (tmp_path/'CAMPAIGN_EXECUTION.json').read_bytes()==original
    assert len(list(tmp_path.glob('CAMPAIGN_RECOVERY_*.json')))==1
    with pytest.raises(RuntimeError,match='CAMPAIGN_EXECUTION_IDENTITY_CHANGED'):
        module.record_campaign_execution(tmp_path,dict(replay,code_commit='c'*40))
