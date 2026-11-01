"""Real fresh-process verification must not depend on Windows argv capacity."""
import hashlib
import json

from runtime.candidate.swebench_claim_audit.generalized import audit_evidence
from runtime.candidate.swebench_claim_audit.generalized_bridge import (
    bind_generalized_audit, recover_generalized_audit,
)
from runtime.candidate.context_engine import Engine


def test_large_observation_map_survives_real_fresh_process_and_recovery(tmp_path):
    data=tmp_path/'data'
    data.mkdir()
    instance='synthetic__large-1'
    sources=[]
    values=[('trajectory.json',{'instance_id':instance,'messages':[
        {'role':'assistant','content':'I resolved the task.'} for _ in range(650)]},
        'AGENT_TRAJECTORY','pgop1.swebench.trajectory.miniswe_json.v1'),
        ('report.json',{instance:{'resolved':True}},'EVALUATOR_REPORT',
         'pgop1.swebench.evaluator_report.resolved_map_json.v1')]
    for name,value,role,parser in values:
        raw=json.dumps(value).encode()
        (data/name).write_bytes(raw)
        sources.append(dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
            role=role,parser_id=parser))
    audit=audit_evidence(data,dict(run_id='synthetic-large-readback',instance_id=instance,
        evidence=sources,claim_attribution_contract='pgop1.swebench.attribution-ambiguity.v1'))
    assert len(audit['observations'])>=650
    context=tmp_path/'context'
    bound=bind_generalized_audit(audit,data,context)
    fresh=bound['context_engine']['fresh_process_readback']
    assert fresh['status']=='PASS'
    assert fresh['expected_observations_found']>=650
    assert fresh['derivation']['status']=='DERIVATION_VERIFIED'
    task='INSTANCE:'+instance
    ids=[row['id'] for row in Engine(context).query(task_id=task,limit=1000)]
    assert len(json.dumps({task:ids}))>32767
    recovered=recover_generalized_audit(context)
    assert recovered['status']=='PASS'
    assert recovered['derivation']['status']=='DERIVATION_VERIFIED'
