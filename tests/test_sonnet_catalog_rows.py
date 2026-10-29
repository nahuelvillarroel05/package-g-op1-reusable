"""Rejected catalog rows retain identifiers, counts, parser and source binding."""
import hashlib,json
from runtime.candidate.swebench_claim_audit.generalized import audit_file,audit_evidence

def test_every_bad_catalog_row_is_identified_before_target_filter(tmp_path):
    doc={'valid__case-1':{'resolved':True},'bad__case-2':{'resolved':1},'missing__case-3':{}}
    raw=json.dumps(doc).encode(); (tmp_path/'catalog.json').write_bytes(raw)
    descriptor=dict(path='catalog.json',sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),
        role='EVALUATOR_CATALOG',parser_id='pgop1.swebench.catalog.per_instance_details_json.v1')
    parsed=audit_file(tmp_path,dict(descriptor,run_id='synthetic',instance_id='valid__case-1'))
    assert parsed['status']=='ERROR' and not parsed['observations']
    rejection=parsed['parser_rejections']
    assert rejection['rejected_row_count']==2 and rejection['input_row_count']==3
    assert {r['instance_id'] for r in rejection['rejected_rows']}=={'bad__case-2','missing__case-3'}
    for row in rejection['rejected_rows']:
        assert row['parser_id']==descriptor['parser_id']
        assert row['source_ref']['sha256']==descriptor['sha256']
        assert row['source_ref']['pointer']=='/'+row['instance_id']
    audit=audit_evidence(tmp_path,dict(run_id='synthetic',instance_id='valid__case-1',evidence=[descriptor]))
    assert audit['AUDIT_VERDICT']=='VERIFICATION_ERROR'
    assert audit['PARSER_REJECTIONS']==[rejection]
