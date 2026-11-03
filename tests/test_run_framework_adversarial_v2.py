"""Observable v2 attack controls; synthetic fixtures, no producer dispatch."""
import json
import subprocess
import sys
import os
from pathlib import Path

import pytest

from runtime.candidate.run_framework import FrameworkError, load_config
from runtime.candidate.run_framework.core import canonical, digest
from test_run_checkpoint_v2 import _campaign, _envelope


def reload_campaign(c):
    root=c.config_path.parent
    other=load_config(c.config_path,[root],c.output,[root],[root])
    other.preflight()
    return other


def bytes_under(root):
    return {str(p.relative_to(root)):p.read_bytes() for p in root.rglob('*') if p.is_file() and '.git' not in p.parts}


@pytest.mark.parametrize('attack',['remove_receipt','truncate_receipt','truncate_delta','remove_checkpoint','corrupt_checkpoint','substitute_manifest','remove_manifest','extra_manifest','duplicate_delta','discontinuous_delta','outside_reference'])
def test_tamper_never_passes_silently(tmp_path,attack):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); c.complete_unit('u1','DONE',_envelope(c,'u1'))
    receipt=sorted((c.output/'receipts').glob('*.json'))[-1]
    delta=sorted((c.output/'deltas').glob('*.json'))[-1]
    cp=next((c.output/'checkpoints').glob('*.json'))
    manifest=next((c.output/'manifest').glob('*.json'))
    if attack=='remove_receipt': receipt.unlink()
    elif attack=='truncate_receipt': receipt.write_bytes(receipt.read_bytes()[:-1])
    elif attack=='truncate_delta': delta.write_bytes(delta.read_bytes()[:-1])
    elif attack=='remove_checkpoint': cp.unlink()
    elif attack=='corrupt_checkpoint': cp.write_bytes(b'{}')
    elif attack=='substitute_manifest': manifest.write_bytes(b'{}')
    elif attack=='remove_manifest': manifest.unlink()
    elif attack=='extra_manifest': (manifest.parent/('a'*64+'.json')).write_bytes(manifest.read_bytes())
    elif attack=='duplicate_delta': (delta.parent/('00000003-'+delta.name.split('-',1)[1])).write_bytes(delta.read_bytes())
    elif attack=='discontinuous_delta': delta.rename(delta.parent/('00000004-'+delta.name.split('-',1)[1]))
    elif attack=='outside_reference':
        obj=json.loads(delta.read_bytes()); obj['receipt_path']='../outside.json'; delta.write_bytes(canonical(obj))
    before=bytes_under(c.output)
    with pytest.raises((FrameworkError,OSError,ValueError)): reload_campaign(c).recover()
    assert bytes_under(c.output)==before, 'Recovery must never repair or write attacked evidence'


@pytest.mark.parametrize('field,value,expected',[('run_id','other-run','RESULT_FROM_ANOTHER_CAMPAIGN'),('campaign_attempt_id','other-attempt','RESULT_FROM_ANOTHER_CAMPAIGN'),('unit_id','u2','RESULT_UNIT_MISMATCH'),('source_id','substituted-source','RESULT_PROVENANCE_MISMATCH'),('candidate_tree','0'*40,'RESULT_PROVENANCE_MISMATCH'),('producer_identity_status','AUTHENTICATED','RESULT_PRODUCER_NOT_AUTHENTICATED')])
def test_integrated_foreign_result_keeps_original_rejection(tmp_path,field,value,expected):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); envelope=_envelope(c,'u1'); envelope[field]=value; original=canonical(envelope)
    with pytest.raises(FrameworkError,match=expected): c.complete_unit('u1','DONE',envelope)
    assert (c.output/'rejected'/f'{digest(original)}.json').read_bytes()==original
    s=reload_campaign(c).recover(); assert s['completed']==set() and s['inflight']=={'u1'} and s['pending']=={'u2'}


def test_integrated_missing_provenance_is_not_completed(tmp_path):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); payload={'opaque_result':'unproven'}
    with pytest.raises(FrameworkError,match='RESULT_WITHOUT_PROVENANCE'): c.complete_unit('u1','DONE',payload)
    s=reload_campaign(c).recover(); assert not s['complete'] and s['completed']==set()


def test_duplicate_lifecycle_rejected_and_full_selection_conserved(tmp_path):
    c=_campaign(tmp_path); c.begin_unit('u1',{})
    with pytest.raises(FrameworkError): c.begin_unit('u1',{})
    c.complete_unit('u1','DONE',_envelope(c,'u1'))
    with pytest.raises(FrameworkError): c.complete_unit('u1','DONE',_envelope(c,'u1'))
    s=reload_campaign(c).recover(); assert s['completed']=={'u1'} and s['pending']=={'u2'} and not s['complete']


def test_fresh_process_recovery_does_not_modify_durable_bytes_or_dispatch(tmp_path):
    c=_campaign(tmp_path); c.begin_unit('u1',{})
    root=c.config_path.parent; before=bytes_under(c.output)
    command=[sys.executable,'-B','-m','runtime.candidate.run_framework','recover','--config',str(c.config_path),'--config-root',str(root),'--trusted-root',str(root),'--output-root',str(root),'--output',str(c.output)]
    result=subprocess.run(command,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,check=True,timeout=30)
    state=json.loads(result.stdout); assert state['inflight']==['u1'] and state['pending']==['u2'] and state['completed']==[]
    assert bytes_under(c.output)==before


def test_budget_denies_large_terminal_before_receipt_and_preserves_last_checkpoint(tmp_path):
    c=_campaign(tmp_path)
    cfg=json.loads(c.config_path.read_bytes()); cfg['resource_budget']['max_bytes']=24000
    c.config_path.write_bytes(canonical(cfg)); c=reload_campaign(c)
    c.begin_unit('u1',{}); c.complete_unit('u1','DONE',_envelope(c,'u1')); c.begin_unit('u2',{})
    before=set((c.output/'receipts').glob('*.json')); checkpoints=bytes_under(c.output/'checkpoints')
    env=_envelope(c,'u2'); env['result_payload']={'large':'x'*30000}; env['result_payload_sha256']=digest(canonical(env['result_payload']))
    with pytest.raises(FrameworkError): c.complete_unit('u2','DONE',env)
    assert set((c.output/'receipts').glob('*.json'))==before
    assert bytes_under(c.output/'checkpoints')==checkpoints
    assert sum(p.stat().st_size for p in c.output.rglob('*') if p.is_file())<=24000
    s=reload_campaign(c).recover(); assert s['completed']=={'u1'} and s['inflight']=={'u2'}


def test_in_memory_configuration_cannot_enlarge_budget_or_selection(tmp_path):
    c=_campaign(tmp_path)
    with pytest.raises((FrameworkError,TypeError,ValueError)): c.config['resource_budget']['max_bytes']=2**63
    with pytest.raises((FrameworkError,TypeError,ValueError)): c.config['expected_units'].append('foreign-unit')


def test_v2_shard_plan_uses_existing_planner_with_detached_mutable_policies(tmp_path):
    c=_campaign(tmp_path); plan=c.shard_plan()
    assert plan['EXPECTED_UNITS']==2 and len(plan['shards'])==1
    plan['RESOURCE_LIMITS']['max_units_per_shard']=900
    assert c.config['resource_budget']['max_units_per_shard']==2


def test_result_identity_cannot_be_admitted_twice_across_units(tmp_path):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); first=_envelope(c,'u1')
    c.complete_unit('u1','DONE',first); c.begin_unit('u2',{})
    second=_envelope(c,'u2'); second['result_id']=first['result_id']
    with pytest.raises(FrameworkError,match='RESULT_ID_ALREADY_ADMITTED'): c.complete_unit('u2','DONE',second)
    s=reload_campaign(c).recover(); assert s['completed']=={'u1'} and s['inflight']=={'u2'}


def test_dict_union_cannot_bypass_frozen_policy(tmp_path):
    c=_campaign(tmp_path); policy=c.config['checkpoint_policy']
    with pytest.raises(FrameworkError): policy |= {'interval':1}
    assert c.config['checkpoint_policy']['interval']==2


def test_reader_stop_request_and_resource_report_do_not_write(tmp_path):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); before=bytes_under(c.output)
    reader=reload_campaign(c)
    with pytest.raises(FrameworkError,match='read-only'): reader.request_stop()
    reader.resources_report()
    assert bytes_under(c.output)==before


def test_missing_tail_receipt_yields_readonly_verified_checkpoint_prefix(tmp_path):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); c.complete_unit('u1','DONE',_envelope(c,'u1')); c.begin_unit('u2',{})
    sorted((c.output/'receipts').glob('*.json'))[-1].unlink(); before=bytes_under(c.output)
    prefix=reload_campaign(c).recover_valid_prefix()
    assert prefix['verified_prefix_sequence']==2 and prefix['completed']=={'u1'} and not prefix['complete']
    assert bytes_under(c.output)==before


@pytest.mark.parametrize('disposition',['',None,7])
def test_coherent_rehash_cannot_admit_invalid_terminal_disposition(tmp_path,disposition):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); c.complete_unit('u1','DONE',_envelope(c,'u1'))
    rp=sorted((c.output/'receipts').glob('*.json'))[-1]; r=json.loads(rp.read_bytes()); r['disposition']=disposition; rr=canonical(r); rh=digest(rr)
    newrp=rp.parent/f'00000002-{rh}.json'; newrp.write_bytes(rr); rp.unlink()
    dp=sorted((c.output/'deltas').glob('*.json'))[-1]; d=json.loads(dp.read_bytes()); d.update(disposition=disposition,receipt_sha256=rh,receipt_path='receipts/'+newrp.name); dr=canonical(d); dh=digest(dr)
    (dp.parent/f'00000002-{dh}.json').write_bytes(dr); dp.unlink()
    cp=next((c.output/'checkpoints').glob('*.json')); obj=json.loads(cp.read_bytes()); obj['head_delta_sha256']=dh; cr=canonical(obj)
    (cp.parent/f'00000002-{digest(cr)}.json').write_bytes(cr); cp.unlink()
    with pytest.raises(FrameworkError,match='terminal disposition'): reload_campaign(c).recover()


def test_checkpoint_interruption_preserves_prefix_and_records_stop(tmp_path,monkeypatch):
    from runtime.candidate.run_framework import incremental
    c=_campaign(tmp_path); c.begin_unit('u1',{}); c.complete_unit('u1','DONE',_envelope(c,'u1')); c.begin_unit('u2',{})
    original=incremental._write_immutable
    def interrupted(path,raw):
        if path.parent.name=='checkpoints': raise KeyboardInterrupt('synthetic interruption during checkpoint')
        return original(path,raw)
    monkeypatch.setattr(incremental,'_write_immutable',interrupted)
    with pytest.raises(KeyboardInterrupt): c.complete_unit('u2','DONE',_envelope(c,'u2'))
    stop=json.loads((c.output/'.resource-stop.json').read_bytes()); assert stop['reason']=='EXTERNAL_INTERRUPTION'
    prefix=reload_campaign(c).recover_valid_prefix()
    assert prefix['verified_prefix_sequence']==2 and prefix['completed']=={'u1'} and prefix['pending']=={'u2'} and not prefix['complete']


def test_same_stat_metadata_replacement_rejected_before_publication(tmp_path):
    c=_campaign(tmp_path); c.begin_unit('u1',{}); path=Path(c.config['contract_path']); before=path.stat()
    path.write_bytes(path.read_bytes().replace(b'DECLARED',b'DISABLED')); os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
    count=len(list((c.output/'receipts').glob('*.json')))
    with pytest.raises(FrameworkError,match='bytes changed'): c.complete_unit('u1','DONE',_envelope(c,'u1'))
    assert len(list((c.output/'receipts').glob('*.json')))==count
