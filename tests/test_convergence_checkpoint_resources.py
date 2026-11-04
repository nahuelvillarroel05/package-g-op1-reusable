"""Bounded prospective engineering controls; inert synthetic development only."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.candidate.run_framework import FrameworkError, load_config
from runtime.candidate.run_framework.core import canonical, digest
from runtime.candidate.run_framework.resources import ResourceGuard, ResourceLimitStop
from test_run_checkpoint_v2 import _campaign, _envelope


def profile(tmp_path, **budget):
    c = _campaign(tmp_path)
    cfg = json.loads(c.config_path.read_bytes())
    cfg['checkpoint_policy']['receipt_parent_chain'] = True
    cfg['resource_budget'].update(max_payload_bytes=65536, **budget)
    c.config_path.write_bytes(canonical(cfg))
    return reload(c)


def reload(c):
    root = c.config_path.parent
    obj = load_config(c.config_path, [root], c.output, [root], [root])
    obj.preflight()
    return obj


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}


def test_parent_chain_binds_exact_prior_receipt_and_preserves_compact_checkpoint(tmp_path):
    c = profile(tmp_path)
    c.begin_unit('u1', {})
    c.complete_unit('u1', 'DONE', _envelope(c, 'u1'))
    receipts = sorted((c.output/'receipts').glob('*.json'))
    assert json.loads(receipts[0].read_bytes())['parent_receipt_sha256'] is None
    assert json.loads(receipts[1].read_bytes())['parent_receipt_sha256'] == digest(receipts[0].read_bytes())
    cp = json.loads(next((c.output/'checkpoints').glob('*.json')).read_bytes())
    assert not {'completed', 'pending', 'inflight', 'selected_units'}.intersection(cp)
    state = reload(c).recover()
    assert state['completed'] == {'u1'} and state['pending'] == {'u2'} and state['inflight'] == set()
    assert cp['state_sha256'] == digest(canonical({'completed':['u1'], 'pending':['u2'], 'inflight':[]}))


@pytest.mark.parametrize('parent', ['0'*64, None])
def test_coherently_rehashed_wrong_parent_is_rejected(tmp_path, parent):
    c = profile(tmp_path)
    c.begin_unit('u1', {})
    c.complete_unit('u1', 'DONE', _envelope(c, 'u1'))
    rp = sorted((c.output/'receipts').glob('*.json'))[-1]
    obj = json.loads(rp.read_bytes()); obj['parent_receipt_sha256'] = parent
    raw = canonical(obj); rh = digest(raw)
    nrp = rp.parent/f'00000002-{rh}.json'; nrp.write_bytes(raw); rp.unlink()
    dp = sorted((c.output/'deltas').glob('*.json'))[-1]
    delta = json.loads(dp.read_bytes()); delta.update(receipt_sha256=rh, receipt_path='receipts/'+nrp.name)
    dr = canonical(delta); dh = digest(dr)
    (dp.parent/f'00000002-{dh}.json').write_bytes(dr); dp.unlink()
    cp = next((c.output/'checkpoints').glob('*.json'))
    checkpoint = json.loads(cp.read_bytes()); checkpoint['head_delta_sha256'] = dh
    cr = canonical(checkpoint); (cp.parent/f'00000002-{digest(cr)}.json').write_bytes(cr); cp.unlink()
    before = snapshot(c.output)
    with pytest.raises(FrameworkError, match='parent receipt chain'):
        reload(c).recover()
    assert snapshot(c.output) == before


def test_legacy_configuration_retains_legacy_wire(tmp_path):
    c = _campaign(tmp_path); c.begin_unit('u1', {})
    assert 'parent_receipt_sha256' not in json.loads(next((c.output/'receipts').glob('*.json')).read_bytes())
    assert reload(c).recover()['inflight'] == {'u1'}


def test_parent_profile_fresh_process_recovery_is_readonly_no_redispatch(tmp_path):
    c = profile(tmp_path); c.begin_unit('u1', {})
    c.complete_unit('u1', 'DONE', _envelope(c, 'u1')); c.begin_unit('u2', {})
    before = snapshot(c.output); root = c.config_path.parent
    command=[sys.executable, '-B', '-m', 'runtime.candidate.run_framework', 'recover', '--config', str(c.config_path),
             '--config-root',str(root),'--trusted-root',str(root),'--output-root',str(root),'--output',str(c.output)]
    result=subprocess.run(command,cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,check=True,timeout=30)
    state=json.loads(result.stdout)
    assert state['completed']==['u1'] and state['inflight']==['u2'] and state['pending']==[]
    assert snapshot(c.output)==before
    with pytest.raises(FrameworkError,match='read-only'):
        reload(c).begin_unit('u2',{})


def test_payload_limit_accepts_exact_bytes_and_rejects_one_byte_over(tmp_path):
    root=tmp_path/'exact'; root.mkdir()
    guard=ResourceGuard(root,max_bytes=65536)
    payload={'value':'x'*128}; size=len(canonical(payload))
    assert guard.payload_bytes(payload,size)==canonical(payload)
    with pytest.raises(ResourceLimitStop) as stopped:
        guard.payload_bytes(payload,size-1)
    assert stopped.value.reason=='PAYLOAD_LIMIT_REACHED'
    assert list(root.iterdir())==[root/'.resource-stop.json']


def test_utf8_and_escaping_are_counted_in_bytes(tmp_path):
    root=tmp_path/'utf8'; root.mkdir(); guard=ResourceGuard(root)
    payload={'text':'é\\\n'*40}; size=len(canonical(payload))
    assert guard.payload_bytes(payload,size)==canonical(payload)
    with pytest.raises(ResourceLimitStop): guard.payload_bytes(payload,size-1)


def test_oversized_terminal_keeps_inflight_and_never_persists_or_truncates(tmp_path):
    c=profile(tmp_path); c.begin_unit('u1',{})
    prior=snapshot(c.output); envelope=_envelope(c,'u1')
    envelope['result_payload']={'huge':'x'*65536}
    envelope['result_payload_sha256']=digest(canonical(envelope['result_payload']))
    with pytest.raises(FrameworkError,match='PAYLOAD_LIMIT_REACHED'):
        c.complete_unit('u1','DONE',envelope)
    assert snapshot(c.output)=={**prior,'.resource-stop.json':(c.output/'.resource-stop.json').read_bytes()}
    stop=json.loads((c.output/'.resource-stop.json').read_bytes())
    assert stop['details']['payload_disposition']=='REJECTED_NOT_PERSISTED'
    state=reload(c).recover()
    assert state['inflight']=={'u1'} and state['pending']=={'u2'} and not state['completed']


@pytest.mark.parametrize('error', [KeyboardInterrupt, MemoryError, OSError])
def test_partial_receipt_write_stops_and_never_false_completes(tmp_path, monkeypatch, error):
    from runtime.candidate.run_framework import incremental
    c=profile(tmp_path); c.begin_unit('u1',{}); c.complete_unit('u1','DONE',_envelope(c,'u1')); c.begin_unit('u2',{})
    original=incremental._write_immutable
    def fail(path,raw):
        if path.parent.name=='receipts':
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw[:len(raw)//2])
            raise error('controlled engineering partial write')
        return original(path,raw)
    monkeypatch.setattr(incremental,'_write_immutable',fail)
    with pytest.raises(error): c.complete_unit('u2','DONE',_envelope(c,'u2'))
    before=snapshot(c.output)
    with pytest.raises(FrameworkError): reload(c).recover()
    prefix=reload(c).recover_valid_prefix()
    assert prefix['completed']=={'u1'} and prefix['pending']=={'u2'} and not prefix['complete']
    assert prefix['verified_prefix_sequence']==2
    assert snapshot(c.output)==before
    stop=json.loads((c.output/'.resource-stop.json').read_bytes())
    assert stop['reason']=={KeyboardInterrupt:'EXTERNAL_INTERRUPTION', MemoryError:'RESOURCE_LIMIT', OSError:'INTEGRITY_FAILURE'}[error]


def test_temp_store_index_bytes_counted_and_budget_stops(tmp_path):
    root=tmp_path/'root'; root.mkdir(); guard=ResourceGuard(root,max_bytes=4096)
    for folder,name in [('tmp','partial.tmp'),('stores','data.bin'),('indexes','index.db')]:
        target=root/folder/name; target.parent.mkdir(); target.write_bytes(b'x'*500)
    assert guard.refresh_usage()==1500
    with pytest.raises(ResourceLimitStop) as stopped: guard.before_publication(1000)
    assert stopped.value.reason=='BYTE_BUDGET_EXHAUSTED'
    assert sum(p.stat().st_size for p in root.rglob('*') if p.is_file())<=4096


def test_explicit_stop_retains_disjoint_pending_and_inflight(tmp_path):
    c=profile(tmp_path); c.begin_unit('u1',{})
    with pytest.raises(ResourceLimitStop): c.request_stop('EXTERNAL_INTERRUPTION')
    before=snapshot(c.output); state=reload(c).recover()
    assert state['pending']=={'u2'} and state['inflight']=={'u1'} and state['completed']==set()
    assert state['pending']|state['inflight']|state['completed']==set(c.config['expected_units'])
    assert snapshot(c.output)==before


@pytest.mark.parametrize('field,value', [('receipt_parent_chain','yes'),('max_payload_bytes',0),('max_payload_bytes',True)])
def test_malformed_profile_policy_rejected(tmp_path,field,value):
    c=_campaign(tmp_path); cfg=json.loads(c.config_path.read_bytes())
    cfg['checkpoint_policy' if field=='receipt_parent_chain' else 'resource_budget'][field]=value
    c.config_path.write_bytes(canonical(cfg))
    with pytest.raises(FrameworkError): reload(c)
