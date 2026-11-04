"""Authored inert integration controls for literal observation over V2."""
import json

import pytest

from runtime.candidate.run_framework.core import FrameworkError, canonical
from runtime.candidate.run_framework.caller import GenericCaller
from runtime.candidate.run_framework import revision004_observer as observer_module
from runtime.candidate.run_framework.revision004_observer import Revision004Observer
from runtime.candidate.run_framework.revision004_sidecar import INDEX_V3, SidecarVerificationError
from test_convergence_caller import fixture, reload


def configured(tmp_path, *, every=1):
    c = fixture(tmp_path)
    cfg = json.loads(c.config_path.read_bytes())
    cfg['audit_policy']['generic_caller']['literal_receipt_profile'] = {
        'schema': INDEX_V3, 'directory': 'REV004_WIRE', 'checkpoint_every_units': every}
    c.config_path.write_bytes(canonical(cfg))
    return reload(c)


def typed_caller(campaign, adapter):
    def auditor(unit, adapted):
        return {'audit_result': adapted, 'processing_disposition': 'TASK_DEFINITION_PROCESSED',
                'audit_disposition': 'NOT_AUDITED_MISSING_AGENT_OUTPUT'}
    return GenericCaller(campaign, {('inert', '1'): adapter}, auditor, producer_id='fixture-producer')


def test_start_is_flushed_before_callback_and_v2_accounts_sidecar(tmp_path, monkeypatch):
    c = configured(tmp_path)
    flushed = []
    original_write = observer_module._write_immutable
    def traced_write(path, raw):
        original_write(path, raw)
        flushed.append(path.relative_to(c.output).as_posix())
    monkeypatch.setattr(observer_module, '_write_immutable', traced_write)
    calls = []
    def adapter(unit, refs):
        calls.append(unit['unit_id'])
        assert any(p.startswith('REV004_WIRE/receipts/00000001-') for p in flushed)
        assert any(p.startswith('REV004_WIRE/checkpoints/00000001-') for p in flushed)
        paths = list((c.output/'REV004_WIRE/receipts').iterdir())
        assert len(paths) == 1
        start = json.loads(paths[0].read_bytes())
        assert start['phase'] == 'START' and start['audit_status'] == 'NOT_PERFORMED'
        return {'definition': True}
    observed = Revision004Observer(typed_caller(c, adapter))
    observed.execute('u1')
    result = observed.finish()
    assert calls == ['u1']
    assert result['receipt_count'] == 2 and result['completed_units'] == ['u1']
    assert result['pending_units'] == ['u2'] and result['inflight_units'] == []
    assert result['index_profile'] == INDEX_V3
    profile_bytes = sum(p.stat().st_size for p in observed.root.rglob('*') if p.is_file())
    assert c.resources_report()['actual_bytes'] >= profile_bytes
    with pytest.raises(FrameworkError, match='BLOCKED_OR_FINISHED'):
        observed.execute('u2')
    assert calls == ['u1']


def test_v2_journal_indexes_batches_without_rewriting_control_index(tmp_path):
    c = configured(tmp_path, every=2)
    observed = Revision004Observer(typed_caller(c, lambda unit, refs: {'definition': True}))
    observed.execute('u1')
    index = (observed.root/'INDEX.json').read_bytes()
    with pytest.raises(SidecarVerificationError, match='COVERED|UNCHECKPOINTED'):
        observed.verify_read_only()
    observed.execute('u2')
    result = observed.finish()
    assert result['receipt_count'] == 4 and result['completed_units'] == ['u1', 'u2']
    assert not result['pending_units'] and not result['inflight_units']
    assert (observed.root/'INDEX.json').read_bytes() == index
    assert result['checkpoint_count'] == 2


def test_partial_start_publication_blocks_callbacks_and_does_not_resume(tmp_path, monkeypatch):
    c = configured(tmp_path)
    calls = []
    caller = typed_caller(c, lambda unit, refs: calls.append(unit['unit_id']) or {'definition': True})
    observed = Revision004Observer(caller)
    original_write = observer_module._write_immutable
    def interrupted(path, raw):
        if path.parent.name == 'receipts':
            original_write(path, raw[:13])
            raise OSError('authored interruption after incomplete literal receipt')
        return original_write(path, raw)
    monkeypatch.setattr(observer_module, '_write_immutable', interrupted)
    with pytest.raises(OSError, match='authored interruption'):
        observed.execute('u1')
    assert calls == []
    state = c.recover()
    assert state['inflight'] == {'u1'} and not state['completed']
    with pytest.raises(FrameworkError, match='CALLER_STARTED_UNIT_REQUIRED'):
        caller.execute_started('u1')
    assert calls == []
    with pytest.raises(SidecarVerificationError):
        observed.verify_read_only()
    with pytest.raises(FrameworkError, match='BLOCKED_OR_FINISHED'):
        observed.execute('u1')
    assert calls == []


def test_invalid_start_cannot_bypass_observer_with_direct_caller(tmp_path):
    c = configured(tmp_path)
    calls = []
    caller = typed_caller(c, lambda unit, refs: calls.append(unit['unit_id']) or {'definition': True})
    observed = Revision004Observer(caller, wall_ns=lambda: 0)
    with pytest.raises(ValueError, match='timing|start/end'):
        observed.execute('u1')
    assert calls == []
    with pytest.raises(FrameworkError, match='CALLER_STARTED_UNIT_REQUIRED'):
        caller.execute_started('u1')
    with pytest.raises(FrameworkError, match='BLOCKED_OR_FINISHED'):
        caller.execute('u2')
    assert calls == []
    state = c.recover()
    assert state['inflight'] == {'u1'} and not state['completed']


def test_missing_declared_output_never_becomes_available_or_bound_start(tmp_path):
    c = fixture(tmp_path, output_available=True)
    cfg = json.loads(c.config_path.read_bytes())
    cfg['audit_policy']['generic_caller']['literal_receipt_profile'] = {
        'schema': INDEX_V3, 'directory': 'REV004_WIRE', 'checkpoint_every_units': 1}
    c.config_path.write_bytes(canonical(cfg)); c = reload(c)
    calls = []
    caller = typed_caller(c, lambda unit, refs: calls.append(unit['unit_id']) or {'definition': True})
    observed = Revision004Observer(caller)
    (tmp_path/'agent-output.json').unlink()
    with pytest.raises(FrameworkError):
        observed.execute('u1')
    assert calls == [] and not c.recover()['receipts']
    assert not observed.root.exists()


def test_configured_caller_routes_through_literal_observer(tmp_path):
    c = configured(tmp_path)
    calls = []
    caller = typed_caller(c, lambda unit, refs: calls.append(unit['unit_id']) or {'definition': True})
    caller.execute('u1')
    assert calls == ['u1']
    assert caller._literal_observer.finish()['receipt_count'] == 2


def test_observer_preserves_typed_result_for_same_authored_input_bytes(tmp_path):
    before_root, after_root = tmp_path/'before', tmp_path/'after'
    before_root.mkdir(); after_root.mkdir()
    before, after = fixture(before_root), configured(after_root)
    from runtime.candidate.run_framework.revision004_profile import project_unit_metadata
    before_metadata = project_unit_metadata(before, 'u1')
    after_metadata = project_unit_metadata(after, 'u1')
    assert sorted(r['sha256'] for r in before_metadata['available_evidence']) == sorted(
        r['sha256'] for r in after_metadata['available_evidence'])
    adapter = lambda unit, refs: {'definition': True}
    prior = typed_caller(before, adapter).execute('u1')
    observed_caller = typed_caller(after, adapter)
    observed = observed_caller.execute('u1')
    observed_caller._literal_observer.finish()
    prior_body = json.loads((before.output/prior['path']).read_bytes())
    observed_body = json.loads((after.output/observed['path']).read_bytes())
    assert canonical(prior_body['payload']['result_payload']) == canonical(observed_body['payload']['result_payload'])
    assert before.config_sha256 != after.config_sha256  # fresh identity/config, same source bytes


def test_configured_manual_start_cannot_skip_literal_admission(tmp_path):
    c = configured(tmp_path)
    calls = []
    caller = typed_caller(c, lambda unit, refs: calls.append(unit['unit_id']) or {'definition': True})
    caller.begin_unit('u1')
    with pytest.raises(FrameworkError, match='LITERAL_START_ADMISSION_REQUIRED'):
        caller.execute_started('u1')
    assert calls == []


def test_observer_cannot_resume_existing_v2_attempt(tmp_path):
    c = configured(tmp_path)
    caller = typed_caller(c, lambda unit, refs: {'definition': True})
    observed = Revision004Observer(caller)
    observed.execute('u1'); observed.finish()
    before = {p.relative_to(c.output).as_posix(): p.read_bytes() for p in c.output.rglob('*') if p.is_file()}
    with pytest.raises(FrameworkError, match='REQUIRES_FRESH_ATTEMPT'):
        Revision004Observer(typed_caller(c, lambda unit, refs: pytest.fail('never called')))
    assert before == {p.relative_to(c.output).as_posix(): p.read_bytes() for p in c.output.rglob('*') if p.is_file()}


def test_observer_requires_explicit_profile_and_does_not_claim_no_attempt_complete(tmp_path):
    c = fixture(tmp_path)
    with pytest.raises(FrameworkError, match='NOT_EXPLICITLY_CONFIGURED'):
        Revision004Observer(typed_caller(c, lambda unit, refs: {'definition': True}))
    other_root = tmp_path/'configured'
    other_root.mkdir()
    other = configured(other_root)
    observed = Revision004Observer(typed_caller(other, lambda unit, refs: {'definition': True}))
    with pytest.raises(FrameworkError, match='HAS_NO_ATTEMPT'):
        observed.finish()
    assert not observed.root.exists()
