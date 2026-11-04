"""Typed caller/source graph adversarial tests, authored development inputs."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.candidate.run_framework import FrameworkError, load_config
from runtime.candidate.run_framework.core import canonical, digest
from runtime.candidate.run_framework.caller import GenericCaller, make_envelope
from runtime.candidate.run_framework.source_bindings import SourceBindings
from test_run_checkpoint_v2 import _campaign


def fixture(tmp_path, *, output_available=False):
    c = _campaign(tmp_path)
    cfg = json.loads(c.config_path.read_bytes())
    dataset_path = Path(cfg['dataset_manifest_path'])
    dataset = json.loads(dataset_path.read_bytes())
    aux = tmp_path / 'auxiliary.txt'
    aux.write_bytes(b'authored auxiliary source\n')
    output = tmp_path / 'agent-output.json'
    output.write_bytes(b'{"declared_result":"development"}')
    primary = cfg['input_bindings'][0]
    source = {'schema': 'pgop1.source-manifest.v1', 'sources': [
        {'source_id': 'fixture-source', **primary, 'role': 'PRIMARY'},
        {'source_id': 'auxiliary', 'path': str(aux), 'sha256': digest(aux.read_bytes()), 'role': 'SUPPORTING'}]}
    source_path = tmp_path / 'source-manifest.json'
    source_path.write_bytes(canonical(source))
    deps = {'schema': 'pgop1.unit-source-dependencies.v1',
            'source_manifest_sha256': digest(source_path.read_bytes()),
            'expected_units_sha256': digest(canonical(sorted(cfg['expected_units']))),
            'groups': {'shared': {'supporting_source_ids': ['auxiliary'], 'normative_companion_ids': []}},
            'units': [{'unit_id': u, 'primary_source_id': 'fixture-source', 'dependency_group_ids': ['shared'],
                       'supporting_source_ids': [], 'normative_companion_ids': []} for u in cfg['expected_units']]}
    deps_path = tmp_path / 'dependencies.json'
    deps_path.write_bytes(canonical(deps))
    predicate_path = Path(cfg['predicate_contracts']['path'])
    predicate_path.write_bytes(canonical({'schema':'development', 'version':'1'}))
    cfg['predicate_contracts']['sha256'] = digest(predicate_path.read_bytes())
    for unit in dataset['units']:
        unit.update(benchmark_id='authored', benchmark_version='1', adapter_id='inert', adapter_version='1',
                    predicate_contract={'contract_id': 'development', 'version': '1', 'sha256': cfg['predicate_contracts']['sha256']},
                    authentic_output_references=[])
        if output_available:
            ref = {'path': str(output), 'sha256': digest(output.read_bytes())}
            unit['authentic_output_references'] = [ref]
            unit['evidence_references'].append(ref)
    dataset_path.write_bytes(canonical(dataset))
    cfg['input_manifest_sha256'] = digest(dataset_path.read_bytes())
    registry_path = Path(cfg['adapter_registry']['path'])
    registry_path.write_bytes(canonical({'families':{'authored':{'adapter_id':'inert','adapter_version':'1','versions':['1']}}}))
    cfg['adapter_registry']['sha256'] = digest(registry_path.read_bytes())
    # This shared fixture file is also its original evidence reference.
    for unit in dataset['units']:
        unit['evidence_references'][0]['sha256'] = cfg['adapter_registry']['sha256']
    dataset_path.write_bytes(canonical(dataset))
    cfg['input_manifest_sha256'] = digest(dataset_path.read_bytes())
    cfg['audit_policy']['generic_caller'] = {'schema': 'pgop1.generic-caller-config.v1',
        'source_manifest': {'path': str(source_path), 'sha256': digest(source_path.read_bytes())},
        'dependency_manifest': {'path': str(deps_path), 'sha256': digest(deps_path.read_bytes())}}
    # Rejection controls remain inspectable without a first-error stop.
    cfg['resource_budget']['max_errors'] = 100
    c.config_path.write_bytes(canonical(cfg))
    c = reload(c)
    return c


def reload(c):
    root = c.config_path.parent
    other = load_config(c.config_path, [root], c.output, [root], [root])
    other.preflight()
    return other


def envelope(c, unit='u1', **kwargs):
    return make_envelope(c, unit, {'finding': 'missing compatible agent output'},
                         producer_id='fixture-producer',
                         processing_disposition=kwargs.get('processing_disposition', 'TASK_DEFINITION_PROCESSED'),
                         audit_disposition=kwargs.get('audit_disposition', 'NOT_AUDITED_MISSING_AGENT_OUTPUT'))


def test_generic_caller_publishes_recovers_and_never_redispatches(tmp_path):
    c = fixture(tmp_path)
    calls = []
    def adapter(unit, refs):
        calls.append(unit['unit_id'])
        assert refs['supporting'][0]['source_id'] == 'auxiliary'
        return {'definition': True}
    def auditor(unit, adapted):
        return {'audit_result': adapted, 'processing_disposition': 'TASK_DEFINITION_PROCESSED',
                'audit_disposition': 'NOT_AUDITED_MISSING_AGENT_OUTPUT'}
    caller = GenericCaller(c, {('inert','1'): adapter}, auditor, producer_id='fixture-producer')
    caller.execute('u1')
    assert calls == ['u1']
    state = reload(c).recover()
    assert state['completed'] == {'u1'} and state['pending'] == {'u2'}
    with pytest.raises(FrameworkError): caller.execute('u1')
    assert calls == ['u1']


def test_explicit_start_then_execute_started_preserves_one_start_and_one_terminal(tmp_path):
    c = fixture(tmp_path)
    calls = []
    def adapter(unit, refs):
        calls.append(unit['unit_id'])
        return {'definition': True}
    def auditor(unit, adapted):
        return {'audit_result': adapted, 'processing_disposition': 'TASK_DEFINITION_PROCESSED',
                'audit_disposition': 'NOT_AUDITED_MISSING_AGENT_OUTPUT'}
    caller = GenericCaller(c, {('inert','1'): adapter}, auditor, producer_id='fixture-producer')
    with pytest.raises(FrameworkError, match='CALLER_STARTED_UNIT_REQUIRED'):
        caller.execute_started('u1')
    start = caller.begin_unit('u1')
    assert start['phase'] == 'start' and start['unit_id'] == 'u1'
    terminal = caller.execute_started('u1')
    assert terminal['phase'] == 'terminal'
    assert calls == ['u1']
    state = reload(c).recover()
    assert state['completed'] == {'u1'} and state['inflight'] == set()


def test_callbacks_cannot_mutate_authoritative_cached_unit(tmp_path):
    c = fixture(tmp_path)
    def adapter(unit, refs):
        unit['benchmark_id'] = 'forged-family'
        unit['predicate_contract']['version'] = 'forged-version'
        refs['primary']['sha256'] = '0'*64
        return {}
    def auditor(unit, adapted):
        assert unit['benchmark_id'] == 'authored' and unit['predicate_contract']['version'] == '1'
        return {'audit_result':{}, 'processing_disposition':'TASK_DEFINITION_PROCESSED',
                'audit_disposition':'NOT_AUDITED_MISSING_AGENT_OUTPUT'}
    GenericCaller(c, {('inert','1'):adapter}, auditor, producer_id='fixture-producer').execute('u1')
    assert reload(c).recover()['completed'] == {'u1'}


def test_mutating_envelope_does_not_change_authoritative_unit_contract(tmp_path):
    c = fixture(tmp_path)
    first = envelope(c)
    first['result_payload']['predicate_contract']['version'] = 'forged-version'
    second = envelope(c)
    assert second['result_payload']['predicate_contract']['version'] == '1'


@pytest.mark.parametrize('field,value', [('benchmark_id','other'), ('benchmark_version','2'),
    ('adapter_id','other'), ('adapter_version','2'), ('predicate_contract',{'wrong':'contract'}),
    ('producer_provenance_status','AUTHENTICATED'), ('supporting_source_references',[]),
    ('normative_companion_references',[{'source_id':'borrowed','sha256':'a'*64}]), ('result_sha256','0'*64)])
def test_typed_substitutions_are_preserved_and_not_completed(tmp_path, field, value):
    c = fixture(tmp_path)
    c.begin_unit('u1', {})
    bad = envelope(c)
    bad['result_payload'][field] = value
    bad['result_payload_sha256'] = digest(canonical(bad['result_payload']))
    raw = canonical(bad)
    with pytest.raises(FrameworkError): c.complete_unit('u1','TASK_DEFINITION_PROCESSED',bad)
    assert (c.output/'rejected'/f'{digest(raw)}.json').read_bytes() == raw
    state = reload(c).recover()
    assert state['completed'] == set() and state['inflight'] == {'u1'}


@pytest.mark.parametrize('field', ['run_id','campaign_id','campaign_attempt_id','unit_id','source_id','source_sha256','contract_sha256','candidate_commit','candidate_tree'])
def test_foreign_outer_envelope_rejected(tmp_path, field):
    c = fixture(tmp_path)
    c.begin_unit('u1', {})
    bad = envelope(c)
    bad[field] = 'different-identity'
    with pytest.raises(FrameworkError): c.complete_unit('u1','TASK_DEFINITION_PROCESSED',bad)
    assert reload(c).recover()['completed'] == set()


def test_auxiliary_tampering_blocks_admission_and_recovery(tmp_path):
    c = fixture(tmp_path)
    c.begin_unit('u1', {})
    valid = envelope(c)
    aux = tmp_path/'auxiliary.txt'
    original = aux.read_bytes()
    aux.write_bytes(b'substituted auxiliary\n')
    with pytest.raises(FrameworkError, match='source dependency'): c.complete_unit('u1','TASK_DEFINITION_PROCESSED',valid)
    aux.write_bytes(original)
    c.complete_unit('u1','TASK_DEFINITION_PROCESSED',valid)
    aux.write_bytes(b'substituted after publication\n')
    with pytest.raises(FrameworkError, match='source dependency'): reload(c).recover()


def test_incomplete_dependency_population_cannot_qualify(tmp_path):
    c = fixture(tmp_path)
    policy = json.loads(c.config_path.read_bytes())
    path = Path(policy['audit_policy']['generic_caller']['dependency_manifest']['path'])
    deps = json.loads(path.read_bytes()); deps['units'].pop(); path.write_bytes(canonical(deps))
    policy['audit_policy']['generic_caller']['dependency_manifest']['sha256'] = digest(path.read_bytes())
    c.config_path.write_bytes(canonical(policy)); c = reload(c)
    with pytest.raises(FrameworkError, match='POPULATION_MISMATCH'): SourceBindings(c)


def test_unbound_manifest_member_cannot_hide_behind_internal_consistency(tmp_path):
    c = fixture(tmp_path)
    cfg = json.loads(c.config_path.read_bytes())
    p = cfg['audit_policy']['generic_caller']
    source_path = Path(p['source_manifest']['path']); deps_path = Path(p['dependency_manifest']['path'])
    source = json.loads(source_path.read_bytes()); source['sources'].append({'source_id':'extra', 'path':str(tmp_path/'not-present'), 'sha256':'a'*64, 'role':'SUPPORTING'})
    source_path.write_bytes(canonical(source)); p['source_manifest']['sha256'] = digest(source_path.read_bytes())
    deps = json.loads(deps_path.read_bytes()); deps['source_manifest_sha256'] = p['source_manifest']['sha256']
    deps_path.write_bytes(canonical(deps)); p['dependency_manifest']['sha256'] = digest(deps_path.read_bytes())
    c.config_path.write_bytes(canonical(cfg)); c = reload(c)
    with pytest.raises(FrameworkError, match='UNBOUND_MEMBERS'): SourceBindings(c)


def test_definition_cannot_claim_semantic_audit_or_missing_output_success(tmp_path):
    c = fixture(tmp_path)
    with pytest.raises(FrameworkError, match='SEMANTIC_AUDIT'):
        envelope(c, audit_disposition='AUDITED')
    with pytest.raises(FrameworkError, match='AUTHENTIC_AGENT_OUTPUT_MISSING'):
        envelope(c, processing_disposition='AGENT_OUTPUT_AUDITED', audit_disposition='AUDITED')


def test_output_audit_requires_qualified_predicates_and_exact_output_bytes(tmp_path):
    c = fixture(tmp_path, output_available=True)
    c.begin_unit('u1', {})
    with pytest.raises(FrameworkError, match='QUALIFIED_PREDICATE_VALIDATION'):
        envelope(c, processing_disposition='AGENT_OUTPUT_AUDITED', audit_disposition='ABSTAIN')
    (tmp_path/'agent-output.json').write_bytes(b'{"substituted":true}')
    with pytest.raises(FrameworkError, match='authentic output'):
        envelope(c, processing_disposition='AGENT_OUTPUT_AUDITED', audit_disposition='ABSTAIN')


@pytest.mark.parametrize('fake_disposition', ['PASS', 'AUDITED', 'AGENT_OUTPUT_AUDITED'])
def test_outer_disposition_cannot_upgrade_definition_to_success(tmp_path, fake_disposition):
    c = fixture(tmp_path)
    c.begin_unit('u1', {})
    bad = envelope(c); raw = canonical(bad)
    with pytest.raises(FrameworkError, match='TYPED_TERMINAL_DISPOSITION_MISMATCH'):
        c.complete_unit('u1', fake_disposition, bad)
    assert (c.output/'rejected'/f'{digest(raw)}.json').read_bytes() == raw
    assert reload(c).recover()['completed'] == set()


def test_adapter_failure_leaves_inflight_without_redispatch(tmp_path):
    c = fixture(tmp_path)
    def broken(*args): raise RuntimeError('authored producer failure')
    caller = GenericCaller(c, {('inert','1'):broken}, lambda *args: {}, producer_id='fixture-producer')
    with pytest.raises(RuntimeError): caller.execute('u1')
    assert reload(c).recover()['inflight'] == {'u1'}
    with pytest.raises(FrameworkError): caller.execute('u1')


@pytest.mark.parametrize('failure', [MemoryError, KeyboardInterrupt])
def test_caller_memory_or_interruption_publishes_stop_and_conserves_inflight(tmp_path, failure):
    c = fixture(tmp_path)
    def broken(*args): raise failure('authored bounded callback failure')
    caller = GenericCaller(c, {('inert','1'):broken}, lambda *args: {}, producer_id='fixture-producer')
    with pytest.raises(failure): caller.execute('u1')
    stop = json.loads((c.output/'.resource-stop.json').read_bytes())
    assert stop['reason'] == ('RESOURCE_LIMIT' if failure is MemoryError else 'EXTERNAL_INTERRUPTION')
    assert stop['details']['exception_type'] == failure.__name__
    state = reload(c).recover()
    assert state['inflight'] == {'u1'} and state['pending'] == {'u2'} and state['completed'] == set()
    with pytest.raises(FrameworkError): caller.execute('u2')


def test_fresh_process_recovery_validates_auxiliary_dependencies(tmp_path):
    c = fixture(tmp_path)
    c.begin_unit('u1', {}); c.complete_unit('u1','TASK_DEFINITION_PROCESSED',envelope(c))
    command = [sys.executable, '-B', '-m', 'runtime.candidate.run_framework', 'recover', '--config',str(c.config_path),
               '--config-root',str(tmp_path),'--trusted-root',str(tmp_path),'--output-root',str(tmp_path),'--output',str(c.output)]
    result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and json.loads(result.stdout)['completed'] == ['u1']
    (tmp_path/'auxiliary.txt').write_bytes(b'changed')
    result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
