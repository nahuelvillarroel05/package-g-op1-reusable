"""Authored metadata controls for the closed definition-only E1 integration."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from runtime.candidate.run_framework.core import FrameworkError, canonical
from runtime.candidate.run_framework.definition_e1 import validate_admission, run


def fixture():
    units, rights = [], []
    for i in range(4):
        ref = {'path': f'authored-{i}.json', 'sha256': 'a' * 64}
        units.append({'unit_id': f'u{i}', 'benchmark_id': 'mcpmark_verified' if i < 2 else 'terminal_bench_2',
            'source_path': ref['path'], 'source_sha256': ref['sha256'], 'predicate_profile': 'DEFINITION_ONLY',
            'authentic_output_references': [], 'evidence_references': [ref]})
        rights.append({'unit_id': f'u{i}', 'processing_status': 'PROCESSING_PERMITTED', 'allowed_source_references': [ref]})
    config = {'run_id': 'RUN008', 'campaign_id': 'PGOP1-RUN008-E1', 'expected_units': [u['unit_id'] for u in units],
              'resource_budget': {'max_units': 4, 'max_units_per_shard': 2}, 'checkpoint_policy': {'interval': 1}}
    admission = {'schema': 'pgop1.definition-e1.admission.v1', 'units': rights}
    return config, admission, units


@pytest.mark.parametrize('run_id', ['RUN008', 'RUN009'])
def test_exact_definition_scope_admits_without_claiming_outputs(run_id):
    config, admission, units = fixture()
    config.update(run_id=run_id, campaign_id=f'PGOP1-{run_id}-E1')
    result = validate_admission(config, admission, units)
    assert result == {'units': 4, 'authentic_agent_outputs': 0, 'rights_granted_by_runner': False}


@pytest.mark.parametrize('fault', ['rights', 'extra-source', 'output', 'duplicate', 'family', 'order'])
def test_definition_gate_rejects_incompatible_scope(fault):
    config, admission, units = deepcopy(fixture())
    if fault == 'rights': admission['units'][0]['processing_status'] = 'RIGHTS_UNRESOLVED'
    elif fault == 'extra-source': units[0]['evidence_references'].append({'path': 'unselected', 'sha256': 'b' * 64})
    elif fault == 'output': units[0]['authentic_output_references'] = units[0]['evidence_references']
    elif fault == 'duplicate': admission['units'].append(admission['units'][0])
    elif fault == 'family': units[0]['benchmark_id'] = 'unqualified'
    else: config['expected_units'] = ['different-unit']
    with pytest.raises(FrameworkError):
        validate_admission(config, admission, units)


def test_direct_definition_launch_without_bound_decision_stops_before_load(tmp_path, monkeypatch):
    from runtime.candidate.run_framework import definition_e1
    path = tmp_path / 'config.json'
    path.write_bytes(canonical({'run_id': 'RUN008', 'campaign_attempt_id': 'authored'}))
    monkeypatch.setattr(definition_e1, 'load_config', lambda *a: pytest.fail('unvalidated load'))
    with pytest.raises(FrameworkError, match='BOUND_OWNER_LAUNCH'):
        run(SimpleNamespace(config=path))
