"""Authored, inert controls for E1 sequential batch boundaries."""
import json
from types import SimpleNamespace

import pytest

from runtime.candidate.run_framework import run005
from runtime.candidate.run_framework.core import FrameworkError
from runtime.candidate.run_framework.resources import ResourceGuard


def test_four_batches_close_before_next_callback(tmp_path):
    output = tmp_path / 'out'
    output.mkdir()
    guard = ResourceGuard(output, max_bytes=1024 * 1024)
    campaign = SimpleNamespace(output=output, config={'resource_budget': {'max_units_per_shard': 5}},
                               _guard=lambda: guard)
    seen = []

    def execute(unit_id):
        index = int(unit_id[1:])
        if index and index % 5 == 0:
            previous = output / 'batches' / f'{index // 5:06d}-terminal.json'
            assert json.loads(previous.read_text())['attempted_units'] == 5
        seen.append(unit_id)
        return {'unit_id': unit_id}

    units = [{'unit_id': f'u{i}'} for i in range(20)]
    operations, batches = run005.execute_batches(campaign, SimpleNamespace(execute=execute), units,
        receipt_reference=lambda _campaign, receipt, _unit: receipt)
    assert seen == [u['unit_id'] for u in units]
    assert [b['attempted_units'] for b in batches] == [5, 5, 5, 5]
    assert len(operations) == 20
    assert len(list((output / 'batches').glob('*.json'))) == 8
    assert all(b['member_ids'] == seen[i * 5:(i + 1) * 5] for i, b in enumerate(batches))


def test_material_failure_preserves_open_batch_and_stops(tmp_path):
    output = tmp_path / 'out'
    output.mkdir()
    guard = ResourceGuard(output, max_bytes=1024 * 1024)
    campaign = SimpleNamespace(output=output, config={'resource_budget': {'max_units_per_shard': 5}},
                               _guard=lambda: guard)
    seen = []

    def execute(unit_id):
        seen.append(unit_id)
        raise FrameworkError('injected material stop')

    with pytest.raises(FrameworkError, match='material stop'):
        run005.execute_batches(campaign, SimpleNamespace(execute=execute),
                              [{'unit_id': 'u0'}, {'unit_id': 'u1'}])
    assert seen == ['u0']
    assert (output / 'batches/000001-start.json').exists()
    assert not (output / 'batches/000001-terminal.json').exists()


def test_run007_direct_legacy_entry_cannot_dispatch(tmp_path, monkeypatch):
    config = tmp_path / 'run007.json'
    config.write_text(json.dumps({'run_id': 'RUN007', 'campaign_attempt_id': 'authored'}))
    monkeypatch.setattr(run005, 'load_config', lambda *a, **k: pytest.fail('unvalidated campaign load'))
    with pytest.raises(FrameworkError, match='OWNER_AUTHORIZED_DISPATCH'):
        run005.run(SimpleNamespace(config=config))


def test_ordinary_error_cannot_close_batch_or_start_next(tmp_path):
    output = tmp_path / 'out'
    output.mkdir()
    guard = ResourceGuard(output, max_bytes=1024 * 1024)
    campaign = SimpleNamespace(output=output, config={'resource_budget': {'max_units_per_shard': 5}},
                               _guard=lambda: guard)
    seen = []

    def execute(unit_id):
        seen.append(unit_id)
        if unit_id == 'u0':
            raise ValueError('ordinary callback failure')
        return {'unit_id': unit_id}

    with pytest.raises(FrameworkError, match='RUN_BATCH_INCOMPLETE_NO_NEXT_BATCH'):
        run005.execute_batches(campaign, SimpleNamespace(execute=execute),
            [{'unit_id': f'u{i}'} for i in range(10)], receipt_reference=lambda c, r, u: r)
    assert seen == [f'u{i}' for i in range(5)]
    record = json.loads((output / 'batches/000001-incomplete.json').read_text())
    assert record['operations'][0]['terminal_receipt'] is None
    assert record['phase'] == 'INCOMPLETE'
    assert (output / 'batches/000001-incomplete.json').exists()
    assert not (output / 'batches/000001-terminal.json').exists()
    assert not (output / 'batches/000002-start.json').exists()
