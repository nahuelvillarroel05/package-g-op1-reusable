"""Preparation CLI validates committed dependencies without dispatch or writes."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_convergence_caller import fixture, reload, envelope
from runtime.candidate.run_framework.core import canonical, digest, FrameworkError
from runtime.candidate.run_framework.caller import validate_typed_result


def test_prepare_verifies_sources_and_plan_without_creating_namespace(tmp_path):
    campaign = fixture(tmp_path)
    root = str(tmp_path)
    result = subprocess.run([sys.executable, '-B', '-m', 'runtime.candidate.run_framework',
        'prepare', '--config', str(campaign.config_path), '--config-root', root,
        '--trusted-root', root, '--output-root', root, '--output', str(campaign.output)],
        capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report['units'] == 2 and report['shards'] == 1
    assert report['source_validation']['sources'] == 2
    assert report['started_units'] == 0
    assert not campaign.output.exists()


def test_prepare_rejects_auxiliary_substitution_without_dispatch(tmp_path):
    campaign = fixture(tmp_path)
    (tmp_path/'auxiliary.txt').write_bytes(b'substituted')
    root = str(tmp_path)
    result = subprocess.run([sys.executable, '-B', '-m', 'runtime.candidate.run_framework',
        'prepare', '--config', str(campaign.config_path), '--config-root', root,
        '--trusted-root', root, '--output-root', root, '--output', str(campaign.output)],
        capture_output=True, text=True)
    assert result.returncode != 0
    assert 'hash mismatch' in result.stderr.lower()
    assert not campaign.output.exists()


@pytest.mark.parametrize('field,value', [('adapter_version', 'incompatible'),
    ('predicate_contract', {'contract_id':'invented', 'version':'999'})])
def test_prepare_rejects_incompatible_typed_manifest_before_dispatch(tmp_path, field, value):
    campaign = fixture(tmp_path)
    cfg = json.loads(campaign.config_path.read_bytes())
    path = Path(cfg['dataset_manifest_path'])
    dataset = json.loads(path.read_bytes())
    if field == 'predicate_contract':
        value['sha256'] = cfg['predicate_contracts']['sha256']
    dataset['units'][0][field] = value
    path.write_bytes(canonical(dataset))
    cfg['input_manifest_sha256'] = digest(path.read_bytes())
    campaign.config_path.write_bytes(canonical(cfg))
    campaign = reload(campaign)
    root = str(tmp_path)
    result = subprocess.run([sys.executable, '-B', '-m', 'runtime.candidate.run_framework',
        'prepare', '--config', str(campaign.config_path), '--config-root', root,
        '--trusted-root', root, '--output-root', root, '--output', str(campaign.output)],
        capture_output=True, text=True)
    assert result.returncode != 0
    assert ('TYPED_ADAPTER_NOT_IN_REGISTRY' if field == 'adapter_version'
            else 'TYPED_PREDICATE_IDENTITY_MISMATCH') in result.stderr
    assert not campaign.output.exists()


def test_typed_payload_cannot_claim_official_result_type(tmp_path):
    campaign = fixture(tmp_path)
    result = envelope(campaign)
    result['result_type'] = 'OFFICIAL_EVALUATOR_ACCEPTANCE'
    with pytest.raises(FrameworkError, match='TYPED_RESULT_TYPE_MISMATCH'):
        validate_typed_result(campaign, 'u1', result)
