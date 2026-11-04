"""Preparation CLI validates committed dependencies without dispatch or writes."""
import json
import subprocess
import sys

from test_convergence_caller import fixture


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
