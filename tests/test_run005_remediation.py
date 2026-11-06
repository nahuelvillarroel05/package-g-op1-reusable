"""Prospective RUN005 regressions; authored fixtures, never RUN004 redispatch."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from runtime.candidate.run_framework import core
from runtime.candidate.run_framework.core import FrameworkError, canonical, digest
from runtime.candidate.run_framework.e1 import verified_receipt_reference
from test_run_checkpoint_v2 import _campaign, _envelope


def snapshot(root):
    return {p.relative_to(root).as_posix(): digest(p.read_bytes())
            for p in root.rglob('*') if p.is_file()}


def test_receipt_bytes_reference_recovery_and_summary_substitution(tmp_path):
    c = _campaign(tmp_path)
    c.begin_unit('u1', {})
    summary = c.complete_unit('u1', 'DONE', _envelope(c, 'u1'))
    binding = verified_receipt_reference(c, summary, 'u1')
    assert binding['sha256'] == digest(Path(binding['path']).read_bytes())
    assert binding['sha256'] != digest(canonical(summary))
    assert _campaign(tmp_path).recover()['completed'] == {'u1'}
    with pytest.raises(FrameworkError, match='IDENTITY_OR_HASH'):
        verified_receipt_reference(c, dict(summary, sha256=digest(canonical(summary))), 'u1')
    with pytest.raises(FrameworkError, match='IDENTITY_OR_HASH'):
        verified_receipt_reference(c, summary, 'u2')
    Path(binding['path']).write_bytes(b'{}')
    with pytest.raises(FrameworkError):
        verified_receipt_reference(c, summary, 'u1')
    with pytest.raises(FrameworkError):
        _campaign(tmp_path).recover()


def test_v2_cli_recovery_fresh_process_has_preflight_and_no_writes(tmp_path):
    c = _campaign(tmp_path)
    c.begin_unit('u1', {})
    c.complete_unit('u1', 'DONE', _envelope(c, 'u1'))
    before = snapshot(c.output)
    cmd = [sys.executable, '-B', '-m', 'runtime.candidate.run_framework', 'recover',
           '--config', str(c.config_path), '--config-root', str(tmp_path),
           '--trusted-root', str(tmp_path), '--output-root', str(tmp_path), '--output', str(c.output)]
    proc = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result['completed'] == ['u1'] and result['pending'] == ['u2']
    assert result['inflight'] == [] and len(result['checkpoints']) == 1
    assert snapshot(c.output) == before
    # A changed checkpoint must fail on the same actual CLI path.
    checkpoint = next((c.output / 'checkpoints').glob('*.json'))
    checkpoint.write_bytes(b'{}')
    failed = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[1],
                            capture_output=True, text=True, timeout=30)
    assert failed.returncode != 0


def test_committed_cache_retains_live_same_stat_code_checks(tmp_path, monkeypatch):
    calls = []
    original = core._verify_committed_code
    def counted(*args):
        calls.append(True)
        return original(*args)
    monkeypatch.setattr(core, '_verify_committed_code', counted)
    c = _campaign(tmp_path)
    assert len(calls) == 1
    c.preflight()
    assert len(calls) == 1
    code = Path(c.config['code_files'][0]['path'])
    st = code.stat()
    raw = code.read_bytes()
    code.write_bytes(raw.replace(b'1', b'2'))
    os.utime(code, ns=(st.st_atime_ns, st.st_mtime_ns))
    with pytest.raises(FrameworkError, match='byte hash mismatch'):
        c.preflight()
    assert len(calls) == 1


def test_committed_cache_does_not_cache_mutated_input(tmp_path):
    c = _campaign(tmp_path)
    source = Path(c.config['input_bindings'][0]['path'])
    original = source.read_bytes()
    st = source.stat()
    source.write_bytes(original.replace(b'1', b'2'))
    os.utime(source, ns=(st.st_atime_ns, st.st_mtime_ns))
    with pytest.raises(FrameworkError, match='byte hash mismatch'):
        c.preflight()
