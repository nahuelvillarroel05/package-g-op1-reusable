"""Prospective Windows recovery tests using disposable synthetic lock files."""
import json
import os
import subprocess
import sys

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.campaign import (
    _acquire_campaign_writer_lock,
    _release_campaign_writer_lock,
)


def test_dead_process_lock_recovers_only_with_explicit_resume(tmp_path):
    lock = tmp_path / 'writer.json'
    code = (
        'from pathlib import Path; '
        'from runtime.candidate.swebench_claim_audit.campaign import _acquire_campaign_writer_lock; '
        f'owner=_acquire_campaign_writer_lock(Path({str(lock)!r}),resume=False); '
        'import os; print(os.getpid(),flush=True); os._exit(0)'
    )
    child = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stderr
    owner_pid = int(child.stdout.strip())
    original = lock.read_bytes()
    assert json.loads(original)['pid'] == owner_pid
    assert json.loads(original)['state'] == 'ACTIVE'
    with pytest.raises(AuditError) as refused:
        _acquire_campaign_writer_lock(lock, resume=False)
    assert refused.value.code == 'CAMPAIGN_WRITER_PRESENT'
    assert lock.read_bytes() == original
    resumed = _acquire_campaign_writer_lock(lock, resume=True)
    try:
        resumed.seek(0)
        assert json.loads(resumed.read())['pid'] == os.getpid()
    finally:
        _release_campaign_writer_lock(resumed)
    assert json.loads(lock.read_bytes())['state'] == 'RELEASED'


def test_live_declared_owner_is_not_stolen_when_os_lock_is_not_held(tmp_path):
    lock = tmp_path / 'writer.json'
    original = json.dumps({'pid': os.getpid(), 'state': 'ACTIVE'}).encode()
    lock.write_bytes(original)
    with pytest.raises(AuditError) as refused:
        _acquire_campaign_writer_lock(lock, resume=True)
    assert refused.value.code == 'CAMPAIGN_WRITER_PRESENT'
    assert lock.read_bytes() == original
