# SPDX-License-Identifier: Apache-2.0
"""Verify deliberate publication exclusions fail before external source reads."""
from pathlib import Path
import importlib.util
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    path = ROOT / 'runtime' / 'candidate' / (name + '.py')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

policy = load('documents_policy')
class Refused(ValueError):
    def __init__(self, code, message): self.code = code
cli = SimpleNamespace(I7Error=Refused, FOCUSED_ROOT=ROOT / 'runtime')
try:
    policy._policy_root_path(cli, 'engineering')
except Refused as exc:
    assert exc.code == 'DOCUMENT_POLICY_DISABLED_PUBLIC_EXPORT'
else:
    raise AssertionError('private engineering corpus policy was enabled')

# Preserve the original Unicode path guards across UTF-8 public sanitization.
assert 'COM1\u00b9' in policy._RESERVED
for name in ('COM1\u00b9', 'LPT1\u00b2', 'COM2\u00b3'):
    try:
        policy._safe_relative(cli, name)
    except Refused as exc:
        assert exc.code == 'DOCUMENT_SELECTION_PATH_INVALID'
    else:
        raise AssertionError('reserved document path suffix was accepted')
runtime_cli = load('pg_i7')
for name in ('COM\u00b9', 'LPT\u00b2', 'COM\u00b3'):
    try:
        runtime_cli._checked_absolute(name, base=ROOT, must_exist=False)
    except runtime_cli.I7Error as exc:
        assert str(exc.code) == 'WINDOWS_PATH_COMPONENT_REJECTED'
    else:
        raise AssertionError('reserved Windows device name was accepted')

sidecar = load('evidence_sidecar')
with tempfile.TemporaryDirectory() as directory:
    target = Path(directory)
    try:
        sidecar.build_artifacts('OP-public-negative', 'UNKNOWN', 'safe.synthetic.totals.v1',
                                {}, {}, target, {'provenance': True})
    except sidecar.EvidenceSidecarError as exc:
        assert str(exc) == 'FROZEN_I5_FIXTURE_UNAVAILABLE_PUBLIC_EXPORT', exc
    else:
        raise AssertionError('unavailable original fixture provenance was accepted')
    assert list(target.iterdir()) == [], 'formal fixture refusal wrote partial evidence'
print({'status': 'PASS', 'private_policy': 'DISABLED', 'formal_fixture_provenance': 'EXPLICITLY_REFUSED',
       'sidecar_files_written': 0, 'native_dispatches': 0})
