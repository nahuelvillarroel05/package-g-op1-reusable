# SPDX-License-Identifier: Apache-2.0
"""Exercise exact public integrity verification in a disposable synthetic Git repo."""
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

VERIFIER = Path(__file__).resolve().parents[1] / 'tools' / 'verify_public_tree.py'


@pytest.mark.parametrize('corruption', ['bytes', 'missing', 'membership', 'duplicate'])
def test_clean_manifest_passes_and_corruption_fails(tmp_path, corruption):
    (tmp_path / 'tools').mkdir()
    (tmp_path / 'manifests').mkdir()
    script = tmp_path / 'tools' / VERIFIER.name
    shutil.copyfile(VERIFIER, script)
    member = tmp_path / 'fixture.txt'
    member.write_bytes(b'public synthetic fixture\n')
    manifest = tmp_path / 'manifests' / 'PUBLIC_TREE_MANIFEST.json'
    manifest.write_text(json.dumps({'files': [], 'member_count': 0, 'I7_STATUS': 'INCOMPLETE'}))
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    subprocess.run(['git', 'add', '.'], cwd=tmp_path, check=True)

    def run(*args):
        return subprocess.run([sys.executable, '-B', str(script), *args], cwd=tmp_path,
                              capture_output=True, text=True, timeout=30)

    written = run('--write')
    assert written.returncode == 0, written.stderr
    assert run().returncode == 0
    if corruption == 'bytes':
        member.write_bytes(b'changed synthetic fixture\n')
    elif corruption == 'missing':
        member.unlink()
    elif corruption == 'membership':
        (tmp_path / 'extra.txt').write_bytes(b'unlisted\n')
        subprocess.run(['git', 'add', 'extra.txt'], cwd=tmp_path, check=True)
    else:
        data = json.loads(manifest.read_text())
        data['files'].append(data['files'][0])
        data['member_count'] += 1
        manifest.write_text(json.dumps(data))
    assert run().returncode != 0, 'corrupt public tree was accepted'
