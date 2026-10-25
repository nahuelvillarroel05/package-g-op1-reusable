# SPDX-License-Identifier: Apache-2.0
"""Check exact public Git membership and bytes; --write updates the derivative manifest."""
from pathlib import Path, PurePosixPath
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'manifests/PUBLIC_TREE_MANIFEST.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Rehash reviewed Git index members')
    args = parser.parse_args()
    tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().strip('\0').split('\0'))
    for name in tracked:
        rel = PurePosixPath(name)
        path = ROOT / name
        if rel.is_absolute() or '..' in rel.parts or path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise ValueError('Unsafe Git member')
    manifest = json.loads((ROOT / MANIFEST).read_bytes())
    if args.write:
        manifest['files'] = [
            {'path': name, 'bytes': len((ROOT / name).read_bytes()),
             'sha256': hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}
            for name in sorted(tracked - {MANIFEST})]
        manifest['member_count'] = len(manifest['files'])
        (ROOT / MANIFEST).write_bytes((json.dumps(manifest, indent=2) + '\n').replace('\n', '\r\n').encode())
    rows = manifest['files']
    names = [r['path'] for r in rows]
    if len(names) != len(set(names)) or len(rows) != manifest['member_count']:
        raise ValueError('Duplicate member or invalid member count')
    if set(names) != tracked - {MANIFEST}:
        raise ValueError('Manifest and Git tracked membership differ')
    for row in rows:
        name = row['path']
        path = ROOT / name
        data = path.read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('Member bytes differ: ' + name)
    print(json.dumps({'status': 'PASS', 'members': len(rows), 'membership': 'EXACT_GIT_TRACKED',
                      'I7_STATUS': manifest['I7_STATUS']}))


if __name__ == '__main__':
    main()
