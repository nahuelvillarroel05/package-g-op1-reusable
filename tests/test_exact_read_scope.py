import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from runtime.candidate.run_framework.read_scope import install_read_scope


def _run_child(script, *args):
    completed = subprocess.run(
        [sys.executable, "-c", script, *(str(arg) for arg in args)],
        capture_output=True, text=True, check=False, timeout=15,
    )
    return completed


def _scope_script(operation):
    return f"""
import json
from pathlib import Path
from runtime.candidate.run_framework.read_scope import install_read_scope
root, allowed, target = map(Path, __import__('sys').argv[1:4])
guard = install_read_scope([root], [allowed])
{operation}
"""


def _fixture_paths(tmp_path):
    root = tmp_path / "protected"
    root.mkdir()
    allowed = root / "allowed.txt"
    allowed.write_text("synthetic allowed body", encoding="utf-8")
    sibling = root / "sibling.txt"
    sibling.write_text("synthetic sibling body", encoding="utf-8")
    return root, allowed, sibling


def test_exact_path_is_allowed_and_scope_metadata_is_frozen(tmp_path):
    root, allowed, _ = _fixture_paths(tmp_path)
    completed = _run_child(_scope_script("""
assert guard.allowed_sources == frozenset({allowed.resolve()})
assert guard.protected_roots == frozenset({root.resolve()})
assert isinstance(guard.denied_events, tuple) and guard.denied_events == ()
try:
    guard.denied_events = ()
except AttributeError:
    pass
else:
    raise AssertionError("denied_events must be read-only")
try:
    guard.allowed_sources.add(target.resolve())
except AttributeError:
    pass
else:
    raise AssertionError("allowlist must be immutable")
assert allowed.read_text(encoding="utf-8") == "synthetic allowed body"
assert guard.denied_events == ()
print(json.dumps({"status": "ALLOWED", "denied": len(guard.denied_events)}))
"""), root, allowed, allowed)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"status": "ALLOWED", "denied": 0}


def test_sibling_read_is_denied_within_protected_root(tmp_path):
    root, allowed, sibling = _fixture_paths(tmp_path)
    completed = _run_child(_scope_script("""
try:
    target.read_text(encoding="utf-8")
except PermissionError:
    pass
else:
    raise AssertionError("sibling read unexpectedly allowed")
assert len(guard.denied_events) == 1
assert guard.denied_events[0].path == str(target.resolve())
print(json.dumps({"status": "DENIED", "path": guard.denied_events[0].path}))
"""), root, allowed, sibling)
    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed == {"status": "DENIED", "path": str(sibling.resolve())}


@pytest.mark.parametrize("operation", ["os_open_read", "builtin_readwrite"])
def test_read_modes_are_denied_for_path_and_readwrite_open(tmp_path, operation):
    root, allowed, sibling = _fixture_paths(tmp_path)
    if operation == "os_open_read":
        body = """
import os
try:
    fd = os.open(target, os.O_RDONLY)
except PermissionError:
    pass
else:
    os.close(fd)
    raise AssertionError("os.open read unexpectedly allowed")
"""
    else:
        body = """
try:
    with target.open("r+") as stream:
        stream.write("must not open")
except PermissionError:
    pass
else:
    raise AssertionError("r+ unexpectedly allowed")
"""
    completed = _run_child(_scope_script(body + """
assert len(guard.denied_events) == 1
print(json.dumps({"status": "DENIED", "mode": guard.denied_events[0].mode,
                  "flags": guard.denied_events[0].flags}))
"""), root, allowed, sibling)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "DENIED"


def test_os_open_integer_mode_and_flags_detect_readwrite(tmp_path):
    root, allowed, sibling = _fixture_paths(tmp_path)
    completed = _run_child(_scope_script("""
import os
try:
    fd = os.open(target, os.O_RDWR | os.O_CREAT, 0o600)
except PermissionError:
    pass
else:
    os.close(fd)
    raise AssertionError("read/write os.open unexpectedly allowed")
assert len(guard.denied_events) == 1
assert guard.denied_events[0].mode is None
assert guard.denied_events[0].flags & (os.O_WRONLY | os.O_RDWR) == os.O_RDWR
print(json.dumps({"status": "DENIED", "mode": guard.denied_events[0].mode,
                  "flags": guard.denied_events[0].flags}))
"""), root, allowed, sibling)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "DENIED"


def test_write_only_open_under_protected_root_is_not_blocked(tmp_path):
    root, allowed, sibling = _fixture_paths(tmp_path)
    output = root / "synthetic-write-only.txt"
    completed = _run_child(_scope_script("""
with target.open("w", encoding="utf-8") as stream:
    stream.write("synthetic write")
print(json.dumps({"status": "WRITE_ALLOWED", "denied": len(guard.denied_events)}))
"""), root, allowed, output)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"status": "WRITE_ALLOWED", "denied": 0}
    assert output.read_text(encoding="utf-8") == "synthetic write"


def test_install_rejects_alias_reparse_path_when_supported(tmp_path):
    root, allowed, _ = _fixture_paths(tmp_path)
    alias = root / "alias.txt"
    try:
        alias.symlink_to(allowed)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    completed = _run_child("""
from pathlib import Path
from runtime.candidate.run_framework.read_scope import install_read_scope
root, alias = map(Path, __import__('sys').argv[1:3])
try:
    install_read_scope([root], [alias])
except (OSError, RuntimeError, ValueError):
    print("REPARSE_REJECTED")
else:
    raise AssertionError("reparse alias unexpectedly accepted")
""", root, alias)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "REPARSE_REJECTED"


def test_runtime_rejects_alias_reparse_path_into_protected_root_when_supported(tmp_path):
    root, allowed, _ = _fixture_paths(tmp_path)
    alias = root / "runtime-alias.txt"
    try:
        alias.symlink_to(allowed)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    completed = _run_child(_scope_script("""
try:
    target.read_text(encoding="utf-8")
except PermissionError:
    pass
else:
    raise AssertionError("reparse alias unexpectedly allowed")
assert len(guard.denied_events) == 1
print(json.dumps([event._asdict() for event in guard.denied_events]))
"""), root, allowed, alias)
    assert completed.returncode == 0, completed.stderr
    events = json.loads(completed.stdout)
    assert events[0]["reason"] == "reparse path component rejected"


def test_captured_trusted_git_version_subprocess_uses_allowed_ipc_descriptors(tmp_path):
    git = shutil.which("git")
    if git is None:
        pytest.skip("git executable unavailable")
    root, allowed, _ = _fixture_paths(tmp_path)
    completed = _run_child(_scope_script("""
import subprocess
git = __import__('sys').argv[4]
result = subprocess.run([git, "--version"], capture_output=True, text=True, check=True)
assert result.stdout.startswith("git version ")
assert guard.denied_events == ()
print(json.dumps({"status": "CAPTURED", "stdout": result.stdout.strip()}))
"""), root, allowed, allowed, git)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "CAPTURED"


def test_regular_integer_file_descriptor_remains_denied(tmp_path):
    root, allowed, _ = _fixture_paths(tmp_path)
    regular = tmp_path / "regular-outside-protected-root.txt"
    regular.write_text("synthetic regular descriptor body", encoding="utf-8")
    completed = _run_child(_scope_script("""
import os
fd = os.open(target, os.O_RDONLY)
try:
    try:
        stream = open(fd, "rb")
    except PermissionError:
        pass
    else:
        stream.close()
        raise AssertionError("unidentified regular descriptor unexpectedly allowed")
finally:
    os.close(fd)
assert len(guard.denied_events) == 1
assert guard.denied_events[0].reason == "unresolved or non-IPC file descriptor"
print(json.dumps({"status": "DENIED", "events": [e._asdict() for e in guard.denied_events]}))
"""), root, allowed, regular)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["status"] == "DENIED"
