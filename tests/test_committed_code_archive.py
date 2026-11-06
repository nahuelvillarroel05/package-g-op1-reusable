"""Exact byte controls for the batched committed-code reader; no extraction."""
import io
import tarfile
from types import SimpleNamespace

import pytest

from runtime.candidate.run_framework import core


def archive_bytes(rows):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, raw, kind in rows:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(raw) if kind == tarfile.REGTYPE else 0
            archive.addfile(info, io.BytesIO(raw) if info.size else None)
    return output.getvalue()


def test_all_exact_committed_bytes_in_one_git_call(tmp_path, monkeypatch):
    rows = [("one.py", b"first", tarfile.REGTYPE), ("two.py", b"second", tarfile.REGTYPE)]
    bindings = []
    for name, raw, kind in rows:
        p = tmp_path / name
        p.write_bytes(raw)
        bindings.append({"path": str(p), "sha256": core.digest(raw)})
    calls = []
    def fake(root, *args, binary=False):
        calls.append((root, args, binary))
        return SimpleNamespace(stdout=archive_bytes(rows))
    monkeypatch.setattr(core, "_git_read", fake)
    core._verify_committed_code(tmp_path, "abc123", bindings)
    assert len(calls) == 1
    assert calls[0][1] == ("archive", "--format=tar", "abc123", "--", "one.py", "two.py")
    assert not list(tmp_path.glob("*.tar"))


@pytest.mark.parametrize("rows", [
    [("one.py", b"wrong", tarfile.REGTYPE)],
    [],
    [("one.py", b"", tarfile.SYMTYPE)],
    [("one.py", b"first", tarfile.REGTYPE), ("one.py", b"first", tarfile.REGTYPE)],
    [("../escape.py", b"first", tarfile.REGTYPE)],
])
def test_missing_changed_duplicate_or_unsafe_members_rejected(tmp_path, monkeypatch, rows):
    p = tmp_path / "one.py"
    p.write_bytes(b"first")
    monkeypatch.setattr(core, "_git_read", lambda *a, **kw: SimpleNamespace(stdout=archive_bytes(rows)))
    with pytest.raises(core.FrameworkError):
        core._verify_committed_code(tmp_path, "abc123", [{"path": str(p), "sha256": core.digest(b"first")}])
