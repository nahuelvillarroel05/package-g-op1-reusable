from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.candidate import context_engine
from runtime.candidate.context_engine import Engine, EngineError


def _committed_store(root: Path) -> tuple[Engine, str]:
    engine = Engine(root)
    event = {"event_id": "evt-001", "state": "observed"}
    event_path = root / "synthetic-event.json"
    raw = json.dumps(event, sort_keys=True, separators=(",", ":")).encode("utf-8")
    event_path.write_bytes(raw)
    descriptor = engine.admit_source(
        event_path, hashlib.sha256(raw).hexdigest(), scope="SYNTHETIC", source_id="event-source-001"
    )
    manifest = engine.ingest([{
        "id": "observation-001",
        "kind": "synthetic_event",
        "task_id": "task-001",
        "event_id": "evt-001",
        "source_id": descriptor["source_id"],
        "evidence_pointer": "",
        "value": event,
    }])
    assert manifest["version"] == 1
    return engine, "observation-001"


def test_corrupt_index_is_preserved_and_recovered_in_fresh_process(tmp_path: Path) -> None:
    root = tmp_path / "context"
    _committed_store(root)
    index = root / "index.sqlite"
    corrupt_bytes = b"not a sqlite database: preserve these bytes"
    index.write_bytes(corrupt_bytes)

    code = (
        "import json,sys; sys.path.insert(0,sys.argv[1]); "
        "from runtime.candidate.context_engine import Engine; "
        "e=Engine(sys.argv[2]); rows=e.query(task_id='task-001'); "
        "print(json.dumps({'verify':e.verify(),'rows':rows,'reconstruction':"
        "e.metrics['RECONSTRUCTION_REQUIRED']}))"
    )
    repo_root = Path(__file__).resolve().parents[1]
    child = subprocess.run(
        [sys.executable, "-I", "-B", "-c", code, str(repo_root), str(root)],
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert child.returncode == 0, child.stderr
    result = json.loads(child.stdout)
    assert result["verify"]["status"] == "PASS"
    assert [row["id"] for row in result["rows"]] == ["observation-001"]
    assert result["reconstruction"] is True
    quarantined = list(root.glob("index.sqlite.corrupt-*"))
    assert len(quarantined) == 1
    assert quarantined[0].read_bytes() == corrupt_bytes


def test_repeated_open_after_recovery_uses_rebuilt_index(tmp_path: Path) -> None:
    root = tmp_path / "context"
    _committed_store(root)
    (root / "index.sqlite").write_bytes(b"broken")

    recovered = Engine(root)
    assert recovered.metrics["RECONSTRUCTION_REQUIRED"] is True
    assert len(recovered.query(task_id="task-001")) == 1

    repeated = Engine(root)
    assert repeated.metrics["RECONSTRUCTION_REQUIRED"] is False
    assert len(repeated.query(task_id="task-001")) == 1
    assert len(list(root.glob("index.sqlite.corrupt-*"))) == 1


def test_valid_but_drifted_index_is_rebuilt_without_quarantine(tmp_path: Path) -> None:
    root = tmp_path / "context"
    _committed_store(root)
    with sqlite3.connect(root / "index.sqlite") as db:
        db.execute("UPDATE observations SET body=? WHERE id=?", ('{}', "observation-001"))

    engine = Engine(root)
    assert engine.metrics["RECONSTRUCTION_REQUIRED"] is True
    assert [row["id"] for row in engine.query(task_id="task-001")] == ["observation-001"]
    assert not list(root.glob("index.sqlite.corrupt-*"))


def test_missing_index_table_is_rebuilt_without_quarantine(tmp_path: Path) -> None:
    root = tmp_path / "context"
    _committed_store(root)
    with sqlite3.connect(root / "index.sqlite") as db:
        db.execute("DROP TABLE observations")

    engine = Engine(root)
    assert engine.metrics["RECONSTRUCTION_REQUIRED"] is True
    assert [row["id"] for row in engine.query(task_id="task-001")] == ["observation-001"]
    assert not list(root.glob("index.sqlite.corrupt-*"))


def test_operational_sqlite_error_propagates_without_quarantine(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "context"
    _committed_store(root)
    index_bytes = (root / "index.sqlite").read_bytes()

    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(context_engine.sqlite3, "connect", unavailable)
    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        Engine(root)
    assert (root / "index.sqlite").read_bytes() == index_bytes
    assert not list(root.glob("index.sqlite.corrupt-*"))


def test_corrupt_index_does_not_mask_authoritative_source_tampering(tmp_path: Path) -> None:
    root = tmp_path / "context"
    _committed_store(root)
    source_object = next((root / "objects").iterdir())
    source_object.write_bytes(b"tampered")
    (root / "index.sqlite").write_bytes(b"broken")

    with pytest.raises(EngineError, match="source object tampering"):
        Engine(root)
    assert (root / "index.sqlite").read_bytes() == b"broken"
    assert not list(root.glob("index.sqlite.corrupt-*"))
