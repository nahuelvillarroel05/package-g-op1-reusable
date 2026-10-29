from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from runtime.candidate.context_engine import Engine, EngineError
from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.swebench_batching import (
    _source_refs,
    _validate_member_shape,
    bind_audit_stream,
    iter_audit_chunks,
)


def _ref(root: Path, name: str, *, role: str, binding: str = "INSTANCE_BOUND") -> dict:
    raw = json.dumps({"name": name}).encode()
    (root / name).write_bytes(raw)
    return {
        "path": name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "role": role,
        "parser_id": "synthetic-v1",
        "parser_version": "1",
        "instance_binding": binding,
    }


def _observation(index: int, ref: dict) -> dict:
    return {
        "observation_id": f"obs-{index}",
        "kind": "agent_statement",
        "run_id": "run-1",
        "instance_id": "UNKNOWN",
        "source_ref": {"path": ref["path"], "sha256": ref["sha256"], "pointer": ""},
    }


def _audit(refs: list[dict], observations: list[dict], execution: list[dict] | None = None) -> dict:
    return {
        "schema": "pgop1.swebench.generalized-audit.v1",
        "run_id": "run-1",
        "instance_id": "UNKNOWN",
        "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE",
        "observations": observations,
        "relationships": [],
        "SOURCE_PROVENANCE": {"evidence_references": refs},
        "EXECUTION_EVIDENCE": execution or [],
    }


def test_duplicate_provenance_and_execution_sources_count_once_and_keep_roles(tmp_path: Path) -> None:
    refs = [_ref(tmp_path, f"source-{index}.json", role="trajectory") for index in range(33)]
    execution = [dict(ref, role="execution_log") for ref in refs]
    audit = _audit(refs, [], execution)

    canonical = _source_refs(audit)

    assert len(canonical) == 33
    assert canonical[0]["roles"] == ["execution_log", "trajectory"]
    assert canonical[0]["parser_ids"] == ["synthetic-v1"]
    assert canonical[0]["instance_bindings"] == ["INSTANCE_BOUND"]
    _validate_member_shape("item", audit)


def test_conflicting_duplicate_source_commitment_is_rejected(tmp_path: Path) -> None:
    ref = _ref(tmp_path, "source.json", role="trajectory")
    conflict = dict(ref, sha256="0" * 64)

    with pytest.raises(AuditError, match="conflicting byte commitments"):
        _source_refs(_audit([ref], [], [conflict]))


def test_oversized_member_is_rejected_early_and_chunking_conserves_observations(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    ref = _ref(data, "source.json", role="trajectory")
    observations = [_observation(index, ref) for index in range(935)]
    audit = _audit([ref], observations)
    output = tmp_path / "oversized"

    result = bind_audit_stream([{"item_id": "large", "audit_result": audit}], data, output, batch_size=1)

    assert result["status"] == "PASS"
    assert result["rejected_item_count"] == 1
    assert result["rejections"] == [{"item_id": "large", "reason_code": "BATCH_MEMBER_TOO_LARGE"}]
    with sqlite3.connect(output / "batch-checkpoint.sqlite") as db:
        assert db.execute("SELECT status, detail FROM items WHERE item_id='large'").fetchone() == (
            "REJECTED", "BATCH_MEMBER_TOO_LARGE"
        )

    chunks = list(iter_audit_chunks(
        "large-source",
        {"run_id": "run-1", "instance_id": "UNKNOWN"},
        {"evidence_references": [ref]},
        observations,
    ))
    assert [len(chunk["audit_result"]["observations"]) for chunk in chunks] == [64] * 14 + [39]
    assert [row["observation_id"] for chunk in chunks for row in chunk["audit_result"]["observations"]] == [
        row["observation_id"] for row in observations
    ]


def test_legacy_lock_recovery_requires_proven_dead_owner(tmp_path: Path) -> None:
    engine = Engine(tmp_path / "engine")
    lock = engine.root / "writer.lock"
    lock.write_bytes(b"")
    with pytest.raises(EngineError, match="writer lock owner is empty"):
        with engine._lock():
            pytest.fail("empty legacy lock owner must not be guessed dead")

    lock.write_text("4000000000", encoding="ascii")

    with engine._lock():
        pass
    record = json.loads(lock.read_text(encoding="utf-8"))
    assert record["schema"] == "pgop1.context-engine-writer-lock.v1"

    lock.write_text(str(os.getpid()), encoding="ascii")
    before = lock.read_bytes()
    with pytest.raises(EngineError, match="legacy writer lock owner is still alive"):
        with engine._lock():
            pytest.fail("live legacy lock owner must not be recovered")
    assert lock.read_bytes() == before


def test_os_lock_blocks_live_writer_and_recovers_after_process_interruption(tmp_path: Path) -> None:
    root = tmp_path / "shared-engine"
    engine = Engine(root)
    script = """
import sys, time
from runtime.candidate.context_engine import Engine
engine = Engine(sys.argv[1])
with engine._lock():
    print('LOCKED', flush=True)
    time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(root)],
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "LOCKED"
        lock = root / "writer.lock"
        os.utime(lock, (1, 1))
        with pytest.raises(EngineError, match="writer lock is held by another process"):
            with engine._lock():
                pytest.fail("concurrent writer entered while another process holds the OS lock")
    finally:
        process.kill()
        process.wait(timeout=10)

    with engine._lock():
        pass
    assert json.loads((root / "writer.lock").read_text(encoding="utf-8"))["pid"] == os.getpid()
