from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import itertools

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.swebench_batching import (
    bind_audit_stream,
    iter_audit_chunks,
    recover_audit_stream,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _item(root: Path, item_id: str, *, span: list[int] | None = None) -> dict:
    path = f"{item_id}.json"
    raw = json.dumps({"item": item_id}).encode()
    (root / path).write_bytes(raw)
    ref = {"path": path, "sha256": _sha(raw), "bytes": len(raw), "role": "trajectory",
           "parser_id": "synthetic-v1", "parser_version": "1", "instance_binding": "RUN_ONLY"}
    observation = {"observation_id": "obs", "kind": "agent_statement", "run_id": "run-1",
                   "instance_id": "UNKNOWN", "claim_id": "claim", "value": "resolved",
                   "source_ref": {"path": path, "sha256": _sha(raw), "pointer": ""},
                   "parser_id": "synthetic-v1", "parser_version": "1"}
    if span is not None:
        observation["source_span"] = span
    return {"item_id": item_id, "audit_result": {
        "schema": "pgop1.swebench.generalized-audit.v1", "run_id": "run-1",
        "instance_id": "UNKNOWN", "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE",
        "observations": [observation], "relationships": [],
        "SOURCE_PROVENANCE": {"evidence_references": [ref]}, "EXECUTION_EVIDENCE": [],
    }}


def test_stream_batches_are_bounded_deterministic_and_preserve_spans(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    items = [_item(data, f"item-{n}", span=[n, n + 2]) for n in range(3)]
    output = tmp_path / "out"
    bound = bind_audit_stream(iter(items), data, output, batch_size=2)
    assert bound["status"] == "PASS"
    assert bound["batch_count"] == 2
    assert bound["completed_item_count"] == 3
    first_capsule = output / "batch-000000" / "normalized-audit-capsule.json"
    capsule = json.loads(first_capsule.read_bytes())
    member_rows = [row for row in capsule["audit_result"]["observations"]
                   if row.get("kind") == "agent_statement"]
    assert [row["source_span"] for row in member_rows] == [[0, 2], [1, 3]]
    assert [row["batch_member_id"] for row in member_rows] == ["item-0", "item-1"]
    recovered = recover_audit_stream(output)
    assert recovered["status"] == "PASS"
    assert recovered["recovered_batch_count"] == 2


def test_duplicate_ids_replay_mismatch_and_invalid_batch_size_are_explicit(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    first = _item(data, "same")
    with pytest.raises(AuditError, match="batch_size"):
        bind_audit_stream([first], data, tmp_path / "bad", batch_size=0)
    result = bind_audit_stream([first], data, tmp_path / "out", batch_size=1)
    assert result["completed_item_count"] == 1
    replay = bind_audit_stream([first], data, tmp_path / "out", batch_size=1, resume=True)
    assert replay["status"] == "PASS"
    changed = _item(data, "same", span=[9, 10])
    with pytest.raises(AuditError, match="replayed item differs"):
        bind_audit_stream([changed], data, tmp_path / "out", batch_size=1, resume=True)


def test_recovery_runs_in_fresh_process(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    output = tmp_path / "out"
    bind_audit_stream([_item(data, "fresh")], data, output, batch_size=1)
    code = ("import json,sys; from pathlib import Path; "
            "sys.path.insert(0,sys.argv[1]); "
            "from runtime.candidate.swebench_claim_audit.swebench_batching import recover_audit_stream; "
            "print(json.dumps(recover_audit_stream(sys.argv[2])))")
    repo = Path(__file__).resolve().parents[1]
    proc = subprocess.run([sys.executable, "-B", "-I", "-c", code, str(repo), str(output)],
                          capture_output=True, text=True, check=True)
    assert json.loads(proc.stdout)["recovered_batch_count"] == 1


def test_twenty_thousand_observations_stream_in_bounded_chunks(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    path = "large-source.json"
    raw = b'{"rows":[]}'
    (data / path).write_bytes(raw)
    ref = {"path": path, "sha256": _sha(raw), "bytes": len(raw), "role": "trajectory",
           "parser_id": "synthetic-v1", "parser_version": "1", "instance_binding": "RUN_ONLY"}

    def observations():
        for number in range(20_000):
            yield {"observation_id": f"observation-{number:05d}", "kind": "synthetic_record",
                   "run_id": "large-run", "instance_id": "UNKNOWN", "value": number,
                   "source_span": [number, number + 1],
                   "source_ref": {"path": path, "sha256": _sha(raw), "pointer": "/rows"},
                   "parser_id": "synthetic-v1", "parser_version": "1"}

    metadata = {"run_id": "large-run", "instance_id": "UNKNOWN",
                "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE"}
    def chunks():
        return iter_audit_chunks("large-run", metadata,
                                 {"evidence_references": [ref]}, observations())

    count = 0
    max_chunk = 0
    for chunk in chunks():
        rows = chunk["audit_result"]["observations"]
        count += len(rows)
        max_chunk = max(max_chunk, len(rows))
    assert count == 20_000
    assert max_chunk == 64

    bound = bind_audit_stream(itertools.islice(chunks(), 16), data, tmp_path / "large-out", batch_size=16)
    assert bound["status"] == "PASS"
    assert bound["completed_item_count"] == 16
    assert bound["batch_count"] == 16  # Readback argument bound gives one chunk per Context Engine root.
    recovered = recover_audit_stream(tmp_path / "large-out")
    assert recovered["recovered_batch_count"] == 16


def test_actual_process_interruption_resumes_after_durable_batch(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    records = [_item(data, "restart-a"), _item(data, "restart-b")]
    input_path = tmp_path / "records.json"
    input_path.write_bytes(json.dumps(records).encode())
    output = tmp_path / "restart-out"
    repo = Path(__file__).resolve().parents[1]
    child = """import json,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from runtime.candidate.swebench_claim_audit.swebench_batching import bind_audit_stream
rows=json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))
if sys.argv[5]=='interrupt':
 def source():
  yield rows[0]
  os._exit(23)
 bind_audit_stream(source(),sys.argv[2],sys.argv[4],batch_size=1)
else:
 print(json.dumps(bind_audit_stream(rows,sys.argv[2],sys.argv[4],batch_size=1,resume=True)))
"""
    interrupted = subprocess.run([sys.executable, "-B", "-I", "-c", child, str(repo), str(data),
                                  str(input_path), str(output), "interrupt"], capture_output=True)
    assert interrupted.returncode == 23
    assert (output / "batch-000000" / "generalized-bridge-receipt.json").is_file()
    resumed = subprocess.run([sys.executable, "-B", "-I", "-c", child, str(repo), str(data),
                              str(input_path), str(output), "resume"],
                             capture_output=True, text=True, check=True)
    result = json.loads(resumed.stdout)
    assert result["completed_item_count"] == 2
    assert result["batch_count"] == 2
    recovered = recover_audit_stream(output)
    assert recovered["status"] == "PASS"
    assert recovered["recovered_batch_count"] == 2


def test_invalid_member_is_counted_once_and_valid_following_input_binds(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    valid = _item(data, "after-invalid")
    invalid = {"item_id": "bad", "audit_result": {"schema": "wrong"}}
    result = bind_audit_stream([invalid, valid], data, tmp_path / "mixed", batch_size=2)
    assert result["rejected_item_count"] == 1
    assert result["rejections"] == [{"item_id": "bad", "reason_code": "BATCH_INPUT_INVALID"}]
    assert result["completed_item_count"] == 1

    malformed_root = tmp_path / "malformed"
    first = bind_audit_stream([None, valid], data, malformed_root, batch_size=2)
    assert first["completed_item_count"] == 1
    assert first["rejected_item_count"] == 1
    replay = bind_audit_stream([None, valid], data, malformed_root, batch_size=2, resume=True)
    assert replay["completed_item_count"] == 1
    assert replay["rejected_item_count"] == 1


def test_run_only_source_does_not_mint_instance_graph_binding(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    record = _item(data, "run-only")
    record["audit_result"]["instance_id"] = "requested-instance"
    record["audit_result"]["observations"][0]["instance_id"] = "requested-instance"
    result = bind_audit_stream([record], data, tmp_path / "run-only-out", batch_size=1)
    assert result["status"] == "PASS"
    capsule = json.loads((tmp_path / "run-only-out" / "batch-000000" /
                          "normalized-audit-capsule.json").read_bytes())
    member = next(row for row in capsule["audit_result"]["observations"]
                  if row.get("kind") == "agent_statement")
    assert member["instance_id"] == "UNKNOWN"
    assert member["requested_instance_id"] == "requested-instance"


def test_rejection_ledger_tampering_is_detected(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    output = tmp_path / "rejection-ledger"
    invalid = {"item_id": "bad", "audit_result": {"schema": "wrong"}}
    result = bind_audit_stream([invalid], data, output, batch_size=1)
    assert result["rejected_item_count"] == 1
    import sqlite3
    with sqlite3.connect(output / "batch-checkpoint.sqlite") as db:
        db.execute("UPDATE rejections SET reason_code='TAMPERED'")
    with pytest.raises(AuditError, match="rejection ledger hash chain"):
        recover_audit_stream(output)
