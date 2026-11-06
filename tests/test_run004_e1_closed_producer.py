"""Authored controls for the closed E1 processor; no benchmark source reads."""
import json
import pytest

from runtime.candidate.run_framework.core import FrameworkError, digest
from runtime.candidate.run_framework.e1 import bounded, process_definition, MAX_INPUT
from runtime.candidate.run_framework.e1 import (
    validate_attempt_id, check_prior_state, write_writer, BATCH_RESERVE,
    SHARD_MAX_BYTES, WRITER_MAX_BYTES,
)


def unit(tmp_path, family, raw, **extra):
    path = tmp_path / "definition.json"
    path.write_bytes(raw)
    return {"source_path": str(path), "source_sha256": digest(raw), "benchmark_id": family, **extra}


def test_bfcl_processes_exact_selected_row(tmp_path):
    u = unit(tmp_path, "bfcl_v4", b'{"id":"example_0"}\n{"id":"example_1"}\n',
             source_row_index=1, task_id="example_1")
    assert process_definition(u, {}) == {"definition": True}


def test_bfcl_mismatched_row_cannot_be_processed(tmp_path):
    u = unit(tmp_path, "bfcl_v4", b'{"id":"example_0"}\n', source_row_index=0, task_id="different")
    with pytest.raises(ValueError, match="SELECTED_ROW_ID_MISMATCH"):
        process_definition(u, {})


def test_bfcl_json_array_processes_selected_row(tmp_path):
    u = unit(tmp_path, "bfcl_v4", b'[{"id":"example_0"},{"id":"example_1"}]',
             source_row_index=1, task_id="example_1")
    assert process_definition(u, {}) == {"definition": True}


def test_duplicate_json_keys_are_processing_error(tmp_path):
    u = unit(tmp_path, "mcpmark_verified", b'{"id":"first","id":"second"}')
    with pytest.raises(ValueError, match="duplicate JSON"):
        process_definition(u, {})


def test_hash_change_is_integrity_failure(tmp_path):
    u = unit(tmp_path, "mcpmark_verified", b'{}')
    u["source_sha256"] = "0" * 64
    with pytest.raises(FrameworkError, match="SOURCE_HASH_MISMATCH"):
        process_definition(u, {})


def test_source_size_rejected_before_open(tmp_path, monkeypatch):
    path = tmp_path / "oversized"
    path.write_bytes(b"x" * (MAX_INPUT + 1))
    def no_open(*args, **kwargs):
        raise AssertionError("oversized body was opened")
    monkeypatch.setattr(type(path), "open", no_open)
    with pytest.raises(ValueError, match="SIZE_OR_TYPE_LIMIT"):
        bounded(path)


def test_content_is_inert_and_unknown_family_rejected(tmp_path):
    marker = tmp_path / "must-not-exist"
    raw = json.dumps({"command": "write " + str(marker)}).encode()
    u = unit(tmp_path, "mcpmark_verified", raw)
    assert process_definition(u, {}) == {"definition": True}
    assert not marker.exists()
    u["benchmark_id"] = "swebench"
    with pytest.raises(ValueError, match="CLOSED_PRODUCER_FAMILY"):
        process_definition(u, {})


def test_terminal_toml_parsed_as_data(tmp_path):
    u = unit(tmp_path, "terminal_bench_2", b'[task]\nname="authored"\n')
    assert process_definition(u, {}) == {"definition": True}


def test_shard_and_writer_caps_fit_whole_batch_reservation():
    assert SHARD_MAX_BYTES + WRITER_MAX_BYTES == BATCH_RESERVE


def test_oversize_writer_rejected_before_file_publication(tmp_path):
    p = tmp_path / "WRITER.json"
    with pytest.raises(FrameworkError, match="WRITER_BYTE_BUDGET"):
        write_writer(p, {"payload": "x" * WRITER_MAX_BYTES})
    assert not p.exists()
    write_writer(p, {"authored": True})
    assert p.read_text() == '{"authored":true}'


def test_prior_inflight_blocks_continuation_without_redispatch():
    with pytest.raises(FrameworkError, match="PRIOR_INFLIGHT_REQUIRES_REVIEW"):
        check_prior_state({"inflight": {"authored-unit"}})
    check_prior_state({"inflight": set()})


@pytest.mark.parametrize("value", ["../escape", "a/b", "..", "", "a\\b"])
def test_unsafe_attempt_names_rejected(value):
    with pytest.raises(FrameworkError, match="UNSAFE_ATTEMPT_ID"):
        validate_attempt_id(value)


def test_actual_v2_summary_sha256_identifies_persisted_receipt(tmp_path):
    from test_run_checkpoint_v2 import _campaign, _envelope
    from runtime.candidate.run_framework.core import canonical
    c = _campaign(tmp_path)
    c.begin_unit("u1", {"scope": "authored receipt shape control"})
    summary = c.complete_unit("u1", "DISPOSITION_RECORDED", _envelope(c, "u1"))
    assert summary["sha256"] == digest((c.output / summary["path"]).read_bytes())
    assert summary["sha256"] != digest(canonical(summary))
    assert summary["phase"] == "terminal"
