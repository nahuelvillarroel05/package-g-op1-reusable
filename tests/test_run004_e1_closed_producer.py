"""Authored controls for the closed E1 processor; no benchmark source reads."""
import json
import pytest

from runtime.candidate.run_framework.core import FrameworkError, digest
from runtime.candidate.run_framework.e1 import bounded, process_definition, MAX_INPUT


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
