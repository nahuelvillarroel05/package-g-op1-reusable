from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit import source_fragments as fragments
from runtime.candidate.swebench_claim_audit.generalized_bridge import bind_generalized_audit


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def test_spool_duplicate_id_lookup_uses_narrow_nonunique_index(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite"
    db = fragments._spool_db(path, create=True)
    try:
        indexes = {row[1] for row in db.execute("PRAGMA index_list(records)")}
        assert "records_mapped_record_id" in indexes
        plan = db.execute(
            "EXPLAIN QUERY PLAN SELECT 1 FROM records WHERE record_kind='OBSERVATION' "
            "AND status='MAPPED' AND record_id=? LIMIT 1", ("id",)
        ).fetchall()
        assert any("records_mapped_record_id" in row[-1] for row in plan)
    finally:
        db.close()

    resumed = fragments._spool_db(path, create=False)
    try:
        indexes = {row[1] for row in resumed.execute("PRAGMA index_list(records)")}
        assert "records_mapped_record_id" in indexes
    finally:
        resumed.close()


def _write_source(root: Path, raw: bytes, name: str = "source.bin") -> tuple[str, int]:
    (root / name).write_bytes(raw)
    return _sha(raw), len(raw)


def _observation(item_id: str, path: str, source_sha: str, run_id: str,
                 start: int | None, end: int | None) -> dict:
    row = {"observation_id": item_id, "kind": "synthetic_source_observation", "run_id": run_id,
           "instance_id": "UNKNOWN", "value": item_id,
           "source_ref": {"path": path, "sha256": source_sha, "bytes": 0, "pointer": "/opaque"}}
    if start is not None and end is not None:
        row["source_byte_span"] = {"unit": "BYTE_SPAN", "start": start, "end": end}
    return row


def _source_ref(path: str, sha: str, size: int) -> dict:
    return {"path": path, "sha256": sha, "bytes": size, "role": "SOURCE_FRAGMENT",
            "parser_id": "source_fragment.bytes.v1", "parser_version": "1",
            "instance_binding": "RUN_ONLY"}


def test_original_file_reads_are_bounded_and_parent_verified_before_binding(tmp_path: Path, monkeypatch) -> None:
    data = tmp_path / "data"
    data.mkdir()
    raw = (bytes(range(256)) * 9000) + b"tail"
    digest, size = _write_source(data, raw)
    requests: list[int] = []
    original_read = fragments._read_source_block

    def guarded_read(stream, requested: int) -> bytes:
        requests.append(requested)
        assert requested <= 1024 * 1024
        return original_read(stream, requested)

    monkeypatch.setattr(fragments, "_read_source_block", guarded_read)
    output = tmp_path / "out"
    prepared = fragments.fragment_source(data, "source.bin", digest, size, output,
                                         fragment_bytes=1024 * 1024)
    manifest = json.loads((output / "origin-manifest.json").read_bytes())
    assert prepared["status"] == "PASS"
    assert prepared["engine_admission"] == "NOT_PERFORMED"
    assert len(manifest["fragments"]) == 3
    assert all(row["bytes"] <= 1024 * 1024 for row in manifest["fragments"])
    assert sum(row["bytes"] for row in manifest["fragments"]) == size
    assert requests and max(requests) <= 1024 * 1024
    assert not (output / "context").exists()


def test_bad_parent_commitment_never_reaches_context_engine(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"inert input")
    output = tmp_path / "bad-parent"
    with pytest.raises(AuditError, match="streamed source differs"):
        fragments.fragment_source(data, "source.bin", "0" * 64, size, output, fragment_bytes=3)
    assert not (output / "origin-manifest.json").exists()
    assert not (output / "context").exists()
    assert not any(output.glob("context/**/generalized-bridge-receipt.json"))


def test_byte_span_mapping_bind_recovery_uses_engine_fragments_after_stage_removal(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    raw = bytes(range(251)) * 50  # Binary input, including invalid UTF-8 sequences.
    digest, size = _write_source(data, raw)
    output = tmp_path / "origin"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4096)
    rows = [
        _observation("mapped-a", "source.bin", digest, "run-a", 10, 40),
        _observation("crossing", "source.bin", digest, "run-a", 4090, 4102),
        _observation("missing-span", "source.bin", digest, "run-a", None, None),
        _observation("mapped-b", "source.bin", digest, "run-a", 9000, 9030),
        _observation("wrong-source", "other.bin", digest, "run-a", 9050, 9070),
    ]
    rows[0]["source_ref"]["bytes"] = size
    rows[1]["source_ref"]["bytes"] = size
    rows[2]["source_ref"]["bytes"] = size
    rows[3]["source_ref"]["bytes"] = size
    rows[4]["source_ref"]["bytes"] = size
    spooled = fragments.spool_fragment_observations(
        output, iter(rows), expected_run_id="run-a",
        relationships=[{"relationship_id": "edge-1", "from": "mapped-a", "to": "mapped-b"}],
    )
    assert spooled["status"] == "PARTIAL"
    assert spooled["mapped_observation_count"] == 3
    assert spooled["rejected_record_count"] == 3

    bound = fragments.bind_fragment_observations(output)
    assert bound["status"] == "PASS"
    assert bound["engine_byte_scope"] == "FRAGMENT_BYTES_ADMITTED_ONLY"
    assert bound["fragment_count"] == 4
    recovered = fragments.recover_fragmented_source(output)
    assert recovered["status"] == "PASS"
    assert recovered["parent_sha256"] == digest
    assert recovered["parent_bytes"] == size
    assert recovered["engine_admitted_fragments_verified"] == 4
    assert recovered["mapped_observations_verified"] == 3
    assert recovered["rejected_records_recovered"] == 3
    assert recovered["input_mapped_observation_count"] == 3
    spool = sqlite3.connect(output / "observation-spool.sqlite")
    try:
        crossing = json.loads(spool.execute(
            "SELECT mapped_json FROM records WHERE record_id='crossing'").fetchone()[0])
    finally:
        spool.close()
    assert crossing["origin_mapping_status"] == "EXACT_PARENT_BYTE_SPAN_V2_PIECE_DIGEST"
    assert crossing["origin_piece_count"] == 2
    assert crossing["origin_source_ref_role"] == "ROUTING_ANCHOR_ONLY"
    assert crossing["source_ref"]["mapping_role"] == "ROUTING_ANCHOR_ONLY"

    # Recovery must be independent of the original and loose staging artifacts.
    (data / "source.bin").unlink()
    shutil.rmtree(output / "fragments")
    for name in ("origin-manifest.json", "fragment-verification.json",
                 "mapping-rejections.json", "observation-spool.sqlite",
                 "observation-spool.sqlite-wal", "observation-spool.sqlite-shm"):
        path = output / name
        if path.exists():
            path.unlink()
    recovered_from_engine = fragments.recover_fragmented_source(output)
    assert recovered_from_engine["status"] == "PASS"
    assert recovered_from_engine["parent_sha256"] == digest
    assert recovered_from_engine["reconstruction_source"] == "ENGINE_IMMUTABLE_FRAGMENT_OBJECTS"
    assert recovered_from_engine["original_file_read"] == "NOT_PERFORMED"
    assert recovered_from_engine["staged_fragment_read"] == "NOT_PERFORMED"


def test_empty_source_and_utf8_codepoint_split_are_raw_byte_preserving(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    output = tmp_path / "empty"
    empty_hash, empty_size = _write_source(data, b"", "empty.bin")
    fragments.fragment_source(data, "empty.bin", empty_hash, empty_size, output, fragment_bytes=2)
    empty_manifest = json.loads((output / "origin-manifest.json").read_bytes())
    assert empty_manifest["fragments"][0]["bytes"] == 0
    assert empty_manifest["fragments"][0]["sha256"] == _sha(b"")
    spooled_empty = fragments.spool_fragment_observations(output, iter(()), expected_run_id="empty-run")
    assert spooled_empty["mapped_observation_count"] == 0
    bound_empty = fragments.bind_fragment_observations(output)
    assert bound_empty["completed_item_count"] == 1
    recovered_empty = fragments.recover_fragmented_source(output)
    assert recovered_empty["engine_admitted_fragments_verified"] == 1
    assert recovered_empty["input_record_count"] == 0

    (data / "empty.bin").unlink()
    raw = "€".encode("utf-8")
    digest, size = _write_source(data, raw, "utf8.bin")
    output2 = tmp_path / "utf8"
    fragments.fragment_source(data, "utf8.bin", digest, size, output2, fragment_bytes=2)
    manifest = json.loads((output2 / "origin-manifest.json").read_bytes())
    assert [row["bytes"] for row in manifest["fragments"]] == [2, 1]
    assert b"".join((output2 / row["path"]).read_bytes() for row in manifest["fragments"]) == raw


def test_invalid_json_observations_are_preserved_schema_rejected_and_replay_bound(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"abcdefgh")
    output = tmp_path / "invalid-inputs"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    valid = _observation("valid", "source.bin", digest, "run-a", 0, 1)
    valid["source_ref"]["bytes"] = size
    missing_id = dict(valid)
    missing_id.pop("observation_id")
    missing_kind = dict(valid)
    missing_kind.pop("kind")
    rows = [None, valid, missing_id, missing_kind]
    result = fragments.spool_fragment_observations(output, rows, expected_run_id="run-a")
    assert result["mapped_observation_count"] == 1
    assert result["rejected_record_count"] == 3
    ledger = json.loads((output / "mapping-rejections.json").read_bytes())
    assert [entry["original_record"] for entry in ledger["rejections"]] == [None, missing_id, missing_kind]
    assert {entry["reason_code"] for entry in ledger["rejections"]} == {
        "OBSERVATION_NOT_OBJECT", "OBSERVATION_NORMALIZED_SCHEMA_INVALID"}
    with pytest.raises(AuditError, match="replayed observation differs"):
        fragments.spool_fragment_observations(output, [1, valid, missing_id, missing_kind],
                                              expected_run_id="run-a", resume=True)
    bound = fragments.bind_fragment_observations(output)
    assert bound["status"] == "PASS"
    recovered = fragments.recover_fragmented_source(output)
    assert recovered["engine_admitted_fragments_verified"] == 2
    assert recovered["mapped_observations_verified"] == 1
    assert recovered["rejected_records_recovered"] == 3


def test_non_json_input_gets_explicit_unverified_identity_rejection(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"x")
    output = tmp_path / "opaque-input"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=1)
    result = fragments.spool_fragment_observations(output, [object()], expected_run_id="run-a")
    assert result["rejected_record_count"] == 1
    ledger = json.loads((output / "mapping-rejections.json").read_bytes())
    assert ledger["rejections"][0]["reason_code"] == "OBSERVATION_INPUT_IDENTITY_UNVERIFIED"
    with pytest.raises(AuditError, match="cannot be identity-verified"):
        fragments.spool_fragment_observations(output, [object()], expected_run_id="run-a", resume=True)
    fragments.bind_fragment_observations(output)
    recovered = fragments.recover_fragmented_source(output)
    assert recovered["status"] == "PARTIAL"
    assert recovered["input_identity_verification"] == "PARTIAL_UNKNOWN"


def test_optional_one_byte_source_size_rejects_boolean_metadata(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"x")
    output = tmp_path / "bool-size"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=1)
    row = _observation("bool-size", "source.bin", digest, "run-a", 0, 1)
    row["source_ref"]["bytes"] = True
    result = fragments.spool_fragment_observations(output, [row], expected_run_id="run-a")
    assert result["mapped_observation_count"] == 0
    ledger = json.loads((output / "mapping-rejections.json").read_bytes())
    assert ledger["rejections"][0]["reason_code"] == "SOURCE_REFERENCE_SIZE_MISMATCH"


@pytest.mark.parametrize("tamper", ["fragment-index", "coverage", "fragment-count", "fragment-size"])
def test_manifest_rejects_boolean_integer_aliases_before_binding(tmp_path: Path, tamper: str) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"x")
    output = tmp_path / tamper
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=1)
    manifest_path = output / "origin-manifest.json"
    verification_path = output / "fragment-verification.json"
    manifest = json.loads(manifest_path.read_bytes())
    verification = json.loads(verification_path.read_bytes())
    if tamper == "fragment-index":
        manifest["fragments"][0]["index"] = False
    elif tamper == "coverage":
        manifest["coverage"]["end"] = True
    elif tamper == "fragment-count":
        verification["fragments"] = True
    else:
        manifest["fragmentation"]["fragment_bytes"] = True
    manifest_raw = fragments.canonical_json(manifest)
    verification["manifest_sha256"] = _sha(manifest_raw)
    manifest_path.write_bytes(manifest_raw)
    verification_path.write_bytes(fragments.canonical_json(verification))
    with pytest.raises(AuditError):
        fragments.bind_origin_manifest(output)
    assert not (output / "context").exists()


@pytest.mark.parametrize("tamper", ["configured-cap-too-small", "verification-cap-mismatch",
                                     "nonfixed-contiguous-layout", "surplus-empty-fragment"])
def test_manifest_rejects_fixed_split_profile_mismatch(tmp_path: Path, tamper: str) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"abc")
    output = tmp_path / tamper
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=2)
    manifest_path = output / "origin-manifest.json"
    verification_path = output / "fragment-verification.json"
    manifest = json.loads(manifest_path.read_bytes())
    verification = json.loads(verification_path.read_bytes())
    if tamper == "configured-cap-too-small":
        manifest["fragmentation"]["fragment_bytes"] = 1
        verification["fragment_bytes"] = 1
    elif tamper == "verification-cap-mismatch":
        verification["fragment_bytes"] = 1
    elif tamper == "nonfixed-contiguous-layout":
        manifest["fragments"][0]["offset_end"] = 1
        manifest["fragments"][0]["bytes"] = 1
        manifest["fragments"][1]["offset_start"] = 1
        manifest["fragments"][1]["offset_end"] = 3
        manifest["fragments"][1]["bytes"] = 2
    else:
        manifest["fragments"].append({"index": 2, "offset_start": 3, "offset_end": 3,
                                      "bytes": 0, "path": "fragments/fragment-000002.bin",
                                      "sha256": _sha(b"")})
        verification["fragments"] = 3
    manifest_raw = fragments.canonical_json(manifest)
    verification["manifest_sha256"] = _sha(manifest_raw)
    manifest_path.write_bytes(manifest_raw)
    verification_path.write_bytes(fragments.canonical_json(verification))
    with pytest.raises(AuditError):
        fragments.bind_origin_manifest(output)
    assert not (output / "context").exists()


@pytest.mark.parametrize("component", ["HoLdOuT", "SeCrEtS", ".AWS"])
def test_excluded_absolute_parent_component_fails_before_read_or_output(tmp_path: Path, monkeypatch, component: str) -> None:
    data = tmp_path / component / "data"
    data.mkdir(parents=True)
    digest, size = _write_source(data, b"synthetic only")
    output = tmp_path / "output"
    calls = []

    def guarded_read(stream, requested):
        calls.append(requested)
        raise AssertionError("excluded path must be rejected before any source read")

    monkeypatch.setattr(fragments, "_read_source_block", guarded_read)
    with pytest.raises(AuditError, match="Engine-excluded"):
        fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    assert calls == []
    assert not output.exists()


def _rewrite_manifest_without_exclusion_policy(output: Path) -> tuple[dict, bytes, bytes]:
    manifest_path = output / "origin-manifest.json"
    verification_path = output / "fragment-verification.json"
    manifest = json.loads(manifest_path.read_bytes())
    verification = json.loads(verification_path.read_bytes())
    parent = manifest["parent_source"]
    manifest["origin_id"] = "origin-" + hashlib.sha256(
        (parent["path"] + "\0" + parent["absolute_path_sha256"] + "\0" + parent["sha256"]).encode()).hexdigest()[:24]
    manifest.pop("input_exclusion_policy")
    verification.pop("input_exclusion_policy")
    manifest_raw = fragments.canonical_json(manifest)
    verification["manifest_sha256"] = _sha(manifest_raw)
    verification_raw = fragments.canonical_json(verification)
    manifest_path.write_bytes(manifest_raw)
    verification_path.write_bytes(verification_raw)
    return manifest, manifest_raw, verification_raw


def test_pre_policy_origin_is_rejected_in_staging_and_engine_only_recovery(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"synthetic only")
    output = tmp_path / "staged-excluded"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    _rewrite_manifest_without_exclusion_policy(output)
    with pytest.raises(AuditError, match="exclusion policy"):
        fragments.bind_origin_manifest(output)
    assert not (output / "context").exists()

    engine_output = tmp_path / "engine-excluded"
    fragments.fragment_source(data, "source.bin", digest, size, engine_output, fragment_bytes=4)
    manifest, manifest_raw, verification_raw = _rewrite_manifest_without_exclusion_policy(engine_output)
    audit = fragments._manifest_audit(manifest, manifest_raw, verification_raw)
    audit["origin_manifest_sha256"] = _sha(manifest_raw)
    audit["origin_parent_commitment"] = manifest["parent_source"]
    bind_generalized_audit(audit, engine_output, engine_output / "context" / "origin-manifest")
    with pytest.raises(AuditError, match="exclusion policy"):
        fragments.recover_fragmented_source(engine_output)


def test_manifest_records_versioned_exclusion_check_without_private_absolute_path(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"synthetic")
    output = tmp_path / "policy"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    manifest_raw = (output / "origin-manifest.json").read_bytes()
    verification = json.loads((output / "fragment-verification.json").read_bytes())
    manifest = json.loads(manifest_raw)
    policy = {"version": "CONTEXT_ENGINE_SOURCE_EXCLUSION_V1", "result": "PASS_BEFORE_ORIGINAL_READ"}
    assert manifest["input_exclusion_policy"] == policy
    assert verification["input_exclusion_policy"] == policy
    assert "absolute_path" not in manifest["parent_source"]
    assert manifest["parent_source"]["absolute_path_sha256"] == _sha(str((data / "source.bin").resolve()).casefold().encode())
    assert b"PGOP1_DATA" not in manifest_raw


def test_large_valid_rows_split_to_safe_aggregate_batches_and_recover_all_four(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    raw = b"z" * (4 * 1024 * 1024)
    digest, size = _write_source(data, raw)
    output = tmp_path / "large-rows"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=1024 * 1024)
    rows = []
    for index in range(4):
        start = index * 1024 * 1024 + 8
        row = _observation(f"large-{index}", "source.bin", digest, "run-large", start, start + 16)
        row["source_ref"]["bytes"] = size
        row["value"] = "x" * 900_000
        assert len(fragments.canonical_json(row)) < 1024 * 1024
        rows.append(row)
    spooled = fragments.spool_fragment_observations(output, iter(rows), expected_run_id="run-large")
    assert spooled["mapped_observation_count"] == 4
    bound = fragments.bind_fragment_observations(output)
    assert bound["status"] == "PASS"
    assert bound["completed_item_count"] == 4
    assert bound["rejected_batch_item_count"] == 0
    recovered = fragments.recover_fragmented_source(output)
    assert recovered["status"] == "PASS"
    assert recovered["input_mapped_observation_count"] == 4
    assert recovered["mapped_observations_verified"] == 4


@pytest.mark.parametrize("fault", ["omit", "duplicate", "reorder"])
def test_immutable_input_completion_detects_binder_loss_duplicate_or_reorder(tmp_path: Path, monkeypatch, fault: str) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"abcdefgh")
    output = tmp_path / fault
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    rows = [_observation("a", "source.bin", digest, "run-a", 0, 1),
            _observation("b", "source.bin", digest, "run-a", 1, 2)]
    for row in rows:
        row["source_ref"]["bytes"] = size
    fragments.spool_fragment_observations(output, rows, expected_run_id="run-a")
    original_bind = fragments.bind_audit_stream

    def corrupted(items, data_root, output_root, **kwargs):
        def changed():
            first = next(iter(items))
            observations = first["audit_result"]["observations"]
            user_rows, marker = observations[:-1], observations[-1]
            if fault == "omit":
                user_rows = user_rows[:-1]
            elif fault == "duplicate":
                user_rows[1] = dict(user_rows[0])
            else:
                user_rows.reverse()
            first["audit_result"]["observations"] = [*user_rows, marker]
            yield first
            yield from items
        return original_bind(changed(), data_root, output_root, **kwargs)

    monkeypatch.setattr(fragments, "bind_audit_stream", corrupted)
    bound = fragments.bind_fragment_observations(output)
    if fault == "duplicate":
        assert bound["status"] == "PARTIAL"
    with pytest.raises(AuditError):
        fragments.recover_fragmented_source(output)


@pytest.mark.parametrize("fault", ["piece-count", "mapped-index", "mapped-range",
                                    "member-count", "marker-count", "fragment-start",
                                    "fragment-end", "fragment-index"])
def test_recovery_rejects_boolean_or_float_integer_aliases_in_capsule(tmp_path: Path, monkeypatch, fault: str) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"xy")
    output = tmp_path / fault
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=1)
    row = _observation("one", "source.bin", digest, "run-a", 0, 1)
    row["source_ref"]["bytes"] = size
    fragments.spool_fragment_observations(output, [row], expected_run_id="run-a")
    original_bind = fragments.bind_audit_stream

    def corrupted(items, data_root, output_root, **kwargs):
        def changed():
            first = next(iter(items))
            result = first["audit_result"]
            observation, marker = result["observations"]
            if fault == "piece-count":
                observation["origin_piece_count"] = True
            elif fault == "mapped-index":
                observation["origin_fragment_index"] = False
            elif fault == "mapped-range":
                observation["origin_fragment_range"] = [False, 1]
            elif fault == "member-count":
                result["fragment_observation_count"] = True
            elif fault == "marker-count":
                marker["value"]["mapped_observation_count"] = True
            elif fault == "fragment-start":
                result["origin_fragment"]["offset_start"] = False
            elif fault == "fragment-end":
                result["origin_fragment"]["offset_end"] = 1.0
            else:
                result["origin_fragment"]["index"] = False
            yield first
            yield from items
        return original_bind(changed(), data_root, output_root, **kwargs)

    monkeypatch.setattr(fragments, "bind_audit_stream", corrupted)
    assert fragments.bind_fragment_observations(output)["status"] == "PASS"
    with pytest.raises(AuditError):
        fragments.recover_fragmented_source(output)


def test_input_completion_ledger_tamper_is_rejected_before_engine_binding(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"abcd")
    output = tmp_path / "tampered-completion"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    row = _observation("one", "source.bin", digest, "run-a", 0, 1)
    row["source_ref"]["bytes"] = size
    fragments.spool_fragment_observations(output, [row], expected_run_id="run-a")
    ledger_path = output / "mapping-rejections.json"
    ledger = json.loads(ledger_path.read_bytes())
    ledger["input_completion"]["mapped_observation_count"] = 0
    ledger_path.write_bytes(fragments.canonical_json(ledger))
    with pytest.raises(AuditError, match="completion differs"):
        fragments.bind_fragment_observations(output)
    assert not (output / "context").exists()


def test_reserved_internal_kinds_and_fields_are_preserved_as_rejections(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"abcdefgh")
    output = tmp_path / "reserved-fields"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    rows = [
        _observation("caller-marker", "source.bin", digest, "run-a", 0, 1),
        _observation("caller-ordinal", "source.bin", digest, "run-a", 1, 2),
        _observation("caller-manifest", "source.bin", digest, "run-a", 2, 3),
        _observation("caller-original-ref", "source.bin", digest, "run-a", 3, 4),
    ]
    for row in rows:
        row["source_ref"]["bytes"] = size
    rows[0]["kind"] = "origin_fragment_commitment"
    rows[1]["origin_input_ordinal"] = 999
    rows[2]["origin_manifest_sha256"] = "f" * 64
    rows[3]["original_source_ref"] = dict(rows[3]["source_ref"])
    spooled = fragments.spool_fragment_observations(output, rows, expected_run_id="run-a")
    assert spooled["mapped_observation_count"] == 0
    assert spooled["rejected_record_count"] == 4
    ledger = json.loads((output / "mapping-rejections.json").read_bytes())
    assert [entry["original_record"] for entry in ledger["rejections"]] == rows
    assert all(entry["reason_code"] == "OBSERVATION_RESERVED_ORIGIN_NAMESPACE" for entry in ledger["rejections"])
    bound = fragments.bind_fragment_observations(output)
    assert bound["status"] == "PASS"
    recovered = fragments.recover_fragmented_source(output)
    assert recovered["input_mapped_observation_count"] == 0
    assert recovered["input_rejected_record_count"] == 4


def test_single_valid_input_at_one_mebibyte_minus_sixteen_bytes_binds(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"one")
    output = tmp_path / "near-cap"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=3)
    row = _observation("near-cap", "source.bin", digest, "run-cap", 0, 1)
    row["source_ref"]["bytes"] = size
    row["value"] = ""
    target = fragments._MAX_OBSERVATION_BYTES - 16
    row["value"] = "x" * (target - len(fragments.canonical_json(row)))
    assert len(fragments.canonical_json(row)) == target
    spooled = fragments.spool_fragment_observations(output, [row], expected_run_id="run-cap")
    assert spooled["mapped_observation_count"] == 1
    bound = fragments.bind_fragment_observations(output)
    assert bound["status"] == "PASS"
    assert bound["rejected_batch_item_count"] == 0
    assert fragments.recover_fragmented_source(output)["mapped_observations_verified"] == 1


def test_many_rows_and_interleaved_fragment_ordinals_conserve_exact_input(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"abcdefgh")
    output = tmp_path / "many"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    rows = []
    for index in range(180):
        start = 0 if index % 2 == 0 else 4
        row = _observation(f"many-{index}", "source.bin", digest, "run-many", start, start + 1)
        row["source_ref"]["bytes"] = size
        rows.append(row)
    spooled = fragments.spool_fragment_observations(output, iter(rows), expected_run_id="run-many")
    assert spooled["mapped_observation_count"] == 180
    bound = fragments.bind_fragment_observations(output)
    assert bound["status"] == "PASS"
    recovered = fragments.recover_fragmented_source(output)
    assert recovered["input_record_count"] == 180
    assert recovered["input_mapped_observation_count"] == 180
    assert recovered["mapped_observations_verified"] == 180


def test_resumed_spool_byte_cap_counts_utf8_bytes_not_sqlite_characters(tmp_path: Path, monkeypatch) -> None:
    data = tmp_path / "data"
    data.mkdir()
    digest, size = _write_source(data, b"x")
    output = tmp_path / "unicode-resume"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=1)
    rows = []
    for index in range(74):
        row = _observation(f"unicode-{index}", "source.bin", digest, "run-u", 0, 1)
        row["value"] = "😀" * 200
        row["source_ref"]["bytes"] = size
        rows.append(row)
    monkeypatch.setattr(fragments, "_MAX_SPOOL_BYTES", 10 * 1024 * 1024)

    def stop_after_committed_prefix():
        yield from rows[:64]
        raise RuntimeError("controlled interruption after ordinal 63 checkpoint")

    with pytest.raises(RuntimeError, match="controlled interruption"):
        fragments.spool_fragment_observations(output, stop_after_committed_prefix(), expected_run_id="run-u")
    db = sqlite3.connect(output / "observation-spool.sqlite")
    actual_prefix_bytes = sum(len(a.encode("utf-8")) + len(b.encode("utf-8"))
                              for a, b in db.execute("SELECT original_json,mapped_json FROM records"))
    db.close()
    monkeypatch.setattr(fragments, "_MAX_SPOOL_BYTES", actual_prefix_bytes + 1000)
    with pytest.raises(AuditError, match="byte limit"):
        fragments.spool_fragment_observations(output, rows, expected_run_id="run-u", resume=True)


def test_fresh_process_resume_after_first_real_engine_fragment_batch(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    raw = b"abcdefgh"
    digest, size = _write_source(data, raw)
    output = tmp_path / "restart"
    fragments.fragment_source(data, "source.bin", digest, size, output, fragment_bytes=4)
    observations = [_observation("first", "source.bin", digest, "run-a", 0, 1),
                    _observation("second", "source.bin", digest, "run-a", 4, 5)]
    for row in observations:
        row["source_ref"]["bytes"] = size
    fragments.spool_fragment_observations(output, observations, expected_run_id="run-a")
    repo = Path(__file__).resolve().parents[1]
    child = """import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from runtime.candidate.swebench_claim_audit import source_fragments as f
from runtime.candidate.swebench_claim_audit import swebench_batching as b
original=b.bind_audit_stream
def interrupted(items,data_root,output_root,**kwargs):
 def source():
  for item in items:
   yield item
   os._exit(37)
 return original(source(),data_root,output_root,batch_size=1,resume=kwargs.get('resume',False))
f.bind_audit_stream=interrupted
f.bind_fragment_observations(sys.argv[2])
"""
    first = subprocess.run([sys.executable, "-B", "-I", "-c", child, str(repo), str(output)],
                           capture_output=True)
    assert first.returncode == 37
    assert (output / "context" / "batches" / "batch-000000" /
            "generalized-bridge-receipt.json").is_file()
    resume_code = """import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from runtime.candidate.swebench_claim_audit.source_fragments import bind_fragment_observations,recover_fragmented_source
print(json.dumps({'bound':bind_fragment_observations(sys.argv[2],resume=True),'recovered':recover_fragmented_source(sys.argv[2])}))
"""
    resumed = subprocess.run([sys.executable, "-B", "-I", "-c", resume_code, str(repo), str(output)],
                             capture_output=True, text=True, check=True)
    result = json.loads(resumed.stdout)
    assert result["bound"]["completed_item_count"] == 2
    assert result["bound"]["context_batch_count"] == 2
    assert result["recovered"]["status"] == "PASS"
    assert result["recovered"]["mapped_observations_verified"] == 2
    assert len(list((output / "context" / "batches").glob("batch-*/generalized-bridge-receipt.json"))) == 2
