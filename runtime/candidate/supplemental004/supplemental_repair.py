# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Append-only, narrowly scoped repair ledger for proven primary-reader false failures.

This module never rewrites primary inventory or scan rows. Production use is only
against the exact Engineering root and an already-finalized primary scan output.
The fixture API is explicit and still requires all artifacts under Validation.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[1]
VALIDATION_ROOT = Path(r"PRIVATE_VALIDATION_NOT_DISTRIBUTED")
READER_PATH = HERE / "engineering_corpus.py"
REPAIR_HELPER_PATH = Path(__file__).resolve()

_SPEC = importlib.util.spec_from_file_location("engineering_corpus_revision_004_repair", READER_PATH)
assert _SPEC and _SPEC.loader
reader = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = reader
_SPEC.loader.exec_module(reader)

READER_SHA256 = hashlib.sha256(READER_PATH.read_bytes()).hexdigest()
REPAIR_HELPER_SHA256 = hashlib.sha256(REPAIR_HELPER_PATH.read_bytes()).hexdigest()
MAX_ROW_BYTES = 4 * 1024 * 1024
JSONL_BUFFER_SIZE = 1024 * 1024
MAX_SEALED_OVERLAY_BYTES = 64 * 1024 * 1024
MAX_SEALED_OVERLAY_ROWS = 200_000
REPAIRABLE_STATUS = "REPARSE_OR_PATH_REDIRECT"
REPAIRABLE_DETAIL = "STAT_CHANGED_AT_OPEN"
PRIMARY_RUN_READER_SHA256 = "1a4d7e9b0d68bda2183f7392e46010aa440fdc183779109e75186d0334cbbafa"
LEGACY_PREFIX_READER_SHA256 = "b78e6beb8d9c120c3d517071a79fb1ef11c91c3ae14a8f5cf45abac21239120a"
R5_PRIMARY_READER_SHA256 = "f8a2d357cd79a3bff0c197564cbfffedf192600ec851608fda5dfe03e6dd1b21"
R5_OWNER_SEAL_SHA256 = "755c8e53d1b5f8dff99cfc1fbe16e20d1fe42f1b9d4061c3e6e5f9ae59bf8f90"
R5_CARRIED_CONTINUATION_READER_SHA256 = R5_PRIMARY_READER_SHA256
R5_PREFIX_ORIGIN_RANGES = [
    {"start_row": 0, "end_row_exclusive": 205000, "reader_sha256": LEGACY_PREFIX_READER_SHA256},
    {"start_row": 205000, "end_row_exclusive": 341500, "reader_sha256": PRIMARY_RUN_READER_SHA256},
]


def _canonical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _inside(path: Path, root: Path) -> bool:
    try:
        _canonical(path).relative_to(_canonical(root))
        return True
    except ValueError:
        return False


def _held_file_stable(path: Path, stream, before, opened, held_path: str) -> None:
    after_fd = os.fstat(stream.fileno())
    after_path = path.lstat()
    final_after = reader._final_path_from_handle(stream.fileno())
    expected_path = os.path.abspath(os.fspath(path))
    if (reader._stat_tuple(opened) != reader._stat_tuple(after_fd)
            or reader._stat_tuple(before) != reader._stat_tuple(after_path)
            or reader._cross_api_stat_tuple(before) != reader._cross_api_stat_tuple(opened)
            or reader._path_has_reparse_ancestor(path) or reader._is_reparse(path, after_path)
            or final_after != held_path
            or os.path.normcase(os.path.normpath(final_after or "")) != os.path.normcase(os.path.normpath(expected_path))):
        raise ValueError("PRIMARY_ARTIFACT_CHANGED_DURING_READ")


def _hash_open_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    stream, before, opened, held_path = reader._open_verified(path)
    try:
        while True:
            chunk = stream.read(reader.CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
    finally:
        try:
            _held_file_stable(path, stream, before, opened, held_path)
        finally:
            stream.close()
    return digest.hexdigest(), count


def _open_verified_buffered(path: Path):
    """Buffer line iteration over an already verified handle without reopening it."""
    raw, _, _, _ = reader._open_verified(path)
    try:
        return io.BufferedReader(raw, buffer_size=JSONL_BUFFER_SIZE)
    except BaseException:
        raw.close()
        raise


def _verify_sealed_jsonl(path: Path, *, expected_sha256: Any, expected_bytes: Any,
                         expected_rows: Any, maximum_bytes: int,
                         row_validator=None) -> dict[str, Any] | None:
    """Stream a sealed JSONL artifact with byte, row, hash, and held-path bounds."""
    if (not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or not isinstance(expected_bytes, int) or expected_bytes < 0
            or expected_bytes > maximum_bytes
            or not isinstance(expected_rows, int) or expected_rows < 0
            or expected_rows > MAX_SEALED_OVERLAY_ROWS):
        raise ValueError("R5_SEALED_JSONL_EXPECTED_BOUNDS_INVALID")
    digest = hashlib.sha256()
    byte_count = 0
    row_count = 0
    selected = None
    raw_stream, before, opened, held_path = reader._open_verified(path)
    stream = io.BufferedReader(raw_stream, buffer_size=JSONL_BUFFER_SIZE)
    try:
        while True:
            raw = stream.readline(MAX_ROW_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_ROW_BYTES or not raw.endswith(b"\n"):
                raise ValueError("R5_SEALED_JSONL_ROW_TORN_OR_OVERSIZE")
            byte_count += len(raw)
            row_count += 1
            if byte_count > expected_bytes or byte_count > maximum_bytes or row_count > expected_rows:
                raise ValueError("R5_SEALED_JSONL_EXCEEDS_COMMITTED_BOUNDS")
            digest.update(raw)
            try:
                record = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError("R5_SEALED_JSONL_ROW_INVALID") from exc
            if not isinstance(record, dict):
                raise ValueError("R5_SEALED_JSONL_ROW_NOT_OBJECT")
            if row_validator is not None:
                row_validator(record)
            selected = record
    finally:
        try:
            _held_file_stable(path, stream, before, opened, held_path)
        finally:
            stream.close()
    if byte_count != expected_bytes or row_count != expected_rows or digest.hexdigest() != expected_sha256:
        raise ValueError("R5_SEALED_JSONL_COMMITMENT_MISMATCH")
    return selected


def _read_bounded_verified_json(path: Path, *, expected_sha256: str,
                                expected_bytes: int, maximum_bytes: int = 4 * 1024 * 1024) -> dict[str, Any]:
    if (not isinstance(expected_bytes, int) or expected_bytes < 0 or expected_bytes > maximum_bytes
            or not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)):
        raise ValueError("R5_SEALED_JSON_EXPECTED_BOUNDS_INVALID")
    stream, before, opened, held_path = reader._open_verified(path)
    try:
        raw = stream.read(expected_bytes + 1)
    finally:
        try:
            _held_file_stable(path, stream, before, opened, held_path)
        finally:
            stream.close()
    if len(raw) != expected_bytes or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("R5_SEALED_JSON_COMMITMENT_MISMATCH")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("R5_SEALED_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise ValueError("R5_SEALED_JSON_NOT_OBJECT")
    return value


def _artifact(base: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or Path(name).is_absolute() or ":" in name:
        raise ValueError("PRIMARY_ARTIFACT_NAME_INVALID")
    normalized = name.replace("\\", "/")
    if any(part in {"", ".", ".."} for part in normalized.split("/")) or "/" in normalized:
        raise ValueError("PRIMARY_ARTIFACT_NAME_NOT_BASENAME")
    candidate = base / name
    if candidate.parent != base:
        raise ValueError("PRIMARY_ARTIFACT_ESCAPES_OUTPUT")
    return candidate


def _read_manifest(path: Path) -> tuple[dict[str, Any], bytes, str, int]:
    stream, before, opened, held_path = reader._open_verified(path)
    selected = None
    selected_raw = None
    digest = hashlib.sha256()
    byte_count = 0
    try:
        while True:
            raw = stream.readline(MAX_ROW_BYTES + 1)
            if not raw:
                break
            digest.update(raw)
            byte_count += len(raw)
            if len(raw) > MAX_ROW_BYTES or not raw.endswith(b"\n"):
                raise ValueError("PRIMARY_MANIFEST_TORN_OR_OVERSIZE")
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError("PRIMARY_MANIFEST_INVALID") from exc
            if not isinstance(value, dict):
                raise ValueError("PRIMARY_MANIFEST_ROW_NOT_OBJECT")
            selected, selected_raw = value, raw
    finally:
        try:
            _held_file_stable(path, stream, before, opened, held_path)
        finally:
            stream.close()
    if selected is None or selected_raw is None:
        raise ValueError("PRIMARY_MANIFEST_EMPTY")
    return selected, selected_raw, digest.hexdigest(), byte_count


def _read_continuation_import(path: Path, snapshot: str) -> tuple[dict[str, Any], str, int]:
    stream, before, opened, held_path = reader._open_verified(path)
    try:
        raw = stream.read(1024 * 1024 + 1)
    finally:
        try:
            _held_file_stable(path, stream, before, opened, held_path)
        finally:
            stream.close()
    if len(raw) > 1024 * 1024:
        raise ValueError("CONTINUATION_IMPORT_OVERSIZE")
    digest, byte_count = hashlib.sha256(raw).hexdigest(), len(raw)
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("CONTINUATION_IMPORT_INVALID") from exc
    if (not isinstance(value, dict)
            or value.get("schema") != "i7-engineering-reader-continuation@2"
            or value.get("status") != "PREFIX_IMPORTED_AWAITING_EXPLICIT_V3_RESUME"
            or value.get("snapshot_id") != snapshot
            or value.get("prepare_only_no_source_reads_or_full_verify") is not True
            or value.get("source_ledger_mutated") is not False
            or not isinstance(value.get("prefix_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["prefix_sha256"])
            or not isinstance(value.get("prefix_byte_count"), int)
            or value["prefix_byte_count"] < 0):
        raise ValueError("CONTINUATION_IMPORT_BINDING_INVALID")
    return value, digest, byte_count


def _validate_r5_owner_prefix(primary: Path, manifest: dict[str, Any],
                              expected: dict[str, Any], snapshot: str,
                              *, test_api: bool) -> tuple[dict[str, Any], str, int]:
    """Bind the R5 trusted-prefix marker to its seal and the exact primary scan.

    The marker is a commitment to inherited rows, not evidence that those bytes
    were re-read during R5. The production seal pin is fixed; fixture mode may
    use the explicitly supplied synthetic seal pin for isolated tests only.
    """
    marker_path = primary / "OWNER_TRUSTED_PREFIX.json"
    if not marker_path.is_file() or reader._is_reparse(marker_path, marker_path.lstat()):
        raise ValueError("R5_TRUSTED_PREFIX_MARKER_REQUIRED")
    marker, marker_raw, marker_sha, marker_bytes = _read_manifest(marker_path)
    if marker_sha != expected.get("trusted_owner_prefix_marker_sha256"):
        raise ValueError("R5_TRUSTED_PREFIX_MARKER_PIN_MISMATCH")
    seal_sha = expected.get("owner_checkpoint_seal_sha256")
    production_seal = seal_sha == R5_OWNER_SEAL_SHA256
    if not production_seal and not test_api:
        raise ValueError("R5_OWNER_CHECKPOINT_SEAL_PIN_MISMATCH")
    trusted_rows = expected.get("trusted_prefix_rows")
    legacy_rows = expected.get("legacy_prefix_row_count")
    expected_prefix_ranges = [
        {"start_row": 0, "end_row_exclusive": legacy_rows, "reader_sha256": LEGACY_PREFIX_READER_SHA256},
        {"start_row": legacy_rows, "end_row_exclusive": trusted_rows, "reader_sha256": PRIMARY_RUN_READER_SHA256},
    ]
    if (marker.get("schema") != "i7-engineering-owner-trusted-prefix@1"
            or marker.get("status") != "TRUSTED_PREFIX_COMMITTED_AFTER_METADATA_PREFLIGHT"
            or marker.get("snapshot_id") != snapshot
            or marker.get("owner_checkpoint_seal_sha256") != seal_sha
            or marker.get("append_reader_sha256") != expected.get("primary_reader_sha256")
            or marker.get("prefix_payload_validation_status") != "PENDING_INDEPENDENT_POSTERIOR_REHASH"
            or marker.get("source_payload_read") is not False
            or marker.get("trusted_prefix_source_payload_bytes_read") != 0
            or marker.get("metadata_preflight_status") != "PASS"
            or marker.get("metadata_protection_policy_sha256") != reader.PROTECTION_POLICY_SHA256
            or marker.get("trusted_prefix_rows") != expected.get("trusted_prefix_rows")
            or marker.get("trusted_prefix_bytes") != expected.get("trusted_prefix_ledger_bytes")
            or marker.get("trusted_prefix_sha256") != expected.get("trusted_prefix_sha256")
            or marker.get("prefix_origin_ranges") != expected_prefix_ranges
            or marker.get("legacy_prefix_rows") != expected.get("legacy_prefix_row_count")
            or marker.get("legacy_prefix_sha256") != expected.get("legacy_prefix_sha256")
            or marker.get("legacy_prefix_bytes") != expected.get("legacy_prefix_bytes")
            or marker.get("legacy_overlay_sha256") != manifest.get("legacy_overlay_sha256")
            or marker.get("legacy_overlay_rows") != manifest.get("legacy_overlay_rows")
            or not isinstance(marker.get("legacy_overlay_bytes"), int)
            or marker.get("legacy_overlay_bytes", -1) < 0
            or not isinstance(marker.get("legacy_overlay_rows"), int)
            or marker.get("legacy_overlay_rows", -1) < 0):
        raise ValueError("R5_TRUSTED_PREFIX_MARKER_BINDING_INVALID")
    if (manifest.get("owner_checkpoint_seal_sha256") != seal_sha
            or manifest.get("trusted_owner_prefix_marker_sha256") != marker_sha
            or manifest.get("prefix_payload_validation_status") != marker.get("prefix_payload_validation_status")
            or manifest.get("trusted_prefix_rows_reused") != marker.get("trusted_prefix_rows")
            or (not isinstance(manifest.get("trusted_prefix_bytes_reused"), int)
                or manifest.get("trusted_prefix_bytes_reused", -1) < 0)
            or manifest.get("legacy_overlay_sha256") != marker.get("legacy_overlay_sha256")
            or manifest.get("legacy_overlay_rows") != marker.get("legacy_overlay_rows")):
        raise ValueError("R5_PRIMARY_MANIFEST_OWNER_PREFIX_MISMATCH")
    file_count = manifest.get("regular_file_count")
    expected_ranges = [*expected_prefix_ranges,
                       {"start_row": trusted_rows, "end_row_exclusive": file_count,
                        "reader_sha256": expected.get("primary_reader_sha256")}]
    if (not isinstance(file_count, int) or file_count < trusted_rows
            or expected.get("primary_reader_sha256") != R5_PRIMARY_READER_SHA256
            or manifest.get("reader_origin_ranges") != expected_ranges
            or manifest.get("trusted_prefix_reused") is not True
            or not isinstance(manifest.get("actual_bytes_read_new_files"), int)
            or manifest.get("actual_bytes_read_new_files", -1) < 0):
        raise ValueError("R5_PRIMARY_MANIFEST_READ_ACCOUNTING_OR_ORIGIN_RANGES_INVALID")
    revalidated_bytes = manifest.get("actual_bytes_read_prefix_revalidation")
    total_hash_bytes = manifest.get("actual_bytes_read_hash")
    if (not isinstance(revalidated_bytes, int) or revalidated_bytes < 0
            or not isinstance(total_hash_bytes, int) or total_hash_bytes < 0
            or total_hash_bytes != manifest["actual_bytes_read_new_files"] + revalidated_bytes):
        raise ValueError("R5_PRIMARY_MANIFEST_READ_ACCOUNTING_INVALID")
    seal_name = marker.get("owner_checkpoint_seal_file")
    seal_path = _artifact(primary, seal_name)
    seal_bytes = marker.get("owner_checkpoint_seal_bytes")
    seal = _read_bounded_verified_json(seal_path, expected_sha256=seal_sha,
                                       expected_bytes=seal_bytes)
    if (seal.get("schema") != "pg_i7.owner-checkpoint-seal.v1"
            or seal.get("status") != "SEALED_PAUSED_BY_OWNER"
            or seal.get("self_excluded") is not True
            or not isinstance(seal.get("files"), list)):
        raise ValueError("R5_COPIED_OWNER_SEAL_MISMATCH")
    if production_seal:
        external_seal = WORKSPACE / "OWNER-CHECKPOINT-20261023T212726Z" / "CHECKPOINT_SEAL.json"
        if _hash_open_file(external_seal) != (seal_sha, seal_bytes):
            raise ValueError("R5_EXTERNAL_OWNER_SEAL_ANCHOR_MISMATCH")
    def _seal_member_key(value: str) -> str:
        return re.sub(r"[^a-z0-9]", "", value.casefold())
    sealed_members = {_seal_member_key(entry["path"]): entry for entry in seal["files"]
                      if isinstance(entry, dict) and isinstance(entry.get("path"), str)}
    overlay_name = marker.get("legacy_overlay_file")
    context_name = marker.get("original_continuation_context_file")
    overlay_member = sealed_members.get(_seal_member_key(overlay_name) if isinstance(overlay_name, str) else "")
    context_member = sealed_members.get(_seal_member_key(context_name) if isinstance(context_name, str) else "")
    if (not isinstance(overlay_member, dict) or not isinstance(context_member, dict)
            or overlay_member.get("sha256") != marker.get("legacy_overlay_sha256")
            or overlay_member.get("bytes") != marker.get("legacy_overlay_bytes")
            or context_member.get("sha256") != marker.get("original_continuation_context_sha256")
            or context_member.get("bytes") != marker.get("original_continuation_context_bytes")):
        raise ValueError("R5_OWNER_SEAL_MEMBER_BINDING_INVALID")
    overlay_path = _artifact(primary, overlay_name)
    def _validate_overlay_row(record: dict[str, Any]) -> None:
        if (record.get("schema") != "i7-engineering-legacy-reference@1"
                or record.get("snapshot_id") != snapshot
                or record.get("source_reader_sha256") != LEGACY_PREFIX_READER_SHA256
                or not isinstance(record.get("source_id"), str) or not record["source_id"]
                or not isinstance(record.get("old_row_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", record["old_row_sha256"])
                or record.get("status") != "LEGACY_PARSER_REFERENCE_UNKNOWN"
                or record.get("reason") not in {"NOT_EXTRACTED_BY_BOUNDED_V3_LITERAL_PATH_PARSER",
                                                  "LEGACY_REFERENCE_RECORD_MALFORMED"}
                or (record.get("reason") == "LEGACY_REFERENCE_RECORD_MALFORMED"
                    and record.get("target_id") != "")
                or (record.get("reason") == "NOT_EXTRACTED_BY_BOUNDED_V3_LITERAL_PATH_PARSER"
                    and (not isinstance(record.get("target_id"), str) or not record["target_id"]))):
            raise ValueError("R5_SEALED_LEGACY_OVERLAY_ROW_INVALID")
    _verify_sealed_jsonl(
        overlay_path, expected_sha256=marker.get("legacy_overlay_sha256"),
        expected_bytes=marker.get("legacy_overlay_bytes"),
        expected_rows=marker.get("legacy_overlay_rows"),
        maximum_bytes=MAX_SEALED_OVERLAY_BYTES, row_validator=_validate_overlay_row)
    overlay_manifest_name = marker.get("legacy_overlay_manifest_file")
    overlay_manifest_path = _artifact(primary, overlay_manifest_name)
    overlay_manifest = _verify_sealed_jsonl(
        overlay_manifest_path, expected_sha256=marker.get("legacy_overlay_manifest_sha256"),
        expected_bytes=marker.get("legacy_overlay_manifest_bytes"), expected_rows=1,
        maximum_bytes=1024 * 1024)
    if (overlay_manifest is None
            or overlay_manifest.get("schema") != "i7-engineering-legacy-reference-overlay-manifest@1"
            or overlay_manifest.get("status") != "CARRIED_FORWARD_SEALED_PRIOR_RECONCILIATION"
            or overlay_manifest.get("snapshot_id") != snapshot
            or overlay_manifest.get("source_reader_sha256") != LEGACY_PREFIX_READER_SHA256
            or overlay_manifest.get("source_document_parser_revision") != "legacy-unbounded-regex-001"
            or overlay_manifest.get("prefix_start_row") != 0
            or overlay_manifest.get("overlay_file") != overlay_name
            or overlay_manifest.get("overlay_sha256") != marker.get("legacy_overlay_sha256")
            or overlay_manifest.get("overlay_bytes") != marker.get("legacy_overlay_bytes")
            or overlay_manifest.get("overlay_row_count") != marker.get("legacy_overlay_rows")
            or overlay_manifest.get("row_hash_convention") != "SHA256(raw JSONL row bytes including trailing LF)"
            or overlay_manifest.get("prefix_end_row_exclusive") != expected.get("legacy_prefix_row_count")
            or overlay_manifest.get("prefix_row_count") != expected.get("legacy_prefix_row_count")
            or overlay_manifest.get("source_ledger_prefix_sha256") != expected.get("legacy_prefix_sha256")
            or overlay_manifest.get("rederived_from_source_payloads") is not False
            or overlay_manifest.get("carried_forward_into_checkpoint_rows") != expected.get("trusted_prefix_rows")):
        raise ValueError("R5_SEALED_LEGACY_OVERLAY_MANIFEST_INVALID")
    return marker, marker_sha, marker_bytes


def _valid_relpath(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("PRIVATE_PATH_MAPPING_INVALID")
    rel = value.replace("\\", "/")
    if rel == ".":
        return rel
    p = Path(rel)
    if p.is_absolute() or re.match(r"^[A-Za-z]:", rel) or any(part in {"..", ""} for part in rel.split("/")):
        raise ValueError("PRIVATE_PATH_MAPPING_NOT_RELATIVE")
    if p.as_posix() != rel:
        raise ValueError("PRIVATE_PATH_MAPPING_NOT_CANONICAL")
    return rel


def _db_row(conn: sqlite3.Connection, query: str, args: tuple[Any, ...]) -> tuple[Any, ...] | None:
    rows = conn.execute(query, args).fetchmany(2)
    if len(rows) > 1:
        raise ValueError("PRIMARY_MAPPING_OR_INVENTORY_AMBIGUOUS")
    return rows[0] if rows else None


def _assert_primary_unlocked(primary: Path) -> None:
    lock = primary / ".scan.lock"
    try:
        st = lock.lstat()
    except FileNotFoundError:
        return
    if reader._is_reparse(lock, st):
        raise ValueError("PRIMARY_LOCK_REPARSE_BLOCKED")
    raise ValueError("PRIMARY_SCAN_LOCK_PRESENT_REVIEW_REQUIRED")


def repair_primary_exceptions(root: str | Path, primary_output: str | Path, repair_output: str | Path,
                              *, expected_primary_pins: dict[str, str],
                              test_api: bool = False) -> dict[str, Any]:
    """Repair only exact primary mode-mismatch exceptions into a separate ledger.

    The complete inventory, path map, ledger, lock state, and candidate metadata
    are validated before the first source file is opened. Target bytes are hashed
    only after every candidate passes this metadata-only preflight.
    """
    root, primary, output = map(lambda x: _canonical(Path(x)), (root, primary_output, repair_output))
    if not test_api and root != _canonical(reader.PRODUCTION_ROOT):
        raise ValueError("PRODUCTION_ROOT_MUST_MATCH_EXACTLY")
    if not root.is_dir() or not primary.is_dir() or output.exists():
        raise ValueError("REPAIR_PATH_STATE_INVALID")
    reader._validate_input_ancestors(root)
    reader._validate_output(root, primary)
    reader._validate_output(root, output)
    if not _inside(primary, VALIDATION_ROOT) or not _inside(output, VALIDATION_ROOT):
        raise ValueError("REPAIR_OUTPUTS_MUST_BE_UNDER_VALIDATION")
    if _inside(primary, output) or _inside(output, primary) or _inside(root, primary) or _inside(root, output):
        raise ValueError("REPAIR_PATHS_OVERLAP")
    _assert_primary_unlocked(primary)

    manifest_path = primary / "corpus-manifest.jsonl"
    manifest, manifest_raw, manifest_file_hash, manifest_file_bytes = _read_manifest(manifest_path)
    snapshot = manifest.get("snapshot_id")
    if not isinstance(snapshot, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        raise ValueError("PRIMARY_SNAPSHOT_ID_INVALID")
    if (manifest.get("final_snapshot_id") != snapshot
            or manifest.get("initial_inventory_sha256") != snapshot
            or manifest.get("final_inventory_sha256") != snapshot
            or manifest.get("inventory_status") != "STABLE"):
        raise ValueError("PRIMARY_FINAL_INVENTORY_NOT_STABLE")
    if manifest.get("protection_policy_sha256") != reader.PROTECTION_POLICY_SHA256:
        raise ValueError("PRIMARY_PROTECTION_POLICY_MISMATCH")
    expected_fields = {"snapshot_id", "manifest_row_sha256", "manifest_file_sha256",
                       "inventory_raw_sha256", "ledger_sha256",
                       "pathmap_sha256", "protection_policy_sha256", "primary_reader_sha256",
                       "legacy_prefix_reader_sha256", "continuation_import_sha256",
                       "continuation_import_bytes", "legacy_prefix_row_count",
                       "owner_checkpoint_seal_sha256", "trusted_owner_prefix_marker_sha256",
                       "trusted_prefix_rows", "trusted_prefix_ledger_bytes", "trusted_prefix_sha256",
                       "legacy_prefix_sha256", "legacy_prefix_bytes"}
    if not isinstance(expected_primary_pins, dict) or set(expected_primary_pins) != expected_fields:
        raise ValueError("EXPECTED_PRIMARY_PINS_REQUIRED")
    hash_fields = expected_fields - {"legacy_prefix_row_count", "continuation_import_bytes",
                                    "trusted_prefix_rows", "trusted_prefix_ledger_bytes", "legacy_prefix_bytes"}
    if any(not isinstance(expected_primary_pins[key], str) or not re.fullmatch(r"[0-9a-f]{64}", expected_primary_pins[key])
           for key in hash_fields):
        raise ValueError("EXPECTED_PRIMARY_PIN_INVALID")
    if (not isinstance(expected_primary_pins["legacy_prefix_row_count"], int)
            or expected_primary_pins["legacy_prefix_row_count"] < 0):
        raise ValueError("EXPECTED_PRIMARY_PREFIX_COUNT_INVALID")
    if (not isinstance(expected_primary_pins["continuation_import_bytes"], int)
            or expected_primary_pins["continuation_import_bytes"] < 0):
        raise ValueError("EXPECTED_CONTINUATION_IMPORT_BYTE_COUNT_INVALID")
    if any(not isinstance(expected_primary_pins[key], int) or expected_primary_pins[key] < 0
           for key in ("trusted_prefix_rows", "trusted_prefix_ledger_bytes", "legacy_prefix_bytes")):
        raise ValueError("EXPECTED_TRUSTED_PREFIX_COUNT_INVALID")
    r5_mode = expected_primary_pins["primary_reader_sha256"] == R5_PRIMARY_READER_SHA256
    if (not r5_mode and (expected_primary_pins["primary_reader_sha256"] != PRIMARY_RUN_READER_SHA256
                        or expected_primary_pins["legacy_prefix_reader_sha256"] != LEGACY_PREFIX_READER_SHA256)):
        raise ValueError("PRIMARY_READER_PROVENANCE_PIN_MISMATCH")
    if r5_mode and expected_primary_pins["owner_checkpoint_seal_sha256"] != R5_OWNER_SEAL_SHA256 and not test_api:
        raise ValueError("R5_OWNER_CHECKPOINT_SEAL_PIN_MISMATCH")
    if (expected_primary_pins["snapshot_id"] != snapshot
            or expected_primary_pins["protection_policy_sha256"] != reader.PROTECTION_POLICY_SHA256):
        raise ValueError("EXPECTED_PRIMARY_SCOPE_PIN_MISMATCH")

    inventory_path = _artifact(primary, manifest.get("initial_inventory"))
    ledger_path = _artifact(primary, manifest.get("digest_ledger"))
    pathmap_path = _artifact(primary, manifest.get("private_path_mapping_local_only"))
    continuation_path = primary / "CONTINUATION_IMPORT.json"
    if not continuation_path.is_file() or reader._is_reparse(continuation_path, continuation_path.lstat()):
        raise ValueError("CONTINUATION_IMPORT_REQUIRED_FOR_PRODUCTION_REPAIR")
    continuation, continuation_hash, continuation_bytes = _read_continuation_import(continuation_path, snapshot)
    if (continuation_hash != expected_primary_pins["continuation_import_sha256"]
            or continuation_bytes != expected_primary_pins["continuation_import_bytes"]
            or continuation.get("old_reader_sha256") != expected_primary_pins["legacy_prefix_reader_sha256"]
            or continuation.get("new_reader_sha256") != (R5_CARRIED_CONTINUATION_READER_SHA256 if r5_mode
                                                             else expected_primary_pins["primary_reader_sha256"])
            or continuation.get("prefix_row_count") != expected_primary_pins["legacy_prefix_row_count"]):
        raise ValueError("CONTINUATION_IMPORT_PIN_MISMATCH")
    owner_marker = None
    owner_marker_sha = None
    owner_marker_bytes = 0
    if r5_mode:
        owner_marker, owner_marker_sha, owner_marker_bytes = _validate_r5_owner_prefix(
            primary, manifest, expected_primary_pins, snapshot, test_api=test_api)
        if (continuation.get("prefix_sha256") != expected_primary_pins["legacy_prefix_sha256"]
                or continuation.get("prefix_byte_count") != expected_primary_pins["legacy_prefix_bytes"]
                or owner_marker.get("legacy_prefix_rows") != continuation.get("prefix_row_count")):
            raise ValueError("R5_CARRIED_CONTINUATION_CONTEXT_MISMATCH")
        if owner_marker.get("trusted_prefix_bytes") != expected_primary_pins["trusted_prefix_ledger_bytes"]:
            raise ValueError("R5_TRUSTED_PREFIX_LEDGER_BYTE_PIN_MISMATCH")
        original_context_path = _artifact(primary, owner_marker.get("original_continuation_context_file"))
        original_context, original_context_sha, original_context_bytes = _read_continuation_import(
            original_context_path, snapshot)
        if (original_context_sha != owner_marker.get("original_continuation_context_sha256")
                or original_context_bytes != owner_marker.get("original_continuation_context_bytes")
                or original_context.get("old_reader_sha256") != expected_primary_pins["legacy_prefix_reader_sha256"]
                or original_context.get("new_reader_sha256") != PRIMARY_RUN_READER_SHA256
                or original_context.get("prefix_row_count") != expected_primary_pins["legacy_prefix_row_count"]
                or original_context.get("prefix_byte_count") != expected_primary_pins["legacy_prefix_bytes"]
                or original_context.get("prefix_sha256") != expected_primary_pins["legacy_prefix_sha256"]):
            raise ValueError("R5_ORIGINAL_CONTINUATION_CONTEXT_MISMATCH")
    output.mkdir(parents=True)
    index_path = output / "supplemental-index-local-only.sqlite3"
    conn = sqlite3.connect(index_path)
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute("PRAGMA cache_size=-8192")
    conn.executescript("""
        CREATE TABLE inventory(path_id TEXT, row_sha256 TEXT, kind TEXT, status TEXT,
                               size INTEGER, mtime_ns INTEGER, device INTEGER, inode INTEGER, mode INTEGER);
        CREATE INDEX inventory_path_id ON inventory(path_id);
        CREATE TABLE pathmap(path_id TEXT, relative_path TEXT);
        CREATE INDEX pathmap_path_id ON pathmap(path_id);
        CREATE TABLE ledger(path_id TEXT PRIMARY KEY, row_ordinal INTEGER, row_sha256 TEXT, status TEXT, detail TEXT,
                            sha256 TEXT, bytes_read_hash INTEGER, snapshot_id TEXT, size INTEGER,
                            mtime_ns INTEGER, device INTEGER, inode INTEGER, mode INTEGER);
    """)
    counts = {"inventory_rows": 0, "inventory_files": 0, "pathmap_rows": 0,
              "ledger_rows": 0, "candidate_rows": 0, "protected_or_opaque_denied": 0}
    inventory_raw_hash = hashlib.sha256()
    inventory_canonical_hash = hashlib.sha256()
    inventory_canonical_hash.update(str(_canonical(root)).casefold().encode("utf-8") + b"\0"
                                    + reader.PROTECTION_POLICY_SHA256.encode() + b"\0")
    ledger_hash = hashlib.sha256()
    legacy_prefix_hash = hashlib.sha256()
    pathmap_hash = hashlib.sha256()
    inventory_byte_count = pathmap_byte_count = ledger_byte_count = legacy_prefix_bytes = 0
    if manifest_file_hash != expected_primary_pins["manifest_file_sha256"]:
        raise ValueError("EXPECTED_PRIMARY_MANIFEST_FILE_PIN_MISMATCH")
    manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    try:
        stream = _open_verified_buffered(inventory_path)
        try:
            while True:
                raw = stream.readline(MAX_ROW_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_ROW_BYTES or not raw.endswith(b"\n"):
                    raise ValueError("PRIMARY_INVENTORY_TORN_OR_OVERSIZE")
                row = json.loads(raw)
                if not isinstance(row, dict) or not isinstance(row.get("path_id"), str):
                    raise ValueError("PRIMARY_INVENTORY_ROW_INVALID")
                canonical = (json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
                if canonical != raw:
                    raise ValueError("PRIMARY_INVENTORY_NOT_CANONICAL")
                inventory_raw_hash.update(raw)
                inventory_canonical_hash.update(raw)
                inventory_byte_count += len(raw)
                conn.execute("INSERT INTO inventory VALUES (?,?,?,?,?,?,?,?,?)",
                             (row["path_id"], hashlib.sha256(raw).hexdigest(), row.get("kind"), row.get("status"),
                              row.get("size"), row.get("mtime_ns"), row.get("device"), row.get("inode"), row.get("mode")))
                counts["inventory_rows"] += 1
                counts["inventory_files"] += int(row.get("kind") == "file")
        finally:
            stream.close()

        stream = _open_verified_buffered(pathmap_path)
        try:
            while True:
                raw = stream.readline(MAX_ROW_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_ROW_BYTES or not raw.endswith(b"\n"):
                    raise ValueError("PRIMARY_PATHMAP_TORN_OR_OVERSIZE")
                row = json.loads(raw)
                if not isinstance(row, dict) or not isinstance(row.get("path_id"), str):
                    raise ValueError("PRIMARY_PATHMAP_ROW_INVALID")
                rel = _valid_relpath(row.get("relative_path"))
                if reader._path_token(rel) != row["path_id"]:
                    raise ValueError("PRIMARY_PATHMAP_ID_MISMATCH")
                pathmap_hash.update(raw)
                pathmap_byte_count += len(raw)
                conn.execute("INSERT INTO pathmap VALUES (?,?)", (row["path_id"], rel))
                counts["pathmap_rows"] += 1
        finally:
            stream.close()

        stream = _open_verified_buffered(ledger_path)
        try:
            while True:
                raw = stream.readline(MAX_ROW_BYTES + 1)
                if not raw:
                    break
                if len(raw) > MAX_ROW_BYTES or not raw.endswith(b"\n"):
                    raise ValueError("PRIMARY_LEDGER_TORN_OR_OVERSIZE")
                row = json.loads(raw)
                if not isinstance(row, dict) or not isinstance(row.get("path_id"), str):
                    raise ValueError("PRIMARY_LEDGER_ROW_INVALID")
                if row.get("snapshot_id") != snapshot:
                    raise ValueError("PRIMARY_LEDGER_SNAPSHOT_MISMATCH")
                ledger_hash.update(raw)
                ledger_byte_count += len(raw)
                if counts["ledger_rows"] < expected_primary_pins["legacy_prefix_row_count"]:
                    legacy_prefix_hash.update(raw)
                    legacy_prefix_bytes += len(raw)
                conn.execute("INSERT INTO ledger VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             (row["path_id"], counts["ledger_rows"], hashlib.sha256(raw).hexdigest(), row.get("status"), row.get("detail"),
                              row.get("sha256"), row.get("bytes_read_hash"), row.get("snapshot_id"), row.get("size"),
                              row.get("mtime_ns"), row.get("device"), row.get("inode"), row.get("mode")))
                counts["ledger_rows"] += 1
                if row.get("status") == REPAIRABLE_STATUS and row.get("detail") == REPAIRABLE_DETAIL:
                    if row.get("sha256") is not None or row.get("bytes_read_hash") != 0:
                        raise ValueError("PRIMARY_EXCEPTION_ROW_NOT_ZERO_BYTE_FAILURE")
                    counts["candidate_rows"] += 1
        finally:
            stream.close()
        conn.commit()
        if inventory_canonical_hash.hexdigest() != snapshot:
            raise ValueError("PRIMARY_INVENTORY_SNAPSHOT_HASH_MISMATCH")
        if (counts["ledger_rows"] < expected_primary_pins["legacy_prefix_row_count"]
                or legacy_prefix_hash.hexdigest() != continuation.get("prefix_sha256")
                or legacy_prefix_bytes != continuation.get("prefix_byte_count")):
            raise ValueError("CONTINUATION_PREFIX_LEDGER_BINDING_MISMATCH")
        if counts["inventory_files"] != manifest.get("regular_file_count") or counts["ledger_rows"] != manifest.get("regular_file_count"):
            raise ValueError("PRIMARY_INVENTORY_OR_LEDGER_FILE_COUNT_MISMATCH")
        if counts["pathmap_rows"] != counts["inventory_rows"]:
            raise ValueError("PRIMARY_PATHMAP_INVENTORY_ROW_COUNT_MISMATCH")
        if r5_mode:
            cached_hashed_payload_bytes = conn.execute(
                "SELECT COALESCE(SUM(size),0) FROM ledger WHERE row_ordinal < ? AND status='HASHED'",
                (expected_primary_pins["trusted_prefix_rows"],)).fetchone()[0]
            if (manifest.get("trusted_prefix_rows_reused") != expected_primary_pins["trusted_prefix_rows"]
                    or manifest.get("trusted_prefix_bytes_reused") != cached_hashed_payload_bytes):
                raise ValueError("R5_TRUSTED_PREFIX_CACHED_PAYLOAD_BYTE_ACCOUNTING_MISMATCH")
        else:
            cached_hashed_payload_bytes = 0
        if (manifest_sha != expected_primary_pins["manifest_row_sha256"]
                or inventory_raw_hash.hexdigest() != expected_primary_pins["inventory_raw_sha256"]
                or ledger_hash.hexdigest() != expected_primary_pins["ledger_sha256"]
                or pathmap_hash.hexdigest() != expected_primary_pins["pathmap_sha256"]):
            raise ValueError("PRIMARY_ARTIFACT_PIN_MISMATCH")

        # Metadata-only preflight for every candidate completes before the first source open.
        cursor = conn.execute("SELECT path_id,row_sha256,size,mtime_ns,device,inode,mode FROM ledger "
                              "WHERE status=? AND detail=? ORDER BY path_id", (REPAIRABLE_STATUS, REPAIRABLE_DETAIL))
        for candidate in cursor:
            path_id, row_hash, size, mtime_ns, device, inode, mode = candidate
            mapped = _db_row(conn, "SELECT relative_path FROM pathmap WHERE path_id=?", (path_id,))
            inv = _db_row(conn, "SELECT row_sha256,kind,status,size,mtime_ns,device,inode,mode FROM inventory "
                          "WHERE path_id=? AND kind='file'", (path_id,))
            if mapped is None or inv is None:
                raise ValueError("PRIMARY_EXCEPTION_PATH_OR_INVENTORY_MISSING")
            rel = _valid_relpath(mapped[0])
            if reader._path_token(rel) != path_id or reader._metadata_only_reason(rel) is not None:
                counts["protected_or_opaque_denied"] += 1
                raise ValueError("PRIMARY_EXCEPTION_SCOPE_DENIED_BEFORE_OPEN")
            if inv[2] != "INVENTORIED" or (inv[3], inv[4], inv[5], inv[6], inv[7]) != (size, mtime_ns, device, inode, mode):
                raise ValueError("PRIMARY_EXCEPTION_METADATA_BINDING_MISMATCH")
            path = _canonical(root / Path(rel))
            if not _inside(path, root):
                raise ValueError("PRIMARY_EXCEPTION_PATH_ESCAPES_ROOT")
            current_path, current = reader._safe_source_file(root, rel)
            if current_path != path or current is None or current.kind != "file" or current.status != "INVENTORIED":
                raise ValueError("PRIMARY_EXCEPTION_SOURCE_NOT_ORDINARY_FILE")
            if (current.size, current.mtime_ns, current.device, current.inode, current.mode) != (size, mtime_ns, device, inode, mode):
                raise ValueError("PRIMARY_EXCEPTION_SOURCE_METADATA_CHANGED")
            conn.execute("INSERT INTO pathmap VALUES (?,?)", ("candidate:" + path_id, rel))
        conn.commit()
        _assert_primary_unlocked(primary)

        ledger_file = output / "supplemental-repair-ledger.jsonl"
        checkpoint_file = output / "supplemental-repair-checkpoints.jsonl"
        output_hash = hashlib.sha256()
        seq = 0
        repaired_count = failed_count = bytes_read = 0
        with ledger_file.open("xb", buffering=0) as ledger_out, checkpoint_file.open("xb", buffering=0) as checkpoint_out:
            cursor = conn.execute("SELECT l.path_id,l.row_ordinal,l.row_sha256,l.size,l.mtime_ns,l.device,l.inode,l.mode,i.row_sha256 "
                                  "FROM ledger l JOIN inventory i ON i.path_id=l.path_id AND i.kind='file' "
                                  "WHERE l.status=? AND l.detail=? ORDER BY l.path_id", (REPAIRABLE_STATUS, REPAIRABLE_DETAIL))
            for path_id, primary_row_ordinal, prior_row_hash, size, mtime_ns, device, inode, mode, inventory_row_hash in cursor:
                _assert_primary_unlocked(primary)
                mapped = _db_row(conn, "SELECT relative_path FROM pathmap WHERE path_id=?", ("candidate:" + path_id,))
                if mapped is None:
                    raise ValueError("PREFLIGHT_PATH_BINDING_LOST")
                rel = mapped[0]
                current_path, current = reader._safe_source_file(root, rel)
                if current_path is None or current is None or (current.size, current.mtime_ns, current.device, current.inode, current.mode) != (
                        size, mtime_ns, device, inode, mode) or reader._metadata_only_reason(rel) is not None:
                    raise ValueError("SOURCE_CHANGED_AFTER_METADATA_PREFLIGHT")
                digest, status, detail, count = reader._stable_hash_details(current_path, current)
                bytes_read += count
                repaired = status == "HASHED" and isinstance(digest, str)
                seq += 1
                if primary_row_ordinal < expected_primary_pins["legacy_prefix_row_count"]:
                    row_emitter = expected_primary_pins["legacy_prefix_reader_sha256"]
                elif r5_mode and primary_row_ordinal < expected_primary_pins["trusted_prefix_rows"]:
                    row_emitter = PRIMARY_RUN_READER_SHA256
                else:
                    row_emitter = expected_primary_pins["primary_reader_sha256"]
                row = {"schema": "i7-engineering-supplemental-repair@1", "sequence": seq,
                       "snapshot_id": snapshot, "reader_sha256": READER_SHA256,
                       "primary_run_reader_sha256": expected_primary_pins["primary_reader_sha256"],
                       "primary_row_emitter_reader_sha256": row_emitter,
                       "primary_row_ordinal": primary_row_ordinal,
                       "path_id": path_id, "primary_row_sha256": prior_row_hash,
                       "primary_inventory_row_sha256": inventory_row_hash,
                       "primary_status": REPAIRABLE_STATUS, "primary_detail": REPAIRABLE_DETAIL,
                       "historical_cause": "UNKNOWN",
                       "interpretation": "TARGETED_GUARDED_REREAD_OF_PRIOR_OPEN_STAT_FAILURE",
                       "status": "SUPPLEMENTAL_HASHED" if repaired else "SUPPLEMENTAL_REPAIR_FAILED",
                       "sha256": digest if repaired else None, "bytes_read": count,
                       "detail": reader._SECRET.sub("[REDACTED]", detail or "") or None}
                raw = (json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
                ledger_out.write(raw); os.fsync(ledger_out.fileno())
                output_hash.update(raw)
                checkpoint = {"schema": "i7-engineering-supplemental-checkpoint@1", "sequence": seq,
                              "ledger_bytes": ledger_out.tell(), "ledger_prefix_sha256": output_hash.hexdigest(),
                              "snapshot_id": snapshot, "path_id": path_id}
                checkpoint_raw = (json.dumps(checkpoint, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
                checkpoint_out.write(checkpoint_raw); os.fsync(checkpoint_out.fileno())
                repaired_count += int(repaired)
                failed_count += int(not repaired)
        _assert_primary_unlocked(primary)
        if _hash_open_file(ledger_path) != (ledger_hash.hexdigest(), ledger_byte_count):
            raise ValueError("PRIMARY_LEDGER_CHANGED_DURING_SUPPLEMENT")
        if _hash_open_file(inventory_path) != (inventory_raw_hash.hexdigest(), inventory_byte_count):
            raise ValueError("PRIMARY_INVENTORY_CHANGED_DURING_SUPPLEMENT")
        if _hash_open_file(pathmap_path) != (pathmap_hash.hexdigest(), pathmap_byte_count):
            raise ValueError("PRIMARY_PATHMAP_CHANGED_DURING_SUPPLEMENT")
        if _hash_open_file(manifest_path) != (manifest_file_hash, manifest_file_bytes):
            raise ValueError("PRIMARY_MANIFEST_CHANGED_DURING_SUPPLEMENT")
        ledger_sha, ledger_bytes = _hash_open_file(ledger_file)
        checkpoint_sha, checkpoint_bytes = _hash_open_file(checkpoint_file)
        primary_ranges = ([
            {"start_row": 0, "end_row_exclusive": expected_primary_pins["legacy_prefix_row_count"],
             "reader_sha256": expected_primary_pins["legacy_prefix_reader_sha256"]},
            {"start_row": expected_primary_pins["legacy_prefix_row_count"],
             "end_row_exclusive": expected_primary_pins["trusted_prefix_rows"],
             "reader_sha256": PRIMARY_RUN_READER_SHA256},
            {"start_row": expected_primary_pins["trusted_prefix_rows"],
             "end_row_exclusive": counts["ledger_rows"],
             "reader_sha256": expected_primary_pins["primary_reader_sha256"]},
        ] if r5_mode else [
            {"start_row": 0, "end_row_exclusive": expected_primary_pins["legacy_prefix_row_count"],
             "reader_sha256": expected_primary_pins["legacy_prefix_reader_sha256"]},
            {"start_row": expected_primary_pins["legacy_prefix_row_count"],
             "end_row_exclusive": counts["ledger_rows"],
             "reader_sha256": expected_primary_pins["primary_reader_sha256"]},
        ])
        result = {"schema": "i7-engineering-supplemental-repair-manifest@1",
                  "status": "COMPLETE_SUPPLEMENTAL_ONLY", "snapshot_id": snapshot,
                  "repair_helper_sha256": REPAIR_HELPER_SHA256,
                  "primary_manifest_row_sha256": manifest_sha,
                  "primary_manifest_file_sha256": manifest_file_hash,
                  "primary_manifest_file_bytes": manifest_file_bytes,
                  "primary_run_reader_sha256": expected_primary_pins["primary_reader_sha256"],
                  "legacy_prefix_reader_sha256": expected_primary_pins["legacy_prefix_reader_sha256"],
                  "legacy_prefix_row_count": expected_primary_pins["legacy_prefix_row_count"],
                  "legacy_prefix_ledger_sha256": continuation["prefix_sha256"],
                  "legacy_prefix_ledger_bytes": continuation["prefix_byte_count"],
                  "continuation_import_sha256": continuation_hash,
                  "continuation_import_bytes": continuation_bytes,
                  "primary_reader_ranges": primary_ranges,
                  "r5_owner_prefix_binding": ({
                      "owner_checkpoint_seal_sha256": expected_primary_pins["owner_checkpoint_seal_sha256"],
                      "trusted_owner_prefix_marker_sha256": owner_marker_sha,
                      "trusted_owner_prefix_marker_bytes": owner_marker_bytes,
                      "trusted_prefix_rows": expected_primary_pins["trusted_prefix_rows"],
                      "trusted_prefix_bytes_reused": manifest.get("trusted_prefix_bytes_reused"),
                      "trusted_prefix_ledger_bytes": expected_primary_pins["trusted_prefix_ledger_bytes"],
                      "trusted_prefix_sha256": expected_primary_pins["trusted_prefix_sha256"],
                      "actual_bytes_read_new_files": manifest.get("actual_bytes_read_new_files"),
                      "actual_bytes_read_prefix_revalidation": manifest.get("actual_bytes_read_prefix_revalidation"),
                      "prefix_payload_validation_status": "PENDING_INDEPENDENT_POSTERIOR_REHASH",
                      "legacy_overlay_file": owner_marker.get("legacy_overlay_file"),
                      "legacy_overlay_sha256": owner_marker.get("legacy_overlay_sha256"),
                      "legacy_overlay_bytes": owner_marker.get("legacy_overlay_bytes"),
                      "legacy_overlay_rows": owner_marker.get("legacy_overlay_rows"),
                      "legacy_overlay_manifest_file": owner_marker.get("legacy_overlay_manifest_file"),
                      "legacy_overlay_manifest_sha256": owner_marker.get("legacy_overlay_manifest_sha256"),
                      "legacy_overlay_manifest_bytes": owner_marker.get("legacy_overlay_manifest_bytes"),
                      "source_payload_read_during_owner_prepare": False,
                  } if r5_mode else None),
                  "primary_initial_inventory": inventory_path.name,
                  "primary_initial_inventory_raw_sha256": inventory_raw_hash.hexdigest(),
                  "primary_initial_inventory_canonical_snapshot_sha256": inventory_canonical_hash.hexdigest(),
                  "primary_ledger": ledger_path.name, "primary_ledger_sha256": ledger_hash.hexdigest(),
                  "primary_ledger_bytes": ledger_byte_count,
                  "primary_pathmap": pathmap_path.name, "primary_pathmap_sha256": pathmap_hash.hexdigest(),
                  "primary_protection_policy_sha256": reader.PROTECTION_POLICY_SHA256,
                  "reader_sha256": READER_SHA256, "repair_ledger": ledger_file.name,
                  "repair_ledger_sha256": ledger_sha, "repair_ledger_bytes": ledger_bytes,
                  "repair_checkpoints": checkpoint_file.name, "repair_checkpoints_sha256": checkpoint_sha,
                  "repair_checkpoints_bytes": checkpoint_bytes,
                  "local_only_index": index_path.name, "index_contains_private_paths_local_only": True,
                  "primary_rows": counts["ledger_rows"],
                  "primary_candidate_rows": counts["candidate_rows"], "supplemental_repaired_count": repaired_count,
                  "supplemental_failed_count": failed_count, "supplemental_bytes_read": bytes_read,
                  "primary_rows_rewritten": False, "primary_coverage_status_promoted": False,
                  "filesystem_atomic_snapshot": False,
                  "interpretation": "Targeted guarded reread of prior open-stat failures; historical cause unknown; primary coverage remains as originally reported."
                  }
        _assert_primary_unlocked(primary)
        if _hash_open_file(REPAIR_HELPER_PATH)[0] != REPAIR_HELPER_SHA256:
            raise ValueError("REPAIR_HELPER_CHANGED_DURING_SUPPLEMENT")
        manifest_out = output / "SUPPLEMENTAL_REPAIR_MANIFEST.json"
        with manifest_out.open("x", encoding="utf-8", newline="\n") as f:
            json.dump(result, f, sort_keys=True, indent=2, ensure_ascii=True)
            f.write("\n"); f.flush(); os.fsync(f.fileno())
        return result
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit("Use the reviewed campaign CLI adapter; no implicit command path is exposed here.")
