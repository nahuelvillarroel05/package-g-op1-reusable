# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Disk-backed, content-free postprocessing for an Engineering scan ledger.

Reads scanner JSONL/manifest artifacts only. It never opens corpus source files.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import ntpath
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import engineering_corpus as scanner

VALIDATION_ROOT = Path(r"PRIVATE_VALIDATION_NOT_DISTRIBUTED")
LEGACY_SOURCE_READER_SHA256 = "b78e6beb8d9c120c3d517071a79fb1ef11c91c3ae14a8f5cf45abac21239120a"
PRIMARY_RUN_READER_SHA256 = "1a4d7e9b0d68bda2183f7392e46010aa440fdc183779109e75186d0334cbbafa"
R5_PRIMARY_RUN_READER_SHA256 = "f8a2d357cd79a3bff0c197564cbfffedf192600ec851608fda5dfe03e6dd1b21"
R5_HISTORICAL_FIXTURE_READER_SHA256 = "0a18afd53ace8ef44e80503089f27d2ed35a7d779bfde4b50c9ac4ea3a3c874d"
R5_SEALBIND_FIXTURE_READER_SHA256 = "8a3b50c26d91095e6906fa4d6299ea7fdc111004ca1e03e63807bbf719a5013a"
R5_OWNER_CHECKPOINT_SEAL_SHA256 = "755c8e53d1b5f8dff99cfc1fbe16e20d1fe42f1b9d4061c3e6e5f9ae59bf8f90"
R5_TRUSTED_PREFIX_ROWS = 341500
R5_LEGACY_PREFIX_ROWS = 205000
SUPPLEMENTAL_REPAIR_READER_SHA256 = "d0923e2613e472a29a22feccd10b4df346f5ade46f43cc6179e41100e92c784e"
HISTORICAL_TEST_REPAIR_READER_SHA256 = "c49d6049e31c5ea47ae6e779bc323cf466447f02d6f0e863c0dddc037aa07d9b"
SUPPLEMENTAL_REPAIR_HELPER_SHA256 = "d21fc0693ee7ef4a204fbb7fc4140831911cafd1c7e6c65f63e3922894b918e4"
HISTORICAL_TEST_REPAIR_HELPER_SHA256 = "16a77479a7ff7fcbed190f7c3b5b4a92d6e61de52d9c5b05907a140ae8f09dff"
MAX_SUPPLEMENTAL_REPAIR_BYTES = 64 * 1024 * 1024
MAX_SUPPLEMENTAL_REPAIR_ROWS = 100_000
MAX_LEGACY_OVERLAY_BYTES = 64 * 1024 * 1024
MAX_LEGACY_OVERLAY_ROWS = 200_000
PUBLIC_FORMAT_SUFFIXES = frozenset({
    ".json", ".jsonl", ".md", ".txt", ".csv", ".log", ".py", ".zip", ".sha256",
    ".toml", ".yaml", ".yml", ".xml", ".rst", ".ini", ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd", ".sh", ".js", ".ts", ".tsx", ".jsx", ".html", ".css", ".map",
    ".pdf", ".docx", ".xlsx", ".pptx", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".sqlite", ".db", ".bin", ".dll", ".exe", ".whl", ".tar", ".gz", ".7z", ".so",
    ".pyc", ".ipynb", ".lock", ".config", ".conf", ".properties", ".gradle",
}) | scanner.TEXT_SUFFIXES


def _public_format(suffix: str | None) -> str:
    if not suffix:
        return "[no-extension]"
    normalized = suffix.casefold()
    return normalized if normalized in PUBLIC_FORMAT_SUFFIXES else "[other-extension]"


def _logical_hashed_file_byte_counts(primary_hashed_file_bytes: int,
                                    supplemental_hashed_file_bytes: int,
                                    supplemental_failed_read_bytes: int = 0) -> dict[str, int]:
    values = (primary_hashed_file_bytes, supplemental_hashed_file_bytes, supplemental_failed_read_bytes)
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("HASHED_FILE_BYTE_COUNT_INVALID")
    return {
        "primary_hashed_file_bytes": primary_hashed_file_bytes,
        "supplemental_hashed_file_bytes": supplemental_hashed_file_bytes,
        "supplemental_failed_read_bytes_excluded": supplemental_failed_read_bytes,
        "effective_unique_hashed_file_bytes": primary_hashed_file_bytes + supplemental_hashed_file_bytes,
    }


def _source_manifest_hash_fields(manifest: dict[str, Any], raw_row_sha256: str,
                                 raw_file_sha256: str, raw_file_bytes: int) -> dict[str, Any]:
    canonical_sha256 = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        # Backward-compatible field: this hashes canonical JSON for the selected final manifest row.
        "source_manifest_sha256": canonical_sha256,
        "source_manifest_canonical_sha256": canonical_sha256,
        "source_manifest_raw_file_sha256": raw_file_sha256,
        "source_manifest_last_row_raw_sha256": raw_row_sha256,
        "source_manifest_raw_file_byte_length": raw_file_bytes,
        "source_manifest_sha256_scope": "canonical JSON hash of the selected final manifest row; raw file and raw row hashes are separately labeled",
    }


def _inside(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(root)))
        return True
    except ValueError:
        return False


def _external_r5_owner_seal_path(scan: Path) -> Path:
    """Resolve the fixed owner-seal anchor from the admitted scan workspace.

    The module may be loaded from an extracted composition anywhere under
    Validation. The scan directory is the caller's admitted workspace root.
    """
    admitted_scan = Path(os.path.abspath(scan))
    if not _inside(admitted_scan, VALIDATION_ROOT):
        raise ValueError("R5_SCAN_OUTSIDE_VALIDATION")
    if admitted_scan.parent.name != "campaign" or admitted_scan.parent.parent.name != "composition":
        raise ValueError("R5_SCAN_LAYOUT_INVALID")
    _assert_no_reparse(admitted_scan)
    if not admitted_scan.is_dir():
        raise ValueError("R5_SCAN_DIRECTORY_UNAVAILABLE")
    workspace = admitted_scan.parents[2]
    if not _inside(workspace, VALIDATION_ROOT):
        raise ValueError("R5_OWNER_WORKSPACE_OUTSIDE_VALIDATION")
    _assert_no_reparse(workspace)
    anchor = workspace / "OWNER-CHECKPOINT-20261023T212726Z" / "CHECKPOINT_SEAL.json"
    if not _inside(anchor, VALIDATION_ROOT):
        raise ValueError("R5_EXTERNAL_OWNER_SEAL_OUTSIDE_VALIDATION")
    _assert_no_reparse(anchor)
    try:
        if not anchor.is_file():
            raise ValueError("R5_EXTERNAL_OWNER_SEAL_UNAVAILABLE")
    except OSError as exc:
        raise ValueError("R5_EXTERNAL_OWNER_SEAL_UNAVAILABLE") from exc
    return anchor


def _verify_external_r5_owner_seal(scan: Path, seal_sha: str, seal_bytes: int) -> None:
    if seal_sha != R5_OWNER_CHECKPOINT_SEAL_SHA256:
        raise ValueError("R5_EXTERNAL_OWNER_SEAL_PIN_MISMATCH")
    anchor = _external_r5_owner_seal_path(scan)
    if _hash_file(anchor) != (seal_sha, seal_bytes):
        raise ValueError("R5_EXTERNAL_OWNER_SEAL_MISMATCH")


def _assert_no_reparse(path: Path) -> None:
    cursor = Path(os.path.abspath(path))
    while True:
        try:
            st = cursor.lstat()
        except OSError as exc:
            raise ValueError(f"PATH_INACCESSIBLE:{cursor.name}") from exc
        if scanner._is_reparse(cursor, st):
            raise ValueError("REPARSE_PATH_BLOCKED")
        if cursor.parent == cursor:
            return
        cursor = cursor.parent


def _artifact(scan: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or name in {".", ".."}:
        raise ValueError("UNSAFE_MANIFEST_ARTIFACT_PATH")
    if ntpath.splitdrive(name)[0] or ":" in name or "/" in name or "\\" in name or Path(name).is_absolute():
        raise ValueError("UNSAFE_MANIFEST_ARTIFACT_PATH")
    path = scan / name
    if not _inside(path, scan):
        raise ValueError("UNSAFE_MANIFEST_ARTIFACT_PATH")
    _assert_no_reparse(path)
    try:
        st = path.lstat()
    except OSError as exc:
        raise ValueError("MANIFEST_ARTIFACT_UNAVAILABLE") from exc
    if scanner._is_reparse(path, st) or not path.is_file():
        raise ValueError("MANIFEST_ARTIFACT_NOT_REGULAR_FILE")
    return path


MAX_JSONL_ROW_BYTES = 8 * 1024 * 1024
MAX_BOUNDED_JSONL_ROW_BYTES = 4 * 1024 * 1024
ARTIFACT_BUFFER_BYTES = 1024 * 1024


class _InitialSizeBoundedRaw(io.RawIOBase):
    """Bound bytes pulled from one already-verified file handle to initial size + 1."""
    def __init__(self, raw: Any, expected_size: int):
        super().__init__()
        if type(expected_size) is not int or expected_size < 0:
            raise ValueError("SUMMARY_ARTIFACT_INITIAL_SIZE_INVALID")
        self._raw = raw
        self.expected_size = expected_size
        self.bytes_read = 0

    def readable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._raw.fileno()

    def readinto(self, buffer: Any) -> int:
        if self.closed:
            raise ValueError("I/O operation on closed artifact")
        view = memoryview(buffer).cast("B")
        if not view:
            return 0
        remaining = self.expected_size - self.bytes_read
        # Permit exactly one byte beyond the opened size as an EOF/growth probe.
        requested = min(len(view), max(1, remaining + 1))
        data = self._raw.read(requested)
        if not data:
            if remaining > 0:
                raise ValueError("SUMMARY_ARTIFACT_TRUNCATED_DURING_READ")
            return 0
        self.bytes_read += len(data)
        if len(data) > remaining:
            raise ValueError("SUMMARY_ARTIFACT_GREW_DURING_READ")
        view[:len(data)] = data
        return len(data)

    def close(self) -> None:
        if not self.closed:
            try:
                self._raw.close()
            finally:
                super().close()


class _TrackedBufferedReader:
    """Track logical consumer position while preserving bounded buffered reads."""
    def __init__(self, stream: io.BufferedReader):
        self._stream = stream
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        data = self._stream.read(size)
        self._position += len(data)
        return data

    def readline(self, size: int = -1) -> bytes:
        data = self._stream.readline(size)
        self._position += len(data)
        return data

    def tell(self) -> int:
        return self._position

    def fileno(self) -> int:
        return self._stream.fileno()

    def close(self) -> None:
        self._stream.close()


@contextmanager
def _stable_artifact_reader(path: Path):
    """Open and fully consume a bounded, held artifact; verify handle and path stability."""
    raw, before, opened, final_path = scanner._open_verified(path)
    bounded = None
    stream = None
    try:
        # Keep construction inside the ownership scope: each completed wrapper owns the
        # preceding handle, and any constructor failure closes the most recent owner.
        bounded = _InitialSizeBoundedRaw(raw, opened.st_size)
        buffered = io.BufferedReader(bounded, buffer_size=ARTIFACT_BUFFER_BYTES)
        stream = _TrackedBufferedReader(buffered)
        yield stream, opened
        if stream.tell() != opened.st_size:
            raise ValueError("SUMMARY_ARTIFACT_NOT_FULLY_CONSUMED")
        # The bounded raw layer allows one and only one extra byte to detect growth.
        if stream.read(1):
            raise ValueError("SUMMARY_ARTIFACT_GREW_DURING_READ")
        if bounded.bytes_read != opened.st_size:
            raise ValueError("SUMMARY_ARTIFACT_BYTE_COUNT_MISMATCH")
        after_fd = os.fstat(stream.fileno())
        after_path = path.lstat()
        if (scanner._cross_api_stat_tuple(before) != scanner._cross_api_stat_tuple(opened)
                or scanner._cross_api_stat_tuple(after_fd) != scanner._cross_api_stat_tuple(opened)
                or scanner._cross_api_stat_tuple(after_path) != scanner._cross_api_stat_tuple(opened)
                or scanner._is_reparse(path, after_path)
                or scanner._path_has_reparse_ancestor(path)):
            raise ValueError("SUMMARY_ARTIFACT_METADATA_CHANGED_DURING_READ")
        final_after = scanner._final_path_from_handle(stream.fileno())
        expected_path = os.path.abspath(os.fspath(path))
        if (final_after is None
                or ntpath.normcase(ntpath.normpath(final_path)) != ntpath.normcase(ntpath.normpath(expected_path))
                or ntpath.normcase(ntpath.normpath(final_after)) != ntpath.normcase(ntpath.normpath(expected_path))):
            raise ValueError("SUMMARY_ARTIFACT_HELD_FINAL_PATH_CHANGED")
    except BaseException:
        try:
            if stream is not None:
                stream.close()
            elif bounded is not None:
                bounded.close()
            else:
                raw.close()
        except BaseException:
            # Preserve the original reader/construction failure and traceback.
            pass
        raise
    else:
        stream.close()


def _jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with _stable_artifact_reader(path) as (stream, _opened):
        for number in range(1, 2**63):
            line = stream.readline(MAX_JSONL_ROW_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_JSONL_ROW_BYTES:
                raise ValueError(f"JSONL_ROW_SIZE_LIMIT:{path.name}:{number}")
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError(f"INVALID_JSONL:{path.name}:{number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"INVALID_JSONL_ROW:{path.name}:{number}")
            yield value


def _jsonl_hashed(path: Path, digest: Any) -> Iterator[tuple[dict[str, Any], bytes]]:
    with _stable_artifact_reader(path) as (stream, _opened):
        for number in range(1, 2**63):
            raw = stream.readline(MAX_JSONL_ROW_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_JSONL_ROW_BYTES:
                raise ValueError(f"JSONL_ROW_SIZE_LIMIT:{path.name}:{number}")
            digest.update(raw)
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError(f"INVALID_JSONL:{path.name}:{number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"INVALID_JSONL_ROW:{path.name}:{number}")
            yield value, raw


def _last_manifest(path: Path) -> dict[str, Any]:
    last = None
    for row in _jsonl(path):
        last = row
    if last is None:
        raise ValueError("EMPTY_CORPUS_MANIFEST")
    if last.get("schema") != "i7-engineering-corpus-scan@1":
        raise ValueError("UNSUPPORTED_SCAN_SCHEMA")
    return last


def _last_manifest_binding(path: Path) -> tuple[dict[str, Any], str, str, int]:
    digest = hashlib.sha256()
    byte_count = 0
    last = None
    last_raw = None
    for row, raw in _jsonl_hashed(path, digest):
        byte_count += len(raw)
        last, last_raw = row, raw
    if last is None or last_raw is None:
        raise ValueError("EMPTY_CORPUS_MANIFEST")
    if last.get("schema") != "i7-engineering-corpus-scan@1":
        raise ValueError("UNSUPPORTED_SCAN_SCHEMA")
    return last, hashlib.sha256(last_raw).hexdigest(), digest.hexdigest(), byte_count


def _legacy_overlay(scan: Path, snapshot: str) -> tuple[dict[str, Any], Path, str, int, str, int] | None:
    manifest_path = scan / "legacy-reference-reconciliation-manifest.jsonl"
    try:
        manifest_stat = manifest_path.lstat()
    except FileNotFoundError:
        return None
    _assert_no_reparse(manifest_path)
    if scanner._is_reparse(manifest_path, manifest_stat) or not manifest_path.is_file():
        raise ValueError("LEGACY_REFERENCE_OVERLAY_MANIFEST_NOT_REGULAR_FILE")
    manifest_rows = [row for row, _ in _bounded_jsonl(
        manifest_path, max_bytes=MAX_LEGACY_OVERLAY_BYTES,
        max_rows=MAX_LEGACY_OVERLAY_ROWS, label="LEGACY_OVERLAY_MANIFEST")]
    if not manifest_rows:
        raise ValueError("EMPTY_LEGACY_REFERENCE_OVERLAY_MANIFEST")
    manifest = manifest_rows[-1]
    prefix_count = manifest.get("prefix_row_count")
    status = manifest.get("status")
    if (manifest.get("schema") != "i7-engineering-legacy-reference-overlay-manifest@1"
            or status not in {"COMPLETE", "CARRIED_FORWARD_SEALED_PRIOR_RECONCILIATION"}
            or manifest.get("snapshot_id") != snapshot
            or manifest.get("source_reader_sha256") != LEGACY_SOURCE_READER_SHA256
            or manifest.get("source_document_parser_revision") != "legacy-unbounded-regex-001"
            or manifest.get("prefix_start_row") != 0
            or not isinstance(prefix_count, int) or prefix_count < 0
            or manifest.get("prefix_end_row_exclusive") != prefix_count
            or manifest.get("row_hash_convention") != "SHA256(raw JSONL row bytes including trailing LF)"):
        raise ValueError("LEGACY_REFERENCE_OVERLAY_MANIFEST_INVALID")
    if status == "CARRIED_FORWARD_SEALED_PRIOR_RECONCILIATION":
        carried_rows = manifest.get("carried_forward_into_checkpoint_rows")
        if (manifest.get("rederived_from_source_payloads") is not False
                or not isinstance(carried_rows, int) or carried_rows < prefix_count):
            raise ValueError("LEGACY_REFERENCE_OVERLAY_CARRIED_FORWARD_BINDING_INVALID")
    overlay_path = _artifact(scan, manifest.get("overlay_file"))
    overlay_sha, overlay_size = _hash_file(overlay_path)
    overlay_manifest_sha, overlay_manifest_size = _hash_file(manifest_path)
    if (overlay_sha != manifest.get("overlay_sha256")
            or (status == "CARRIED_FORWARD_SEALED_PRIOR_RECONCILIATION"
                and overlay_size != manifest.get("overlay_bytes"))
            or ("overlay_bytes" in manifest and overlay_size != manifest.get("overlay_bytes"))):
        raise ValueError("LEGACY_REFERENCE_OVERLAY_HASH_MISMATCH")
    count = 0
    allowed_reasons = {"NOT_EXTRACTED_BY_BOUNDED_V3_LITERAL_PATH_PARSER", "LEGACY_REFERENCE_RECORD_MALFORMED"}
    for row, _ in _bounded_jsonl(overlay_path, max_bytes=MAX_LEGACY_OVERLAY_BYTES,
                                 max_rows=MAX_LEGACY_OVERLAY_ROWS, label="LEGACY_OVERLAY"):
        target_id = row.get("target_id")
        if (row.get("schema") != "i7-engineering-legacy-reference@1"
                or row.get("snapshot_id") != snapshot
                or row.get("source_reader_sha256") != LEGACY_SOURCE_READER_SHA256
                or not isinstance(row.get("source_id"), str) or len(row["source_id"]) != 64
                or not isinstance(row.get("old_row_sha256"), str) or len(row["old_row_sha256"]) != 64
                or row.get("status") != "LEGACY_PARSER_REFERENCE_UNKNOWN"
                or row.get("reason") not in allowed_reasons
                or (target_id != "" and (not isinstance(target_id, str) or len(target_id) != 64))
                or (target_id == "") != (row.get("reason") == "LEGACY_REFERENCE_RECORD_MALFORMED")):
            raise ValueError("LEGACY_REFERENCE_OVERLAY_ROW_INVALID")
        count += 1
    if count != manifest.get("overlay_row_count"):
        raise ValueError("LEGACY_REFERENCE_OVERLAY_ROW_COUNT_MISMATCH")
    return manifest, overlay_path, overlay_sha, overlay_size, overlay_manifest_sha, overlay_manifest_size


def verify_legacy_overlay_binding(scan_dir: str | Path, snapshot_id: str,
                                  digest_doc: dict[str, Any], coverage_doc: dict[str, Any],
                                  summary_dir: str | Path | None = None) -> dict[str, Any] | None:
    """Revalidate legacy overlay bytes and their exact old-ledger bindings.

    This is used by graph construction and graph verification. An overlay row
    can only reduce certainty: its exact old reference is emitted UNKNOWN even
    when the current snapshot contains a readable target with the same ID.
    """
    scan = Path(scan_dir).resolve(strict=True)
    summary = Path(summary_dir).resolve(strict=True) if summary_dir is not None else scan
    _assert_no_reparse(scan)
    _assert_no_reparse(summary)
    legacy = _legacy_overlay(scan, snapshot_id)
    digest_binding = digest_doc.get("legacy_reference_overlay")
    coverage_binding = coverage_doc.get("legacy_reference_overlay")
    binding_path = summary / "ENGINEERING_LEGACY_REFERENCE_OVERLAY_BINDING.json"
    if legacy is None:
        if digest_binding is not None or coverage_binding is not None or binding_path.exists():
            raise ValueError("LEGACY_REFERENCE_BINDING_WITHOUT_OVERLAY")
        return None

    manifest, overlay_path, overlay_sha, overlay_size, overlay_manifest_sha, overlay_manifest_size = legacy
    if digest_binding is None or coverage_binding is None or not binding_path.is_file():
        raise ValueError("LEGACY_REFERENCE_OVERLAY_BINDING_MISSING")
    expected = {"schema": "i7-engineering-legacy-reference-binding@1", "snapshot_id": snapshot_id,
        "source_reader_sha256": manifest["source_reader_sha256"],
        "source_document_parser_revision": manifest["source_document_parser_revision"],
        "prefix_start_row": manifest["prefix_start_row"],
        "prefix_end_row_exclusive": manifest["prefix_end_row_exclusive"],
        "prefix_row_count": manifest["prefix_row_count"],
        "source_ledger_prefix_sha256": manifest["source_ledger_prefix_sha256"],
        "overlay_file": overlay_path.name, "overlay_sha256": overlay_sha,
        "overlay_byte_length": overlay_size, "overlay_manifest_sha256": overlay_manifest_sha,
        "overlay_manifest_byte_length": overlay_manifest_size,
        "overlay_row_count": manifest["overlay_row_count"],
        "legacy_reference_unknown_count": manifest["overlay_row_count"]}
    try:
        stored_binding = json.loads(binding_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("LEGACY_REFERENCE_BINDING_INVALID") from exc
    if stored_binding != expected or digest_binding != expected or coverage_binding != expected:
        raise ValueError("LEGACY_REFERENCE_BINDING_MISMATCH")

    ledger_path = _artifact(scan, digest_doc.get("ledger", "scan-ledger.jsonl"))
    prefix_count = manifest["prefix_row_count"]
    overlay_rows = [row for row, _ in _bounded_jsonl(
        overlay_path, max_bytes=MAX_LEGACY_OVERLAY_BYTES,
        max_rows=MAX_LEGACY_OVERLAY_ROWS, label="LEGACY_OVERLAY")]
    if len({(row["source_id"], row["target_id"], row["old_row_sha256"]) for row in overlay_rows}) != len(overlay_rows):
        raise ValueError("LEGACY_REFERENCE_OVERLAY_DUPLICATE_ROW")
    by_source_hash: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in overlay_rows:
        by_source_hash.setdefault((row["source_id"], row["old_row_sha256"]), []).append(row)
    prefix_digest = hashlib.sha256()
    prefix_rows = matched_rows = 0
    for row_index, (row, raw_line) in enumerate(_jsonl_hashed(ledger_path, hashlib.sha256())):
        if row_index >= prefix_count:
            break
        prefix_digest.update(raw_line)
        prefix_rows += 1
        row_sha = hashlib.sha256(raw_line).hexdigest()
        candidates = by_source_hash.get((row.get("path_id"), row_sha), [])
        refs = row.get("document", {}).get("explicit_references", [])
        malformed = any(not isinstance(ref, dict) or not isinstance(ref.get("target_id"), str)
                        or not ref.get("target_id") for ref in refs)
        for overlay_row in candidates:
            target_id = overlay_row["target_id"]
            if target_id == "":
                valid = malformed and overlay_row["reason"] == "LEGACY_REFERENCE_RECORD_MALFORMED"
            else:
                valid = (overlay_row["reason"] == "NOT_EXTRACTED_BY_BOUNDED_V3_LITERAL_PATH_PARSER"
                         and any(isinstance(ref, dict) and ref.get("target_id") == target_id for ref in refs))
            if not valid or overlay_row["status"] != "LEGACY_PARSER_REFERENCE_UNKNOWN":
                raise ValueError("LEGACY_REFERENCE_OVERLAY_DOES_NOT_MATCH_EXACT_OLD_ROW")
            matched_rows += 1
    if (prefix_rows != prefix_count or prefix_digest.hexdigest() != manifest["source_ledger_prefix_sha256"]
            or matched_rows != len(overlay_rows)):
        raise ValueError("LEGACY_REFERENCE_PREFIX_OR_MATCH_COUNT_MISMATCH")

    references_path = _artifact(summary, digest_doc.get("document_references", "ENGINEERING_DOCUMENT_REFERENCES.jsonl"))
    expected_unknown = {(row["source_id"], row["target_id"] or None, row["old_row_sha256"])
                        for row in overlay_rows}
    expected_relations = {(row["source_id"], row["target_id"] or None) for row in overlay_rows}
    seen_unknown: set[tuple[str, str | None, str]] = set()
    for ref in _jsonl(references_path):
        relation = (ref.get("source_id"), ref.get("target_id"))
        if relation in expected_relations and ref.get("status") != "LEGACY_PARSER_REFERENCE_UNKNOWN":
            raise ValueError("LEGACY_REFERENCE_PROMOTED_OR_REATTRIBUTED")
        if ref.get("status") != "LEGACY_PARSER_REFERENCE_UNKNOWN":
            continue
        if (ref.get("legacy_source_reader_sha256") != LEGACY_SOURCE_READER_SHA256
                or ref.get("target_sha256") is not None or ref.get("target_bytes") is not None):
            raise ValueError("LEGACY_REFERENCE_PROMOTED_OR_REATTRIBUTED")
        key = (ref.get("source_id"), ref.get("target_id"), ref.get("legacy_old_row_sha256"))
        if key not in expected_unknown or key in seen_unknown:
            raise ValueError("LEGACY_REFERENCE_OUTPUT_BINDING_MISMATCH")
        seen_unknown.add(key)
    if seen_unknown != expected_unknown:
        raise ValueError("LEGACY_REFERENCE_OUTPUT_BINDING_MISMATCH")
    return expected


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    count = 0
    with _stable_artifact_reader(path) as (stream, _opened):
        while True:
            chunk = stream.read(ARTIFACT_BUFFER_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            count += len(chunk)
    return digest.hexdigest(), count


def verify_supplemental_repair_binding(scan_dir: str | Path, summary_dir: str | Path,
                                       repair_dir: str | Path | None, snapshot_id: str,
                                       *, test_api: bool = False,
                                       scope_root: str | Path | None = None) -> dict[str, Any] | None:
    """Authenticate supplement rows against the exact unchanged primary artifacts.

    This reads only scan/repair evidence under Validation. It never opens Engineering
    source documents and never promotes the primary scan status.
    """
    scan = Path(os.path.abspath(scan_dir))
    summary = Path(os.path.abspath(summary_dir))
    if not _inside(scan, VALIDATION_ROOT) or not _inside(summary, VALIDATION_ROOT):
        raise ValueError("SUPPLEMENTAL_VERIFY_PATH_OUTSIDE_VALIDATION")
    _assert_no_reparse(scan); _assert_no_reparse(summary)
    digest_doc = _read_verified_json(_artifact(summary, "ENGINEERING_CORPUS_DIGEST.json"))[0]
    coverage_doc = _read_verified_json(_artifact(summary, "COVERAGE.json"))[0]
    ledger_doc = _read_verified_json(_artifact(summary, "READ_LEDGER.json"))[0]
    binding_path = summary / "ENGINEERING_SUPPLEMENTAL_REPAIR_BINDING.json"
    if not binding_path.exists():
        if (repair_dir is not None or digest_doc.get("supplemental_repair") is not None
                or digest_doc.get("supplemental_repair_binding") is not None
                or coverage_doc.get("supplemental_repair") is not None
                or ledger_doc.get("supplemental_repair") is not None):
            raise ValueError("SUPPLEMENTAL_REPAIR_BINDING_MISSING")
        return None
    binding_path = _artifact(summary, binding_path.name)
    binding = _read_verified_json(binding_path)[0]
    if digest_doc.get("snapshot_id") != snapshot_id or coverage_doc.get("snapshot_id") != snapshot_id or ledger_doc.get("snapshot_id") != snapshot_id:
        raise ValueError("SUPPLEMENTAL_VERIFY_SNAPSHOT_MISMATCH")
    if (digest_doc.get("supplemental_repair") != binding
            or coverage_doc.get("supplemental_repair") != binding
            or ledger_doc.get("supplemental_repair") != binding
            or digest_doc.get("supplemental_repair_binding") != binding):
        raise ValueError("SUPPLEMENTAL_VERIFY_SUMMARY_BINDING_MISMATCH")
    if repair_dir is None:
        raise ValueError("SUPPLEMENTAL_REPAIR_DIRECTORY_REQUIRED")
    repair = Path(os.path.abspath(repair_dir))
    if not _inside(repair, VALIDATION_ROOT) or not repair.is_dir():
        raise ValueError("SUPPLEMENTAL_VERIFY_REPAIR_DIRECTORY_INVALID")
    _assert_no_reparse(repair)
    repair_manifest, repair_rows, source_binding = _load_supplemental_repair(repair, snapshot_id, test_api=test_api)
    if (source_binding.get("repair_manifest_sha256") != binding.get("repair_manifest_sha256")
            or source_binding.get("repair_manifest_byte_length") != binding.get("repair_manifest_byte_length")
            or source_binding.get("repair_ledger_sha256") != binding.get("repair_ledger_sha256")
            or source_binding.get("repair_ledger_byte_length") != binding.get("repair_ledger_byte_length")
            or source_binding.get("repair_checkpoints_sha256") != binding.get("repair_checkpoints_sha256")
            or source_binding.get("repair_checkpoints_byte_length") != binding.get("repair_checkpoints_byte_length")
            or source_binding.get("supplemental_reader_sha256") != binding.get("supplemental_reader_sha256")
            or source_binding.get("supplemental_helper_sha256") != binding.get("supplemental_helper_sha256")):
        raise ValueError("SUPPLEMENTAL_VERIFY_REPAIR_ARTIFACT_MISMATCH")
    manifest_path = _artifact(scan, "corpus-manifest.jsonl")
    manifest, manifest_row_sha, manifest_file_sha, manifest_file_bytes = _last_manifest_binding(manifest_path)
    if (manifest.get("snapshot_id") != snapshot_id
            or repair_manifest.get("primary_initial_inventory") != manifest.get("initial_inventory")
            or repair_manifest.get("primary_ledger") != manifest.get("digest_ledger")
            or repair_manifest.get("primary_protection_policy_sha256") != manifest.get("protection_policy_sha256")
            or manifest_row_sha != repair_manifest.get("primary_manifest_row_sha256")
            or manifest_file_sha != repair_manifest.get("primary_manifest_file_sha256")
            or manifest_file_bytes != repair_manifest.get("primary_manifest_file_bytes")):
        raise ValueError("SUPPLEMENTAL_VERIFY_PRIMARY_MANIFEST_MISMATCH")
    owner_binding = _verify_r5_owner_prefix_binding(scan, manifest, repair_manifest, snapshot_id, test_api=test_api)
    if owner_binding != binding.get("r5_owner_prefix_binding"):
        raise ValueError("SUPPLEMENTAL_VERIFY_R5_OWNER_BINDING_MISMATCH")
    ledger = _artifact(scan, manifest.get("digest_ledger", "scan-ledger.jsonl"))
    initial_pathmap_name = manifest.get("private_path_mapping_local_only")
    if initial_pathmap_name != repair_manifest.get("primary_pathmap"):
        raise ValueError("SUPPLEMENTAL_VERIFY_PATHMAP_NAME_MISMATCH")
    pathmap = _artifact(scan, initial_pathmap_name)
    ledger_hash = hashlib.sha256(); ledger_bytes = 0
    pathmap_hash = hashlib.sha256(); pathmap_bytes = 0
    for _, raw in _jsonl_hashed(pathmap, pathmap_hash):
        pathmap_bytes += len(raw)
    if pathmap_hash.hexdigest() != repair_manifest.get("primary_pathmap_sha256"):
        raise ValueError("SUPPLEMENTAL_VERIFY_PATHMAP_HASH_MISMATCH")
    selected_pathmap_name = (manifest.get("final_private_path_mapping_local_only")
                             if manifest.get("final_inventory") else initial_pathmap_name)
    selected_pathmap = _artifact(scan, selected_pathmap_name)
    selected_pathmap_hash, selected_pathmap_bytes = _hash_file(selected_pathmap)
    prefix_hash = hashlib.sha256(); prefix_bytes = prefix_rows = 0
    matched: set[str] = set()
    candidate_count = 0
    for ordinal, (row, raw) in enumerate(_jsonl_hashed(ledger, ledger_hash)):
        ledger_bytes += len(raw)
        if row.get("snapshot_id") != snapshot_id:
            raise ValueError("SUPPLEMENTAL_VERIFY_CROSS_SNAPSHOT_PRIMARY_ROW")
        if ordinal < repair_manifest.get("legacy_prefix_row_count", 0):
            prefix_hash.update(raw); prefix_bytes += len(raw); prefix_rows += 1
        eligible = row.get("status") == "REPARSE_OR_PATH_REDIRECT" and row.get("detail") == "STAT_CHANGED_AT_OPEN"
        if eligible:
            candidate_count += 1
        path_id = row.get("path_id")
        repair_row = repair_rows.get(path_id)
        if repair_row is None:
            continue
        if ordinal < repair_manifest["legacy_prefix_row_count"]:
            expected_emitter = LEGACY_SOURCE_READER_SHA256
        elif repair_manifest.get("r5_owner_prefix_binding") is not None and ordinal < R5_TRUSTED_PREFIX_ROWS:
            expected_emitter = PRIMARY_RUN_READER_SHA256
        else:
            expected_emitter = repair_manifest["primary_run_reader_sha256"]
        if (not eligible or repair_row.get("primary_row_ordinal") != ordinal
                or repair_row.get("primary_row_sha256") != hashlib.sha256(raw).hexdigest()
                or repair_row.get("primary_row_emitter_reader_sha256") != expected_emitter
                or repair_row.get("primary_status") != row.get("status")
                or repair_row.get("primary_detail") != row.get("detail")
                or row.get("sha256") is not None or int(row.get("bytes_read_hash", 0) or 0) != 0):
            raise ValueError("SUPPLEMENTAL_VERIFY_PRIMARY_ROW_MISMATCH")
        matched.add(path_id)
    if (matched != set(repair_rows) or candidate_count != repair_manifest.get("primary_candidate_rows")
            or ledger_bytes != repair_manifest.get("primary_ledger_bytes")
            or ledger_hash.hexdigest() != repair_manifest.get("primary_ledger_sha256")
            or prefix_rows != repair_manifest.get("legacy_prefix_row_count")
            or prefix_bytes != repair_manifest.get("legacy_prefix_ledger_bytes")
            or prefix_hash.hexdigest() != repair_manifest.get("legacy_prefix_ledger_sha256")):
        raise ValueError("SUPPLEMENTAL_VERIFY_PRIMARY_LEDGER_OR_PREFIX_MISMATCH")
    initial_inventory = _artifact(scan, repair_manifest["primary_initial_inventory"])
    inventory_raw, inventory_canonical, inventory_bytes, _ = _validate_inventory(
        initial_inventory, Path(os.path.abspath(scope_root or r"PRIVATE_ENGINEERING_NOT_DISTRIBUTED")),
        str(manifest.get("protection_policy_sha256", "")), repair_rows=repair_rows)
    if (inventory_raw != repair_manifest.get("primary_initial_inventory_raw_sha256")
            or inventory_canonical != repair_manifest.get("primary_initial_inventory_canonical_snapshot_sha256")
            or inventory_canonical != snapshot_id
            or any(row.get("inventory_match_count") != 1 for row in repair_rows.values())):
        raise ValueError("SUPPLEMENTAL_VERIFY_INITIAL_INVENTORY_MISMATCH")
    continuation, continuation_sha, continuation_bytes = _read_verified_json(_artifact(scan, "CONTINUATION_IMPORT.json"))
    if (continuation_sha != repair_manifest.get("continuation_import_sha256")
            or continuation_bytes != repair_manifest.get("continuation_import_bytes")
            or continuation.get("status") != "PREFIX_IMPORTED_AWAITING_EXPLICIT_V3_RESUME"
            or continuation.get("snapshot_id") != snapshot_id
            or continuation.get("old_reader_sha256") != LEGACY_SOURCE_READER_SHA256
            or continuation.get("new_reader_sha256") != repair_manifest.get("primary_run_reader_sha256")
            or continuation.get("prefix_row_count") != prefix_rows
            or continuation.get("prefix_byte_count") != prefix_bytes
            or continuation.get("prefix_sha256") != prefix_hash.hexdigest()):
        raise ValueError("SUPPLEMENTAL_VERIFY_CONTINUATION_MISMATCH")
    if (binding.get("primary_ledger_sha256") != ledger_hash.hexdigest()
            or binding.get("primary_ledger_byte_length") != ledger_bytes
            or binding.get("primary_pathmap_sha256") != selected_pathmap_hash
            or binding.get("primary_pathmap_byte_length") != selected_pathmap_bytes
            or binding.get("primary_pinned_pathmap_sha256") != pathmap_hash.hexdigest()
            or binding.get("primary_pinned_pathmap_byte_length") != pathmap_bytes
            or binding.get("supplemental_hash_join_count") != len(repair_rows)
            or binding.get("supplemental_reader_sha256") != repair_manifest.get("reader_sha256")
            or binding.get("supplemental_helper_sha256") != repair_manifest.get("repair_helper_sha256")
            or binding.get("primary_initial_inventory_sha256") != inventory_raw
            or binding.get("primary_initial_inventory_byte_length") != inventory_bytes
            or binding.get("continuation_import_sha256") != continuation_sha
            or binding.get("continuation_import_byte_length") != continuation_bytes):
        raise ValueError("SUPPLEMENTAL_VERIFY_DERIVED_BINDING_MISMATCH")
    return binding


def _read_verified_json(path: Path, *, max_bytes: int = 1024 * 1024) -> tuple[dict[str, Any], str, int]:
    digest = hashlib.sha256()
    chunks = bytearray()
    with _stable_artifact_reader(path) as (stream, opened):
        if opened.st_size > max_bytes:
            raise ValueError("SUPPLEMENTAL_JSON_SIZE_LIMIT")
        while True:
            block = stream.read(min(ARTIFACT_BUFFER_BYTES, max_bytes + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
            digest.update(block)
            if len(chunks) > max_bytes:
                raise ValueError("SUPPLEMENTAL_JSON_SIZE_LIMIT")
    try:
        value = json.loads(chunks)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
        raise ValueError("SUPPLEMENTAL_JSON_INVALID") from exc
    if not isinstance(value, dict):
        raise ValueError("SUPPLEMENTAL_JSON_NOT_OBJECT")
    return value, digest.hexdigest(), len(chunks)


def _bounded_jsonl(path: Path, *, max_bytes: int, max_rows: int,
                   label: str) -> Iterator[tuple[dict[str, Any], bytes]]:
    with _stable_artifact_reader(path) as (stream, opened):
        if opened.st_size > max_bytes:
            raise ValueError(f"{label}_BYTE_LIMIT")
        rows = total = 0
        while True:
            raw = stream.readline(MAX_BOUNDED_JSONL_ROW_BYTES + 1)
            if not raw:
                break
            total += len(raw)
            if len(raw) > MAX_BOUNDED_JSONL_ROW_BYTES or total > max_bytes:
                raise ValueError(f"{label}_BYTE_LIMIT")
            if not raw.endswith(b"\n") or not raw.strip():
                raise ValueError(f"{label}_INVALID_JSONL_ROW")
            try:
                value = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError(f"{label}_INVALID_JSONL_ROW") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{label}_INVALID_JSONL_ROW")
            rows += 1
            if rows > max_rows:
                raise ValueError(f"{label}_ROW_LIMIT")
            yield value, raw


def _load_supplemental_repair(repair_dir: Path, snapshot: str, *, test_api: bool = False) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Any]]:
    repair = Path(os.path.abspath(repair_dir))
    if not _inside(repair, VALIDATION_ROOT) or not repair.is_dir():
        raise ValueError("SUPPLEMENTAL_REPAIR_DIRECTORY_OUTSIDE_VALIDATION")
    _assert_no_reparse(repair)
    manifest_path = _artifact(repair, "SUPPLEMENTAL_REPAIR_MANIFEST.json")
    ledger_path = _artifact(repair, "supplemental-repair-ledger.jsonl")
    checkpoints_path = _artifact(repair, "supplemental-repair-checkpoints.jsonl")
    manifest, manifest_sha, manifest_bytes = _read_verified_json(manifest_path)
    r5_mode = (manifest.get("primary_run_reader_sha256") == R5_PRIMARY_RUN_READER_SHA256
               or manifest.get("r5_owner_prefix_binding") is not None)
    allowed_primary_readers = ({PRIMARY_RUN_READER_SHA256, R5_PRIMARY_RUN_READER_SHA256,
                                R5_HISTORICAL_FIXTURE_READER_SHA256, R5_SEALBIND_FIXTURE_READER_SHA256}
                               if test_api else {R5_PRIMARY_RUN_READER_SHA256})
    if (manifest.get("schema") != "i7-engineering-supplemental-repair-manifest@1"
            or manifest.get("status") != "COMPLETE_SUPPLEMENTAL_ONLY"
            or manifest.get("snapshot_id") != snapshot
            or manifest.get("reader_sha256") not in ({SUPPLEMENTAL_REPAIR_READER_SHA256, HISTORICAL_TEST_REPAIR_READER_SHA256} if test_api else {SUPPLEMENTAL_REPAIR_READER_SHA256})
            or (manifest.get("reader_sha256") == SUPPLEMENTAL_REPAIR_READER_SHA256
                and manifest.get("repair_helper_sha256") != SUPPLEMENTAL_REPAIR_HELPER_SHA256
                and not (test_api and manifest.get("repair_helper_sha256") == HISTORICAL_TEST_REPAIR_HELPER_SHA256))
            or (manifest.get("reader_sha256") == HISTORICAL_TEST_REPAIR_READER_SHA256
                and not test_api)
            or manifest.get("primary_run_reader_sha256") not in allowed_primary_readers
            or manifest.get("legacy_prefix_reader_sha256") != LEGACY_SOURCE_READER_SHA256
            or manifest.get("primary_rows_rewritten") is not False
            or manifest.get("primary_coverage_status_promoted") is not False
            or manifest.get("filesystem_atomic_snapshot") is not False
            or manifest.get("interpretation") != "Targeted guarded reread of prior open-stat failures; historical cause unknown; primary coverage remains as originally reported."):
        raise ValueError("SUPPLEMENTAL_REPAIR_MANIFEST_INVALID")
    reader_ranges = manifest.get("primary_reader_ranges")
    if not isinstance(reader_ranges, list) or not reader_ranges:
        raise ValueError("SUPPLEMENTAL_PRIMARY_READER_RANGES_INVALID")
    range_end = 0
    for reader_range in reader_ranges:
        if (not isinstance(reader_range, dict)
                or reader_range.get("start_row") != range_end
                or not isinstance(reader_range.get("end_row_exclusive"), int)
                or reader_range.get("end_row_exclusive", -1) < range_end
                or not isinstance(reader_range.get("reader_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", reader_range["reader_sha256"])):
            raise ValueError("SUPPLEMENTAL_PRIMARY_READER_RANGES_INVALID")
        range_end = reader_range["end_row_exclusive"]
    if range_end != manifest.get("primary_rows"):
        raise ValueError("SUPPLEMENTAL_PRIMARY_READER_RANGES_INVALID")
    if r5_mode:
        r5_binding = manifest.get("r5_owner_prefix_binding")
        trusted_rows = r5_binding.get("trusted_prefix_rows") if isinstance(r5_binding, dict) else None
        if (not isinstance(r5_binding, dict)
                or (r5_binding.get("owner_checkpoint_seal_sha256") != R5_OWNER_CHECKPOINT_SEAL_SHA256 and not test_api)
                or r5_binding.get("prefix_payload_validation_status") != "PENDING_INDEPENDENT_POSTERIOR_REHASH"
                or r5_binding.get("source_payload_read_during_owner_prepare") is not False
                or not isinstance(trusted_rows, int) or trusted_rows < 0
                or (not test_api and trusted_rows != R5_TRUSTED_PREFIX_ROWS)
                or not isinstance(r5_binding.get("trusted_prefix_bytes_reused"), int)
                or r5_binding.get("trusted_prefix_bytes_reused", -1) < 0
                or not isinstance(r5_binding.get("trusted_prefix_ledger_bytes"), int)
                or r5_binding.get("trusted_prefix_ledger_bytes", -1) < 0
                or not re.fullmatch(r"[0-9a-f]{64}", str(r5_binding.get("trusted_owner_prefix_marker_sha256", "")))):
            raise ValueError("SUPPLEMENTAL_R5_OWNER_PREFIX_BINDING_INVALID")
    for name, path in (("repair_ledger", ledger_path), ("repair_checkpoints", checkpoints_path)):
        if manifest.get(name) != path.name:
            raise ValueError("SUPPLEMENTAL_REPAIR_ARTIFACT_NAME_MISMATCH")
    rows: dict[str, dict[str, Any]] = {}
    ledger_bytes = count = repaired = failed = read_bytes = 0
    checkpoints = iter(_bounded_jsonl(checkpoints_path, max_bytes=MAX_SUPPLEMENTAL_REPAIR_BYTES,
                                      max_rows=MAX_SUPPLEMENTAL_REPAIR_ROWS,
                                      label="SUPPLEMENTAL_CHECKPOINTS"))
    ledger_digest = hashlib.sha256()
    for row, raw in _bounded_jsonl(ledger_path, max_bytes=MAX_SUPPLEMENTAL_REPAIR_BYTES,
                                  max_rows=MAX_SUPPLEMENTAL_REPAIR_ROWS,
                                  label="SUPPLEMENTAL_REPAIR_LEDGER"):
        ledger_digest.update(raw)
        ledger_bytes += len(raw)
        count += 1
        if row.get("sequence") != count or row.get("schema") != "i7-engineering-supplemental-repair@1":
            raise ValueError("SUPPLEMENTAL_REPAIR_SEQUENCE_OR_SCHEMA_INVALID")
        path_id = row.get("path_id")
        hash_fields = ("primary_row_sha256", "primary_inventory_row_sha256")
        ordinal = row.get("primary_row_ordinal")
        emitter_ranges = [reader_range for reader_range in reader_ranges
                          if isinstance(ordinal, int)
                          and reader_range["start_row"] <= ordinal < reader_range["end_row_exclusive"]]
        if (row.get("snapshot_id") != snapshot
                or row.get("reader_sha256") != manifest.get("reader_sha256")
                or row.get("primary_run_reader_sha256") != manifest.get("primary_run_reader_sha256")
                or len(emitter_ranges) != 1
                or row.get("primary_row_emitter_reader_sha256") != emitter_ranges[0]["reader_sha256"]
                or row.get("primary_status") != "REPARSE_OR_PATH_REDIRECT"
                or row.get("primary_detail") != "STAT_CHANGED_AT_OPEN"
                or row.get("historical_cause") != "UNKNOWN"
                or row.get("interpretation") != "TARGETED_GUARDED_REREAD_OF_PRIOR_OPEN_STAT_FAILURE"
                or not isinstance(path_id, str) or len(path_id) != 64
                or any(not isinstance(row.get(key), str) or len(row[key]) != 64 for key in hash_fields)
                or not isinstance(ordinal, int) or ordinal < 0
                or row.get("status") not in {"SUPPLEMENTAL_HASHED", "SUPPLEMENTAL_REPAIR_FAILED"}
                or not isinstance(row.get("bytes_read"), int) or row["bytes_read"] < 0
                or path_id in rows):
            raise ValueError("SUPPLEMENTAL_REPAIR_ROW_INVALID")
        if row["status"] == "SUPPLEMENTAL_HASHED":
            if not isinstance(row.get("sha256"), str) or len(row["sha256"]) != 64:
                raise ValueError("SUPPLEMENTAL_REPAIRED_HASH_INVALID")
            repaired += 1
        else:
            if row.get("sha256") is not None:
                raise ValueError("SUPPLEMENTAL_FAILED_ROW_HAS_DIGEST")
            failed += 1
        read_bytes += row["bytes_read"]
        try:
            checkpoint, checkpoint_raw = next(checkpoints)
        except StopIteration as exc:
            raise ValueError("SUPPLEMENTAL_CHECKPOINT_MISSING") from exc
        if (checkpoint.get("schema") != "i7-engineering-supplemental-checkpoint@1"
                or checkpoint.get("sequence") != count
                or checkpoint.get("snapshot_id") != snapshot
                or checkpoint.get("path_id") != path_id
                or checkpoint.get("ledger_bytes") != ledger_bytes
                or checkpoint.get("ledger_prefix_sha256") != ledger_digest.hexdigest()):
            raise ValueError("SUPPLEMENTAL_CHECKPOINT_BINDING_MISMATCH")
        row["_supplemental_row_sha256"] = hashlib.sha256(raw).hexdigest()
        row["inventory_match_count"] = 0
        row["inventory_row"] = None
        rows[path_id] = row
    try:
        next(checkpoints)
        raise ValueError("SUPPLEMENTAL_CHECKPOINT_EXTRA_ROW")
    except StopIteration:
        pass
    primary_rows = manifest.get("primary_rows")
    prefix_count = manifest.get("legacy_prefix_row_count")
    if isinstance(prefix_count, int) and isinstance(primary_rows, int):
        if manifest.get("r5_owner_prefix_binding") is not None:
            trusted_rows = manifest["r5_owner_prefix_binding"]["trusted_prefix_rows"]
            if not test_api and (trusted_rows != R5_TRUSTED_PREFIX_ROWS
                                 or manifest.get("primary_run_reader_sha256") != R5_PRIMARY_RUN_READER_SHA256):
                raise ValueError("SUPPLEMENTAL_R5_PRIMARY_ORIGIN_PIN_MISMATCH")
            expected_ranges = [
                {"start_row": 0, "end_row_exclusive": prefix_count,
                 "reader_sha256": LEGACY_SOURCE_READER_SHA256},
                {"start_row": prefix_count, "end_row_exclusive": trusted_rows,
                 "reader_sha256": PRIMARY_RUN_READER_SHA256},
                {"start_row": trusted_rows, "end_row_exclusive": primary_rows,
                 "reader_sha256": manifest.get("primary_run_reader_sha256")},
            ]
        else:
            expected_ranges = [{"start_row": 0, "end_row_exclusive": prefix_count,
                                "reader_sha256": LEGACY_SOURCE_READER_SHA256},
                               {"start_row": prefix_count, "end_row_exclusive": primary_rows,
                                "reader_sha256": PRIMARY_RUN_READER_SHA256}]
    else:
        expected_ranges = None
    if (not isinstance(primary_rows, int) or primary_rows < count
            or not isinstance(prefix_count, int) or prefix_count < 0 or prefix_count > primary_rows
            or manifest.get("primary_reader_ranges") != expected_ranges
            or manifest.get("legacy_prefix_ledger_sha256") is None
            or not isinstance(manifest.get("legacy_prefix_ledger_bytes"), int)
            or manifest.get("continuation_import_sha256") is None
            or not isinstance(manifest.get("continuation_import_bytes"), int)
            or manifest.get("primary_candidate_rows") != count
            or manifest.get("supplemental_repaired_count") != repaired
            or manifest.get("supplemental_failed_count") != failed
            or manifest.get("supplemental_bytes_read") != read_bytes
            or manifest.get("repair_ledger_sha256") != ledger_digest.hexdigest()
            or manifest.get("repair_ledger_bytes") != ledger_bytes):
        raise ValueError("SUPPLEMENTAL_REPAIR_COUNT_OR_HASH_MISMATCH")
    checkpoint_hash, checkpoint_bytes = _hash_file(checkpoints_path)
    if (manifest.get("repair_checkpoints_sha256") != checkpoint_hash
            or manifest.get("repair_checkpoints_bytes") != checkpoint_bytes
            or count > MAX_SUPPLEMENTAL_REPAIR_ROWS):
        raise ValueError("SUPPLEMENTAL_CHECKPOINT_HASH_OR_COUNT_MISMATCH")
    summary_binding = {"schema": "i7-engineering-supplemental-repair-binding@1",
        "snapshot_id": snapshot, "repair_manifest_sha256": manifest_sha,
        "repair_manifest_byte_length": manifest_bytes,
        "repair_ledger_sha256": ledger_digest.hexdigest(), "repair_ledger_byte_length": ledger_bytes,
        "repair_checkpoints_sha256": checkpoint_hash, "repair_checkpoints_byte_length": checkpoint_bytes,
        "supplemental_reader_sha256": manifest["reader_sha256"],
        "supplemental_helper_sha256": manifest.get("repair_helper_sha256"),
        "primary_run_reader_sha256": manifest["primary_run_reader_sha256"],
        "legacy_prefix_reader_sha256": LEGACY_SOURCE_READER_SHA256,
        "primary_candidate_rows": count, "supplemental_repaired_count": repaired,
        "supplemental_failed_count": failed, "supplemental_bytes_read": read_bytes,
        "primary_rows_rewritten": False, "primary_coverage_status_promoted": False,
        "filesystem_atomic_snapshot": False,
        "processing_limit_rows": MAX_SUPPLEMENTAL_REPAIR_ROWS,
        "processing_limit_bytes_per_artifact": MAX_SUPPLEMENTAL_REPAIR_BYTES}
    if r5_mode:
        summary_binding["r5_owner_prefix_binding"] = manifest["r5_owner_prefix_binding"]
    return manifest, rows, summary_binding


def _validate_inventory(path: Path, root: Path, policy_sha256: str, *,
                        repair_rows: dict[str, dict[str, Any]] | None = None) -> tuple[str, str, int, int]:
    raw_hash = hashlib.sha256()
    canonical = hashlib.sha256()
    canonical.update(str(Path(os.path.abspath(root))).casefold().encode("utf-8") + b"\0" + policy_sha256.encode() + b"\0")
    raw_bytes = entries = 0
    with _stable_artifact_reader(path) as (stream, _opened):
        for number in range(1, 2**63):
            raw = stream.readline(MAX_JSONL_ROW_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_JSONL_ROW_BYTES:
                raise ValueError(f"JSONL_ROW_SIZE_LIMIT:{path.name}:{number}")
            raw_hash.update(raw)
            raw_bytes += len(raw)
            try:
                row = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
                raise ValueError(f"INVALID_JSONL:{path.name}:{number}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"INVALID_JSONL_ROW:{path.name}:{number}")
            if repair_rows is not None:
                candidate = repair_rows.get(row.get("path_id"))
                if candidate is not None and hashlib.sha256(raw).hexdigest() == candidate["primary_inventory_row_sha256"]:
                    candidate["inventory_match_count"] += 1
                    candidate["inventory_row"] = row
            encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            canonical.update(encoded.encode("utf-8") + b"\n")
            entries += 1
    return raw_hash.hexdigest(), canonical.hexdigest(), raw_bytes, entries


def _verify_r5_owner_prefix_binding(scan: Path, primary_manifest: dict[str, Any],
                                   repair_manifest: dict[str, Any], snapshot: str,
                                   *, test_api: bool = False) -> dict[str, Any] | None:
    binding = repair_manifest.get("r5_owner_prefix_binding")
    if binding is None:
        return None
    if not isinstance(binding, dict):
        raise ValueError("SUPPLEMENTAL_R5_OWNER_PREFIX_BINDING_INVALID")
    marker_path = _artifact(scan, "OWNER_TRUSTED_PREFIX.json")
    marker, marker_sha, marker_bytes = _read_verified_json(marker_path)
    seal_sha = binding.get("owner_checkpoint_seal_sha256")
    if (marker_sha != binding.get("trusted_owner_prefix_marker_sha256")
            or marker.get("schema") != "i7-engineering-owner-trusted-prefix@1"
            or marker.get("status") != "TRUSTED_PREFIX_COMMITTED_AFTER_METADATA_PREFLIGHT"
            or marker.get("snapshot_id") != snapshot
            or marker.get("owner_checkpoint_seal_sha256") != seal_sha
            or marker.get("append_reader_sha256") != repair_manifest.get("primary_run_reader_sha256")
            or marker.get("trusted_prefix_rows") != binding.get("trusted_prefix_rows")
            or marker.get("trusted_prefix_bytes") != binding.get("trusted_prefix_ledger_bytes")
            or marker.get("trusted_prefix_sha256") != binding.get("trusted_prefix_sha256")
            or marker.get("prefix_payload_validation_status") != binding.get("prefix_payload_validation_status")
            or marker.get("source_payload_read") is not False
            or marker.get("trusted_prefix_source_payload_bytes_read") != 0
            or marker.get("metadata_preflight_status") != "PASS"):
        raise ValueError("SUPPLEMENTAL_R5_OWNER_PREFIX_MARKER_MISMATCH")
    if seal_sha != R5_OWNER_CHECKPOINT_SEAL_SHA256 and not test_api:
        raise ValueError("SUPPLEMENTAL_R5_OWNER_SEAL_PIN_MISMATCH")
    seal_path = _artifact(scan, marker.get("owner_checkpoint_seal_file"))
    copied_seal_sha, copied_seal_bytes = _hash_file(seal_path)
    if copied_seal_sha != seal_sha or copied_seal_bytes != marker.get("owner_checkpoint_seal_bytes"):
        raise ValueError("SUPPLEMENTAL_R5_COPIED_OWNER_SEAL_MISMATCH")
    if seal_sha == R5_OWNER_CHECKPOINT_SEAL_SHA256:
        _verify_external_r5_owner_seal(scan, seal_sha, copied_seal_bytes)
    _verify_r5_original_continuation(scan, marker, test_api=test_api)
    trusted_rows = binding.get("trusted_prefix_rows")
    legacy_rows = marker.get("legacy_prefix_rows")
    if (not isinstance(trusted_rows, int) or not isinstance(legacy_rows, int)
            or trusted_rows < legacy_rows or (not test_api and
               (trusted_rows != R5_TRUSTED_PREFIX_ROWS or legacy_rows != R5_LEGACY_PREFIX_ROWS
                or repair_manifest.get("primary_run_reader_sha256") != R5_PRIMARY_RUN_READER_SHA256))):
        raise ValueError("SUPPLEMENTAL_R5_TRUSTED_PREFIX_COUNT_INVALID")
    prefix_ranges = marker.get("prefix_origin_ranges")
    expected_prefix_ranges = [
        {"start_row": 0, "end_row_exclusive": legacy_rows, "reader_sha256": LEGACY_SOURCE_READER_SHA256},
        {"start_row": legacy_rows, "end_row_exclusive": trusted_rows, "reader_sha256": PRIMARY_RUN_READER_SHA256},
    ]
    expected_ranges = ([*prefix_ranges,
                        {"start_row": trusted_rows, "end_row_exclusive": primary_manifest.get("regular_file_count"),
                         "reader_sha256": repair_manifest.get("primary_run_reader_sha256")}]
                       if isinstance(prefix_ranges, list) else None)
    if (prefix_ranges != expected_prefix_ranges
            or primary_manifest.get("reader_origin_ranges") != expected_ranges
            or repair_manifest.get("primary_reader_ranges") != expected_ranges
            or primary_manifest.get("owner_checkpoint_seal_sha256") != seal_sha
            or primary_manifest.get("trusted_owner_prefix_marker_sha256") != marker_sha
            or primary_manifest.get("trusted_prefix_rows_reused") != trusted_rows
            or primary_manifest.get("trusted_prefix_bytes_reused") != binding.get("trusted_prefix_bytes_reused")
            or primary_manifest.get("legacy_overlay_sha256") != marker.get("legacy_overlay_sha256")
            or primary_manifest.get("legacy_overlay_rows") != marker.get("legacy_overlay_rows")
            or primary_manifest.get("prefix_payload_validation_status") != marker.get("prefix_payload_validation_status")
            or not isinstance(primary_manifest.get("actual_bytes_read_new_files"), int)
            or primary_manifest.get("actual_bytes_read_new_files", -1) < 0
            or not isinstance(primary_manifest.get("actual_bytes_read_prefix_revalidation"), int)
            or primary_manifest.get("actual_bytes_read_prefix_revalidation", -1) < 0
            or primary_manifest.get("actual_bytes_read_hash") != (
                primary_manifest.get("actual_bytes_read_new_files", -1)
                + primary_manifest.get("actual_bytes_read_prefix_revalidation", -1))):
        raise ValueError("SUPPLEMENTAL_R5_PRIMARY_MANIFEST_BINDING_MISMATCH")
    return {"owner_checkpoint_seal_sha256": seal_sha,
            "trusted_owner_prefix_marker_sha256": marker_sha,
            "trusted_owner_prefix_marker_bytes": marker_bytes,
            "trusted_prefix_rows": trusted_rows,
            "trusted_prefix_bytes_reused": primary_manifest.get("trusted_prefix_bytes_reused"),
            "trusted_prefix_ledger_bytes": marker.get("trusted_prefix_bytes"),
            "trusted_prefix_sha256": marker.get("trusted_prefix_sha256"),
            "actual_bytes_read_new_files": primary_manifest.get("actual_bytes_read_new_files"),
            "actual_bytes_read_prefix_revalidation": primary_manifest.get("actual_bytes_read_prefix_revalidation"),
            "prefix_payload_validation_status": marker.get("prefix_payload_validation_status"),
            "legacy_overlay_file": marker.get("legacy_overlay_file"),
            "legacy_overlay_sha256": marker.get("legacy_overlay_sha256"),
            "legacy_overlay_bytes": marker.get("legacy_overlay_bytes"),
            "legacy_overlay_rows": marker.get("legacy_overlay_rows"),
            "legacy_overlay_manifest_file": marker.get("legacy_overlay_manifest_file"),
            "legacy_overlay_manifest_sha256": marker.get("legacy_overlay_manifest_sha256"),
            "legacy_overlay_manifest_bytes": marker.get("legacy_overlay_manifest_bytes"),
            "source_payload_read_during_owner_prepare": False}


def _verify_primary_r5_owner_prefix(scan: Path, manifest: dict[str, Any], snapshot: str,
                                    *, test_api: bool = False) -> dict[str, Any] | None:
    if manifest.get("trusted_owner_prefix_marker_sha256") is None:
        if manifest.get("owner_checkpoint_seal_sha256") is not None:
            raise ValueError("R5_OWNER_MARKER_PIN_MISSING")
        return None
    marker_path = _artifact(scan, "OWNER_TRUSTED_PREFIX.json")
    marker, marker_sha, marker_bytes = _read_verified_json(marker_path)
    origins = manifest.get("reader_origin_ranges")
    current_reader = (origins[-1].get("reader_sha256")
                      if isinstance(origins, list) and origins and isinstance(origins[-1], dict) else None)
    seal_sha = manifest.get("owner_checkpoint_seal_sha256")
    if (marker_sha != manifest.get("trusted_owner_prefix_marker_sha256")
            or marker.get("schema") != "i7-engineering-owner-trusted-prefix@1"
            or marker.get("status") != "TRUSTED_PREFIX_COMMITTED_AFTER_METADATA_PREFLIGHT"
            or marker.get("snapshot_id") != snapshot
            or marker.get("owner_checkpoint_seal_sha256") != seal_sha
            or marker.get("append_reader_sha256") != current_reader
            or current_reader != R5_PRIMARY_RUN_READER_SHA256
            or marker.get("prefix_payload_validation_status") != "PENDING_INDEPENDENT_POSTERIOR_REHASH"
            or marker.get("source_payload_read") is not False
            or marker.get("trusted_prefix_source_payload_bytes_read") != 0
            or marker.get("metadata_preflight_status") != "PASS"
            or marker.get("metadata_protection_policy_sha256") != manifest.get("protection_policy_sha256")
            or marker.get("metadata_preflight_file_count") != manifest.get("regular_file_count")
            or manifest.get("trusted_prefix_rows_reused") != marker.get("trusted_prefix_rows")
            or not isinstance(manifest.get("trusted_prefix_bytes_reused"), int)
            or manifest.get("trusted_prefix_bytes_reused", -1) < 0
            or manifest.get("legacy_overlay_sha256") != marker.get("legacy_overlay_sha256")
            or not isinstance(marker.get("legacy_overlay_bytes"), int)
            or marker.get("legacy_overlay_bytes", -1) < 0
            or manifest.get("legacy_overlay_rows") != marker.get("legacy_overlay_rows")
            or manifest.get("prefix_payload_validation_status") != marker.get("prefix_payload_validation_status")):
        raise ValueError("R5_OWNER_MARKER_OR_MANIFEST_BINDING_INVALID")
    if seal_sha != R5_OWNER_CHECKPOINT_SEAL_SHA256 and not test_api:
        raise ValueError("R5_OWNER_SEAL_PIN_MISMATCH")
    seal_path = _artifact(scan, marker.get("owner_checkpoint_seal_file"))
    seal_actual = _hash_file(seal_path)
    if seal_actual[0] != seal_sha or seal_actual[1] != marker.get("owner_checkpoint_seal_bytes"):
        raise ValueError("R5_COPIED_OWNER_SEAL_MISMATCH")
    if seal_sha == R5_OWNER_CHECKPOINT_SEAL_SHA256:
        _verify_external_r5_owner_seal(scan, seal_sha, seal_actual[1])
    _verify_r5_original_continuation(scan, marker, test_api=test_api)
    if (not isinstance(manifest.get("actual_bytes_read_new_files"), int)
            or manifest.get("actual_bytes_read_new_files", -1) < 0
            or not isinstance(manifest.get("actual_bytes_read_prefix_revalidation"), int)
            or manifest.get("actual_bytes_read_prefix_revalidation", -1) < 0
            or manifest.get("actual_bytes_read_hash") != (
                manifest.get("actual_bytes_read_new_files", -1)
                + manifest.get("actual_bytes_read_prefix_revalidation", -1))):
        raise ValueError("R5_CURRENT_READ_ACCOUNTING_INVALID")
    trusted_rows = marker.get("trusted_prefix_rows")
    prefix_ranges = marker.get("prefix_origin_ranges")
    legacy_rows = marker.get("legacy_prefix_rows")
    expected_prefix_ranges = [
        {"start_row": 0, "end_row_exclusive": legacy_rows, "reader_sha256": LEGACY_SOURCE_READER_SHA256},
        {"start_row": legacy_rows, "end_row_exclusive": trusted_rows, "reader_sha256": PRIMARY_RUN_READER_SHA256},
    ]
    expected_ranges = ([*prefix_ranges,
                        {"start_row": trusted_rows, "end_row_exclusive": manifest.get("regular_file_count"),
                         "reader_sha256": current_reader}]
                       if isinstance(prefix_ranges, list) else None)
    if (not isinstance(trusted_rows, int) or trusted_rows < 0
            or prefix_ranges != expected_prefix_ranges
            or manifest.get("reader_origin_ranges") != expected_ranges):
        raise ValueError("R5_READER_ORIGIN_RANGES_INVALID")
    return {"owner_checkpoint_seal_sha256": seal_sha,
            "trusted_owner_prefix_marker_sha256": marker_sha,
            "trusted_owner_prefix_marker_bytes": marker_bytes,
            "trusted_prefix_rows": marker.get("trusted_prefix_rows"),
            "trusted_prefix_bytes_reused": manifest.get("trusted_prefix_bytes_reused"),
            "trusted_prefix_ledger_bytes": marker.get("trusted_prefix_bytes"),
            "trusted_prefix_sha256": marker.get("trusted_prefix_sha256"),
            "actual_bytes_read_new_files": manifest.get("actual_bytes_read_new_files"),
            "actual_bytes_read_prefix_revalidation": manifest.get("actual_bytes_read_prefix_revalidation"),
            "prefix_payload_validation_status": marker.get("prefix_payload_validation_status"),
            "legacy_overlay_file": marker.get("legacy_overlay_file"),
            "legacy_overlay_sha256": marker.get("legacy_overlay_sha256"),
            "legacy_overlay_bytes": marker.get("legacy_overlay_bytes"),
            "legacy_overlay_rows": marker.get("legacy_overlay_rows"),
            "legacy_overlay_manifest_file": marker.get("legacy_overlay_manifest_file"),
            "legacy_overlay_manifest_sha256": marker.get("legacy_overlay_manifest_sha256"),
            "legacy_overlay_manifest_bytes": marker.get("legacy_overlay_manifest_bytes"),
            "source_payload_read_during_owner_prepare": False}


def _verify_r5_original_continuation(scan: Path, marker: dict[str, Any], *, test_api: bool) -> None:
    original_path = _artifact(scan, marker.get("original_continuation_context_file"))
    original, original_sha, original_bytes = _read_verified_json(original_path)
    if (original_sha != marker.get("original_continuation_context_sha256")
            or original_bytes != marker.get("original_continuation_context_bytes")):
        raise ValueError("R5_ORIGINAL_CONTINUATION_CONTEXT_HASH_MISMATCH")
    if (original.get("old_reader_sha256") != LEGACY_SOURCE_READER_SHA256
            or original.get("new_reader_sha256") != PRIMARY_RUN_READER_SHA256
            or original.get("prefix_row_count") != marker.get("legacy_prefix_rows")
            or original.get("prefix_byte_count") != marker.get("legacy_prefix_bytes")
            or original.get("prefix_sha256") != marker.get("legacy_prefix_sha256")):
        raise ValueError("R5_ORIGINAL_CONTINUATION_CONTEXT_BINDING_INVALID")


def _write_json(path: Path, value: dict[str, Any]) -> None:
    fd, tmp_name = tempfile.mkstemp(prefix=".summary-", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def summarize_scan(scan_dir: str | Path, output_dir: str | Path | None = None, *,
                   test_api: bool = False, scope_root: str | Path | None = None,
                   repair_dir: str | Path | None = None) -> dict[str, Any]:
    """Summarize one frozen scan. `output_dir` must be beneath Validation.

    SQLite holds only path IDs, file metadata/digests/status and suffixes; it never
    stores raw private paths or source content. Outputs contain opaque IDs only.
    """
    scan = Path(os.path.abspath(scan_dir))
    out = Path(os.path.abspath(output_dir or scan))
    scope = Path(os.path.abspath(scope_root or r"PRIVATE_ENGINEERING_NOT_DISTRIBUTED"))
    if not test_api and scope != Path(os.path.abspath(r"PRIVATE_ENGINEERING_NOT_DISTRIBUTED")):
        raise ValueError("PRODUCTION_SCOPE_ROOT_MUST_BE_EXACT_ENGINEERING")
    if not _inside(scan, VALIDATION_ROOT) or not _inside(out, VALIDATION_ROOT):
        raise ValueError("SCAN_AND_OUTPUT_MUST_BE_UNDER_VALIDATION")
    if not scan.is_dir() or not out.is_dir():
        raise ValueError("SCAN_AND_OUTPUT_DIRECTORIES_MUST_EXIST")
    _assert_no_reparse(scan)
    _assert_no_reparse(out)
    repair = Path(os.path.abspath(repair_dir)) if repair_dir is not None else None
    if repair is not None:
        if (not _inside(repair, VALIDATION_ROOT) or not repair.is_dir()
                or _inside(repair, scan) or _inside(scan, repair)
                or _inside(repair, out) or _inside(out, repair)):
            raise ValueError("SUPPLEMENTAL_REPAIR_DIRECTORY_INVALID_OR_OVERLAPPING")
        _assert_no_reparse(repair)
    manifest_path = _artifact(scan, "corpus-manifest.jsonl")
    manifest, manifest_row_sha, manifest_file_sha, manifest_file_bytes = _last_manifest_binding(manifest_path)
    source_manifest_hash_fields = _source_manifest_hash_fields(
        manifest, manifest_row_sha, manifest_file_sha, manifest_file_bytes)
    snapshot = manifest.get("snapshot_id")
    if not snapshot or manifest.get("final_snapshot_id") != snapshot:
        raise ValueError("SCAN_SNAPSHOT_NOT_STABLE")
    r5_primary_binding = _verify_primary_r5_owner_prefix(scan, manifest, snapshot, test_api=test_api)
    supplemental = None
    repair_manifest = None
    repair_rows: dict[str, dict[str, Any]] = {}
    supplemental_binding = None
    if repair is not None:
        repair_manifest, repair_rows, supplemental_binding = _load_supplemental_repair(repair, snapshot, test_api=test_api)
        if (repair_manifest.get("primary_manifest_row_sha256") != manifest_row_sha
                or repair_manifest.get("primary_manifest_file_sha256") != manifest_file_sha
                or repair_manifest.get("primary_manifest_file_bytes") != manifest_file_bytes
                or repair_manifest.get("primary_rows") != int(manifest.get("regular_file_count", -1))
                or repair_manifest.get("primary_initial_inventory") != manifest.get("initial_inventory")
                or repair_manifest.get("primary_ledger") != manifest.get("digest_ledger")
                or repair_manifest.get("primary_pathmap") != manifest.get("private_path_mapping_local_only")
                or repair_manifest.get("primary_protection_policy_sha256") != manifest.get("protection_policy_sha256")):
            raise ValueError("SUPPLEMENTAL_REPAIR_PRIMARY_MANIFEST_BINDING_MISMATCH")
    ledger_path = _artifact(scan, manifest.get("digest_ledger", "scan-ledger.jsonl"))
    inventory_name = manifest.get("final_inventory")
    inventory_path = _artifact(scan, inventory_name if inventory_name else manifest.get("initial_inventory", "initial-inventory.jsonl"))
    expected_inventory_hash = manifest.get("final_inventory_sha256") if inventory_name else manifest.get("initial_inventory_sha256")
    actual_inventory_hash, canonical_inventory_hash, inventory_bytes, inventory_entry_count = _validate_inventory(
        inventory_path, scope, str(manifest.get("protection_policy_sha256", "")))
    if expected_inventory_hash and canonical_inventory_hash != expected_inventory_hash:
        raise ValueError("INVENTORY_HASH_MISMATCH")
    if repair_manifest is not None:
        pinned_pathmap_name = manifest.get("private_path_mapping_local_only")
        if pinned_pathmap_name != repair_manifest.get("primary_pathmap"):
            raise ValueError("SUPPLEMENTAL_REPAIR_PRIMARY_PATHMAP_NAME_MISMATCH")
        pinned_pathmap_sha, pinned_pathmap_bytes = _hash_file(_artifact(scan, pinned_pathmap_name))
        if pinned_pathmap_sha != repair_manifest.get("primary_pathmap_sha256"):
            raise ValueError("SUPPLEMENTAL_REPAIR_PRIMARY_PATHMAP_HASH_MISMATCH")
        primary_initial_inventory = _artifact(scan, repair_manifest.get("primary_initial_inventory"))
        initial_raw_hash, initial_canonical_hash, initial_inventory_bytes, _ = _validate_inventory(
            primary_initial_inventory, scope, str(manifest.get("protection_policy_sha256", "")),
            repair_rows=repair_rows)
        if (repair_manifest.get("primary_initial_inventory_raw_sha256") != initial_raw_hash
                or repair_manifest.get("primary_initial_inventory_canonical_snapshot_sha256") != initial_canonical_hash
                or initial_canonical_hash != snapshot):
            raise ValueError("SUPPLEMENTAL_REPAIR_INITIAL_INVENTORY_BINDING_MISMATCH")
        for candidate in repair_rows.values():
            inv = candidate.get("inventory_row")
            if (candidate.get("inventory_match_count") != 1 or not isinstance(inv, dict)
                    or inv.get("kind") != "file" or inv.get("status") != "INVENTORIED"):
                raise ValueError("SUPPLEMENTAL_REPAIR_INVENTORY_ROW_MISMATCH")
        continuation_path = _artifact(scan, "CONTINUATION_IMPORT.json")
        continuation, continuation_sha, continuation_bytes = _read_verified_json(continuation_path)
        if (repair_manifest.get("continuation_import_sha256") != continuation_sha
                or repair_manifest.get("continuation_import_bytes") != continuation_bytes
                or continuation.get("schema") != "i7-engineering-reader-continuation@2"
                or continuation.get("status") != "PREFIX_IMPORTED_AWAITING_EXPLICIT_V3_RESUME"
                or continuation.get("snapshot_id") != snapshot
                or continuation.get("old_reader_sha256") != LEGACY_SOURCE_READER_SHA256
                or continuation.get("new_reader_sha256") != repair_manifest.get("primary_run_reader_sha256")
                or continuation.get("prefix_row_count") != repair_manifest.get("legacy_prefix_row_count")
                or continuation.get("prefix_sha256") != repair_manifest.get("legacy_prefix_ledger_sha256")
                or continuation.get("prefix_byte_count") != repair_manifest.get("legacy_prefix_ledger_bytes")):
            raise ValueError("SUPPLEMENTAL_REPAIR_CONTINUATION_BINDING_MISMATCH")
        owner_binding = _verify_r5_owner_prefix_binding(scan, manifest, repair_manifest, snapshot, test_api=test_api)
        if owner_binding != supplemental_binding.get("r5_owner_prefix_binding"):
            raise ValueError("SUPPLEMENTAL_REPAIR_R5_OWNER_BINDING_MISMATCH")
        supplemental = {"manifest": repair_manifest, "rows": repair_rows,
                        "prefix_rows": continuation.get("prefix_row_count"),
                        "prefix_bytes": continuation.get("prefix_byte_count"),
                        "prefix_sha256": continuation.get("prefix_sha256"),
                        "r5_owner_prefix_binding": owner_binding,
                        "primary_initial_inventory_bytes": initial_inventory_bytes,
                        "primary_pathmap_sha256": pinned_pathmap_sha,
                        "primary_pathmap_bytes": pinned_pathmap_bytes}
    legacy_overlay = _legacy_overlay(scan, snapshot)
    if r5_primary_binding is not None:
        marker_binding = r5_primary_binding
        if (legacy_overlay is None
                or legacy_overlay[1].name != marker_binding.get("legacy_overlay_file")
                or legacy_overlay[2] != marker_binding.get("legacy_overlay_sha256")
                or legacy_overlay[3] != marker_binding.get("legacy_overlay_bytes")
                or legacy_overlay[0].get("overlay_row_count") != marker_binding.get("legacy_overlay_rows")
                or legacy_overlay[4] != marker_binding.get("legacy_overlay_manifest_sha256")
                or legacy_overlay[5] != marker_binding.get("legacy_overlay_manifest_bytes")
                or (scan / "legacy-reference-reconciliation-manifest.jsonl").name
                   != marker_binding.get("legacy_overlay_manifest_file")
                or (legacy_overlay[0].get("status") == "CARRIED_FORWARD_SEALED_PRIOR_RECONCILIATION"
                    and legacy_overlay[0].get("carried_forward_into_checkpoint_rows")
                    != marker_binding.get("trusted_prefix_rows"))):
            raise ValueError("R5_LEGACY_OVERLAY_MARKER_BINDING_MISMATCH")
    if legacy_overlay and legacy_overlay[0]["prefix_row_count"] > int(manifest.get("regular_file_count", -1)):
        raise ValueError("LEGACY_REFERENCE_PREFIX_EXCEEDS_SCAN_LEDGER")

    output_names = ("ENGINEERING_DOCUMENT_REFERENCES.jsonl", "ENGINEERING_DOCUMENT_GRAPH_EDGES.jsonl",
                    "ENGINEERING_DIRECTORY_MANIFEST.json", "READ_LEDGER.json", "COVERAGE.json",
                    "ENGINEERING_CORPUS_DIGEST.json", "ENGINEERING_CORPUS_INDEX.sqlite3",
                    "ENGINEERING_LEGACY_REFERENCE_OVERLAY_BINDING.json",
                    "ENGINEERING_SUPPLEMENTAL_REPAIR_BINDING.json")
    if any((out / name).exists() for name in output_names):
        raise ValueError("POSTPROCESS_OUTPUT_ALREADY_EXISTS")

    db_path = out / "ENGINEERING_CORPUS_INDEX.sqlite3"
    try:
        db_path.lstat()
        raise ValueError("POSTPROCESS_OUTPUT_ALREADY_EXISTS")
    except FileNotFoundError:
        pass
    with db_path.open("xb"):
        pass
    db = sqlite3.connect(db_path)
    try:
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("CREATE TABLE files(path_id TEXT PRIMARY KEY, sha256 TEXT, status TEXT NOT NULL, size INTEGER, suffix TEXT, kind TEXT)")
        db.execute("CREATE TABLE supplemental_files(path_id TEXT PRIMARY KEY, repair_status TEXT NOT NULL, sha256 TEXT, bytes_read INTEGER NOT NULL, primary_row_sha256 TEXT NOT NULL, primary_inventory_row_sha256 TEXT NOT NULL, repair_row_sha256 TEXT NOT NULL)")
        db.execute("CREATE TABLE refs_seen(source_id TEXT NOT NULL, target_id TEXT, observed_resolution TEXT, legacy_status TEXT, legacy_reason TEXT, old_row_sha256 TEXT, UNIQUE(source_id,target_id,observed_resolution,legacy_status,old_row_sha256))")
        db.execute("CREATE TABLE legacy_overlay(source_id TEXT NOT NULL, target_id TEXT NOT NULL, old_row_sha256 TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL, matched INTEGER NOT NULL DEFAULT 0, UNIQUE(source_id,target_id,old_row_sha256))")
        if legacy_overlay:
            overlay_manifest, overlay_path, overlay_sha, overlay_size, overlay_manifest_sha, overlay_manifest_size = legacy_overlay
            for overlay_row in _jsonl(overlay_path):
                db.execute("INSERT INTO legacy_overlay(source_id,target_id,old_row_sha256,reason,status) VALUES(?,?,?,?,?)",
                           (overlay_row["source_id"], overlay_row["target_id"], overlay_row["old_row_sha256"],
                            overlay_row["reason"], overlay_row["status"]))

        # Build suffix-only resolver index from the private local path map; discard each raw path immediately.
        pathmap_name = manifest.get("final_private_path_mapping_local_only") if inventory_name else manifest.get("private_path_mapping_local_only")
        pathmap = _artifact(scan, pathmap_name) if pathmap_name else None
        if pathmap:
            pathmap_digest = hashlib.sha256()
            pathmap_bytes = 0
            for row, raw_pathmap_row in _jsonl_hashed(pathmap, pathmap_digest):
                pathmap_bytes += len(raw_pathmap_row)
                raw = row.get("relative_path")
                if isinstance(raw, str):
                    suffix = Path(raw).suffix.casefold()
                    db.execute("INSERT OR IGNORE INTO files(path_id,sha256,status,size,suffix,kind) VALUES(?,NULL,'PATH_ONLY',NULL,?,NULL)",
                               (row.get("path_id"), suffix))
        else:
            pathmap_digest = hashlib.sha256()
            pathmap_bytes = 0

        ledger_rows = 0
        ledger_bytes = 0
        hashed_bytes = 0
        trusted_prefix_hashed_payload_bytes = 0
        trusted_prefix_expected_rows = int(manifest.get("trusted_prefix_rows_reused", 0) or 0) if r5_primary_binding else 0
        ledger_digest = hashlib.sha256()
        ledger_raw_bytes = 0
        supplemental_matched = 0
        observed_supplement_candidates = 0
        status_counts: Counter[str] = Counter()
        doc_kind_counts: Counter[str] = Counter()
        structure_status_counts: Counter[str] = Counter()
        zip_inspection_status_counts: Counter[str] = Counter()
        non_hashed_file_status_counts: Counter[str] = Counter()
        ref_count = 0
        binary_hashed_without_document_structure_count = 0
        protected_metadata_only_zero_bytes_count = 0
        prefix_digest = hashlib.sha256()
        prefix_rows = 0
        legacy_overlay_matched = 0
        legacy_prefix_count = legacy_overlay[0]["prefix_row_count"] if legacy_overlay else 0
        for row_index, (row, raw_line) in enumerate(_jsonl_hashed(ledger_path, ledger_digest)):
            ledger_raw_bytes += len(raw_line)
            if row_index < legacy_prefix_count:
                prefix_digest.update(raw_line)
                prefix_rows += 1
            if row.get("snapshot_id") != snapshot:
                raise ValueError("CROSS_SNAPSHOT_LEDGER_ROW")
            path_id = row.get("path_id")
            if not isinstance(path_id, str):
                raise ValueError("LEDGER_ROW_WITHOUT_PATH_ID")
            status = str(row.get("status", "UNKNOWN"))
            if r5_primary_binding is not None and row_index < trusted_prefix_expected_rows and status == "HASHED":
                trusted_prefix_hashed_payload_bytes += int(row.get("size", 0) or 0)
            if status == "REPARSE_OR_PATH_REDIRECT" and row.get("detail") == "STAT_CHANGED_AT_OPEN":
                observed_supplement_candidates += 1
            suffix = None
            old = db.execute("SELECT suffix FROM files WHERE path_id=?", (path_id,)).fetchone()
            if old:
                suffix = old[0]
            document = row.get("document") if isinstance(row.get("document"), dict) else None
            kind = document.get("kind") if document else None
            db.execute("INSERT INTO files(path_id,sha256,status,size,suffix,kind) VALUES(?,?,?,?,?,?) "
                       "ON CONFLICT(path_id) DO UPDATE SET sha256=excluded.sha256,status=excluded.status,size=excluded.size,"
                       "suffix=COALESCE(files.suffix,excluded.suffix),kind=excluded.kind",
                       (path_id, row.get("sha256"), status, row.get("size"), suffix, kind))
            ledger_rows += 1
            ledger_bytes += int(row.get("bytes_read_hash", 0) or 0)
            if status == "HASHED":
                hashed_bytes += int(row.get("size", 0) or 0)
            status_counts[status] += 1
            structure_status_counts[str(document.get("status", "UNKNOWN")) if document else "NO_DOCUMENT_STRUCTURE"] += 1
            if status != "HASHED":
                non_hashed_file_status_counts[status] += 1
            if status == "PROTECTED_METADATA_ONLY" and int(row.get("bytes_read_hash", 0) or 0) == 0:
                protected_metadata_only_zero_bytes_count += 1
            if suffix == ".zip":
                zip_info = row.get("zip") if isinstance(row.get("zip"), dict) else None
                zip_status = str(zip_info.get("status", "UNKNOWN")) if zip_info else f"NOT_INSPECTED:{status}"
                zip_inspection_status_counts[zip_status] += 1
            if (status == "HASHED" and document is None and suffix not in scanner.TEXT_SUFFIXES
                    and suffix != ".zip" and not isinstance(row.get("zip"), dict)):
                binary_hashed_without_document_structure_count += 1
            if kind:
                doc_kind_counts[kind] += 1
            explicit_references = (document or {}).get("explicit_references", [])
            raw_row_sha = hashlib.sha256(raw_line).hexdigest()
            if supplemental is not None and path_id in repair_rows:
                repair_row = repair_rows[path_id]
                if row_index < repair_manifest["legacy_prefix_row_count"]:
                    expected_emitter = LEGACY_SOURCE_READER_SHA256
                elif (repair_manifest.get("r5_owner_prefix_binding") is not None
                      and row_index < repair_manifest["r5_owner_prefix_binding"]["trusted_prefix_rows"]):
                    expected_emitter = PRIMARY_RUN_READER_SHA256
                else:
                    expected_emitter = repair_manifest["primary_run_reader_sha256"]
                if (repair_row.get("primary_row_ordinal") != row_index
                        or repair_row.get("primary_row_sha256") != raw_row_sha
                        or repair_row.get("primary_row_emitter_reader_sha256") != expected_emitter
                        or repair_row.get("primary_status") != status
                        or repair_row.get("primary_detail") != row.get("detail")
                        or status != "REPARSE_OR_PATH_REDIRECT"
                        or row.get("detail") != "STAT_CHANGED_AT_OPEN"
                        or row.get("sha256") is not None
                        or int(row.get("bytes_read_hash", 0) or 0) != 0):
                    raise ValueError("SUPPLEMENTAL_REPAIR_PRIMARY_ROW_MISMATCH")
                inv = repair_row.get("inventory_row")
                if (repair_row.get("inventory_match_count") != 1 or not isinstance(inv, dict)
                        or inv.get("path_id") != path_id or inv.get("kind") != "file"
                        or inv.get("status") != "INVENTORIED"):
                    raise ValueError("SUPPLEMENTAL_REPAIR_INVENTORY_ROW_MISMATCH")
                db.execute("INSERT INTO supplemental_files(path_id,repair_status,sha256,bytes_read,primary_row_sha256,primary_inventory_row_sha256,repair_row_sha256) VALUES(?,?,?,?,?,?,?)",
                           (path_id, repair_row["status"], repair_row.get("sha256"), repair_row["bytes_read"],
                            raw_row_sha, repair_row["primary_inventory_row_sha256"], repair_row["_supplemental_row_sha256"]))
                supplemental_matched += 1
            legacy_rows_for_source = []
            if row_index < legacy_prefix_count:
                legacy_rows_for_source = db.execute(
                    "SELECT target_id,reason,status FROM legacy_overlay WHERE source_id=? AND old_row_sha256=?",
                    (path_id, raw_row_sha)).fetchall()
                malformed = any(not isinstance(ref, dict) or not isinstance(ref.get("target_id"), str)
                                or not ref.get("target_id") for ref in explicit_references)
                for legacy_target, reason, legacy_status in legacy_rows_for_source:
                    if legacy_target == "":
                        valid_legacy_match = malformed and reason == "LEGACY_REFERENCE_RECORD_MALFORMED"
                    else:
                        valid_legacy_match = (reason == "NOT_EXTRACTED_BY_BOUNDED_V3_LITERAL_PATH_PARSER"
                            and any(isinstance(ref, dict) and ref.get("target_id") == legacy_target
                                    for ref in explicit_references))
                    if not valid_legacy_match or legacy_status != "LEGACY_PARSER_REFERENCE_UNKNOWN":
                        raise ValueError("LEGACY_REFERENCE_OVERLAY_DOES_NOT_MATCH_EXACT_OLD_ROW")
                    db.execute("UPDATE legacy_overlay SET matched=1 WHERE source_id=? AND target_id=? AND old_row_sha256=?",
                               (path_id, legacy_target, raw_row_sha))
                    legacy_overlay_matched += 1
            for ref in explicit_references:
                if not isinstance(ref, dict):
                    continue
                target_id = ref.get("target_id")
                if not isinstance(target_id, str) or not target_id:
                    if not any(entry[0] == "" for entry in legacy_rows_for_source):
                        ref_count += 1
                    continue
                ref_count += 1
                legacy = db.execute("SELECT status,reason,old_row_sha256 FROM legacy_overlay "
                                    "WHERE source_id=? AND target_id=? AND old_row_sha256=? AND matched=1",
                                    (path_id, target_id, raw_row_sha)).fetchone() if row_index < legacy_prefix_count else None
                db.execute("INSERT OR IGNORE INTO refs_seen(source_id,target_id,observed_resolution,legacy_status,legacy_reason,old_row_sha256) VALUES(?,?,?,?,?,?)",
                           (path_id, target_id, ref.get("resolution"), legacy[0] if legacy else None,
                            legacy[1] if legacy else None, legacy[2] if legacy else None))
            malformed_legacy = [entry for entry in legacy_rows_for_source if entry[0] == ""]
            for _, reason, legacy_status in malformed_legacy:
                ref_count += 1
                db.execute("INSERT OR IGNORE INTO refs_seen(source_id,target_id,observed_resolution,legacy_status,legacy_reason,old_row_sha256) VALUES(?,?,?,?,?,?)",
                           (path_id, None, "LEGACY_REFERENCE_RECORD_MALFORMED", legacy_status, reason, raw_row_sha))
        db.commit()
        expected_files = int(manifest.get("regular_file_count", -1))
        if ledger_rows != expected_files:
            raise ValueError(f"LEDGER_COUNT_MISMATCH:{ledger_rows}:{expected_files}")
        if (r5_primary_binding is not None
                and trusted_prefix_hashed_payload_bytes != manifest.get("trusted_prefix_bytes_reused")):
            raise ValueError("R5_TRUSTED_PREFIX_CACHED_PAYLOAD_BYTE_ACCOUNTING_MISMATCH")
        if supplemental is not None:
            if (supplemental_matched != len(repair_rows)
                    or repair_manifest.get("primary_candidate_rows") != supplemental_matched
                    or observed_supplement_candidates != supplemental_matched
                    or repair_manifest.get("primary_ledger_sha256") != ledger_digest.hexdigest()
                    or repair_manifest.get("primary_ledger_bytes") != ledger_raw_bytes
                    or repair_manifest.get("primary_pathmap_sha256") != pathmap_digest.hexdigest()
                    or (repair_manifest.get("primary_pathmap_bytes") is not None
                        and repair_manifest.get("primary_pathmap_bytes") != pathmap_bytes)):
                raise ValueError("SUPPLEMENTAL_REPAIR_PRIMARY_LEDGER_OR_PATHMAP_MISMATCH")
        format_rows = db.execute(
            "SELECT suffix,COUNT(*) FROM files WHERE status!='PATH_ONLY' GROUP BY suffix ORDER BY suffix").fetchall()
        safe_format_counts: Counter[str] = Counter()
        for suffix, count in format_rows:
            safe_format_counts[_public_format(suffix)] += count
        file_format_counts = dict(sorted(safe_format_counts.items()))
        if sum(file_format_counts.values()) != expected_files:
            raise ValueError("FILE_FORMAT_COUNT_MISMATCH")
        if legacy_overlay:
            overlay_manifest = legacy_overlay[0]
            if (prefix_rows != legacy_prefix_count
                    or prefix_digest.hexdigest() != overlay_manifest.get("source_ledger_prefix_sha256")
                    or legacy_overlay_matched != overlay_manifest.get("overlay_row_count")
                    or db.execute("SELECT count(*) FROM legacy_overlay WHERE matched=0").fetchone()[0] != 0):
                raise ValueError("LEGACY_REFERENCE_PREFIX_OR_MATCH_COUNT_MISMATCH")

        # The graph relation stream is a documented projection, with no causal or actor inference.
        refs_path = out / "ENGINEERING_DOCUMENT_REFERENCES.jsonl"
        edges_path = out / "ENGINEERING_DOCUMENT_GRAPH_EDGES.jsonl"
        ref_status_counts: Counter[str] = Counter()
        format_counts: Counter[str] = Counter()
        verified_count = 0
        unknown_count = 0
        legacy_unknown_count = 0
        with refs_path.open("x", encoding="utf-8", newline="\n") as refs_out, edges_path.open("x", encoding="utf-8", newline="\n") as edges_out:
            query = db.execute("SELECT source_id,target_id,observed_resolution,legacy_status,legacy_reason,old_row_sha256 FROM refs_seen ORDER BY source_id,target_id,legacy_status")
            for source_id, target_id, observed, legacy_status, legacy_reason, old_row_sha256 in query:
                source = db.execute("SELECT sha256,status,size,kind FROM files WHERE path_id=?", (source_id,)).fetchone()
                target = db.execute("SELECT sha256,status,size,suffix FROM files WHERE path_id=?", (target_id,)).fetchone() if target_id else None
                source_repair = db.execute("SELECT repair_status,sha256,bytes_read FROM supplemental_files WHERE path_id=?", (source_id,)).fetchone()
                target_repair = db.execute("SELECT repair_status,sha256,bytes_read FROM supplemental_files WHERE path_id=?", (target_id,)).fetchone() if target_id else None
                source_hash = source[0] if source and source[0] and source[1] == "HASHED" else source_repair[1] if source_repair and source_repair[0] == "SUPPLEMENTAL_HASHED" else None
                target_hash = target[0] if target and target[0] and target[1] == "HASHED" else target_repair[1] if target_repair and target_repair[0] == "SUPPLEMENTAL_HASHED" else None
                source_effective = bool(source_hash)
                target_effective = bool(target_hash)
                verified = bool(not legacy_status and source_effective and target_effective)
                used_supplement = bool(verified and ((source and source[1] != "HASHED") or (target and target[1] != "HASHED")))
                status = legacy_status if legacy_status else "RESOLVED_USING_SUPPLEMENTAL_HASH" if used_supplement else "RESOLVED_EXACT_PATH" if verified else "UNKNOWN"
                ref_status_counts[status] += 1
                if verified:
                    verified_count += 1
                    format_counts[_public_format(target[3])] += 1
                else:
                    unknown_count += 1
                if legacy_status == "LEGACY_PARSER_REFERENCE_UNKNOWN":
                    legacy_unknown_count += 1
                record = {"snapshot_id": snapshot, "source_id": source_id, "source_sha256": source_hash,
                          "source_bytes": source[2] if source and source[1] == "HASHED" else source_repair[2] if source_repair and source_repair[0] == "SUPPLEMENTAL_HASHED" else None,
                          "source_primary_status": source[1] if source else "UNKNOWN",
                          "source_hash_basis": "PRIMARY_HASHED" if source and source[1] == "HASHED" else "SUPPLEMENTAL_HASHED" if source_repair and source_repair[0] == "SUPPLEMENTAL_HASHED" else "NONE",
                          "target_id": target_id, "target_sha256": target_hash if verified else None,
                          "target_bytes": (target[2] if target and target[1] == "HASHED" else target_repair[2] if target_repair and target_repair[0] == "SUPPLEMENTAL_HASHED" else None) if verified else None,
                          "target_primary_status": target[1] if target else "UNKNOWN",
                          "target_hash_basis": ("PRIMARY_HASHED" if target and target[1] == "HASHED" else "SUPPLEMENTAL_HASHED" if target_repair and target_repair[0] == "SUPPLEMENTAL_HASHED" else "NONE") if verified else "NONE",
                          "status": status,
                          "resolution_basis": legacy_reason if legacy_status else "exact target_id in same snapshot ledger" if verified else "missing, denied, unresolved, or unhashed target"}
                if legacy_status:
                    record["legacy_source_reader_sha256"] = LEGACY_SOURCE_READER_SHA256
                    record["legacy_old_row_sha256"] = old_row_sha256
                refs_out.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                if verified:
                    edge = {"snapshot_id": snapshot, "source_id": source_id, "source_sha256": source_hash,
                            "target_id": target_id, "target_sha256": target_hash, "relation": "DOCUMENT_REFERENCE",
                            "status": "VERIFIED_WITH_SUPPLEMENTAL_HASH" if used_supplement else "VERIFIED", "causal": False}
                    edges_out.write(json.dumps(edge, sort_keys=True, separators=(",", ":")) + "\n")
            refs_out.flush(); os.fsync(refs_out.fileno())
            edges_out.flush(); os.fsync(edges_out.fileno())

        directory_manifest = {"schema": "i7-engineering-directory-manifest@1", "snapshot_id": snapshot,
                              "inventory": inventory_path.name, "inventory_sha256": actual_inventory_hash,
                              "inventory_bytes": inventory_bytes, "inventory_entry_count": inventory_entry_count,
                              "initial_inventory": manifest.get("initial_inventory"),
                              "final_inventory": manifest.get("final_inventory"),
                              "empty_directories_included": True, "path_identity": "opaque path_id and parent_id",
                              "private_resolver_local_only": pathmap.name if pathmap else None,
                              "index_local_only": db_path.name}
        actual_read_bytes = (int(manifest.get("actual_bytes_read_hash", 0) or 0)
                             if r5_primary_binding is not None else ledger_bytes)
        actual_new_file_read_bytes = (int(r5_primary_binding["actual_bytes_read_new_files"])
                                      if r5_primary_binding is not None else None)
        actual_prefix_revalidation_bytes = (int(r5_primary_binding["actual_bytes_read_prefix_revalidation"])
                                            if r5_primary_binding is not None else None)
        cached_prefix_bytes = (int(manifest.get("trusted_prefix_bytes_reused", 0) or 0)
                               if r5_primary_binding is not None else 0)
        cached_prefix_rows = (int(manifest.get("trusted_prefix_rows_reused", 0) or 0)
                              if r5_primary_binding is not None else 0)
        cached_prefix_ledger_bytes = (int(r5_primary_binding.get("trusted_prefix_ledger_bytes", 0) or 0)
                                      if r5_primary_binding is not None else 0)
        supplemental_stats = db.execute(
            "SELECT COUNT(CASE WHEN s.repair_status='SUPPLEMENTAL_HASHED' THEN 1 END), "
            "COALESCE(SUM(CASE WHEN s.repair_status='SUPPLEMENTAL_HASHED' THEN s.bytes_read ELSE 0 END),0), "
            "COUNT(CASE WHEN s.repair_status='SUPPLEMENTAL_REPAIR_FAILED' THEN 1 END), "
            "COALESCE(SUM(CASE WHEN s.repair_status='SUPPLEMENTAL_REPAIR_FAILED' THEN s.bytes_read ELSE 0 END),0), "
            "COALESCE(SUM(CASE WHEN s.repair_status='SUPPLEMENTAL_HASHED' THEN f.size ELSE 0 END),0), "
            "COUNT(CASE WHEN s.repair_status='SUPPLEMENTAL_HASHED' AND s.bytes_read!=f.size THEN 1 END) "
            "FROM supplemental_files AS s LEFT JOIN files AS f ON f.path_id=s.path_id").fetchone()
        supplemental_hash_count, supplemental_hash_bytes_read, supplemental_failed_count, supplemental_failed_bytes, supplemental_hash_size_bytes, supplemental_size_mismatch_count = supplemental_stats
        if (supplemental_hash_count != (repair_manifest.get("supplemental_repaired_count", 0) if supplemental is not None else 0)
                or supplemental_failed_count != (repair_manifest.get("supplemental_failed_count", 0) if supplemental is not None else 0)
                or supplemental_size_mismatch_count != 0
                or (supplemental is None and (supplemental_hash_bytes_read or supplemental_failed_bytes or supplemental_hash_size_bytes))):
            raise ValueError("SUPPLEMENTAL_HASHED_BYTE_ACCOUNTING_MISMATCH")
        if supplemental_hash_bytes_read != supplemental_hash_size_bytes:
            raise ValueError("SUPPLEMENTAL_HASHED_SIZE_BYTE_COUNT_MISMATCH")
        hashed_file_byte_counts = _logical_hashed_file_byte_counts(
            hashed_bytes, int(supplemental_hash_size_bytes), int(supplemental_failed_bytes))
        read_ledger = {"schema": "i7-engineering-read-ledger@1", "snapshot_id": snapshot,
                       "ledger": ledger_path.name, "ledger_sha256": ledger_digest.hexdigest(),
                       "entry_count": ledger_rows,
                       "status_counts": dict(sorted(status_counts.items())),
                       "file_format_counts": dict(sorted(file_format_counts.items())),
                       "structure_status_counts": dict(sorted(structure_status_counts.items())),
                       "zip_inspection_status_counts": dict(sorted(zip_inspection_status_counts.items())),
                       "binary_hashed_without_document_structure_count": binary_hashed_without_document_structure_count,
                       "non_hashed_file_status_counts": dict(sorted(non_hashed_file_status_counts.items())),
                       "protected_metadata_only_zero_bytes_count": protected_metadata_only_zero_bytes_count,
                       "supplemental_repair": supplemental_binding if supplemental is not None else None,
                       "count_scopes": {
                           "file_format_counts": "one primary scan-ledger row per regular file; all primary statuses except PATH_ONLY; finite public suffix allowlist, unknown suffix aggregated as [other-extension]",
                           "structure_status_counts": "one primary scan-ledger row per regular file; missing document object is NO_DOCUMENT_STRUCTURE",
                           "zip_inspection_status_counts": "all primary .zip rows; absent inspection is NOT_INSPECTED:<primary status>",
                           "binary_hashed_without_document_structure_count": "primary HASHED non-text, non-ZIP rows with no document or ZIP inspection object",
                           "non_hashed_file_status_counts": "primary scan-ledger rows whose primary status is not HASHED",
                           "protected_metadata_only_zero_bytes_count": "primary PROTECTED_METADATA_ONLY rows with zero bytes_read_hash",
                           "primary_hashed_file_bytes": "sum of sizes for primary HASHED rows only",
                           "supplemental_hashed_file_bytes": "sum of sizes for authenticated SUPPLEMENTAL_HASHED rows whose primary status was non-HASHED",
                           "supplemental_failed_read_bytes_excluded": "physical bytes read by failed supplemental rows; excluded from logical hashed byte totals",
                           "effective_unique_hashed_file_bytes": "disjoint sum of primary HASHED sizes and successful authenticated supplemental file sizes",
                           "hashed_file_bytes_by_inventory_size": "backward-compatible alias for primary_hashed_file_bytes; supplemental rows excluded"},
                       "actual_bytes_read_hash": actual_read_bytes,
                       "current_attempt_actual_bytes_read_new_files": actual_new_file_read_bytes,
                       "actual_bytes_read_prefix_revalidation": actual_prefix_revalidation_bytes,
                       "trusted_prefix_bytes_reused": cached_prefix_bytes,
                       "trusted_prefix_ledger_bytes": cached_prefix_ledger_bytes,
                       "trusted_prefix_rows_reused": cached_prefix_rows,
                       "ledger_recorded_hash_read_bytes": ledger_bytes,
                       **hashed_file_byte_counts,
                       "hashed_file_bytes_by_inventory_size": hashed_bytes,
                       "document_kind_counts": dict(sorted(doc_kind_counts.items())),
                       "full_file_hashing_status": manifest.get("coverage_status"),
                       "content_excerpts_serialized": False, "source_contents_reread": False}
        read_ledger.update(source_manifest_hash_fields)
        legacy_binding = None
        if legacy_overlay:
            overlay_manifest, overlay_path, overlay_sha, overlay_size, overlay_manifest_sha, overlay_manifest_size = legacy_overlay
            legacy_binding = {"schema": "i7-engineering-legacy-reference-binding@1", "snapshot_id": snapshot,
                "source_reader_sha256": overlay_manifest["source_reader_sha256"],
                "source_document_parser_revision": overlay_manifest.get("source_document_parser_revision"),
                "prefix_start_row": overlay_manifest["prefix_start_row"],
                "prefix_end_row_exclusive": overlay_manifest["prefix_end_row_exclusive"],
                "prefix_row_count": overlay_manifest["prefix_row_count"],
                "source_ledger_prefix_sha256": overlay_manifest["source_ledger_prefix_sha256"],
                "overlay_file": overlay_path.name, "overlay_sha256": overlay_sha,
                "overlay_byte_length": overlay_size, "overlay_manifest_sha256": overlay_manifest_sha,
                "overlay_manifest_byte_length": overlay_manifest_size,
                "overlay_row_count": overlay_manifest["overlay_row_count"],
                "legacy_reference_unknown_count": legacy_unknown_count}
            _write_json(out / "ENGINEERING_LEGACY_REFERENCE_OVERLAY_BINDING.json", legacy_binding)
        supplemental_output_binding = None
        if supplemental is not None:
            supplemental_output_binding = dict(supplemental_binding)
            supplemental_output_binding.update({
                "status": "SUPPLEMENTAL_ROWS_AUTHENTICATED_PRIMARY_COVERAGE_UNCHANGED",
                "primary_ledger_sha256": ledger_digest.hexdigest(),
                "primary_ledger_byte_length": ledger_raw_bytes,
                "primary_pathmap_sha256": pathmap_digest.hexdigest(),
                "primary_pathmap_byte_length": pathmap_bytes,
                "primary_pinned_pathmap_sha256": supplemental["primary_pathmap_sha256"],
                "primary_pinned_pathmap_byte_length": supplemental["primary_pathmap_bytes"],
                "primary_initial_inventory_sha256": repair_manifest["primary_initial_inventory_raw_sha256"],
                "primary_initial_inventory_byte_length": supplemental["primary_initial_inventory_bytes"],
                "continuation_import_sha256": repair_manifest["continuation_import_sha256"],
                "continuation_import_byte_length": repair_manifest["continuation_import_bytes"],
                "legacy_prefix_row_count": supplemental["prefix_rows"],
                "legacy_prefix_byte_length": supplemental["prefix_bytes"],
                "legacy_prefix_sha256": supplemental["prefix_sha256"],
                "supplemental_hash_join_count": supplemental_matched,
                "supplemental_effective_hash_count": db.execute("SELECT count(*) FROM supplemental_files WHERE repair_status='SUPPLEMENTAL_HASHED'").fetchone()[0],
                "supplemental_repair_failed_count": supplemental_failed_count,
                "effective_hash_count": int(manifest.get("hashed_count", 0) or 0) + supplemental_hash_count,
                **hashed_file_byte_counts,
                "effective_hash_bytes_including_supplement": hashed_file_byte_counts["effective_unique_hashed_file_bytes"],
                "repair_helper_source_sha256": repair_manifest.get("repair_helper_sha256"),
                "repair_helper_source_attestation": "exact helper SHA-256 in the supplemental manifest, checked against the selected source pin",
                "reference_resolution_uses_supplemental_hashes": True,
                "primary_status_counts_unchanged": True,
            })
            _write_json(out / "ENGINEERING_SUPPLEMENTAL_REPAIR_BINDING.json", supplemental_output_binding)
        coverage = {"schema": "i7-engineering-coverage@1", "snapshot_id": snapshot,
                    "inventory_coverage_status": manifest.get("inventory_coverage_status"),
                    "inventory_entry_count": directory_manifest["inventory_entry_count"],
                    "directory_count": manifest.get("directory_count"), "regular_file_count": expected_files,
                    "ledger_entry_count": ledger_rows, "hashed_count": manifest.get("hashed_count"),
                    "unreadable_or_failed_count": manifest.get("unreadable_or_failed_count"),
                    "protected_metadata_only_count": manifest.get("protected_metadata_only_count"),
                    "opaque_git_metadata_only_count": manifest.get("opaque_git_metadata_only_count"),
                    "reparse_count": manifest.get("reparse_count"), "inventory_error_count": manifest.get("inventory_error_count"),
                    "coverage_status": manifest.get("coverage_status"), "actual_bytes_read_hash": actual_read_bytes,
                    "current_attempt_actual_bytes_read_new_files": actual_new_file_read_bytes,
                    "actual_bytes_read_prefix_revalidation": actual_prefix_revalidation_bytes,
                    "trusted_prefix_bytes_reused": cached_prefix_bytes,
                    "trusted_prefix_ledger_bytes": cached_prefix_ledger_bytes,
                    "trusted_prefix_rows_reused": cached_prefix_rows,
                    "ledger_recorded_hash_read_bytes": ledger_bytes,
                    **hashed_file_byte_counts,
                    "file_format_counts": dict(sorted(file_format_counts.items())),
                    "structure_status_counts": dict(sorted(structure_status_counts.items())),
                    "zip_inspection_status_counts": dict(sorted(zip_inspection_status_counts.items())),
                    "binary_hashed_without_document_structure_count": binary_hashed_without_document_structure_count,
                    "non_hashed_file_status_counts": dict(sorted(non_hashed_file_status_counts.items())),
                    "protected_metadata_only_zero_bytes_count": protected_metadata_only_zero_bytes_count,
                    "document_reference_count": ref_count, "reference_verified_count": verified_count,
                    "reference_unknown_count": unknown_count, "legacy_reference_unknown_count": legacy_unknown_count,
                    "legacy_reference_overlay": legacy_binding,
                    "supplemental_repair": supplemental_output_binding,
                    "reference_status_counts": dict(sorted(ref_status_counts.items())),
                    "document_kind_counts": dict(sorted(doc_kind_counts.items())), "reference_target_format_counts": dict(sorted(format_counts.items())),
                    "causal_edges_inferred": 0, "limits": ["References are exact path-ID matches only.",
                    "UNKNOWN includes absent, protected, inaccessible, or unhashed targets.",
                    "No source document text, excerpts, private paths, or causal claims are emitted."]}
        coverage.update(hashed_file_byte_counts)
        coverage.update(source_manifest_hash_fields)
        digest = {"schema": "i7-engineering-corpus-digest@1", "snapshot_id": snapshot,
                  **source_manifest_hash_fields,
                  "protection_policy_sha256": manifest.get("protection_policy_sha256"),
                  "inventory_sha256": actual_inventory_hash, "ledger": ledger_path.name,
                  "ledger_sha256": ledger_digest.hexdigest(),
                  "ledger_entries": ledger_rows, "regular_file_count": expected_files,
                  "hashed_count": manifest.get("hashed_count"),
                  "actual_bytes_read_hash": actual_read_bytes,
                  "current_attempt_actual_bytes_read_new_files": actual_new_file_read_bytes,
                  "actual_bytes_read_prefix_revalidation": actual_prefix_revalidation_bytes,
                  "ledger_recorded_hash_read_bytes": ledger_bytes,
                  "trusted_prefix_bytes_reused": cached_prefix_bytes,
                  "trusted_prefix_ledger_bytes": cached_prefix_ledger_bytes,
                  "trusted_prefix_rows_reused": cached_prefix_rows,
                  **hashed_file_byte_counts,
                  "status_counts": dict(sorted(status_counts.items())),
                  "non_hashed_file_status_counts": dict(sorted(non_hashed_file_status_counts.items())),
                  "primary_coverage_status_promoted": False,
                  "primary_rows_rewritten": False,
                  "supplemental_repaired_count": supplemental_output_binding["supplemental_effective_hash_count"] if supplemental_output_binding else 0,
                  "supplemental_failed_count": supplemental_output_binding["supplemental_repair_failed_count"] if supplemental_output_binding else 0,
                  "effective_hash_count": supplemental_output_binding["effective_hash_count"] if supplemental_output_binding else int(manifest.get("hashed_count", 0) or 0),
                  "supplemental_repair_binding": supplemental_output_binding,
                  "file_format_counts": dict(sorted(file_format_counts.items())),
                  "structure_status_counts": dict(sorted(structure_status_counts.items())),
                  "zip_inspection_status_counts": dict(sorted(zip_inspection_status_counts.items())),
                  "binary_hashed_without_document_structure_count": binary_hashed_without_document_structure_count,
                  "non_hashed_file_status_counts": dict(sorted(non_hashed_file_status_counts.items())),
                  "protected_metadata_only_zero_bytes_count": protected_metadata_only_zero_bytes_count,
                  "count_scopes": read_ledger["count_scopes"],
                  "document_references": refs_path.name, "document_graph_edges": edges_path.name,
                  "document_reference_count": ref_count, "verified_document_reference_count": verified_count,
                  "unknown_document_reference_count": unknown_count, "causal_edges": 0,
                  "legacy_reference_unknown_count": legacy_unknown_count,
                  "legacy_reference_overlay": legacy_binding,
                  "supplemental_repair": supplemental_output_binding,
                  "index_local_only": db_path.name}
        read_ledger["supplemental_repair"] = supplemental_output_binding
        coverage["supplemental_repair"] = supplemental_output_binding
        for name, obj in (("ENGINEERING_DIRECTORY_MANIFEST.json", directory_manifest),
                          ("READ_LEDGER.json", read_ledger), ("COVERAGE.json", coverage),
                          ("ENGINEERING_CORPUS_DIGEST.json", digest)):
            _write_json(out / name, obj)
        return digest
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", required=True)
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    result = summarize_scan(args.scan_dir, args.output_dir)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
