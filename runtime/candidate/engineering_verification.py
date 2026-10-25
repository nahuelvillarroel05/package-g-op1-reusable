# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Prospective held-artifact, bounded, same-snapshot verifier adapter.

The scanner policy, independent inventory walk, and per-file hash implementation are
imported unchanged from the selected engineering_corpus.py reader. This module
changes only how verification metadata artifacts are opened and consumed.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import ntpath
from typing import Any, Iterator

import engineering_corpus as reader

ARTIFACT_BUFFER_BYTES = 1024 * 1024
MAX_MANIFEST_TAIL_BYTES = 1024 * 1024
MAX_MANIFEST_ROW_BYTES = 1024 * 1024
MAX_LEDGER_ROW_BYTES = 8 * 1024 * 1024
HASH_WORKERS = 4
MAX_INFLIGHT_HASHES = 8
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_ADAPTER_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
TEST_FIXTURE_ROOT = Path(
    r"PRIVATE_VALIDATION_NOT_DISTRIBUTED\I7-ENGINEERING-CORPUS-20261023T194007Z-2b94e3a5\fixture-attempts"
)


class VerificationInputError(ValueError):
    def __init__(self, code: str, message: str, *, source_walk_started: bool = False):
        super().__init__(message)
        self.code = code
        self.source_walk_started = source_walk_started


@dataclass
class _HeldArtifact:
    name: str
    path: Path
    stream: io.BufferedReader
    before: os.stat_result
    opened: os.stat_result
    held_path: str
    initial_size: int
    bytes_read: int = 0

    @classmethod
    def open(cls, output: Path, name: str) -> "_HeldArtifact":
        if name not in {"corpus-manifest.jsonl", "scan-ledger.jsonl"}:
            raise VerificationInputError("ARTIFACT_NAME_REJECTED", "verification artifact name is not admitted")
        path = output / name
        try:
            raw, before, opened, held_path = reader._open_verified(path)
        except (OSError, ValueError) as exc:
            raise VerificationInputError(
                "ARTIFACT_UNSAFE_PATH", f"{name}: held-path validation rejected ({type(exc).__name__})"
            ) from exc
        try:
            buffered = io.BufferedReader(raw, buffer_size=ARTIFACT_BUFFER_BYTES)
        except BaseException:
            raw.close()
            raise
        if opened.st_size < 0:
            buffered.close()
            raise VerificationInputError("ARTIFACT_SIZE_INVALID", f"{name}: negative initial size")
        return cls(name, path, buffered, before, opened, held_path, opened.st_size)

    def assert_stable(self) -> None:
        try:
            after_fd = os.fstat(self.stream.fileno())
            after_path = self.path.lstat()
            final_path = reader._final_path_from_handle(self.stream.fileno())
        except OSError as exc:
            raise VerificationInputError(
                "ARTIFACT_CHANGED_DURING_VERIFY", f"{self.name}: final handle check failed ({type(exc).__name__})"
            ) from exc
        expected_path = os.path.abspath(os.fspath(self.path))
        if (reader._stat_tuple(self.opened) != reader._stat_tuple(after_fd)
                or reader._cross_api_stat_tuple(self.before) != reader._cross_api_stat_tuple(self.opened)
                or reader._stat_tuple(self.before) != reader._stat_tuple(after_path)
                or reader._path_has_reparse_ancestor(self.path)
                or reader._is_reparse(self.path, after_path)
                or final_path is None
                or ntpath.normcase(ntpath.normpath(final_path)) != ntpath.normcase(ntpath.normpath(self.held_path))
                or ntpath.normcase(ntpath.normpath(final_path)) != ntpath.normcase(ntpath.normpath(expected_path))):
            raise VerificationInputError(
                "ARTIFACT_CHANGED_DURING_VERIFY", f"{self.name}: held identity or path changed"
            )

    def close(self) -> None:
        self.stream.close()


def _strict_json(line: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(line.decode("utf-8"), object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise VerificationInputError("ARTIFACT_JSON_INVALID", f"{label}: invalid JSON ({type(exc).__name__})") from exc
    if not isinstance(value, dict):
        raise VerificationInputError("ARTIFACT_SCHEMA_INVALID", f"{label}: expected a JSON object")
    return value


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON constant")


def _read_last_manifest(artifact: _HeldArtifact) -> dict[str, Any]:
    stream = artifact.stream
    stream.seek(0, os.SEEK_END)
    end = stream.tell()
    if end != artifact.initial_size:
        raise VerificationInputError("MANIFEST_CHANGED_DURING_READ", "manifest extent differs from held initial size")
    if end <= 0:
        raise VerificationInputError("MANIFEST_EMPTY", "corpus manifest is empty")
    span = min(end, MAX_MANIFEST_TAIL_BYTES + 1)
    stream.seek(end - span)
    tail = stream.read(span)
    artifact.bytes_read += len(tail)
    if len(tail) != span:
        raise VerificationInputError("MANIFEST_SHORT_READ", "manifest tail ended before its initial extent")
    stream.seek(artifact.initial_size)
    growth_probe = stream.read(1)
    artifact.bytes_read += len(growth_probe)
    if growth_probe:
        raise VerificationInputError("MANIFEST_GREW_DURING_READ", "manifest grew past its held initial extent")
    if not tail.endswith(b"\n"):
        raise VerificationInputError("MANIFEST_TORN_TAIL", "corpus manifest ends with an incomplete row")
    content = tail[:-1]
    boundary = content.rfind(b"\n")
    line = content[boundary + 1:]
    if end > len(tail) and boundary < 0:
        raise VerificationInputError("MANIFEST_ROW_TOO_LARGE", "last manifest row exceeds its byte limit")
    if len(line) > MAX_MANIFEST_ROW_BYTES:
        raise VerificationInputError("MANIFEST_ROW_TOO_LARGE", "last corpus-manifest row exceeds its byte limit")
    manifest = _strict_json(line, "corpus manifest")
    if (manifest.get("schema") != "i7-engineering-corpus-scan@1"
            or not isinstance(manifest.get("snapshot_id"), str)
            or not _HEX64.fullmatch(manifest["snapshot_id"])
            or manifest.get("protection_policy_sha256") != reader.PROTECTION_POLICY_SHA256
            or type(manifest.get("regular_file_count")) is not int
            or manifest["regular_file_count"] < 0):
        raise VerificationInputError("MANIFEST_SCHEMA_INVALID", "last corpus-manifest row has an invalid schema")
    return manifest


def _ledger_rows(artifact: _HeldArtifact) -> Iterator[dict[str, Any]]:
    stream = artifact.stream
    stream.seek(0)
    remaining = artifact.initial_size
    while remaining:
        limit = min(MAX_LEDGER_ROW_BYTES + 1, remaining + 1)
        line = stream.readline(limit)
        if not line:
            raise VerificationInputError("LEDGER_SHORT_READ", "scan ledger ended before its held initial extent")
        artifact.bytes_read += len(line)
        if len(line) > remaining:
            raise VerificationInputError("LEDGER_GREW_DURING_READ", "scan ledger grew past its held initial extent")
        remaining -= len(line)
        if len(line) > MAX_LEDGER_ROW_BYTES:
            raise VerificationInputError("LEDGER_ROW_TOO_LARGE", "scan ledger row exceeds the byte limit")
        if not line.endswith(b"\n"):
            raise VerificationInputError("LEDGER_TORN_TAIL", "scan ledger contains an incomplete row")
        if not line.strip():
            raise VerificationInputError("LEDGER_BLANK_ROW", "scan ledger contains an empty or whitespace-only row")
        row = _strict_json(line, "scan ledger row")
        if (not isinstance(row.get("path_id"), str) or not _HEX64.fullmatch(row["path_id"])
                or not isinstance(row.get("snapshot_id"), str) or not _HEX64.fullmatch(row["snapshot_id"])
                or not isinstance(row.get("status"), str) or not row["status"]
                or type(row.get("size")) is not int or row["size"] < 0
                or (row.get("sha256") is not None and (not isinstance(row["sha256"], str)
                                                        or not _HEX64.fullmatch(row["sha256"])) )):
            raise VerificationInputError("LEDGER_SCHEMA_INVALID", "scan ledger row has invalid required fields")
        yield row
    stream.seek(artifact.initial_size)
    growth_probe = stream.read(1)
    artifact.bytes_read += len(growth_probe)
    if growth_probe:
        raise VerificationInputError("LEDGER_GREW_DURING_READ", "scan ledger grew past its held initial extent")


def _admit_roots(root: Path, output_dir: Path, *, test_api: bool) -> tuple[Path, Path]:
    root = reader._canonical(Path(root))
    output = reader._canonical(Path(output_dir))
    if not test_api and root != reader._canonical(reader.PRODUCTION_ROOT):
        raise VerificationInputError("PRODUCTION_ROOT_MUST_MATCH_EXACTLY", "production verification root is fixed")
    if test_api:
        if root == reader._canonical(reader.PRODUCTION_ROOT) or not reader._inside(root, TEST_FIXTURE_ROOT):
            raise VerificationInputError("TEST_ROOT_OUTSIDE_FIXTURE_SCOPE", "test_api root must remain under Validation fixture-attempts")
    try:
        reader._validate_output(root, output)
        reader._validate_input_ancestors(root)
    except (OSError, ValueError) as exc:
        raise VerificationInputError("VERIFY_PATH_SCOPE", f"verification path guard rejected ({type(exc).__name__})") from exc
    if not root.is_dir():
        raise VerificationInputError("INPUT_ROOT_NOT_DIRECTORY", "verification root is not a directory")
    return root, output


def verify_snapshot(root: str | Path, output_dir: str | Path, *, snapshot_id: str | None = None,
                    test_api: bool = False) -> dict[str, Any]:
    """Verify one exact snapshot while holding verified manifest and ledger handles."""
    root, output = _admit_roots(Path(root), Path(output_dir), test_api=test_api)
    if snapshot_id is not None and (not isinstance(snapshot_id, str) or not _HEX64.fullmatch(snapshot_id)):
        raise VerificationInputError("SNAPSHOT_ID_INVALID", "expected snapshot ID must be lowercase SHA-256")

    held: list[_HeldArtifact] = []
    source_walk_started = False
    try:
        # Both names are opened through the frozen reader's held-path check before source walking begins.
        manifest_artifact = _HeldArtifact.open(output, "corpus-manifest.jsonl")
        held.append(manifest_artifact)
        ledger_artifact = _HeldArtifact.open(output, "scan-ledger.jsonl")
        held.append(ledger_artifact)
        manifest = _read_last_manifest(manifest_artifact)
        expected_snapshot = snapshot_id or manifest["snapshot_id"]
        if manifest["snapshot_id"] != expected_snapshot:
            raise VerificationInputError("SNAPSHOT_NOT_IN_MANIFEST_LEDGER", "last manifest row does not match expected snapshot")

        independent_hash = hashlib.sha256()
        independent_hash.update(str(reader._canonical(root)).casefold().encode("utf-8") + b"\0"
                                + reader.PROTECTION_POLICY_SHA256.encode() + b"\0")
        independent_files = 0
        checks = 0
        mismatches = 0
        missing = 0
        extra = 0
        actual_hash_bytes = 0
        rows = iter(_ledger_rows(ledger_artifact))
        pending = deque()
        with ThreadPoolExecutor(max_workers=HASH_WORKERS, thread_name_prefix="i7-guarded-verify") as pool:
            def drain_oldest() -> None:
                nonlocal mismatches, actual_hash_bytes
                source_path, entry, row, future = pending.popleft()
                digest, status, _detail, bytes_read = future.result()
                actual_hash_bytes += bytes_read
                if status != "HASHED" or row.get("status") != "HASHED" or digest != row.get("sha256"):
                    mismatches += 1

            source_walk = reader._independent_walk(root)
            source_walk_started = True
            for source_path, entry in source_walk:
                public_entry = reader._public_entry(entry)
                if entry.kind == "file" and reader._metadata_only_reason(entry.relpath):
                    public_entry["status"] = reader._metadata_only_reason(entry.relpath)
                encoded = json.dumps(public_entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                independent_hash.update(encoded.encode("utf-8") + b"\n")
                if entry.kind != "file":
                    continue
                independent_files += 1
                token = reader._path_token(entry.relpath)
                try:
                    row = next(rows)
                except StopIteration:
                    missing += 1
                    continue
                checks += 1
                if row.get("path_id") != token or row.get("snapshot_id") != manifest["snapshot_id"]:
                    mismatches += 1
                    continue
                metadata_reason = reader._metadata_only_reason(entry.relpath)
                if metadata_reason:
                    if row.get("status") != metadata_reason or row.get("sha256") is not None:
                        mismatches += 1
                    continue
                if len(pending) >= MAX_INFLIGHT_HASHES:
                    drain_oldest()
                pending.append((source_path, entry, row,
                                pool.submit(reader._stable_hash_details, source_path, entry)))
            while pending:
                drain_oldest()
            extra = sum(1 for _ in rows)

        independent_id = independent_hash.hexdigest()
        for artifact in held:
            artifact.assert_stable()
        ok = (not missing and not extra and not mismatches
              and independent_id == manifest.get("snapshot_id")
              and independent_files == manifest.get("regular_file_count"))
        return {
            "status": "VERIFIED" if ok else "INCOMPLETE_OR_MISMATCH",
            "snapshot_id": independent_id,
            "inventory_matches": independent_id == manifest.get("snapshot_id"),
            "checked_count": checks,
            "missing_count": missing,
            "extra_count": extra,
            "mismatch_count": mismatches,
            "adapter_sha256": _ADAPTER_SHA256,
            "actual_bytes_read_hash": actual_hash_bytes,
            "verification_artifact_bytes_consumed": sum(item.bytes_read for item in held),
            "verification_artifacts_held_until_complete": True,
            "hash_workers": HASH_WORKERS,
            "max_inflight_hashes": MAX_INFLIGHT_HASHES,
        }
    except VerificationInputError as exc:
        exc.source_walk_started = source_walk_started
        raise
    finally:
        for artifact in reversed(held):
            artifact.close()

