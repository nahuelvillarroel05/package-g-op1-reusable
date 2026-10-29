"""Bounded source fragmentation with explicit parent-origin verification.

This adapter admits fragments through the existing generalized bridge. A
fragment SHA-256 is never presented as the original parent's SHA-256. Parent
coverage and source-byte mapping are verified by this adapter separately from
Context Engine fragment-byte verification.
"""
from __future__ import annotations

import hashlib
import gc
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import sqlite3
import stat
import tempfile
from typing import Any, Iterable, Mapping

from .adapter import AuditError, _checked_root, _safe_path
from .generalized_bridge import bind_generalized_audit, recover_generalized_audit
from .swebench_batching import _batch_fits, bind_audit_stream, iter_audit_chunks, recover_audit_stream
from runtime.candidate.context_engine import Engine, canonical_json


MANIFEST_SCHEMA = "pgop1.swebench.source-fragment-origin.v1"
VERIFICATION_SCHEMA = "pgop1.swebench.source-fragment-verification.v1"
SPOOL_SCHEMA = "pgop1.swebench.source-fragment-observation-spool.v1"
REJECTION_SCHEMA = "pgop1.swebench.source-fragment-rejections.v2"
MAPPING_SCHEMA = "BYTE_SPAN_HALF_OPEN_V2_PIECE_DIGEST"
CONTENT_ASSERTION_SCHEMA = "pgop1.swebench.source-span-text-assertion.v1"
INPUT_EXCLUSION_POLICY_VERSION = "CONTEXT_ENGINE_SOURCE_EXCLUSION_V1"
INPUT_EXCLUSION_POLICY_RESULT = "PASS_BEFORE_ORIGINAL_READ"
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_MAX_FRAGMENT_BYTES = 64 * 1024 * 1024
_MAX_PARENT_BYTES = 256 * 1024 * 1024
_MAX_FRAGMENTS = 4096
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_OBSERVATIONS = 100_000
_MAX_OBSERVATION_BYTES = 1024 * 1024
_MAX_FRAGMENT_CHUNK_BYTES = 1_310_720
_MAX_SPOOL_BYTES = 256 * 1024 * 1024
_MAX_REJECTIONS_BYTES = 8 * 1024 * 1024
_EXCLUDED_SOURCE_COMPONENTS = frozenset({"holdout", "secrets", ".aws"})
_INTERNAL_FRAGMENT_COMMITMENT_KIND = "origin_fragment_commitment"
_RESERVED_MAPPED_FIELDS = frozenset({
    "original_source_ref", "origin_manifest_sha256", "origin_parent_source",
    "origin_fragment_index", "origin_fragment_range", "origin_mapping_status",
    "origin_input_ordinal", "origin_input_sha256", "origin_piece_count",
    "origin_piece_sha256", "origin_source_ref_role",
    "origin_content_verification",
})


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _update_framed(digest: Any, raw: bytes) -> None:
    digest.update(len(raw).to_bytes(8, "big"))
    digest.update(raw)


def _piece_digest(start: int, end: int, fragments: list[Mapping[str, Any]]) -> tuple[int, str, int]:
    digest = hashlib.sha256()
    count = 0
    first_index = -1
    for fragment in fragments:
        piece_start = max(start, fragment["offset_start"])
        piece_end = min(end, fragment["offset_end"])
        if piece_start >= piece_end:
            continue
        if first_index < 0:
            first_index = fragment["index"]
        piece = {"fragment_index": fragment["index"], "fragment_path": fragment["path"],
                 "fragment_sha256": fragment["sha256"], "parent_start": piece_start,
                 "parent_end": piece_end, "fragment_start": piece_start - fragment["offset_start"],
                 "fragment_end": piece_end - fragment["offset_start"], "bytes": piece_end - piece_start}
        _update_framed(digest, canonical_json(piece))
        count += 1
    return count, digest.hexdigest(), first_index


def _text_assertion_bytes(row: Mapping[str, Any]) -> bytes | None:
    """Return bytes only for an explicit exact UTF-8 source-span assertion."""
    assertion = row.get("source_text_assertion")
    if assertion is None:
        return None
    if (not isinstance(assertion, dict)
            or assertion.get("schema") != CONTENT_ASSERTION_SCHEMA
            or assertion.get("association") != "EXACT_BYTE_SPAN"
            or assertion.get("encoding") != "utf-8"
            or not isinstance(assertion.get("text"), str)):
        raise AuditError("BYTE_SPAN_CONTENT_MISMATCH", "source text assertion must declare exact UTF-8 byte-span content")
    try:
        return assertion["text"].encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise AuditError("BYTE_SPAN_CONTENT_MISMATCH", "source text assertion is not valid UTF-8 text") from exc


def _read_staged_span(root: Path, manifest: Mapping[str, Any], start: int, end: int) -> bytes:
    """Read at most one observation-sized source span from staged fragments."""
    pieces: list[bytes] = []
    for fragment in manifest["fragments"]:
        left = max(start, fragment["offset_start"])
        right = min(end, fragment["offset_end"])
        if left >= right:
            continue
        path = root / fragment["path"]
        with path.open("rb") as stream:
            stream.seek(left - fragment["offset_start"])
            piece = stream.read(right - left)
        if len(piece) != right - left:
            raise AuditError("FRAGMENT_STAGED_BYTES_MISMATCH", "staged fragment span is truncated")
        pieces.append(piece)
    return b"".join(pieces)


def _hash_file_bounded(path: Path, block_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            block = _read_source_block(stream, block_bytes)
            if not block:
                break
            digest.update(block)
            total += len(block)
    return digest.hexdigest(), total


def _read_source_block(stream: Any, size: int) -> bytes:
    """Small seam used by tests to prove original reads never exceed the cap."""
    return stream.read(size)


def _read_small_file(path: Path, limit: int) -> bytes:
    if path.stat().st_size > limit:
        raise AuditError("FRAGMENT_METADATA_TOO_LARGE", "bounded metadata file exceeds its byte limit")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise AuditError("FRAGMENT_METADATA_TOO_LARGE", "bounded metadata file exceeds its byte limit")
    return raw


def _reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _check_path(path: Path) -> None:
    candidate = path.absolute()
    cursor = Path(candidate.anchor)
    if _reparse(cursor):
        raise AuditError("FRAGMENT_OUTPUT_REPARSE", "output path contains a reparse point")
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if _reparse(cursor):
            raise AuditError("FRAGMENT_OUTPUT_REPARSE", "output path contains a reparse point")


def _parent_absolute_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        absolute = candidate
        parts = candidate.parts
    else:
        windows = PureWindowsPath(path)
        if not windows.is_absolute():
            raise AuditError("FRAGMENT_PARENT_PATH_INVALID", "parent absolute source path is invalid")
        absolute = candidate
        parts = windows.parts
    if any(part.casefold() in _EXCLUDED_SOURCE_COMPONENTS for part in parts):
        raise AuditError("FRAGMENT_PARENT_EXCLUDED", "parent source path contains an Engine-excluded component")
    return absolute


def _write_immutable(path: Path, raw: bytes) -> None:
    _check_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise AuditError("FRAGMENT_OUTPUT_EXISTS", "immutable fragment artifact already exists") from exc


def _strict_manifest(root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
    manifest_path = root / "origin-manifest.json"
    verification_path = root / "fragment-verification.json"
    _check_path(manifest_path)
    _check_path(verification_path)
    try:
        manifest_raw = _read_small_file(manifest_path, _MAX_MANIFEST_BYTES)
        verification_raw = _read_small_file(verification_path, 64 * 1024)
        manifest = json.loads(manifest_raw)
        verification = json.loads(verification_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditError("FRAGMENT_MANIFEST_UNAVAILABLE", "origin manifest or verification record is unavailable") from exc
    if (len(manifest_raw) > _MAX_MANIFEST_BYTES or canonical_json(manifest) != manifest_raw
            or not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA):
        raise AuditError("FRAGMENT_MANIFEST_INVALID", "origin manifest is noncanonical or unsupported")
    if (canonical_json(verification) != verification_raw or not isinstance(verification, dict)
            or verification.get("schema") != VERIFICATION_SCHEMA):
        raise AuditError("FRAGMENT_VERIFICATION_INVALID", "fragment verification record is noncanonical or unsupported")
    manifest_sha = _sha(manifest_raw)
    parent = manifest.get("parent_source")
    fragments = manifest.get("fragments")
    fragmentation = manifest.get("fragmentation")
    if (not isinstance(parent, dict) or not _HASH_RE.fullmatch(str(parent.get("sha256", "")))
            or type(parent.get("bytes")) is not int or not isinstance(fragments, list)
            or not fragments or len(fragments) > _MAX_FRAGMENTS):
        raise AuditError("FRAGMENT_MANIFEST_INVALID", "origin commitment or fragment list is invalid")
    if (not isinstance(manifest.get("fragmentation"), dict)
            or verification.get("manifest_sha256") != manifest_sha
            or verification.get("parent_sha256") != parent["sha256"]
            or type(verification.get("parent_bytes")) is not int
            or verification.get("parent_bytes") != parent["bytes"]
            or type(verification.get("fragments")) is not int
            or verification.get("fragments") != len(fragments)
            or verification.get("streamed_parent_sha256") != parent["sha256"]
            or type(verification.get("streamed_parent_bytes")) is not int
            or verification.get("streamed_parent_bytes") != parent["bytes"]
            or type(verification.get("fragment_bytes")) is not int
            or verification.get("fragment_bytes") != manifest.get("fragmentation", {}).get("fragment_bytes")
            or verification.get("input_exclusion_policy") != manifest.get("input_exclusion_policy")):
        raise AuditError("FRAGMENT_VERIFICATION_MISMATCH", "stream verification does not bind the origin manifest")
    # The digest is derived from canonical bytes; it is not a self-referential
    # field in the immutable manifest document.
    manifest["origin_manifest_sha256"] = manifest_sha
    _validate_manifest_shape(manifest, verification, manifest_sha)
    return manifest, manifest_raw, verification, verification_raw


def _verify_staged_fragments(root: Path, manifest: Mapping[str, Any], block_bytes: int = 1024 * 1024) -> None:
    fragments = manifest["fragments"]
    parent = manifest["parent_source"]
    cursor = 0
    digest = hashlib.sha256()
    for index, row in enumerate(fragments):
        if (not isinstance(row, dict) or type(row.get("index")) is not int or row.get("index") != index
                or type(row.get("offset_start")) is not int or row.get("offset_start") != cursor):
            raise AuditError("FRAGMENT_RANGE_INVALID", "fragment ranges are not contiguous and ordered")
        start, end = row.get("offset_start"), row.get("offset_end")
        size = row.get("bytes")
        configured_fragment_bytes = manifest["fragmentation"]["fragment_bytes"]
        if (type(start) is not int or type(end) is not int or type(size) is not int
                or end < start or end - start != size or size > _MAX_FRAGMENT_BYTES
                or size > configured_fragment_bytes
                or not _HASH_RE.fullmatch(str(row.get("sha256", "")))):
            raise AuditError("FRAGMENT_RANGE_INVALID", "fragment commitment is malformed")
        relative = row.get("path")
        expected_name = f"fragments/fragment-{index:06d}.bin"
        if relative != expected_name:
            raise AuditError("FRAGMENT_PATH_INVALID", "fragment path does not match its stable index")
        path = root / relative
        _check_path(path)
        fragment_hash, fragment_size = _hash_file_bounded(path, block_bytes)
        if fragment_hash != row["sha256"] or fragment_size != size:
            raise AuditError("FRAGMENT_BYTES_MISMATCH", "staged fragment differs from its commitment")
        # Hash the fragment a second time into the parent stream without joining bytes.
        with path.open("rb") as stream:
            while True:
                block = _read_source_block(stream, block_bytes)
                if not block:
                    break
                digest.update(block)
        cursor = end
    if cursor != parent["bytes"] or digest.hexdigest() != parent["sha256"]:
        raise AuditError("FRAGMENT_PARENT_RECONSTRUCTION_MISMATCH", "ordered fragments do not reconstruct the parent commitment")


def fragment_source(
    data_root: str | os.PathLike[str],
    source_path: str,
    expected_sha256: str,
    expected_bytes: int,
    output_root: str | os.PathLike[str],
    *,
    fragment_bytes: int = 1024 * 1024,
    max_parent_bytes: int = _MAX_PARENT_BYTES,
) -> dict[str, Any]:
    """Stream and verify one original source, writing immutable bounded fragments.

    No Context Engine admission occurs until the complete parent SHA-256, size,
    and pre/post file identity checks pass.
    """
    if not isinstance(source_path, str) or not _HASH_RE.fullmatch(expected_sha256 or ""):
        raise AuditError("FRAGMENT_PARENT_COMMITMENT_INVALID", "source path and expected SHA-256 are required")
    if (type(max_parent_bytes) is not int or not 1 <= max_parent_bytes <= _MAX_PARENT_BYTES
            or type(expected_bytes) is not int or not 0 <= expected_bytes <= max_parent_bytes):
        raise AuditError("FRAGMENT_PARENT_SIZE_INVALID", "parent size exceeds configured bound")
    if type(fragment_bytes) is not int or not 1 <= fragment_bytes <= _MAX_FRAGMENT_BYTES:
        raise AuditError("FRAGMENT_SIZE_INVALID", "fragment_bytes must be from 1 through 64 MiB")
    root = _checked_root(data_root)
    source = _safe_path(root, source_path)
    absolute_source = _parent_absolute_path(str(source))
    absolute_source_sha = _sha(str(absolute_source).casefold().encode("utf-8"))
    before = source.stat()
    if before.st_size != expected_bytes:
        raise AuditError("FRAGMENT_PARENT_SIZE_MISMATCH", "pre-read source size differs from its commitment")
    output = Path(output_root).absolute()
    _check_path(output)
    if output.exists():
        raise AuditError("FRAGMENT_OUTPUT_EXISTS", "fragmentation requires a fresh output root")
    output.mkdir(parents=True, exist_ok=False)
    (output / "fragments").mkdir()
    digest = hashlib.sha256()
    total = 0
    fragments: list[dict[str, Any]] = []
    try:
        with source.open("rb") as stream:
            while total < expected_bytes:
                request = min(fragment_bytes, expected_bytes - total)
                block = _read_source_block(stream, request)
                if not block:
                    raise AuditError("FRAGMENT_PARENT_TRUNCATED", "source ended before its committed byte count")
                index = len(fragments)
                if index >= _MAX_FRAGMENTS:
                    raise AuditError("FRAGMENT_COUNT_LIMIT", "source needs more fragments than configured")
                start, end = total, total + len(block)
                relative = f"fragments/fragment-{index:06d}.bin"
                fragment_path = output / relative
                _write_immutable(fragment_path, block)
                fragment_hash = _sha(block)
                fragments.append({"index": index, "offset_start": start, "offset_end": end,
                                  "bytes": len(block), "path": relative, "sha256": fragment_hash})
                digest.update(block)
                total = end
            if _read_source_block(stream, 1):
                raise AuditError("FRAGMENT_PARENT_GREW", "source has bytes beyond its pre-read size")
        after = source.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise AuditError("FRAGMENT_PARENT_CHANGED", "source identity changed during streaming read")
        if total != expected_bytes or digest.hexdigest() != expected_sha256:
            raise AuditError("FRAGMENT_PARENT_HASH_MISMATCH", "streamed source differs from expected parent commitment")
        if not fragments:
            # Represent an empty original with one explicit empty fragment.
            relative = "fragments/fragment-000000.bin"
            _write_immutable(output / relative, b"")
            fragments.append({"index": 0, "offset_start": 0, "offset_end": 0,
                              "bytes": 0, "path": relative, "sha256": hashlib.sha256(b"").hexdigest()})
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "origin_id": "origin-" + hashlib.sha256(
                (source_path + "\0" + absolute_source_sha + "\0" + expected_sha256).encode()).hexdigest()[:24],
            "parent_source": {"path": source_path, "absolute_path_sha256": absolute_source_sha,
                              "sha256": expected_sha256, "bytes": expected_bytes},
            "input_exclusion_policy": {"version": INPUT_EXCLUSION_POLICY_VERSION,
                                       "result": INPUT_EXCLUSION_POLICY_RESULT},
            "fragmentation": {"algorithm": "FIXED_SIZE_BINARY_SPLIT_V1", "fragment_bytes": fragment_bytes,
                              "mapping_schema": MAPPING_SCHEMA},
            "fragments": fragments,
            "coverage": {"start": 0, "end": expected_bytes, "contiguous": True,
                         "parent_sha256_verified_by_stream": digest.hexdigest()},
        }
        manifest_raw = canonical_json(manifest)
        if len(manifest_raw) > _MAX_MANIFEST_BYTES:
            raise AuditError("FRAGMENT_MANIFEST_TOO_LARGE", "origin manifest exceeds its byte bound")
        manifest_sha = _sha(manifest_raw)
        verification = {"schema": VERIFICATION_SCHEMA, "manifest_sha256": manifest_sha,
                        "parent_sha256": expected_sha256, "parent_bytes": expected_bytes,
                        "streamed_parent_sha256": digest.hexdigest(), "streamed_parent_bytes": total,
                        "fragments": len(fragments), "verification_scope": "ADAPTER_STREAMED_BYTES_ONLY",
                        "fragment_bytes": fragment_bytes,
                        "input_exclusion_policy": {"version": INPUT_EXCLUSION_POLICY_VERSION,
                                                   "result": INPUT_EXCLUSION_POLICY_RESULT}}
        _write_immutable(output / "origin-manifest.json", manifest_raw)
        _write_immutable(output / "fragment-verification.json", canonical_json(verification))
        _verify_staged_fragments(output, manifest)
        return {"status": "PASS", "output_root": str(output), "manifest_sha256": manifest_sha,
                "parent_sha256": expected_sha256, "parent_bytes": expected_bytes,
                "fragments": len(fragments), "fragment_bytes": fragment_bytes,
                "engine_admission": "NOT_PERFORMED", "authority": "ADVISORY_ENGINEERING_ONLY"}
    except Exception:
        # Partial files remain as immutable failure evidence; never auto-restart over them.
        raise


def _bridge_manifest_context(root: Path) -> Path:
    return root / "context" / "origin-manifest"


def _manifest_audit(manifest: Mapping[str, Any], manifest_raw: bytes,
                    verification_raw: bytes) -> dict[str, Any]:
    manifest_sha, verification_sha = _sha(manifest_raw), _sha(verification_raw)
    refs = [
        {"path": "origin-manifest.json", "sha256": manifest_sha, "bytes": len(manifest_raw),
         "role": "SOURCE_FRAGMENT_ORIGIN_MANIFEST", "parser_id": "source_fragment_manifest.v1",
         "parser_version": "1", "instance_binding": "RUN_ONLY"},
        {"path": "fragment-verification.json", "sha256": verification_sha, "bytes": len(verification_raw),
         "role": "SOURCE_FRAGMENT_STREAM_VERIFICATION", "parser_id": "source_fragment_verification.v1",
         "parser_version": "1", "instance_binding": "RUN_ONLY"},
    ]
    run_id = str(manifest["origin_id"])
    batch_id = "origin-manifest-" + manifest_sha[:32]
    return {
        "schema": "pgop1.swebench.generalized-audit.v1", "result_scope": "BATCH_AGGREGATE",
        "instance_id": "UNBOUND", "batch_id": batch_id, "run_id": run_id,
        "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE", "observations": [
            {"observation_id": "origin-manifest-" + manifest_sha[:24], "kind": "origin_source_manifest",
             "run_id": run_id, "instance_id": "UNKNOWN", "value": {"schema": MANIFEST_SCHEMA,
             "manifest_sha256": manifest_sha, "parent_source": manifest["parent_source"],
             "fragment_count": len(manifest["fragments"])},
             "source_ref": {"path": refs[0]["path"], "sha256": refs[0]["sha256"], "pointer": ""}},
            {"observation_id": "origin-verification-" + verification_sha[:24], "kind": "origin_stream_verification",
             "run_id": run_id, "instance_id": "UNKNOWN", "value": {"schema": VERIFICATION_SCHEMA,
             "verification_sha256": verification_sha, "manifest_sha256": manifest_sha,
             "scope": "ADAPTER_STREAMED_BYTES_ONLY"},
             "source_ref": {"path": refs[1]["path"], "sha256": refs[1]["sha256"], "pointer": ""}},
        ],
        "relationships": [], "SOURCE_PROVENANCE": {"evidence_references": refs},
        "EXECUTION_EVIDENCE": [],
        "authority": {"claim_audit": "ADVISORY_ENGINEERING_EVIDENCE_ONLY", "OP1_authority_claimed": False},
    }


def _read_context_capsule(context_root: Path) -> tuple[dict[str, Any], bytes, Engine]:
    recovered = recover_generalized_audit(context_root)
    if recovered.get("status") != "PASS":
        raise AuditError("FRAGMENT_CONTEXT_RECOVERY_FAILED", "existing fragment context did not recover")
    receipt_path = context_root / "generalized-bridge-receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    engine = Engine(context_root)
    capsule_raw = engine.read_source(receipt["capsule"]["source_id"])
    capsule = json.loads(capsule_raw)
    if canonical_json(capsule) != capsule_raw:
        raise AuditError("FRAGMENT_CAPSULE_INVALID", "verified fragment capsule is noncanonical")
    return capsule, capsule_raw, engine


def bind_origin_manifest(output_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Bind the single canonical manifest and streamed verification record once."""
    root = Path(output_root).absolute()
    _check_path(root)
    manifest, manifest_raw, verification, verification_raw = _strict_manifest(root)
    _verify_staged_fragments(root, manifest)
    context = _bridge_manifest_context(root)
    if context.exists():
        saved_manifest, saved_raw, saved_verification, saved_verification_raw = _recover_manifest(root)
        if (_sha(saved_raw) == _sha(manifest_raw) and saved_verification_raw == verification_raw
                and saved_manifest == manifest and saved_verification == verification):
            return {"status": "PASS", "manifest_sha256": _sha(manifest_raw), "reused": True}
        raise AuditError("FRAGMENT_MANIFEST_ORPHAN", "manifest context exists but differs; no rebind performed")
    # Store explicit origin metadata in the capsule, while the full manifest is
    # admitted only once (not copied into every fragment batch).
    audit = _manifest_audit(manifest, manifest_raw, verification_raw)
    audit["origin_manifest_sha256"] = _sha(manifest_raw)
    audit["origin_parent_commitment"] = manifest["parent_source"]
    result = bind_generalized_audit(audit, root, context)
    return {"status": "PASS", "manifest_sha256": _sha(manifest_raw),
            "manifest_context": str(context), "fresh_process_readback": result["context_engine"]["fresh_process_readback"]["status"],
            "fragment_bytes_admitted": "NOT_PERFORMED"}


def _spool_db(path: Path, *, create: bool) -> sqlite3.Connection:
    if not create and not path.is_file():
        raise AuditError("FRAGMENT_SPOOL_MISSING", "observation spool checkpoint is missing")
    db = sqlite3.connect(path)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    if create:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS records (
                ordinal INTEGER PRIMARY KEY, record_kind TEXT NOT NULL, record_id TEXT NOT NULL,
                input_sha256 TEXT NOT NULL, status TEXT NOT NULL, fragment_index INTEGER,
                original_json TEXT NOT NULL, mapped_json TEXT, reason_code TEXT,
                previous_sha256 TEXT NOT NULL, event_sha256 TEXT NOT NULL);
        """)
        db.commit()
    # Duplicate observation-ID checks run once per input row.  Keep the
    # existing predicate and rejection semantics, but make the lookup bounded
    # by matching rows rather than rescanning the entire growing spool.
    db.execute("CREATE INDEX IF NOT EXISTS records_mapped_record_id "
               "ON records(record_kind, record_id, status)")
    db.commit()
    return db


def _record_event(db: sqlite3.Connection, ordinal: int, kind: str, record_id: str,
                  raw: bytes, status: str, fragment_index: int | None,
                  original: str, mapped: str | None, reason: str | None) -> None:
    previous_row = db.execute("SELECT event_sha256 FROM records ORDER BY ordinal DESC LIMIT 1").fetchone()
    previous = previous_row[0] if previous_row else "0" * 64
    input_sha = _sha(raw)
    payload = {"ordinal": ordinal, "record_kind": kind, "record_id": record_id,
               "input_sha256": input_sha, "status": status, "fragment_index": fragment_index,
               "original_json": original, "mapped_json": mapped, "reason_code": reason,
               "previous_sha256": previous}
    entry_hash = _sha(canonical_json(payload))
    db.execute("INSERT INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?)",
               (ordinal, kind, record_id, input_sha, status, fragment_index, original, mapped,
                reason, previous, entry_hash))


def _canonical_input(record: Any) -> tuple[bytes, bool]:
    """Return exact JSON bytes where possible, otherwise a nonidentity marker."""
    try:
        return canonical_json(dict(record) if isinstance(record, Mapping) else record), True
    except (TypeError, ValueError, OverflowError):
        marker = {"unserializable_input_type": type(record).__module__ + "." + type(record).__qualname__}
        return canonical_json(marker), False


def _verify_spool(db: sqlite3.Connection, manifest_sha: str) -> int:
    config = db.execute("SELECT value FROM metadata WHERE key='manifest_sha256'").fetchone()
    if not config or config[0] != manifest_sha:
        raise AuditError("FRAGMENT_SPOOL_MANIFEST_MISMATCH", "observation spool is not bound to this origin manifest")
    previous = "0" * 64
    total_bytes = 0
    count = 0
    for index, row in enumerate(db.execute("SELECT ordinal,record_kind,record_id,input_sha256,status,fragment_index,original_json,mapped_json,reason_code,previous_sha256,event_sha256 FROM records ORDER BY ordinal")):
        ordinal, kind, record_id, input_sha, status, frag_index, original, mapped, reason, parent, entry = row
        payload = {"ordinal": ordinal, "record_kind": kind, "record_id": record_id,
                   "input_sha256": input_sha, "status": status, "fragment_index": frag_index,
                   "original_json": original, "mapped_json": mapped, "reason_code": reason,
                   "previous_sha256": parent}
        if ordinal != index or parent != previous or _sha(canonical_json(payload)) != entry:
            raise AuditError("FRAGMENT_SPOOL_CHAIN_INVALID", "observation spool hash chain differs")
        if _sha(original.encode("utf-8")) != input_sha:
            raise AuditError("FRAGMENT_SPOOL_INPUT_HASH_MISMATCH", "spooled original record differs from its hash")
        total_bytes += len(original.encode("utf-8")) + (len(mapped.encode("utf-8")) if mapped else 0)
        if total_bytes > _MAX_SPOOL_BYTES:
            raise AuditError("FRAGMENT_SPOOL_LIMIT", "observation spool exceeds its byte limit")
        previous = entry
        count += 1
        if count > _MAX_OBSERVATIONS:
            raise AuditError("FRAGMENT_SPOOL_LIMIT", "observation spool exceeds its record limit")
    return count


def _spool_existing_bytes(db: sqlite3.Connection) -> int:
    total = 0
    for original, mapped in db.execute("SELECT original_json,mapped_json FROM records"):
        total += len(original.encode("utf-8")) + (len(mapped.encode("utf-8")) if mapped else 0)
        if total > _MAX_SPOOL_BYTES:
            raise AuditError("FRAGMENT_SPOOL_LIMIT", "observation spool exceeds its byte limit")
    return total


def _map_observation(row: Mapping[str, Any], manifest: Mapping[str, Any], manifest_sha: str,
                     expected_run_id: str | None, input_ordinal: int,
                     input_sha256: str, source_span_bytes: bytes | None = None
                     ) -> tuple[dict[str, Any] | None, int | None, str | None]:
    parent = manifest["parent_source"]
    source_ref = row.get("source_ref")
    if not isinstance(source_ref, dict) or source_ref.get("path") != parent["path"] or source_ref.get("sha256") != parent["sha256"]:
        return None, None, "SOURCE_REFERENCE_MISMATCH"
    if "bytes" in source_ref and (type(source_ref.get("bytes")) is not int
                                  or source_ref.get("bytes") != parent["bytes"]):
        return None, None, "SOURCE_REFERENCE_SIZE_MISMATCH"
    if not isinstance(row.get("run_id"), str) or not row.get("run_id"):
        return None, None, "RUN_ID_UNKNOWN"
    if expected_run_id is not None and row.get("run_id") != expected_run_id:
        return None, None, "RUN_ID_MISMATCH"
    span = row.get("source_byte_span")
    if not isinstance(span, dict) or span.get("unit") != "BYTE_SPAN":
        return None, None, "BYTE_SPAN_UNKNOWN"
    start, end = span.get("start"), span.get("end")
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= parent["bytes"]:
        return None, None, "BYTE_SPAN_INVALID"
    try:
        asserted_text = _text_assertion_bytes(row)
    except AuditError as exc:
        return None, None, exc.code
    content_status = "CONTENT_NOT_VERIFIED"
    if asserted_text is not None:
        if (len(asserted_text) != end - start or source_span_bytes is None
                or len(source_span_bytes) != end - start or source_span_bytes != asserted_text):
            return None, None, "BYTE_SPAN_CONTENT_MISMATCH"
        content_status = "CONTENT_VERIFIED"
    piece_count, piece_sha, first_index = _piece_digest(start, end, manifest["fragments"])
    if not piece_count or first_index < 0:
        return None, None, "BYTE_SPAN_UNMAPPED"
    fragment = manifest["fragments"][first_index]
    mapped = dict(row)
    mapped["original_source_ref"] = dict(source_ref)
    mapped["source_ref"] = {"path": fragment["path"], "sha256": fragment["sha256"],
                            "pointer": "", "mapping_role": "ROUTING_ANCHOR_ONLY"}
    mapped["origin_manifest_sha256"] = manifest_sha
    mapped["origin_parent_source"] = dict(parent)
    mapped["origin_fragment_index"] = fragment["index"]
    mapped["origin_fragment_range"] = [fragment["offset_start"], fragment["offset_end"]]
    mapped["origin_mapping_status"] = "EXACT_PARENT_BYTE_SPAN_V2_PIECE_DIGEST"
    mapped["origin_source_ref_role"] = "ROUTING_ANCHOR_ONLY"
    mapped["origin_piece_count"] = piece_count
    mapped["origin_piece_sha256"] = piece_sha
    mapped["origin_content_verification"] = content_status
    mapped["origin_input_ordinal"] = input_ordinal
    mapped["origin_input_sha256"] = input_sha256
    return mapped, fragment["index"], None


def _input_completion(db: sqlite3.Connection, fragment_count: int) -> dict[str, Any]:
    stream_digest = hashlib.sha256()
    record_count = observation_count = relationship_count = mapped_count = rejected_count = identity_unknown = 0
    for row in db.execute("SELECT ordinal,record_kind,record_id,input_sha256,status,fragment_index,reason_code FROM records ORDER BY ordinal"):
        ordinal, kind, record_id, input_sha, status, fragment_index, reason = row
        event = {"ordinal": ordinal, "record_kind": kind,
                 "input_sha256": input_sha, "status": status, "fragment_index": fragment_index,
                 "reason_code": reason}
        _update_framed(stream_digest, canonical_json(event))
        record_count += 1
        observation_count += int(kind == "OBSERVATION")
        relationship_count += int(kind == "RELATIONSHIP")
        mapped_count += int(kind == "OBSERVATION" and status == "MAPPED")
        rejected_count += int(status == "REJECTED")
        identity_unknown += int(reason == "OBSERVATION_INPUT_IDENTITY_UNVERIFIED")
    fragment_rows = []
    for index in range(fragment_count):
        digest = hashlib.sha256()
        mapped_for_fragment = 0
        for ordinal, input_sha in db.execute(
                "SELECT ordinal,input_sha256 FROM records WHERE status='MAPPED' AND record_kind='OBSERVATION' AND fragment_index=? ORDER BY ordinal",
                (index,)):
            _update_framed(digest, canonical_json({"ordinal": ordinal, "input_sha256": input_sha}))
            mapped_for_fragment += 1
        fragment_rows.append({"fragment_index": index, "mapped_count": mapped_for_fragment,
                              "mapped_input_sha256": digest.hexdigest()})
    return {"schema": "pgop1.swebench.source-fragment-input-completion.v1",
            "record_count": record_count, "observation_count": observation_count,
            "relationship_count": relationship_count,
            "mapped_observation_count": mapped_count, "rejected_record_count": rejected_count,
            "identity_unverified_count": identity_unknown,
            "ordered_input_sha256": stream_digest.hexdigest(), "fragments": fragment_rows}


def _build_rejection_ledger(db: sqlite3.Connection, manifest_sha: str,
                            fragment_count: int) -> dict[str, Any]:
    completion = _input_completion(db, fragment_count)
    entries: list[dict[str, Any]] = []
    used_bytes = 0
    for row in db.execute("SELECT ordinal,record_kind,record_id,input_sha256,status,reason_code,original_json FROM records WHERE status='REJECTED' ORDER BY ordinal"):
        ordinal, kind, record_id, input_sha, _, reason, original = row
        entry = {"ordinal": ordinal, "record_kind": kind, "record_id": record_id,
                 "input_sha256": input_sha, "reason_code": reason,
                 "original_record": json.loads(original)}
        used_bytes += len(canonical_json(entry))
        if used_bytes > _MAX_REJECTIONS_BYTES:
            raise AuditError("FRAGMENT_REJECTION_LEDGER_TOO_LARGE", "rejected original records exceed ledger byte cap")
        entries.append(entry)
    result = {"schema": REJECTION_SCHEMA, "origin_manifest_sha256": manifest_sha,
              "input_completion": completion, "rejections": entries}
    if len(canonical_json(result)) > _MAX_REJECTIONS_BYTES:
        raise AuditError("FRAGMENT_REJECTION_LEDGER_TOO_LARGE", "rejection ledger exceeds its byte bound")
    return result


def spool_fragment_observations(
    output_root: str | os.PathLike[str],
    observations: Iterable[Mapping[str, Any]],
    *,
    expected_run_id: str | None = None,
    relationships: Iterable[Mapping[str, Any]] = (),
    resume: bool = False,
) -> dict[str, Any]:
    """Durably map caller observations to fragments using explicit BYTE_SPAN only."""
    root = Path(output_root).absolute()
    _check_path(root)
    manifest, manifest_raw, _, _ = _strict_manifest(root)
    _verify_staged_fragments(root, manifest)
    manifest_sha = _sha(manifest_raw)
    spool_path = root / "observation-spool.sqlite"
    _check_path(spool_path)
    if spool_path.exists() and not resume:
        raise AuditError("FRAGMENT_SPOOL_EXISTS", "spool exists; explicit resume is required")
    if resume and not spool_path.is_file():
        raise AuditError("FRAGMENT_SPOOL_MISSING", "resume requires an existing observation spool")
    db = _spool_db(spool_path, create=not resume)
    prior = db.execute("SELECT value FROM metadata WHERE key='manifest_sha256'").fetchone()
    if not prior:
        if resume:
            raise AuditError("FRAGMENT_SPOOL_INVALID", "spool lacks origin manifest binding")
        db.execute("INSERT INTO metadata VALUES ('manifest_sha256', ?)", (manifest_sha,))
        db.execute("INSERT INTO metadata VALUES ('state', 'OPEN')")
        db.execute("INSERT INTO metadata VALUES ('expected_run_id', ?)", (expected_run_id or "UNKNOWN",))
        db.commit()
    elif prior[0] != manifest_sha:
        raise AuditError("FRAGMENT_SPOOL_MANIFEST_MISMATCH", "spool belongs to another origin manifest")
    existing_count = _verify_spool(db, manifest_sha)
    existing_bytes = _spool_existing_bytes(db)
    state = db.execute("SELECT value FROM metadata WHERE key='state'").fetchone()[0]
    if state == "COMPLETE" and not resume:
        raise AuditError("FRAGMENT_SPOOL_COMPLETE", "spool already completed")
    saved_run = db.execute("SELECT value FROM metadata WHERE key='expected_run_id'").fetchone()[0]
    if (expected_run_id or "UNKNOWN") != saved_run:
        raise AuditError("FRAGMENT_SPOOL_CONFIG_MISMATCH", "expected run binding differs from spool")
    ordinal = 0
    rejected = 0
    for record_kind, record in (("OBSERVATION", item) for item in observations):
        raw, input_identity_verified = _canonical_input(record)
        if len(raw) > _MAX_OBSERVATION_BYTES:
            raise AuditError("FRAGMENT_OBSERVATION_TOO_LARGE", "one observation exceeds its byte bound")
        if not input_identity_verified:
            original = raw.decode("utf-8")
            record_id = f"UNKNOWN-{ordinal}"
            status, frag_index, mapped_text, reason = "REJECTED", None, None, "OBSERVATION_INPUT_IDENTITY_UNVERIFIED"
        elif not isinstance(record, Mapping):
            # Keep JSON scalar/list inputs verbatim so changed replay is detectable.
            original = raw.decode("utf-8")
            record_id = f"UNKNOWN-{ordinal}"
            status, frag_index, mapped_text, reason = "REJECTED", None, None, "OBSERVATION_NOT_OBJECT"
        else:
            if any(not isinstance(key, str) for key in record):
                original = raw.decode("utf-8")
                record_id = f"UNKNOWN-{ordinal}"
                status, frag_index, mapped_text, reason = "REJECTED", None, None, "OBSERVATION_INPUT_IDENTITY_UNVERIFIED"
            else:
                original = raw.decode("utf-8")
                record_id = record.get("observation_id") if isinstance(record.get("observation_id"), str) else f"UNKNOWN-{ordinal}"
                observation_id = record.get("observation_id")
                kind = record.get("kind")
                reserved = (kind == _INTERNAL_FRAGMENT_COMMITMENT_KIND
                            or (isinstance(kind, str) and kind.startswith("origin_"))
                            or any(key.startswith("origin_") or key in _RESERVED_MAPPED_FIELDS for key in record))
                if reserved:
                    status, frag_index, mapped_text, reason = "REJECTED", None, None, "OBSERVATION_RESERVED_ORIGIN_NAMESPACE"
                elif (not isinstance(observation_id, str) or not observation_id or len(observation_id) > 512
                        or not isinstance(kind, str) or not kind or len(kind) > 128):
                    status, frag_index, mapped_text, reason = "REJECTED", None, None, "OBSERVATION_NORMALIZED_SCHEMA_INVALID"
                else:
                    source_span_bytes = None
                    span = record.get("source_byte_span")
                    if (isinstance(span, dict) and type(span.get("start")) is int
                            and type(span.get("end")) is int):
                        try:
                            if _text_assertion_bytes(record) is not None:
                                source_span_bytes = _read_staged_span(root, manifest, span["start"], span["end"])
                        except AuditError:
                            pass
                    mapped, frag_index, reason = _map_observation(record, manifest, manifest_sha,
                                                                  expected_run_id, ordinal, _sha(raw),
                                                                  source_span_bytes)
                    status = "MAPPED" if mapped is not None else "REJECTED"
                    mapped_text = canonical_json(mapped).decode("utf-8") if mapped is not None else None
        if ordinal < existing_count:
            old = db.execute("SELECT input_sha256,reason_code FROM records WHERE ordinal=?", (ordinal,)).fetchone()
            if old and old[1] == "OBSERVATION_INPUT_IDENTITY_UNVERIFIED":
                raise AuditError("FRAGMENT_SPOOL_REPLAY_IDENTITY_UNVERIFIED", "prior non-JSON input cannot be identity-verified on replay")
            if not old or old[0] != _sha(raw):
                raise AuditError("FRAGMENT_SPOOL_REPLAY_MISMATCH", "replayed observation differs from durable spool")
            ordinal += 1
            continue
        if ordinal != existing_count:
            raise AuditError("FRAGMENT_SPOOL_ORDER_INVALID", "spool input order is not contiguous")
        if existing_bytes + len(original.encode("utf-8")) + (len(mapped_text.encode("utf-8")) if mapped_text else 0) > _MAX_SPOOL_BYTES:
            raise AuditError("FRAGMENT_SPOOL_LIMIT", "observation spool exceeds its byte limit")
        if status == "MAPPED" and record_kind == "OBSERVATION" and db.execute(
                "SELECT 1 FROM records WHERE record_kind='OBSERVATION' AND status='MAPPED' AND record_id=? LIMIT 1",
                (str(record_id)[:256],)).fetchone():
            status, frag_index, mapped_text, reason = "REJECTED", None, None, "DUPLICATE_OBSERVATION_ID"
        _record_event(db, ordinal, record_kind, str(record_id)[:256], raw, status,
                      frag_index, original, mapped_text, reason)
        existing_count += 1
        existing_bytes += len(original.encode("utf-8")) + (len(mapped_text.encode("utf-8")) if mapped_text else 0)
        rejected += int(status == "REJECTED")
        ordinal += 1
        if ordinal > _MAX_OBSERVATIONS:
            raise AuditError("FRAGMENT_SPOOL_LIMIT", "observation count exceeds configured bound")
        if ordinal % 64 == 0:
            db.commit()
    # Explicitly reject, preserve, and hash-chain relationships; their endpoints
    # are not rebound unless the caller can provide byte spans for both sides.
    for relationship in relationships:
        raw = canonical_json(dict(relationship)) if isinstance(relationship, Mapping) else canonical_json({"unsupported_type": type(relationship).__name__})
        if len(raw) > _MAX_OBSERVATION_BYTES:
            raise AuditError("FRAGMENT_RELATIONSHIP_TOO_LARGE", "one relationship exceeds its byte bound")
        if ordinal < existing_count:
            old = db.execute("SELECT input_sha256 FROM records WHERE ordinal=?", (ordinal,)).fetchone()
            if not old or old[0] != _sha(raw):
                raise AuditError("FRAGMENT_SPOOL_REPLAY_MISMATCH", "replayed relationship differs from durable spool")
            ordinal += 1
            continue
        original = raw.decode("utf-8")
        record_id = relationship.get("relationship_id", f"UNKNOWN-{ordinal}") if isinstance(relationship, Mapping) else f"UNKNOWN-{ordinal}"
        if existing_bytes + len(original.encode("utf-8")) > _MAX_SPOOL_BYTES:
            raise AuditError("FRAGMENT_SPOOL_LIMIT", "observation spool exceeds its byte limit")
        _record_event(db, ordinal, "RELATIONSHIP", str(record_id)[:256], raw, "REJECTED", None,
                      original, None, "RELATIONSHIP_BYTE_MAPPING_UNPROVEN")
        existing_count += 1
        existing_bytes += len(original.encode("utf-8"))
        rejected += 1
        ordinal += 1
        if ordinal > _MAX_OBSERVATIONS:
            raise AuditError("FRAGMENT_SPOOL_LIMIT", "record count exceeds configured bound")
    if resume and ordinal < existing_count:
        raise AuditError("FRAGMENT_SPOOL_REPLAY_TRUNCATED", "resume ended before all prior spool records")
    db.execute("UPDATE metadata SET value='COMPLETE' WHERE key='state'")
    db.commit()
    rejection_ledger = _build_rejection_ledger(db, manifest_sha, len(manifest["fragments"]))
    completion = rejection_ledger["input_completion"]
    observation_count = completion["observation_count"]
    mapped_count = completion["mapped_observation_count"]
    rejection_raw = canonical_json(rejection_ledger)
    rejection_path = root / "mapping-rejections.json"
    if not rejection_path.exists():
        _write_immutable(rejection_path, rejection_raw)
    elif rejection_path.read_bytes() != rejection_raw:
        db.close()
        raise AuditError("FRAGMENT_REJECTION_LEDGER_MISMATCH", "saved rejection ledger differs from spool")
    db.close()
    return {"status": "PARTIAL" if rejection_ledger["rejections"] else "PASS",
            "manifest_sha256": manifest_sha, "observation_count": observation_count,
            "mapped_observation_count": mapped_count,
            "rejected_record_count": len(rejection_ledger["rejections"]),
            "rejection_ledger_sha256": _sha(rejection_raw), "manifest_binding": "DEFERRED_UNTIL_BIND",
            "dispatch": "NOT_PERFORMED", "authority": "ADVISORY_ENGINEERING_ONLY"}


def _manifest_fragment_ref(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"path": row["path"], "sha256": row["sha256"], "bytes": row["bytes"],
            "role": "SOURCE_FRAGMENT", "parser_id": "source_fragment.bytes.v1",
            "parser_version": "1", "instance_binding": "RUN_ONLY"}


def bind_fragment_observations(output_root: str | os.PathLike[str], *, resume: bool = False) -> dict[str, Any]:
    """Bind mapped observations through existing chunk and bridge APIs."""
    root = Path(output_root).absolute()
    _check_path(root)
    manifest, manifest_raw, _, _ = _strict_manifest(root)
    manifest_sha = _sha(manifest_raw)
    _verify_staged_fragments(root, manifest)
    spool_path = root / "observation-spool.sqlite"
    _check_path(spool_path)
    db = _spool_db(spool_path, create=False)
    if db.execute("SELECT value FROM metadata WHERE key='state'").fetchone() != ("COMPLETE",):
        db.close()
        raise AuditError("FRAGMENT_SPOOL_INCOMPLETE", "observation input stream is not durably complete")
    _verify_spool(db, manifest_sha)
    expected_ledger = _build_rejection_ledger(db, manifest_sha, len(manifest["fragments"]))
    ledger_path = root / "mapping-rejections.json"
    try:
        saved_ledger_raw = _read_small_file(ledger_path, _MAX_REJECTIONS_BYTES)
        saved_ledger = json.loads(saved_ledger_raw)
    except (OSError, json.JSONDecodeError) as exc:
        db.close()
        raise AuditError("FRAGMENT_REJECTION_LEDGER_MISSING", "completed input lacks a valid rejection ledger") from exc
    if (canonical_json(saved_ledger) != saved_ledger_raw
            or saved_ledger_raw != canonical_json(expected_ledger)):
        db.close()
        raise AuditError("FRAGMENT_REJECTION_LEDGER_MISMATCH", "durable input completion differs from the observation spool")
    completion = expected_ledger["input_completion"]
    mapped_by_fragment = {index: db.execute(
        "SELECT COUNT(*) FROM records WHERE status='MAPPED' AND fragment_index=? AND record_kind='OBSERVATION'",
        (index,)).fetchone()[0] for index in range(len(manifest["fragments"]))}
    db.close()
    context_root = root / "context" / "batches"
    origin_id = manifest["origin_id"]
    parent = manifest["parent_source"]
    if not (root / "mapping-rejections.json").is_file():
        raise AuditError("FRAGMENT_REJECTION_LEDGER_MISSING", "mapping rejection ledger was not finalized")
    bind_origin_manifest(root)
    rejection_binding = _bind_rejection_ledger(root, manifest)

    def items() -> Iterable[dict[str, Any]]:
        for fragment in manifest["fragments"]:
            index = fragment["index"]
            db_local = _spool_db(spool_path, create=False)
            def observations() -> Iterable[dict[str, Any]]:
                cursor = db_local.execute(
                    "SELECT mapped_json FROM records WHERE status='MAPPED' AND fragment_index=? AND record_kind='OBSERVATION' ORDER BY ordinal",
                    (index,))
                for (mapped_json,) in cursor:
                    yield json.loads(mapped_json)
            stream_id = f"{origin_id}-f{index:06d}"
            meta = {"run_id": origin_id, "instance_id": "UNBOUND", "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE"}
            provenance = {"evidence_references": [_manifest_fragment_ref(fragment)]}
            for chunk_number, chunk in enumerate(iter_audit_chunks(
                    stream_id, meta, provenance, observations(), max_bytes=_MAX_FRAGMENT_CHUNK_BYTES)):
                result = chunk["audit_result"]
                fragment_ref = {"path": fragment["path"], "sha256": fragment["sha256"], "pointer": ""}
                result["observations"].append({
                    "observation_id": f"origin-fragment-{index:06d}-{chunk_number:06d}",
                    "kind": "origin_fragment_commitment", "run_id": origin_id,
                    "instance_id": "UNKNOWN", "value": {
                        "origin_manifest_sha256": manifest_sha,
                        "parent_source": parent,
                        "fragment": fragment,
                        "mapped_observation_count": mapped_by_fragment[index],
                        "engine_byte_scope": "FRAGMENT_BYTES_ADMITTED_ONLY",
                    }, "source_ref": fragment_ref,
                })
                result.update({"origin_manifest_sha256": manifest_sha,
                               "origin_parent_commitment": parent,
                               "origin_fragment": fragment,
                               "origin_mapping_schema": MAPPING_SCHEMA,
                               "fragment_observation_count": mapped_by_fragment[index],
                               "input_completion_sha256": rejection_binding["ledger_sha256"]})
                chunk["item_id"] = f"{origin_id}-f{index:06d}-c{chunk_number:06d}"
                if not _batch_fits([], chunk["item_id"], result):
                    raise AuditError("FRAGMENT_CHUNK_AGGREGATE_TOO_LARGE",
                                     "bounded chunk exceeds the existing bridge aggregate envelope")
                yield chunk
            db_local.close()

    result = bind_audit_stream(items(), root, context_root, batch_size=1, resume=resume)
    return {"status": "PARTIAL" if result["rejected_item_count"] else result["status"],
            "origin_manifest_sha256": manifest_sha,
            "parent_source": parent, "fragment_count": len(manifest["fragments"]),
            "context_batch_count": result["batch_count"], "completed_item_count": result["completed_item_count"],
            "rejected_batch_item_count": result["rejected_item_count"],
            "batch_item_rejections": result["rejections"],
            "input_completion": completion,
            "rejected_mapping_count": json.loads((root / "mapping-rejections.json").read_bytes()).get("rejections", []).__len__(),
            "engine_byte_scope": "FRAGMENT_BYTES_ADMITTED_ONLY", "dispatch": "NOT_PERFORMED",
            "authority": "ADVISORY_ENGINEERING_ONLY"}


def _bind_rejection_ledger(root: Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    ledger_path = root / "mapping-rejections.json"
    _check_path(ledger_path)
    raw = ledger_path.read_bytes()
    if len(raw) > _MAX_REJECTIONS_BYTES:
        raise AuditError("FRAGMENT_REJECTION_LEDGER_TOO_LARGE", "rejection ledger exceeds its byte bound")
    digest = _sha(raw)
    ledger = json.loads(raw)
    if canonical_json(ledger) != raw or ledger.get("schema") != REJECTION_SCHEMA:
        raise AuditError("FRAGMENT_REJECTION_LEDGER_INVALID", "rejection ledger is noncanonical or unsupported")
    if ledger.get("origin_manifest_sha256") != manifest["origin_manifest_sha256"]:
        raise AuditError("FRAGMENT_REJECTION_CONTEXT_MISMATCH", "rejection ledger belongs to another manifest")
    completion = _validate_input_completion(ledger.get("input_completion"), len(manifest["fragments"]))
    context = root / "context" / "mapping-rejections"
    if context.exists():
        capsule, _, engine = _read_context_capsule(context)
        refs = capsule.get("source_refs", [])
        audit_saved = capsule.get("audit_result", {})
        if (not any(ref.get("sha256") == digest for ref in refs)
                or audit_saved.get("origin_manifest_sha256") != manifest["origin_manifest_sha256"]
                or audit_saved.get("input_completion_sha256") != digest):
            del engine
            raise AuditError("FRAGMENT_REJECTION_CONTEXT_MISMATCH", "existing rejection context differs")
        ledger_observations = audit_saved.get("observations", [])
        if (len(ledger_observations) != 1
                or canonical_json(ledger_observations[0].get("value", {}).get("input_completion"))
                != canonical_json(completion)):
            del engine
            raise AuditError("FRAGMENT_INPUT_COMPLETION_MISMATCH", "immutable rejection context completion differs")
        del engine
        return {"status": "PASS", "reused": True, "ledger_sha256": digest}
    ref = {"path": "mapping-rejections.json", "sha256": digest, "bytes": len(raw),
           "role": "SOURCE_FRAGMENT_MAPPING_REJECTIONS", "parser_id": "source_fragment_rejections.v2",
           "parser_version": "1", "instance_binding": "RUN_ONLY"}
    audit = {"schema": "pgop1.swebench.generalized-audit.v1", "result_scope": "BATCH_AGGREGATE",
             "instance_id": "UNBOUND", "batch_id": "mapping-rejections-" + digest[:32],
             "run_id": manifest["origin_id"], "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE",
             "origin_manifest_sha256": manifest["origin_manifest_sha256"],
             "input_completion_sha256": digest,
             "observations": [{"observation_id": "mapping-rejections-" + digest[:24],
                               "kind": "mapping_rejection_ledger", "run_id": manifest["origin_id"],
                               "instance_id": "UNKNOWN", "value": {"ledger_sha256": digest,
                               "count": len(ledger.get("rejections", [])),
                               "input_completion": completion,
                               "parent_sha256": manifest["parent_source"]["sha256"]},
                               "source_ref": {"path": ref["path"], "sha256": digest, "pointer": ""}}],
             "relationships": [], "SOURCE_PROVENANCE": {"evidence_references": [ref]},
             "EXECUTION_EVIDENCE": [], "authority": {"claim_audit": "ADVISORY_ENGINEERING_EVIDENCE_ONLY",
             "OP1_authority_claimed": False}}
    result = bind_generalized_audit(audit, root, context)
    return {"status": "PASS", "fresh_process_readback": result["context_engine"]["fresh_process_readback"]["status"],
            "ledger_sha256": digest}


def _recover_manifest(root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any], bytes]:
    context = _bridge_manifest_context(root)
    capsule, _, engine = _read_context_capsule(context)
    audit = capsule.get("audit_result", {})
    if not isinstance(audit, dict):
        raise AuditError("FRAGMENT_MANIFEST_CONTEXT_INVALID", "manifest context audit result is invalid")
    refs = capsule.get("source_refs", [])
    by_role = {ref.get("roles", [None])[0]: ref for ref in refs}
    manifest_ref = by_role.get("SOURCE_FRAGMENT_ORIGIN_MANIFEST")
    verification_ref = by_role.get("SOURCE_FRAGMENT_STREAM_VERIFICATION")
    if not manifest_ref or not verification_ref:
        raise AuditError("FRAGMENT_MANIFEST_CONTEXT_INVALID", "manifest context lacks both source commitments")
    manifest_raw = engine.read_source(manifest_ref["source_id"])
    verification_raw = engine.read_source(verification_ref["source_id"])
    if (_sha(manifest_raw) != manifest_ref["sha256"] or _sha(verification_raw) != verification_ref["sha256"]
            or audit.get("origin_manifest_sha256") != _sha(manifest_raw)):
        raise AuditError("FRAGMENT_MANIFEST_CONTEXT_MISMATCH", "immutable manifest context commitments differ")
    manifest = json.loads(manifest_raw)
    verification = json.loads(verification_raw)
    if canonical_json(manifest) != manifest_raw or canonical_json(verification) != verification_raw:
        raise AuditError("FRAGMENT_MANIFEST_CONTEXT_INVALID", "immutable manifest objects are not canonical")
    manifest["origin_manifest_sha256"] = _sha(manifest_raw)
    _validate_manifest_shape(manifest, verification, _sha(manifest_raw))
    del engine
    return manifest, manifest_raw, verification, verification_raw


def _validate_manifest_shape(manifest: Mapping[str, Any], verification: Mapping[str, Any], manifest_sha: str) -> None:
    parent = manifest.get("parent_source")
    fragments = manifest.get("fragments")
    fragmentation = manifest.get("fragmentation")
    if (manifest.get("schema") != MANIFEST_SCHEMA or not isinstance(parent, dict)
            or not isinstance(fragments, list) or not fragments or len(fragments) > _MAX_FRAGMENTS
            or not _HASH_RE.fullmatch(str(parent.get("sha256", "")))
            or not isinstance(parent.get("path"), str)
            or not _HASH_RE.fullmatch(str(parent.get("absolute_path_sha256", "")))
            or not isinstance(fragmentation, dict)
            or type(parent.get("bytes")) is not int or not 0 <= parent["bytes"] <= _MAX_PARENT_BYTES):
        raise AuditError("FRAGMENT_MANIFEST_INVALID", "immutable origin manifest is malformed")
    expected_origin_id = "origin-" + hashlib.sha256(
        (parent["path"] + "\0" + parent["absolute_path_sha256"] + "\0" + parent["sha256"]).encode("utf-8")).hexdigest()[:24]
    if (manifest.get("origin_id") != expected_origin_id
            or fragmentation.get("algorithm") != "FIXED_SIZE_BINARY_SPLIT_V1"
            or fragmentation.get("mapping_schema") != MAPPING_SCHEMA
            or type(fragmentation.get("fragment_bytes")) is not int
            or not 1 <= fragmentation["fragment_bytes"] <= _MAX_FRAGMENT_BYTES):
        raise AuditError("FRAGMENT_MANIFEST_INVALID", "origin identity or mapping schema is invalid")
    expected_exclusion_policy = {"version": INPUT_EXCLUSION_POLICY_VERSION,
                                 "result": INPUT_EXCLUSION_POLICY_RESULT}
    if (manifest.get("input_exclusion_policy") != expected_exclusion_policy
            or verification.get("input_exclusion_policy") != expected_exclusion_policy):
        raise AuditError("FRAGMENT_INPUT_EXCLUSION_POLICY_INVALID", "origin does not carry the required input exclusion policy evidence")
    if (verification.get("manifest_sha256") != manifest_sha
            or verification.get("parent_sha256") != parent.get("sha256")
            or type(verification.get("parent_bytes")) is not int
            or verification.get("parent_bytes") != parent.get("bytes")
            or verification.get("streamed_parent_sha256") != parent.get("sha256")
            or type(verification.get("streamed_parent_bytes")) is not int
            or verification.get("streamed_parent_bytes") != parent.get("bytes")
            or type(verification.get("fragment_bytes")) is not int
            or verification.get("fragment_bytes") != fragmentation.get("fragment_bytes")
            or type(verification.get("fragments")) is not int
            or verification.get("fragments") != len(fragments)
            or verification.get("schema") != VERIFICATION_SCHEMA
            or verification.get("verification_scope") != "ADAPTER_STREAMED_BYTES_ONLY"):
        raise AuditError("FRAGMENT_VERIFICATION_MISMATCH", "immutable verification record differs from manifest")
    coverage = manifest.get("coverage")
    if (not isinstance(coverage, dict) or type(coverage.get("start")) is not int
            or type(coverage.get("end")) is not int or coverage.get("start") != 0
            or coverage.get("end") != parent["bytes"] or coverage.get("contiguous") is not True
            or coverage.get("parent_sha256_verified_by_stream") != parent["sha256"]):
        raise AuditError("FRAGMENT_RANGE_INVALID", "manifest does not bind exact streamed parent coverage")
    cursor = 0
    for index, row in enumerate(fragments):
        if (not isinstance(row, dict) or type(row.get("index")) is not int or row.get("index") != index
                or type(row.get("offset_start")) is not int or row.get("offset_start") != cursor
                or type(row.get("offset_end")) is not int or row.get("offset_end") < cursor
                or type(row.get("bytes")) is not int
                or row.get("bytes") != row.get("offset_end") - cursor
                or row.get("bytes") > _MAX_FRAGMENT_BYTES
                or row.get("path") != f"fragments/fragment-{index:06d}.bin"
                or not _HASH_RE.fullmatch(str(row.get("sha256", "")))):
            raise AuditError("FRAGMENT_RANGE_INVALID", "immutable fragment coverage is not exact and ordered")
        cursor = row["offset_end"]
    if cursor != parent.get("bytes"):
        raise AuditError("FRAGMENT_RANGE_INVALID", "immutable fragment ranges do not cover the parent length")
    expected_fragment_count = max(1, (parent["bytes"] + fragmentation["fragment_bytes"] - 1)
                                 // fragmentation["fragment_bytes"])
    if len(fragments) != expected_fragment_count:
        raise AuditError("FRAGMENT_RANGE_INVALID", "fragment count differs from fixed-size fragmentation profile")
    for index, row in enumerate(fragments):
        expected_size = 0 if parent["bytes"] == 0 else min(
            fragmentation["fragment_bytes"], parent["bytes"] - index * fragmentation["fragment_bytes"])
        if row["bytes"] != expected_size:
            raise AuditError("FRAGMENT_RANGE_INVALID", "fragment length differs from fixed-size fragmentation profile")


def _validate_input_completion(value: Any, fragment_count: int) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema") != "pgop1.swebench.source-fragment-input-completion.v1":
        raise AuditError("FRAGMENT_INPUT_COMPLETION_INVALID", "input completion commitment is missing or unsupported")
    for field in ("record_count", "observation_count", "mapped_observation_count",
                  "relationship_count", "rejected_record_count", "identity_unverified_count"):
        if type(value.get(field)) is not int or not 0 <= value[field] <= _MAX_OBSERVATIONS:
            raise AuditError("FRAGMENT_INPUT_COMPLETION_INVALID", "input completion counts are malformed")
    if (value["observation_count"] + value["relationship_count"] != value["record_count"]
            or value["mapped_observation_count"] + value["rejected_record_count"] != value["record_count"]
            or value["mapped_observation_count"] > value["observation_count"]
            or value["identity_unverified_count"] > value["rejected_record_count"]
            or not _HASH_RE.fullmatch(str(value.get("ordered_input_sha256", "")))):
        raise AuditError("FRAGMENT_INPUT_COMPLETION_INVALID", "input completion totals or hash are inconsistent")
    rows = value.get("fragments")
    if not isinstance(rows, list) or len(rows) != fragment_count:
        raise AuditError("FRAGMENT_INPUT_COMPLETION_INVALID", "per-fragment input commitments are incomplete")
    for index, row in enumerate(rows):
        if (not isinstance(row, dict) or type(row.get("fragment_index")) is not int
                or row.get("fragment_index") != index or type(row.get("mapped_count")) is not int
                or not 0 <= row["mapped_count"] <= value["mapped_observation_count"]
                or not _HASH_RE.fullmatch(str(row.get("mapped_input_sha256", "")))):
            raise AuditError("FRAGMENT_INPUT_COMPLETION_INVALID", "per-fragment input commitment is malformed")
    if sum(row["mapped_count"] for row in rows) != value["mapped_observation_count"]:
        raise AuditError("FRAGMENT_INPUT_COMPLETION_INVALID", "per-fragment counts differ from total mapped observations")
    return value


def _completion_scratch() -> sqlite3.Connection:
    # Empty filename asks SQLite for a private temporary database. It is not
    # placed in or recovered from the caller's output root.
    db = sqlite3.connect("")
    db.execute("PRAGMA temp_store=FILE")
    db.execute("CREATE TABLE recovered_input (ordinal INTEGER PRIMARY KEY, record_kind TEXT NOT NULL, record_id TEXT NOT NULL, input_sha256 TEXT NOT NULL, status TEXT NOT NULL, fragment_index INTEGER, reason_code TEXT)")
    db.execute("CREATE TABLE content_checks (ordinal INTEGER PRIMARY KEY, start INTEGER NOT NULL, end INTEGER NOT NULL, expected BLOB NOT NULL)")
    return db


def _insert_recovered_input(db: sqlite3.Connection, *, ordinal: Any, record_kind: str,
                            record_id: Any, input_sha256: Any, status: str,
                            fragment_index: int | None, reason_code: str | None) -> None:
    if (type(ordinal) is not int or ordinal < 0 or ordinal >= _MAX_OBSERVATIONS
            or record_kind not in {"OBSERVATION", "RELATIONSHIP"}
            or status not in {"MAPPED", "REJECTED"}
            or not isinstance(record_id, str) or not _HASH_RE.fullmatch(str(input_sha256))
            or (status == "MAPPED" and (record_kind != "OBSERVATION" or type(fragment_index) is not int))
            or (status == "REJECTED" and (fragment_index is not None or not isinstance(reason_code, str)))):
        raise AuditError("FRAGMENT_INPUT_COMPLETION_INVALID", "recovered input identity is malformed")
    try:
        db.execute("INSERT INTO recovered_input VALUES (?,?,?,?,?,?,?)",
                   (ordinal, record_kind, record_id, input_sha256, status, fragment_index, reason_code))
    except sqlite3.IntegrityError as exc:
        raise AuditError("FRAGMENT_INPUT_ORDINAL_DUPLICATE", "mapped and rejected records reuse an input ordinal") from exc


def _restore_mapped_input(observation: Mapping[str, Any]) -> bytes:
    original_ref = observation.get("original_source_ref")
    if not isinstance(original_ref, dict):
        raise AuditError("FRAGMENT_INPUT_ORIGINAL_MISSING", "mapped observation lacks original source reference")
    restored = dict(observation)
    for field in _RESERVED_MAPPED_FIELDS:
        restored.pop(field, None)
    for field in tuple(restored):
        if field.startswith("origin_"):
            raise AuditError("FRAGMENT_INPUT_RESERVED_FIELD", "mapped observation contains an unrecognized adapter field")
    restored["source_ref"] = original_ref
    return canonical_json(restored)


def recover_fragmented_source(output_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Verify complete parent coverage using Engine-admitted immutable objects only."""
    root = Path(output_root).absolute()
    _check_path(root)
    manifest, manifest_raw, verification, verification_raw = _recover_manifest(root)
    manifest_sha = _sha(manifest_raw)
    parent = manifest["parent_source"]
    rejection_context = root / "context" / "mapping-rejections"
    rejection_capsule, _, rejection_engine = _read_context_capsule(rejection_context)
    rejection_audit = rejection_capsule.get("audit_result", {})
    if (rejection_audit.get("origin_manifest_sha256") != manifest_sha
            or rejection_audit.get("run_id") != manifest["origin_id"]):
        raise AuditError("FRAGMENT_REJECTION_CONTEXT_MISMATCH", "rejection context belongs to another origin")
    rejection_refs = rejection_capsule.get("source_refs", [])
    if len(rejection_refs) != 1:
        raise AuditError("FRAGMENT_REJECTION_CONTEXT_INVALID", "rejection context has an unexpected source count")
    rejection_raw = rejection_engine.read_source(rejection_refs[0]["source_id"])
    rejection_ledger = json.loads(rejection_raw)
    if _sha(rejection_raw) != rejection_refs[0]["sha256"] or canonical_json(rejection_ledger) != rejection_raw:
        raise AuditError("FRAGMENT_REJECTION_CONTEXT_INVALID", "rejection ledger immutable source differs")
    if rejection_ledger.get("origin_manifest_sha256") != manifest_sha:
        raise AuditError("FRAGMENT_REJECTION_CONTEXT_MISMATCH", "rejection ledger belongs to another manifest")
    if rejection_ledger.get("schema") != REJECTION_SCHEMA:
        raise AuditError("FRAGMENT_REJECTION_LEDGER_INVALID", "immutable rejection ledger version is not current")
    completion = _validate_input_completion(rejection_ledger.get("input_completion"), len(manifest["fragments"]))
    rejection_rows = rejection_ledger.get("rejections")
    if not isinstance(rejection_rows, list) or len(rejection_rows) != completion["rejected_record_count"]:
        raise AuditError("FRAGMENT_INPUT_COMPLETION_MISMATCH", "rejection rows differ from immutable completion count")
    if rejection_audit.get("input_completion_sha256") != rejection_refs[0]["sha256"]:
        raise AuditError("FRAGMENT_INPUT_COMPLETION_MISMATCH", "immutable rejection capsule does not bind its completion ledger")
    ledger_audit_rows = rejection_audit.get("observations", [])
    if (len(ledger_audit_rows) != 1
            or canonical_json(ledger_audit_rows[0].get("value", {}).get("input_completion"))
            != canonical_json(completion)):
        raise AuditError("FRAGMENT_INPUT_COMPLETION_MISMATCH", "immutable rejection capsule has a different completion record")
    del rejection_engine

    batch_root = root / "context" / "batches"
    batch_recovery = recover_audit_stream(batch_root)
    if batch_recovery.get("status") != "PASS":
        raise AuditError("FRAGMENT_BATCH_RECOVERY_FAILED", "one or more fragment batches did not recover")
    checkpoint = sqlite3.connect(str(batch_root / "batch-checkpoint.sqlite"))
    rejected_batch_rows = list(checkpoint.execute(
        "SELECT item_id,detail FROM items WHERE status='REJECTED' ORDER BY ordinal"))
    checkpoint.close()
    if rejected_batch_rows:
        raise AuditError("FRAGMENT_BATCH_ITEM_REJECTED", "batch checkpoint contains rejected fragment chunks")
    contexts = sorted((p for p in batch_root.iterdir() if p.is_dir() and p.name.startswith("batch-")), key=lambda p: p.name)
    next_fragment = 0
    next_chunk_by_fragment = [0 for _ in manifest["fragments"]]
    seen_fragment: set[int] = set()
    parent_hasher = hashlib.sha256()
    parent_total = 0
    bound_observation_count = 0
    bound_fragment_count = 0
    completion_db = _completion_scratch()
    reconstructed_parent = tempfile.TemporaryFile(mode="w+b")
    content_verified_count = 0
    content_not_verified_count = 0
    mapped_by_fragment_count = [0 for _ in manifest["fragments"]]
    mapped_by_fragment_digest = [hashlib.sha256() for _ in manifest["fragments"]]
    mapped_last_ordinal = [-1 for _ in manifest["fragments"]]
    for rejection in rejection_ledger.get("rejections", []):
        if (not isinstance(rejection, dict) or not isinstance(rejection.get("record_kind"), str)
                or not isinstance(rejection.get("reason_code"), str)):
            raise AuditError("FRAGMENT_REJECTION_LEDGER_INVALID", "rejection record is malformed")
        original_raw = canonical_json(rejection.get("original_record"))
        if _sha(original_raw) != rejection.get("input_sha256"):
            raise AuditError("FRAGMENT_REJECTION_INPUT_HASH_MISMATCH", "rejected original input differs from its hash")
        _insert_recovered_input(completion_db, ordinal=rejection.get("ordinal"),
                                record_kind=rejection["record_kind"], record_id=rejection.get("record_id"),
                                input_sha256=rejection.get("input_sha256"), status="REJECTED",
                                fragment_index=None, reason_code=rejection["reason_code"])
    for context in contexts:
        capsule, _, engine = _read_context_capsule(context)
        aggregate = capsule.get("audit_result", {})
        member_results = aggregate.get("batch_members", [])
        if len(member_results) != 1 or not isinstance(member_results[0].get("audit_result"), dict):
            raise AuditError("FRAGMENT_BATCH_MEMBER_COUNT_INVALID", "each fragment context must contain one deterministic item")
        member = member_results[0]["audit_result"]
        if (member.get("origin_manifest_sha256") != manifest_sha
                or canonical_json(member.get("origin_parent_commitment")) != canonical_json(parent)):
            raise AuditError("FRAGMENT_BATCH_ORIGIN_MISMATCH", "batch capsule is not bound to the verified parent manifest")
        if member.get("input_completion_sha256") != rejection_refs[0]["sha256"]:
            raise AuditError("FRAGMENT_INPUT_COMPLETION_MISMATCH", "batch member is not bound to input completion ledger")
        fragment = member.get("origin_fragment")
        if (not isinstance(fragment, dict) or type(fragment.get("index")) is not int
                or not 0 <= fragment["index"] < len(manifest["fragments"])):
            raise AuditError("FRAGMENT_BATCH_MAPPING_INVALID", "batch capsule lacks a valid fragment identity")
        index = fragment["index"]
        if canonical_json(fragment) != canonical_json(manifest["fragments"][index]):
            raise AuditError("FRAGMENT_BATCH_MAPPING_INVALID", "batch fragment metadata differs from origin manifest")
        if index < next_fragment - 1 or index > next_fragment:
            raise AuditError("FRAGMENT_BATCH_ORDER_INVALID", "fragment batch order is not monotonic")
        refs = [ref for ref in capsule.get("source_refs", [])
                if ref.get("path") == fragment["path"] and ref.get("sha256") == fragment["sha256"]]
        if not refs:
            raise AuditError("FRAGMENT_BATCH_SOURCE_MISSING", "fragment bytes are not admitted in the batch context")
        if index == next_fragment:
            raw_fragment = engine.read_source(refs[0]["source_id"])
            if len(raw_fragment) != fragment["bytes"] or _sha(raw_fragment) != fragment["sha256"]:
                raise AuditError("FRAGMENT_ENGINE_BYTES_MISMATCH", "Engine-admitted fragment differs from manifest")
            reconstructed_parent.seek(parent_total)
            reconstructed_parent.write(raw_fragment)
            parent_hasher.update(raw_fragment)
            parent_total += len(raw_fragment)
            del raw_fragment
            seen_fragment.add(index)
            bound_fragment_count += 1
            next_fragment += 1
        item_id = member_results[0]["item_id"]
        try:
            chunk_number = int(item_id.rsplit("-c", 1)[1])
        except (IndexError, ValueError) as exc:
            raise AuditError("FRAGMENT_BATCH_ID_INVALID", "batch item lacks a stable chunk ordinal") from exc
        if item_id != f"{manifest['origin_id']}-f{index:06d}-c{chunk_number:06d}":
            raise AuditError("FRAGMENT_BATCH_ID_INVALID", "batch item identity differs from fragment and chunk")
        if chunk_number != next_chunk_by_fragment[index]:
            raise AuditError("FRAGMENT_BATCH_ORDER_INVALID", "fragment chunk sequence is missing or reordered")
        next_chunk_by_fragment[index] += 1
        member_observations = member.get("observations", [])
        if not isinstance(member_observations, list):
            raise AuditError("FRAGMENT_BATCH_MEMBER_INVALID", "fragment member observations are not an array")
        marker_rows = [row for row in member_observations
                       if isinstance(row, dict) and row.get("kind") == _INTERNAL_FRAGMENT_COMMITMENT_KIND]
        expected_marker_value = {"origin_manifest_sha256": manifest_sha, "parent_source": parent,
                                 "fragment": fragment,
                                 "mapped_observation_count": completion["fragments"][index]["mapped_count"],
                                 "engine_byte_scope": "FRAGMENT_BYTES_ADMITTED_ONLY"}
        if (len(marker_rows) != 1 or not member_observations or member_observations[-1] is not marker_rows[0]
                or marker_rows[0].get("observation_id") != f"origin-fragment-{index:06d}-{chunk_number:06d}"
                or marker_rows[0].get("run_id") != manifest["origin_id"]
                or not isinstance(marker_rows[0].get("value"), dict)
                or type(marker_rows[0]["value"].get("mapped_observation_count")) is not int
                or canonical_json(marker_rows[0].get("value")) != canonical_json(expected_marker_value)
                or marker_rows[0].get("source_ref") != {"path": fragment["path"], "sha256": fragment["sha256"], "pointer": ""}):
            raise AuditError("FRAGMENT_INTERNAL_MARKER_INVALID", "producer fragment marker is missing or malformed")
        if (type(member.get("fragment_observation_count")) is not int
                or member.get("fragment_observation_count") != completion["fragments"][index]["mapped_count"]
                or member.get("origin_mapping_schema") != MAPPING_SCHEMA):
            raise AuditError("FRAGMENT_INPUT_COMPLETION_MISMATCH", "member fragment counts or mapping version differ")
        for observation in member_observations[:-1]:
            if (not isinstance(observation, dict)
                    or observation.get("origin_manifest_sha256") != manifest_sha
                    or canonical_json(observation.get("origin_parent_source")) != canonical_json(parent)
                    or observation.get("origin_mapping_status") != "EXACT_PARENT_BYTE_SPAN_V2_PIECE_DIGEST"
                    or observation.get("origin_source_ref_role") != "ROUTING_ANCHOR_ONLY"):
                raise AuditError("FRAGMENT_OBSERVATION_MAPPING_INVALID", "observation origin mapping differs from manifest")
            span = observation.get("source_byte_span")
            if (not isinstance(span, dict) or span.get("unit") != "BYTE_SPAN"
                    or type(span.get("start")) is not int or type(span.get("end")) is not int
                    or not 0 <= span["start"] < span["end"] <= parent["bytes"]):
                raise AuditError("FRAGMENT_OBSERVATION_MAPPING_INVALID", "observation has an invalid parent byte span")
            piece_count, piece_sha, anchor_index = _piece_digest(span["start"], span["end"], manifest["fragments"])
            if (type(observation.get("origin_piece_count")) is not int
                    or piece_count != observation.get("origin_piece_count")
                    or piece_sha != observation.get("origin_piece_sha256")
                    or type(observation.get("origin_fragment_index")) is not int
                    or anchor_index != index
                    or observation.get("origin_fragment_index") != index
                    or not isinstance(observation.get("origin_fragment_range"), list)
                    or len(observation["origin_fragment_range"]) != 2
                    or any(type(value) is not int for value in observation["origin_fragment_range"])
                    or observation.get("origin_fragment_range") != [fragment["offset_start"], fragment["offset_end"]]):
                raise AuditError("FRAGMENT_OBSERVATION_PIECE_MISMATCH", "observation piece map differs from parent byte span")
            original_ref = observation.get("original_source_ref")
            if (not isinstance(original_ref, dict) or original_ref.get("path") != parent["path"]
                    or original_ref.get("sha256") != parent["sha256"]):
                raise AuditError("FRAGMENT_OBSERVATION_MAPPING_INVALID", "original source reference differs from parent commitment")
            source_ref = observation.get("source_ref")
            if (not isinstance(source_ref, dict) or source_ref.get("path") != fragment["path"]
                    or source_ref.get("sha256") != fragment["sha256"]
                    or source_ref.get("mapping_role") != "ROUTING_ANCHOR_ONLY"):
                raise AuditError("FRAGMENT_OBSERVATION_MAPPING_INVALID", "routing anchor source differs from primary fragment")
            try:
                expected_text = _text_assertion_bytes(observation)
            except AuditError as exc:
                raise AuditError("BYTE_SPAN_CONTENT_MISMATCH", "recovered source text assertion is malformed") from exc
            content_status = observation.get("origin_content_verification", "CONTENT_NOT_VERIFIED")
            if expected_text is None:
                if content_status != "CONTENT_NOT_VERIFIED":
                    raise AuditError("FRAGMENT_CONTENT_STATUS_MISMATCH", "observation claims text verification without an exact source text assertion")
                content_not_verified_count += 1
            else:
                if (content_status != "CONTENT_VERIFIED" or len(expected_text) != span["end"] - span["start"]):
                    raise AuditError("FRAGMENT_CONTENT_STATUS_MISMATCH", "exact source text assertion lacks a matching verification status")
                completion_db.execute("INSERT INTO content_checks VALUES (?,?,?,?)",
                                      (observation.get("origin_input_ordinal"), span["start"], span["end"], expected_text))
                content_verified_count += 1
            original_raw = _restore_mapped_input(observation)
            input_sha = observation.get("origin_input_sha256")
            if _sha(original_raw) != input_sha:
                raise AuditError("FRAGMENT_INPUT_ORIGINAL_HASH_MISMATCH", "mapped original input does not reproduce its input hash")
            input_ordinal = observation.get("origin_input_ordinal")
            _insert_recovered_input(completion_db, ordinal=input_ordinal,
                                    record_kind="OBSERVATION", record_id=observation.get("observation_id"),
                                    input_sha256=input_sha, status="MAPPED", fragment_index=index,
                                    reason_code=None)
            if type(input_ordinal) is not int or input_ordinal <= mapped_last_ordinal[index]:
                raise AuditError("FRAGMENT_INPUT_ORDER_INVALID", "mapped observations are not ordered within their anchor fragment")
            mapped_last_ordinal[index] = input_ordinal
            _update_framed(mapped_by_fragment_digest[index], canonical_json(
                {"ordinal": input_ordinal, "input_sha256": input_sha}))
            mapped_by_fragment_count[index] += 1
            bound_observation_count += 1
        del engine
        gc.collect()
    if seen_fragment != set(range(len(manifest["fragments"]))):
        raise AuditError("FRAGMENT_COVERAGE_INCOMPLETE", "not all fragments have an Engine-admitted batch")
    if parent_total != parent["bytes"] or parent_hasher.hexdigest() != parent["sha256"]:
        raise AuditError("FRAGMENT_PARENT_RECONSTRUCTION_MISMATCH", "Engine fragments do not reconstruct parent SHA-256/size")
    for _, start, end, expected_text in completion_db.execute(
            "SELECT ordinal,start,end,expected FROM content_checks ORDER BY ordinal"):
        reconstructed_parent.seek(start)
        actual_text = reconstructed_parent.read(end - start)
        if actual_text != expected_text:
            raise AuditError("BYTE_SPAN_CONTENT_MISMATCH", "Engine-admitted parent bytes differ from the mapped exact text assertion")
    reconstructed_parent.close()
    if bound_observation_count != completion["mapped_observation_count"]:
        raise AuditError("FRAGMENT_INPUT_COVERAGE_MISMATCH", "Engine capsules omit accepted mapped input observations")
    expected_fragment_digests = completion["fragments"]
    for index, expected in enumerate(expected_fragment_digests):
        if (mapped_by_fragment_count[index] != expected["mapped_count"]
                or mapped_by_fragment_digest[index].hexdigest() != expected["mapped_input_sha256"]):
            raise AuditError("FRAGMENT_INPUT_FRAGMENT_COMMITMENT_MISMATCH", "Engine mapped input rows differ from per-fragment completion")
    scratch_count = completion_db.execute("SELECT COUNT(*) FROM recovered_input").fetchone()[0]
    if scratch_count != completion["record_count"]:
        raise AuditError("FRAGMENT_INPUT_COVERAGE_MISMATCH", "mapped and rejected input rows do not cover the committed record count")
    ordered_input_digest = hashlib.sha256()
    observed_count = relationship_count = mapped_count = rejected_count = identity_unknown = 0
    for ordinal, record_kind, record_id, input_sha, status, fragment_index, reason in completion_db.execute(
            "SELECT ordinal,record_kind,record_id,input_sha256,status,fragment_index,reason_code FROM recovered_input ORDER BY ordinal"):
        if ordinal != observed_count + relationship_count:
            raise AuditError("FRAGMENT_INPUT_ORDINAL_GAP", "input ordinals are not contiguous from zero")
        event = {"ordinal": ordinal, "record_kind": record_kind, "input_sha256": input_sha,
                 "status": status, "fragment_index": fragment_index, "reason_code": reason}
        _update_framed(ordered_input_digest, canonical_json(event))
        observed_count += int(record_kind == "OBSERVATION")
        relationship_count += int(record_kind == "RELATIONSHIP")
        mapped_count += int(status == "MAPPED")
        rejected_count += int(status == "REJECTED")
        identity_unknown += int(reason == "OBSERVATION_INPUT_IDENTITY_UNVERIFIED")
    completion_db.close()
    if (observed_count != completion["observation_count"]
            or relationship_count != completion["relationship_count"]
            or mapped_count != completion["mapped_observation_count"]
            or rejected_count != completion["rejected_record_count"]
            or identity_unknown != completion["identity_unverified_count"]
            or ordered_input_digest.hexdigest() != completion["ordered_input_sha256"]):
        raise AuditError("FRAGMENT_INPUT_COMPLETION_MISMATCH", "ordered original and rejected inputs differ from completion commitment")
    return {"schema": "pgop1.swebench.source-fragment-recovery.v2",
            "status": "PARTIAL" if identity_unknown else "PASS",
            "input_identity_verification": "PARTIAL_UNKNOWN" if identity_unknown else "EXACT_CANONICAL_JSON",
            "input_record_count": completion["record_count"],
            "input_observation_count": observed_count,
            "input_mapped_observation_count": mapped_count,
            "input_rejected_record_count": rejected_count,
            "ordered_input_sha256": completion["ordered_input_sha256"],
            "origin_manifest_sha256": manifest_sha, "parent_sha256": parent["sha256"],
            "parent_bytes": parent_total, "fragment_count": len(manifest["fragments"]),
            "engine_admitted_fragments_verified": bound_fragment_count,
            "mapped_observations_verified": bound_observation_count,
            "content_verified_observations": content_verified_count,
            "content_not_verified_observations": content_not_verified_count,
            "rejected_records_recovered": len(rejection_ledger.get("rejections", [])),
            "reconstruction_source": "ENGINE_IMMUTABLE_FRAGMENT_OBJECTS",
            "original_file_read": "NOT_PERFORMED", "staged_fragment_read": "NOT_PERFORMED",
            "semantic_claim_validation": "NOT_PERFORMED", "authority": "ADVISORY_ENGINEERING_ONLY"}
