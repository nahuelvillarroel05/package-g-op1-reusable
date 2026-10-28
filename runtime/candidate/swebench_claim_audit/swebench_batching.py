"""Bounded, restartable composition over the existing generalized bridge.

The checkpoint is a local engineering ledger. It does not add Context Engine
authority, and a batch verdict is deliberately not inferred from member verdicts.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Callable, Iterable, Mapping

from .adapter import AuditError
from .generalized_bridge import bind_generalized_audit, recover_generalized_audit
from runtime.candidate.context_engine import Engine, canonical_json


SCHEMA = "pgop1.swebench.batching-checkpoint.v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_MAX_BATCH_ITEMS = 64
_MAX_BATCH_SOURCES = 64
_MAX_BATCH_OBSERVATIONS = 935  # Bridge reserves room for sources and result node.
_MAX_BATCH_RELATIONSHIPS = 1000
_MAX_CHUNK_BYTES = 3 * 1024 * 1024
_MAX_CHUNK_OBSERVATIONS = 64
_MAX_BATCH_READBACK_IDS = 120
_MAX_BATCH_PAYLOAD_BYTES = 3 * 1024 * 1024
_MAX_BATCH_SOURCE_BYTES = 128 * 1024 * 1024


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def iter_audit_chunks(
    stream_id: str,
    audit_metadata: Mapping[str, Any],
    source_provenance: Mapping[str, Any],
    observations: Iterable[Mapping[str, Any]],
    *,
    max_observations: int = _MAX_CHUNK_OBSERVATIONS,
    max_bytes: int = _MAX_CHUNK_BYTES,
    relationships_for_chunk: Callable[[int, set[str]], Iterable[Mapping[str, Any]]] | None = None,
) -> Iterable[dict[str, Any]]:
    """Yield bounded audit results from a possibly long observation stream.

    Only the current chunk is held in memory. The callback can retrieve the
    relationship records attached to the current chunk's original observation
    and claim IDs from an external stream or index. Any relationship that crosses
    chunks must provide its endpoint observations as explicit stubs through the
    callback; an unresolved endpoint is rejected rather than silently dropped.
    """
    if not _ID_RE.fullmatch(stream_id):
        raise AuditError("BATCH_STREAM_ID_INVALID", "stream_id is not a stable bounded identifier")
    if type(max_observations) is not int or not 1 <= max_observations <= _MAX_CHUNK_OBSERVATIONS:
        raise AuditError("BATCH_CHUNK_SIZE_INVALID", "max_observations must be 1 through 64")
    if type(max_bytes) is not int or not 1024 <= max_bytes <= _MAX_CHUNK_BYTES:
        raise AuditError("BATCH_CHUNK_BYTES_INVALID", "max_bytes must be 1024 through 3145728")
    refs = source_provenance.get("evidence_references")
    if not isinstance(refs, list) or not refs:
        raise AuditError("BATCH_INPUT_INVALID", "chunk source provenance needs a nonempty reference list")
    chunk: list[dict[str, Any]] = []
    chunk_bytes = 0
    chunk_number = 0

    def emit(rows: list[dict[str, Any]], number: int) -> dict[str, Any]:
        ids: set[str] = set()
        for row in rows:
            for key in ("observation_id", "claim_id"):
                if isinstance(row.get(key), str):
                    ids.add(row[key])
        relationships = list(relationships_for_chunk(number, ids)) if relationships_for_chunk else []
        for relationship in relationships:
            if not isinstance(relationship, Mapping) or relationship.get("from") not in ids or relationship.get("to") not in ids:
                raise AuditError("BATCH_RELATIONSHIP_CROSS_CHUNK", "relationship endpoint requires an explicit in-chunk observation or stub")
        audit = {
            "schema": "pgop1.swebench.generalized-audit.v1",
            "run_id": audit_metadata.get("run_id", "UNKNOWN"),
            "instance_id": audit_metadata.get("instance_id", "UNBOUND"),
            "AUDIT_VERDICT": audit_metadata.get("AUDIT_VERDICT", "INSUFFICIENT_EVIDENCE"),
            "reason_codes": audit_metadata.get("reason_codes", []),
            "observations": rows, "relationships": relationships,
            "SOURCE_PROVENANCE": {"evidence_references": refs},
            "EXECUTION_EVIDENCE": audit_metadata.get("EXECUTION_EVIDENCE", []),
            "chunk": {"stream_id": stream_id, "chunk_index": number,
                      "association_scope": "SOURCE_REFERENCES_PRESERVED; RELATIONSHIPS_CALLBACK_BOUND"},
        }
        if len(canonical_json(audit)) > max_bytes:
            raise AuditError("BATCH_CHUNK_PAYLOAD_TOO_LARGE", "complete chunk payload exceeds configured byte bound")
        return {"item_id": f"{stream_id}:chunk:{number:06d}", "audit_result": audit}

    for observation in observations:
        if not isinstance(observation, Mapping):
            raise AuditError("BATCH_INPUT_INVALID", "streamed observation must be an object")
        row = dict(observation)
        row_bytes = len(canonical_json(row))
        if row_bytes > max_bytes:
            raise AuditError("BATCH_OBSERVATION_TOO_LARGE", "one observation exceeds configured chunk byte bound")
        if chunk and (len(chunk) >= max_observations or chunk_bytes + row_bytes > max_bytes):
            yield emit(chunk, chunk_number)
            chunk_number += 1
            chunk, chunk_bytes = [], 0
        chunk.append(row)
        chunk_bytes += row_bytes
    if chunk or chunk_number == 0:
        yield emit(chunk, chunk_number)


def _flush(db: sqlite3.Connection) -> None:
    db.commit()


def _reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _check_no_reparse(path: Path) -> None:
    candidate = path.absolute()
    cursor = Path(candidate.anchor)
    if _reparse(cursor):
        raise AuditError("BATCH_OUTPUT_REPARSE", "output path contains a reparse point")
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if _reparse(cursor):
            raise AuditError("BATCH_OUTPUT_REPARSE", "output path contains a reparse point")


def _insert_item(db: sqlite3.Connection, item_id: str, ordinal: int, item_sha: str,
                 status: str, batch_id: str | None, detail: str) -> None:
    previous_row = db.execute("SELECT commitment_sha256 FROM item_commitments ORDER BY ordinal DESC LIMIT 1").fetchone()
    previous = previous_row[0] if previous_row else "0" * 64
    payload = {"ordinal": ordinal, "item_id": item_id, "item_sha256": item_sha,
               "previous_sha256": previous}
    digest = _digest(canonical_json(payload))
    db.execute("INSERT INTO items VALUES (?,?,?,?,?,?)",
               (item_id, ordinal, item_sha, status, batch_id, detail))
    db.execute("INSERT INTO item_commitments VALUES (?,?,?,?,?)",
               (ordinal, item_id, item_sha, previous, digest))


def _insert_rejection(db: sqlite3.Connection, input_id: str, reason_code: str, item_ref: str) -> None:
    previous_row = db.execute("SELECT entry_sha256 FROM rejections ORDER BY rejection_id DESC LIMIT 1").fetchone()
    previous = previous_row[0] if previous_row else "0" * 64
    ordinal = db.execute("SELECT COUNT(*) FROM rejections").fetchone()[0]
    payload = {"ordinal": ordinal, "input_id": input_id[:256], "reason_code": reason_code,
               "item_ref": item_ref, "previous_sha256": previous}
    digest = _digest(canonical_json(payload))
    db.execute("INSERT INTO rejections(input_id,reason_code,item_ref,previous_sha256,entry_sha256) VALUES (?,?,?,?,?)",
               (payload["input_id"], reason_code, item_ref, previous, digest))


def _db(path: Path, *, create: bool) -> sqlite3.Connection:
    if not create and not path.is_file():
        raise AuditError("BATCH_CHECKPOINT_MISSING", "batch checkpoint does not exist")
    db = sqlite3.connect(path)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA journal_mode=WAL")
    if create:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS items (
                item_id TEXT PRIMARY KEY, ordinal INTEGER NOT NULL UNIQUE,
                item_sha256 TEXT NOT NULL, status TEXT NOT NULL,
                batch_id TEXT, detail TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS item_commitments (
                ordinal INTEGER PRIMARY KEY, item_id TEXT NOT NULL UNIQUE,
                item_sha256 TEXT NOT NULL, previous_sha256 TEXT NOT NULL,
                commitment_sha256 TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS batches (
                batch_id TEXT PRIMARY KEY, ordinal INTEGER NOT NULL UNIQUE,
                input_sha256 TEXT NOT NULL, context_path TEXT NOT NULL,
                bridge_receipt_sha256 TEXT NOT NULL, previous_sha256 TEXT NOT NULL,
                checkpoint_sha256 TEXT NOT NULL, status TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS rejections (
                rejection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                input_id TEXT NOT NULL, reason_code TEXT NOT NULL, item_ref TEXT NOT NULL,
                previous_sha256 TEXT NOT NULL, entry_sha256 TEXT NOT NULL);
        """)
        _flush(db)
    return db


def _source_refs(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    provenance = result.get("SOURCE_PROVENANCE")
    refs = provenance.get("evidence_references", []) if isinstance(provenance, dict) else []
    execution = result.get("EXECUTION_EVIDENCE", [])
    if not isinstance(refs, list) or not isinstance(execution, list):
        raise AuditError("BATCH_INPUT_INVALID", "audit source references must be arrays")
    unique: list[dict[str, Any]] = []
    for ref in [*refs, *execution]:
        if not isinstance(ref, dict) or not isinstance(ref.get("path"), str):
            raise AuditError("BATCH_INPUT_INVALID", "audit source reference is malformed")
        unique.append(dict(ref))
    return unique


def _validate_member_shape(item_id: str, result: dict[str, Any]) -> None:
    refs = _source_refs(result)
    if not refs or len(refs) > _MAX_BATCH_SOURCES:
        raise AuditError("BATCH_SOURCE_COUNT", "member has no sources or exceeds the source count bound")
    by_path: dict[str, tuple[str, int]] = {}
    for ref in refs:
        path, digest, size = ref.get("path"), ref.get("sha256"), ref.get("bytes")
        if (not isinstance(path, str) or not path or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest) or type(size) is not int
                or size < 0 or size > 64 * 1024 * 1024):
            raise AuditError("BATCH_SOURCE_REFERENCE_INVALID", "member source reference is malformed or oversized")
        if ref.get("instance_binding", "INSTANCE_BOUND") not in {"INSTANCE_BOUND", "RUN_ONLY"}:
            raise AuditError("BATCH_SOURCE_REFERENCE_INVALID", "member source binding scope is unsupported")
        previous = by_path.get(path)
        if previous is not None and previous != (digest, size):
            raise AuditError("BATCH_SOURCE_CONFLICT", "member source path has conflicting commitments")
        by_path[path] = (digest, size)
    scopes = {(ref["path"], ref["sha256"]): ref.get("instance_binding", "INSTANCE_BOUND")
              for ref in refs}
    observations = result.get("observations", [])
    if not isinstance(observations, list):
        raise AuditError("BATCH_INPUT_INVALID", "member observations must be an array")
    for obs in observations:
        if not isinstance(obs, dict) or not isinstance(obs.get("run_id", result.get("run_id", "UNKNOWN")), str):
            raise AuditError("BATCH_INPUT_INVALID", "observation run identity is malformed")
    relationships = result.get("relationships", [])
    if not isinstance(relationships, list):
        raise AuditError("BATCH_INPUT_INVALID", "member relationships must be an array")
    for relationship in relationships:
        if not isinstance(relationship, dict):
            raise AuditError("BATCH_RELATIONSHIP_INVALID", "relationship must be an object")
        bindings = relationship.get("evidence_bindings")
        if not isinstance(bindings, list) or not bindings:
            raise AuditError("BATCH_RELATIONSHIP_INVALID", "relationship evidence bindings are missing")
        for binding in bindings:
            if not isinstance(binding, dict):
                raise AuditError("BATCH_RELATIONSHIP_INVALID", "relationship evidence binding is malformed")
            key = (binding.get("path"), binding.get("sha256"))
            if key not in scopes:
                raise AuditError("BATCH_RELATIONSHIP_SOURCE_UNBOUND", "relationship cites an uncommitted source")
            if scopes[key] == "RUN_ONLY":
                raise AuditError("BATCH_RUN_ONLY_RELATIONSHIP", "RUN_ONLY evidence cannot bind an instance comparison")
    # Validate every observation and relationship before staging the member so a
    # bad row cannot poison otherwise valid neighboring input records.
    _member_observations(item_id, result, set(scopes), scopes)


def _batch_fits(results: list[tuple[str, dict[str, Any]]], item_id: str,
                result: dict[str, Any]) -> bool:
    refs: set[tuple[str, str]] = set()
    observations = relationships = readback_ids = 0
    for _, row in [*results, (item_id, result)]:
        refs.update((r.get("path"), r.get("sha256")) for r in _source_refs(row))
        obs = row.get("observations", [])
        rel = row.get("relationships", [])
        if not isinstance(obs, list) or not isinstance(rel, list):
            return False
        observations += len(obs) + 1  # Include member audit summary node.
        readback_ids += len(obs) + 1
        relationships += len(rel)
    unique_refs: dict[tuple[str, str], int] = {}
    for _, row in [*results, (item_id, result)]:
        for ref in _source_refs(row):
            unique_refs[(ref.get("path"), ref.get("sha256"))] = ref.get("bytes", 0)
    source_bytes = sum(unique_refs.values())
    aggregate_bytes = len(canonical_json(_aggregate("batch-size-probe", [*results, (item_id, result)])))
    return (bool(refs) and len(refs) <= _MAX_BATCH_SOURCES and observations <= _MAX_BATCH_OBSERVATIONS
            and readback_ids <= _MAX_BATCH_READBACK_IDS
            and aggregate_bytes <= _MAX_BATCH_PAYLOAD_BYTES and source_bytes <= _MAX_BATCH_SOURCE_BYTES
            and relationships <= _MAX_BATCH_RELATIONSHIPS)


def _member_observations(item_id: str, result: dict[str, Any],
                         refs: set[tuple[str, str]],
                         scopes: Mapping[tuple[str, str], str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    observations = result.get("observations", [])
    relationships = result.get("relationships", [])
    if not isinstance(observations, list) or not isinstance(relationships, list):
        raise AuditError("BATCH_INPUT_INVALID", "audit observations and relationships must be arrays")
    mapping: dict[str, str] = {}
    normalized: list[dict[str, Any]] = []
    for index, original in enumerate(observations):
        if not isinstance(original, dict):
            raise AuditError("BATCH_INPUT_INVALID", "audit observation must be an object")
        old_id = original.get("observation_id")
        ref = original.get("source_ref")
        if not isinstance(old_id, str) or not old_id or not isinstance(ref, dict):
            raise AuditError("BATCH_INPUT_INVALID", "observation lacks stable identity or source binding")
        key = (ref.get("path"), ref.get("sha256"))
        if key not in refs:
            raise AuditError("BATCH_SOURCE_UNBOUND", "observation source is not committed in member provenance")
        new_id = f"{item_id}:{index}:{_digest(old_id.encode())[:16]}"
        if old_id in mapping:
            raise AuditError("BATCH_DUPLICATE_OBSERVATION", "member repeats an observation identifier")
        mapping[old_id] = new_id
        if isinstance(original.get("claim_id"), str):
            mapping[original["claim_id"]] = new_id
        row = dict(original)
        row["observation_id"] = new_id
        if isinstance(row.get("claim_id"), str):
            row["claim_id"] = f"{item_id}:{row['claim_id']}"
        row["batch_member_id"] = item_id
        row["original_observation_id"] = old_id
        if scopes.get(key) == "RUN_ONLY" and row.get("instance_id") not in {None, "", "UNKNOWN", "UNBOUND"}:
            row["requested_instance_id"] = row["instance_id"]
            row["instance_id"] = "UNKNOWN"
        # All parser supplied source spans and pointers are retained verbatim.
        normalized.append(row)
    normalized_relationships: list[dict[str, Any]] = []
    for index, original in enumerate(relationships):
        if not isinstance(original, dict):
            raise AuditError("BATCH_INPUT_INVALID", "audit relationship must be an object")
        row = dict(original)
        start, end = row.get("from"), row.get("to")
        start, end = mapping.get(start), mapping.get(end)
        if start not in set(mapping.values()) or end not in set(mapping.values()):
            raise AuditError("BATCH_RELATIONSHIP_UNBOUND", "relationship endpoints do not resolve within member")
        row["relationship_id"] = f"{item_id}:{index}:{row.get('relationship_id', 'relationship')}"
        row["from"], row["to"] = start, end
        normalized_relationships.append(row)
    return normalized, normalized_relationships


def _aggregate(batch_id: str, members: list[tuple[str, dict[str, Any]]]) -> dict[str, Any]:
    refs_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    all_member_refs: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    for item_id, result in members:
        member_refs = _source_refs(result)
        all_member_refs.extend(dict(ref) for ref in member_refs)
        member_scopes = {(r["path"], r["sha256"]): r.get("instance_binding", "INSTANCE_BOUND")
                         for r in member_refs}
        for ref in member_refs:
            key = (ref["path"], ref["sha256"])
            previous = refs_by_key.get(key)
            if previous is not None and (previous.get("bytes") != ref.get("bytes")):
                raise AuditError("BATCH_SOURCE_CONFLICT", "same source commitment has conflicting byte counts")
            if previous is None:
                refs_by_key[key] = dict(ref)
            elif (previous.get("instance_binding", "INSTANCE_BOUND") == "RUN_ONLY"
                  or ref.get("instance_binding", "INSTANCE_BOUND") == "RUN_ONLY"):
                previous["instance_binding"] = "RUN_ONLY"
            if ref.get("instance_binding") == "RUN_ONLY":
                member_scopes[key] = "RUN_ONLY"
        member_ref_keys = set(member_scopes)
        member_obs, member_rel = _member_observations(item_id, result, member_ref_keys, member_scopes)
        observations.extend(member_obs)
        relationships.extend(member_rel)
        if member_ref_keys:
            ref = sorted((refs_by_key[k] for k in member_ref_keys), key=lambda v: (v["path"], v["sha256"]))[0]
            source_scope = member_scopes[(ref["path"], ref["sha256"])]
            instance_id = result.get("instance_id", "UNKNOWN")
            observations.append({
                "observation_id": f"{item_id}:member-audit", "kind": "batch_member_audit",
                "run_id": result.get("run_id", "UNKNOWN"),
                "instance_id": "UNKNOWN" if source_scope == "RUN_ONLY" else instance_id,
                "requested_instance_id": instance_id if source_scope == "RUN_ONLY" else None,
                "member_status": result.get("AUDIT_VERDICT", result.get("status", "UNKNOWN")),
                "member_reason_codes": result.get("reason_codes", []),
                "source_ref": {"path": ref["path"], "sha256": ref["sha256"], "pointer": ""},
                "batch_member_id": item_id,
            })
    return {
        "schema": "pgop1.swebench.generalized-audit.v1",
        "result_scope": "BATCH_AGGREGATE", "instance_id": "UNBOUND",
        "batch_id": batch_id, "run_id": "BATCHED",
        "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE",
        "batch_verdict_semantics": "NOT_COMPUTED; member verdicts retained as observations",
        "batch_members": [{"item_id": item_id, "item_sha256": _digest(canonical_json(result)),
                           "audit_result": result} for item_id, result in members],
        "observations": observations, "relationships": relationships,
        "SOURCE_PROVENANCE": {"evidence_references": all_member_refs},
        "EXECUTION_EVIDENCE": [],
        "authority": {"claim_audit": "ADVISORY_ENGINEERING_EVIDENCE_ONLY", "OP1_authority_claimed": False},
    }


def _checkpoint_record(db: sqlite3.Connection, batch_id: str, ordinal: int,
                      input_sha: str, context_path: Path, bridge_receipt_sha: str) -> str:
    previous_row = db.execute("SELECT checkpoint_sha256 FROM batches ORDER BY ordinal DESC LIMIT 1").fetchone()
    previous = previous_row[0] if previous_row else "0" * 64
    payload = {"schema": SCHEMA, "batch_id": batch_id, "ordinal": ordinal,
               "input_sha256": input_sha, "context_path": str(context_path),
               "bridge_receipt_sha256": bridge_receipt_sha, "previous_sha256": previous,
               "status": "COMPLETE"}
    digest = _digest(canonical_json(payload))
    db.execute("INSERT INTO batches VALUES (?,?,?,?,?,?,?,?)",
               (batch_id, ordinal, input_sha, str(context_path), bridge_receipt_sha,
                previous, digest, "COMPLETE"))
    return digest


def bind_audit_stream(items: Iterable[Mapping[str, Any]], data_root: str | os.PathLike[str],
                      output_root: str | os.PathLike[str], *, batch_size: int = 16,
                      resume: bool = False) -> dict[str, Any]:
    """Consume {item_id, audit_result} records incrementally into bounded bridge batches.

    `batch_size` is the maximum member count; source/observation/relationship
    limits may close a batch earlier. Resume requires replaying the same ordered
    stream and exact item bytes. An output without a durable checkpoint is orphaned
    and is never automatically rebound.
    """
    if type(batch_size) is not int or not 1 <= batch_size <= _MAX_BATCH_ITEMS:
        raise AuditError("BATCH_SIZE_INVALID", "batch_size must be an integer from 1 through 64")
    root = Path(output_root).absolute()
    _check_no_reparse(root)
    db_path = root / "batch-checkpoint.sqlite"
    if resume:
        if not root.is_dir() or not db_path.is_file():
            raise AuditError("BATCH_CHECKPOINT_MISSING", "resume requires an existing checkpoint")
        recover_audit_stream(root)
    elif db_path.exists() or (root.exists() and any(root.iterdir())):
        raise AuditError("BATCH_RESUME_REQUIRED", "existing output requires explicit resume")
    root.mkdir(parents=True, exist_ok=True)
    _check_no_reparse(root)
    if db_path.exists() and _reparse(db_path):
        raise AuditError("BATCH_CHECKPOINT_REPARSE", "checkpoint path cannot be a reparse point")
    db = _db(db_path, create=not resume)
    config = json.dumps({"schema": SCHEMA, "batch_size": batch_size}, sort_keys=True)
    prior_config = db.execute("SELECT value FROM metadata WHERE key='config'").fetchone()
    if prior_config and prior_config[0] != config:
        raise AuditError("BATCH_CONFIG_MISMATCH", "resume configuration differs from checkpoint")
    if not prior_config:
        if resume:
            raise AuditError("BATCH_CHECKPOINT_INVALID", "checkpoint lacks configuration")
        db.execute("INSERT INTO metadata VALUES ('config', ?)", (config,))
        _flush(db)

    members: list[tuple[str, dict[str, Any]]] = []
    pending_ids: list[str] = []
    batch_ordinal = db.execute("SELECT COUNT(*) FROM batches").fetchone()[0]
    next_item = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
    checkpoint_item_count = next_item
    completed = rejected = 0
    committing = False

    def commit_batch() -> None:
        nonlocal members, pending_ids, batch_ordinal, completed, committing
        if not members:
            return
        committing = True
        batch_id = f"batch-{batch_ordinal:06d}"
        aggregate = _aggregate(batch_id, members)
        input_sha = _digest(canonical_json([
            {"item_id": iid, "item_sha256": _digest(canonical_json(row))} for iid, row in members]))
        context_path = root / batch_id
        # If bridge completed but the process died before checkpoint commit, do not redispatch.
        if context_path.exists():
            raise AuditError("BATCH_ORPHAN_CONTEXT", "batch output exists without a durable completion record")
        bound = bind_generalized_audit(aggregate, data_root, context_path)
        receipt_path = context_path / "generalized-bridge-receipt.json"
        receipt_sha = _digest(receipt_path.read_bytes())
        _checkpoint_record(db, batch_id, batch_ordinal, input_sha, context_path, receipt_sha)
        for iid in pending_ids:
            db.execute("UPDATE items SET status='COMPLETE', batch_id=?, detail=? WHERE item_id=?",
                       (batch_id, bound["context_engine"]["manifest"]["graph_sha256"], iid))
        _flush(db)
        completed += len(members)
        batch_ordinal += 1
        members, pending_ids = [], []
        committing = False

    replay_ordinal = 0

    def record_invalid_item(raw_item: Any, reason_code: str, label: str) -> None:
        nonlocal replay_ordinal
        synthetic_id = f"__invalid_input__{replay_ordinal:06d}"
        try:
            raw = canonical_json(raw_item)
        except (TypeError, ValueError):
            raw = canonical_json({"unsupported_type": type(raw_item).__module__ + "." + type(raw_item).__qualname__})
        item_sha = _digest(raw)
        prior = db.execute("SELECT item_sha256,status,ordinal FROM items WHERE item_id=?", (synthetic_id,)).fetchone()
        if prior:
            if prior[0] != item_sha:
                raise AuditError("BATCH_REPLAY_MISMATCH", "replayed invalid input differs from checkpoint")
            if prior[2] != replay_ordinal:
                raise AuditError("BATCH_ORDER_MISMATCH", "replayed invalid input order differs from checkpoint")
            replay_ordinal += 1
            return
        ordinal = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
        if ordinal != replay_ordinal:
            raise AuditError("BATCH_ORDER_MISMATCH", "invalid input arrived out of checkpoint order")
        _insert_item(db, synthetic_id, ordinal, item_sha, "REJECTED", None, reason_code)
        _insert_rejection(db, label, reason_code, synthetic_id)
        _flush(db)
        replay_ordinal += 1

    for item in items:
        if not isinstance(item, Mapping):
            rejected += 1
            record_invalid_item(item, "BATCH_ITEM_NOT_OBJECT", f"ordinal-{replay_ordinal}")
            continue
        item_id = item.get("item_id")
        result = item.get("audit_result")
        if not isinstance(item_id, str) or not _ID_RE.fullmatch(item_id):
            rejected += 1
            record_invalid_item(item, "BATCH_ITEM_ID_INVALID", str(item_id))
            continue
        item_sha = "UNKNOWN"
        try:
            raw = canonical_json(result)
            item_sha = _digest(raw)
            prior = db.execute("SELECT item_sha256,status,ordinal FROM items WHERE item_id=?", (item_id,)).fetchone()
            if prior:
                if prior[0] != item_sha:
                    raise AuditError("BATCH_REPLAY_MISMATCH", "replayed item differs from checkpoint")
                if prior[2] != replay_ordinal:
                    raise AuditError("BATCH_ORDER_MISMATCH", "replayed item order differs from checkpoint")
                replay_ordinal += 1
                if prior[1] == "PENDING":
                    if not _batch_fits(members, item_id, result):
                        if members and (not resume or replay_ordinal >= checkpoint_item_count):
                            commit_batch()
                    members.append((item_id, result))
                    pending_ids.append(item_id)
                    if len(members) >= batch_size and (not resume or replay_ordinal >= checkpoint_item_count):
                        commit_batch()
                continue
            if not isinstance(result, dict):
                raise AuditError("BATCH_INPUT_INVALID", "audit_result must be an object")
            if result.get("schema") != "pgop1.swebench.generalized-audit.v1":
                raise AuditError("BATCH_INPUT_INVALID", "audit_result schema is unsupported")
            if result.get("AUDIT_VERDICT") not in {"SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE",
                                                   "INTEGRITY_FAILURE", "VERIFICATION_ERROR"}:
                raise AuditError("BATCH_INPUT_INVALID", "audit_result verdict is unsupported")
            if not _source_refs(result):
                raise AuditError("BATCH_INPUT_INVALID", "audit_result has no committed source references")
            _validate_member_shape(item_id, result)
            if resume and replay_ordinal < checkpoint_item_count:
                raise AuditError("BATCH_REPLAY_TRUNCATED", "new item arrived before checkpoint replay was complete")
            if resume and members:
                commit_batch()
            ordinal = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
            if ordinal != replay_ordinal:
                raise AuditError("BATCH_ORDER_MISMATCH", "new item was inserted before earlier checkpoint items")
            if not _batch_fits(members, item_id, result):
                if members:
                    commit_batch()
                if not _batch_fits([], item_id, result):
                    raise AuditError("BATCH_MEMBER_TOO_LARGE", "member exceeds bridge batch bounds")
            _insert_item(db, item_id, ordinal, item_sha, "PENDING", None, "")
            _flush(db)
            members.append((item_id, result))
            pending_ids.append(item_id)
            next_item += 1
            replay_ordinal += 1
            if len(members) >= batch_size:
                commit_batch()
        except AuditError as exc:
            if committing or (members and item_id not in pending_ids):
                # A failed commit is a batch-level interruption, never an item rejection.
                raise
            rejected += 1
            reason_code = str(exc.code)[:128]
            # Preserve the rejection and its exact reason; do not retry it on resume.
            prior_item = db.execute("SELECT 1 FROM items WHERE item_id=?", (item_id,)).fetchone()
            if prior_item and reason_code in {"BATCH_REPLAY_MISMATCH", "BATCH_ORDER_MISMATCH"}:
                raise
            if not prior_item:
                ordinal = db.execute("SELECT COUNT(*) FROM items").fetchone()[0]
                _insert_item(db, item_id, ordinal, item_sha if 'item_sha' in locals() else "UNKNOWN",
                             "REJECTED", None, reason_code)
                _insert_rejection(db, item_id, reason_code, item_id)
                _flush(db)
                replay_ordinal += 1
    if resume and replay_ordinal < checkpoint_item_count:
        raise AuditError("BATCH_REPLAY_TRUNCATED", "resume stream ended before all checkpointed items were replayed")
    commit_batch()
    status = {row[0]: row[1] for row in db.execute("SELECT status,COUNT(*) FROM items GROUP BY status")}
    result = {"schema": SCHEMA, "status": "PASS", "batch_count": batch_ordinal,
              "completed_item_count": db.execute("SELECT COUNT(*) FROM items WHERE status='COMPLETE'").fetchone()[0],
              "rejected_item_count": db.execute("SELECT COUNT(*) FROM rejections").fetchone()[0],
              "rejections": [{"item_id": r[0], "reason_code": r[1]}
                             for r in db.execute("SELECT input_id,reason_code FROM rejections ORDER BY rejection_id")],
              "checkpoint": str(db_path), "item_status_counts": status,
              "dispatch": "NOT_PERFORMED", "redispatch": "NOT_PERFORMED",
              "authority": "ADVISORY_ENGINEERING_ONLY; NO_OP1_AUTHORITY_EFFECT"}
    db.close()
    return result


def recover_audit_stream(output_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Verify the append-only batch chain and each bridge using the existing recovery API."""
    root = Path(output_root).absolute()
    _check_no_reparse(root)
    if not root.is_dir():
        raise AuditError("BATCH_CHECKPOINT_MISSING", "batch output root does not exist")
    db_path = root / "batch-checkpoint.sqlite"
    _check_no_reparse(db_path)
    db = _db(db_path, create=False)
    previous = "0" * 64
    recovered = []
    batches = list(db.execute(
        "SELECT batch_id,ordinal,input_sha256,context_path,bridge_receipt_sha256,previous_sha256,checkpoint_sha256,status FROM batches ORDER BY ordinal"))
    known_contexts: set[str] = set()
    for batch_id, ordinal, input_sha, context_path, receipt_sha, parent, digest, status in batches:
        if batch_id != f"batch-{ordinal:06d}" or not _ID_RE.fullmatch(batch_id):
            raise AuditError("BATCH_CHECKPOINT_CHAIN_INVALID", "batch identity or ordinal is invalid")
        expected_context = root / batch_id
        saved_context = Path(context_path).absolute()
        if saved_context != expected_context:
            raise AuditError("BATCH_CONTEXT_PATH_INVALID", "saved batch context escapes its output root")
        _check_no_reparse(expected_context)
        known_contexts.add(batch_id)
        item_rows = list(db.execute(
            "SELECT item_id,item_sha256,status,batch_id FROM items WHERE batch_id=? ORDER BY ordinal", (batch_id,)))
        if not item_rows or any(row[2] != "COMPLETE" or row[3] != batch_id for row in item_rows):
            raise AuditError("BATCH_ITEM_STATUS_INVALID", "completed batch has incomplete or rebound item records")
        expected_input = _digest(canonical_json([{"item_id": row[0], "item_sha256": row[1]} for row in item_rows]))
        if expected_input != input_sha:
            raise AuditError("BATCH_INPUT_COMMITMENT_MISMATCH", "batch item commitments differ from completion record")
        payload = {"schema": SCHEMA, "batch_id": batch_id, "ordinal": ordinal,
                   "input_sha256": input_sha, "context_path": context_path,
                   "bridge_receipt_sha256": receipt_sha, "previous_sha256": parent,
                   "status": status}
        if parent != previous or _digest(canonical_json(payload)) != digest or status != "COMPLETE":
            raise AuditError("BATCH_CHECKPOINT_CHAIN_INVALID", "batch checkpoint chain verification failed")
        receipt_path = expected_context / "generalized-bridge-receipt.json"
        _check_no_reparse(receipt_path)
        if _digest(receipt_path.read_bytes()) != receipt_sha:
            raise AuditError("BATCH_RECEIPT_HASH_MISMATCH", "bridge receipt differs from checkpoint")
        bridge_status = recover_generalized_audit(expected_context)
        if bridge_status.get("status") != "PASS":
            raise AuditError("BATCH_BRIDGE_RECOVERY_FAILED", "existing bridge recovery did not pass")
        receipt = json.loads(receipt_path.read_bytes())
        engine = Engine(expected_context)
        try:
            capsule_raw = engine.read_source(receipt["capsule"]["source_id"])
            capsule = json.loads(capsule_raw)
        except (KeyError, TypeError, ValueError, OSError) as exc:
            raise AuditError("BATCH_MEMBER_CAPSULE_UNAVAILABLE", "immutable aggregate capsule is unavailable") from exc
        if canonical_json(capsule) != capsule_raw or not isinstance(capsule, dict):
            raise AuditError("BATCH_MEMBER_CAPSULE_INVALID", "aggregate capsule is not canonical JSON")
        aggregate = capsule.get("audit_result")
        capsule_members = aggregate.get("batch_members") if isinstance(aggregate, dict) else None
        if not isinstance(capsule_members, list):
            raise AuditError("BATCH_MEMBER_CAPSULE_INVALID", "aggregate capsule lacks original member results")
        expected_members = [(row[0], row[1]) for row in item_rows]
        actual_members: list[tuple[str, str]] = []
        for member in capsule_members:
            if (not isinstance(member, dict) or not isinstance(member.get("item_id"), str)
                    or not isinstance(member.get("audit_result"), dict)):
                raise AuditError("BATCH_MEMBER_CAPSULE_INVALID", "capsule member record is malformed")
            actual_hash = _digest(canonical_json(member["audit_result"]))
            if member.get("item_sha256") != actual_hash:
                raise AuditError("BATCH_MEMBER_HASH_MISMATCH", "capsule member body differs from its hash")
            actual_members.append((member["item_id"], actual_hash))
        if actual_members != expected_members:
            raise AuditError("BATCH_MEMBER_SET_MISMATCH", "capsule member results differ from checkpoint membership")
        recovered.append({**bridge_status, "original_member_results_verified": len(actual_members)})
        previous = digest
    item_previous = "0" * 64
    item_commitments = list(db.execute(
        "SELECT ordinal,item_id,item_sha256,previous_sha256,commitment_sha256 FROM item_commitments ORDER BY ordinal"))
    items = list(db.execute("SELECT item_id,ordinal,item_sha256,status,batch_id,detail FROM items ORDER BY ordinal"))
    if len(item_commitments) != len(items):
        raise AuditError("BATCH_ITEM_COMMITMENT_MISSING", "item commitment ledger is incomplete")
    known_items = {row[0]: row for row in items}
    for commitment, item in zip(item_commitments, items):
        ordinal, item_id, item_sha, item_parent, item_digest = commitment
        payload = {"ordinal": ordinal, "item_id": item_id, "item_sha256": item_sha,
                   "previous_sha256": item_parent}
        if (item_parent != item_previous or _digest(canonical_json(payload)) != item_digest
                or item != (item_id, ordinal, item_sha, item[3], item[4], item[5])):
            raise AuditError("BATCH_ITEM_COMMITMENT_MISMATCH", "item hash or commitment chain differs")
        if item[3] not in {"PENDING", "COMPLETE", "REJECTED"}:
            raise AuditError("BATCH_ITEM_STATUS_INVALID", "checkpoint item status is unsupported")
        if item[3] == "COMPLETE" and item[4] not in known_contexts:
            raise AuditError("BATCH_ITEM_STATUS_INVALID", "completed item references an unknown batch")
        item_previous = item_digest
    rejection_previous = "0" * 64
    rejection_rows = list(db.execute(
        "SELECT rejection_id,input_id,reason_code,item_ref,previous_sha256,entry_sha256 FROM rejections ORDER BY rejection_id"))
    rejected_by_item: dict[str, list[tuple[str, str]]] = {}
    for rejection_ordinal, row in enumerate(rejection_rows):
        _, input_id, reason_code, item_ref, parent, entry_hash = row
        payload = {"ordinal": rejection_ordinal, "input_id": input_id,
                   "reason_code": reason_code, "item_ref": item_ref,
                   "previous_sha256": parent}
        if parent != rejection_previous or _digest(canonical_json(payload)) != entry_hash:
            raise AuditError("BATCH_REJECTION_COMMITMENT_MISMATCH", "rejection ledger hash chain differs")
        rejected_by_item.setdefault(item_ref, []).append((reason_code, input_id))
        rejection_previous = entry_hash
    for item_id, item in known_items.items():
        matching = rejected_by_item.get(item_id, [])
        if item[3] == "REJECTED":
            if len(matching) != 1 or matching[0][0] != item[5]:
                raise AuditError("BATCH_REJECTION_ITEM_MISMATCH", "rejected item and rejection ledger differ")
        elif matching:
            raise AuditError("BATCH_REJECTION_ITEM_MISMATCH", "non-rejected item has a rejection record")
    orphan_dirs = {p.name for p in root.iterdir() if p.is_dir() and p.name.startswith("batch-")} - known_contexts
    if orphan_dirs:
        raise AuditError("BATCH_ORPHAN_CONTEXT", "uncheckpointed batch context exists")
    pending_count = sum(row[3] == "PENDING" for row in items)
    db.close()
    return {"schema": SCHEMA, "status": "PARTIAL" if pending_count else "PASS",
            "pending_item_count": pending_count, "recovered_batch_count": len(recovered),
            "original_member_results_verified": sum(row.get("original_member_results_verified", 0) for row in recovered),
            "batches": recovered, "adapter_rerun": "NOT_PERFORMED",
            "producer_redispatch": "NOT_PERFORMED", "authority": "ADVISORY_ENGINEERING_ONLY"}
