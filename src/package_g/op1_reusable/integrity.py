"""Read-only I1 synthetic integrity verification; never repairs store bytes."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .identity import canonical_json, sha256_bytes, strict_json_loads, validate_id, validate_sha256
from . import native_ntfs
from .schema_registry import SchemaRegistry
from .storage_paths import Scope, StoragePaths

_MANIFEST = re.compile(r"([0-9]{12})-(PG-ART-[0-9a-f]{32})\.json\Z")


def checkpoint_payload(store_id: str, lineage_id: str, sequence: int, manifest_sha256: str | None) -> bytes:
    validate_id(store_id, "RESOURCE")
    validate_id(lineage_id, "LINEAGE")
    if not isinstance(sequence, int) or sequence < 0 or isinstance(sequence, bool):
        raise ValueError("invalid checkpoint sequence")
    if (sequence == 0) != (manifest_sha256 is None):
        raise ValueError("checkpoint sequence/hash mismatch")
    if manifest_sha256 is not None:
        validate_sha256(manifest_sha256)
    return canonical_json({
        "store_id": store_id, "lineage_id": lineage_id,
        "sequence": sequence, "manifest_sha256": manifest_sha256,
    })


class IntegrityVerifier:
    """Checks immutable objects and external checkpoint pins without writing."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.schemas = SchemaRegistry()
        self.identity_schema = self.schemas.find_document("OP1_IDENTITY_ENVELOPE_SCHEMA.json")
        self.event_schema = self.schemas.find_document("OP1_EVENT_SCHEMA.json")
        self.evidence_schema = self.schemas.find_document("OP1_EVIDENCE_SCHEMA.json")

    def _read(self, paths: StoragePaths, relative: str) -> bytes:
        path = paths.checked_path(relative, require_existing=True)
        with paths.guard_paths(path) as pins:
            return native_ntfs.read_file(pins.handle_for(path.parent), path.name)

    @staticmethod
    def _files_under(paths: StoragePaths, root: Path) -> tuple[Path, ...]:
        found = []
        pending = [root]
        while pending:
            current = pending.pop()
            try:
                with paths.guard_paths(current / "_scan_") as pins:
                    for name, attributes in native_ntfs.list_directory(pins.handle_for(current)):
                        child = current / name
                        if attributes & 0x400:
                            raise ValueError(f"reparse in store scan: {child}")
                        if attributes & 0x10:
                            pending.append(child)
                        else:
                            found.append(child)
            except FileNotFoundError:
                if current == root:
                    return ()
                raise
        return tuple(sorted(found, key=lambda path: str(path).casefold()))

    def verify(
        self,
        *,
        trusted_checkpoint: Mapping[str, Any] | None = None,
        trusted_checkpoint_public_key_hex: str | None = None,
        _held_writer_lock_handle: Any | None = None,
    ) -> dict[str, Any]:
        findings: list[dict[str, str]] = []
        def fail(code: str, detail: str) -> None:
            findings.append({"code": code, "detail": detail})
        try:
            paths = StoragePaths(self.root)
            header_raw = self._read(paths, "store_header.json")
            header = strict_json_loads(header_raw)
            if header_raw != canonical_json(header):
                fail("STORE_HEADER_CANONICAL", "store_header.json")
            store_id = validate_id(header["store_id"], "RESOURCE")
            lineage_id = validate_id(header["lineage_id"], "LINEAGE")
            if header.get("mode") not in {"SYNTHETIC_I1_NONAUTHORITATIVE", "I3_NATIVE_ENGINEERING_NONAUTHORITATIVE"}:
                fail("STORE_MODE", "header mode is not a bound nonauthoritative evidence mode")
            identity = header["identity"]
            if identity["entity_id"] != store_id or identity["entity_type"] != "RESOURCE":
                fail("STORE_IDENTITY", "header identity does not bind store")
            if not self.schemas.validate(self.identity_schema.schema_id, self.identity_schema.version, identity).valid:
                fail("STORE_IDENTITY", "header envelope schema rejected")
            writer_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(header["writer_public_key_hex"]))
            writer_ref = sha256_bytes(bytes.fromhex(header["writer_public_key_hex"]))
            if _held_writer_lock_handle is None:
                lock_bytes = self._read(paths, "writer.lock")
            else:
                _held_writer_lock_handle.seek(0)
                lock_bytes = _held_writer_lock_handle.read()
                _held_writer_lock_handle.seek(0)
            if lock_bytes != bytes(1):
                fail("WRITER_LOCK", "lock machinery changed")
            manifest_paths = self._files_under(paths, paths.root / "manifests")
            rows: list[dict[str, Any]] = []
            prior_hash = None
            seen_ids: set[str] = set()
            seen_paths: set[str] = set()
            seen_artifact_ids: set[str] = set()
            expected_files = {
                paths.root / "store_header.json", paths.root / "writer.lock",
            }
            expected_locators: dict[str, dict[str, Any]] = {}
            published: dict[str, int] = {}
            evidence_rows: dict[str, dict[str, Any]] = {}
            prior_rows: dict[str, dict[str, Any]] = {}
            closure_runs: set[str] = set()
            for index, manifest_path in enumerate(manifest_paths, 1):
                relative_manifest = manifest_path.relative_to(paths.root).as_posix()
                match = _MANIFEST.fullmatch(manifest_path.name)
                if match is None or int(match.group(1)) != index:
                    fail("MANIFEST_SEQUENCE", relative_manifest)
                    continue
                try:
                    raw = self._read(paths, relative_manifest)
                    row = strict_json_loads(raw)
                    if raw != canonical_json(row):
                        fail("MANIFEST_CANONICAL", relative_manifest)
                    if row.get("sequence") != index or row.get("previous_manifest_sha256") != prior_hash:
                        fail("MANIFEST_CHAIN", relative_manifest)
                    if row.get("store_id") != store_id or row.get("manifest_id") != match.group(2):
                        fail("MANIFEST_BINDING", relative_manifest)
                    signed = dict(row)
                    signature = bytes.fromhex(signed.pop("writer_signature_hex"))
                    writer_key.verify(signature, canonical_json(signed))
                    manifest_identity = row["identity"]
                    if manifest_identity["entity_type"] != "ARTIFACT" or manifest_identity["entity_id"] != row["manifest_id"]:
                        fail("MANIFEST_IDENTITY", relative_manifest)
                    if not self.schemas.validate(self.identity_schema.schema_id, self.identity_schema.version, manifest_identity).valid:
                        fail("MANIFEST_IDENTITY", relative_manifest)
                    validate_id(row["object_id"])
                    if row["object_id"] in seen_ids:
                        fail("DUPLICATE_ID", row["object_id"])
                    seen_ids.add(row["object_id"])
                    if row["object_relative_path"].casefold() in seen_paths:
                        fail("DUPLICATE_PATH", row["object_relative_path"])
                    seen_paths.add(row["object_relative_path"].casefold())
                    if row.get("artifact_id") is not None:
                        validate_id(row["artifact_id"], "ARTIFACT")
                        if row["artifact_id"] in seen_artifact_ids:
                            fail("DUPLICATE_ARTIFACT", row["artifact_id"])
                        seen_artifact_ids.add(row["artifact_id"])
                    scope = Scope(**row["scope"])
                    if scope.lineage_id != lineage_id:
                        fail("STORE_LINEAGE", row["object_id"])
                    if row["identity"].get("actor_id") != row.get("actor_id"):
                        fail("MANIFEST_ACTOR", row["object_id"])
                    for locator in paths.expected_locator_rows(scope):
                        previous = expected_locators.get(locator["relative_path"])
                        if previous is not None and previous != locator:
                            fail("LOCATOR_COLLISION", locator["relative_path"])
                        expected_locators[locator["relative_path"]] = locator
                    object_raw = self._read(paths, row["object_relative_path"])
                    if len(object_raw) != row["object_byte_length"] or sha256_bytes(object_raw) != row["object_sha256"]:
                        fail("OBJECT_MUTATION", row["object_relative_path"])
                    object_path = paths.root / row["object_relative_path"]
                    expected_files.add(object_path)
                    record_raw = self._read(paths, row["record_relative_path"])
                    if len(record_raw) != row["record_byte_length"] or sha256_bytes(record_raw) != row["record_sha256"]:
                        fail("RECORD_MUTATION", row["record_relative_path"])
                    expected_files.add(paths.root / row["record_relative_path"])
                    if row["object_type"] == "EVENT":
                        expected_rel = paths.object_relative(scope, "events", row["object_id"], "json")
                        if row["object_relative_path"] != expected_rel or row["record_relative_path"] != expected_rel:
                            fail("EVENT_PATH", row["object_id"])
                        event = strict_json_loads(record_raw)
                        if not self.schemas.validate(self.event_schema.schema_id, self.event_schema.version, event).valid:
                            fail("EVENT_SCHEMA", row["object_id"])
                        if event["identity"]["schema_id"] != self.event_schema.schema_id or event["event_id"] != row["object_id"] or event["identity"]["entity_id"] != row["object_id"]:
                            fail("EVENT_IDENTITY", row["object_id"])
                        if event["identity"].get("schema_version") != self.event_schema.version or event["identity"].get("entity_type") != "EVENT" or event["actor_id"] != row.get("actor_id") or event["identity"].get("actor_id") != event["actor_id"]:
                            fail("EVENT_ACTOR_SCHEMA", row["object_id"])
                        for field in ("project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id"):
                            if event["identity"].get(field) != getattr(scope, field):
                                fail("EVENT_ENVELOPE_SCOPE", row["object_id"])
                        if event["committed_sequence"] != index or event["writer_authentication_ref"] != writer_ref:
                            fail("EVENT_SEQUENCE_AUTH", row["object_id"])
                        if event["session_id"] != scope.session_id or event.get("run_id") != scope.run_id or event.get("attempt_id") != scope.attempt_id:
                            fail("EVENT_SCOPE", row["object_id"])
                        if event["event_role"] != row.get("event_role"):
                            fail("EVENT_ROLE", row["object_id"])
                        if event["evidence_ids"] != row.get("referenced_evidence_ids"):
                            fail("EVENT_MANIFEST_REFERENCES", row["object_id"])
                        for reference in event["parent_ids"] + event["caused_by_ids"]:
                            target = prior_rows.get(reference["entity_id"])
                            if target is None or target["object_type"] != reference["entity_type"] or reference["entity_id"] == event["event_id"]:
                                fail("EVENT_CAUSAL_REFERENCE", row["object_id"])
                        if event["event_role"] == "PUBLICATION":
                            for evidence_id in event["evidence_ids"]:
                                source = evidence_rows.get(evidence_id)
                                if source is None or source["scope"] != row["scope"]:
                                    fail("FORWARD_PUBLICATION", evidence_id)
                                elif source.get("artifact_id") is not None and source["artifact_id"] not in event["produced_artifact_ids"]:
                                    fail("PUBLICATION_ARTIFACT", evidence_id)
                                published[evidence_id] = published.get(evidence_id, 0) + 1
                        elif event["evidence_ids"]:
                            fail("PREPUBLICATION_EVIDENCE", row["object_id"])
                    elif row["object_type"] == "EVIDENCE":
                        record = strict_json_loads(record_raw)
                        if not self.schemas.validate(self.evidence_schema.schema_id, self.evidence_schema.version, record).valid:
                            fail("EVIDENCE_SCHEMA", row["object_id"])
                        klass = "raw" if record["derivation_class"] == "RAW_IMMUTABLE" else "derived"
                        expected_rel = paths.object_relative(scope, klass, row["object_id"], "bin")
                        if row["object_relative_path"] != expected_rel or record["relative_path"] != expected_rel:
                            fail("EVIDENCE_PATH", row["object_id"])
                        if row["record_relative_path"] != f"records/evidence/{row['object_id']}.json":
                            fail("EVIDENCE_RECORD_PATH", row["object_id"])
                        if record["evidence_id"] != row["object_id"] or record["identity"]["entity_id"] != row["object_id"] or record["identity"]["schema_id"] != self.evidence_schema.schema_id:
                            fail("EVIDENCE_IDENTITY", row["object_id"])
                        if record["identity"].get("schema_version") != self.evidence_schema.version or record["identity"].get("entity_type") != "EVIDENCE" or record["actor_id"] != row.get("actor_id") or record["identity"].get("actor_id") != record["actor_id"]:
                            fail("EVIDENCE_ACTOR_SCHEMA", row["object_id"])
                        for field in ("project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id"):
                            if record["identity"].get(field) != getattr(scope, field):
                                fail("EVIDENCE_ENVELOPE_SCOPE", row["object_id"])
                        if record["run_id"] != scope.run_id or record["attempt_id"] != scope.attempt_id:
                            fail("EVIDENCE_SCOPE", row["object_id"])
                        if record["identity"]["content_sha256"] != row["object_sha256"] or record["sha256"] != row["object_sha256"] or record["byte_length"] != row["object_byte_length"]:
                            fail("EVIDENCE_BYTES", row["object_id"])
                        cause = prior_rows.get(record["event_id"])
                        if cause is None or cause["object_type"] != "EVENT" or cause.get("event_role") not in {"ROOT", "ACTION", "OBSERVATION"} or cause["scope"] != row["scope"]:
                            fail("MISSING_CAUSE_EVENT", row["object_id"])
                        if row["event_id"] != record["event_id"] or row["derivation_class"] != record["derivation_class"] or row["evidence_class"] != record["evidence_class"]:
                            fail("EVIDENCE_MANIFEST", row["object_id"])
                        if row.get("artifact_id") != record.get("artifact_id"):
                            fail("ARTIFACT_BINDING", row["object_id"])
                        if row["producer_kind"] == "TOOL" and not ("tool_id" in record and "tool_invocation_id" in record):
                            fail("TOOL_PROVENANCE", row["object_id"])
                        if row["producer_kind"] == "ACTOR" and ("tool_id" in record or "tool_invocation_id" in record):
                            fail("ACTOR_PROVENANCE", row["object_id"])
                        sources = record.get("source_evidence_ids", [])
                        if sources != row.get("source_evidence_ids"):
                            fail("SOURCE_MANIFEST_MISMATCH", row["object_id"])
                        for reference in record["identity"].get("caused_by_ids", []):
                            target = prior_rows.get(reference["entity_id"])
                            if target is None or target["object_type"] != reference["entity_type"] or reference["entity_id"] == record["evidence_id"]:
                                fail("EVIDENCE_CAUSAL_REFERENCE", row["object_id"])
                        if record["evidence_class"] == "CORRECTION" and (record["derivation_class"] != "DERIVED_IMMUTABLE" or not any(ref["entity_type"] == "EVIDENCE" for ref in record["identity"].get("caused_by_ids", []))):
                            fail("CORRECTION_CAUSE", row["object_id"])
                        if record["derivation_class"] == "RAW_IMMUTABLE" and sources:
                            fail("RAW_HAS_SOURCES", row["object_id"])
                        if record["derivation_class"] == "DERIVED_IMMUTABLE":
                            if not sources:
                                fail("DERIVED_NO_SOURCES", row["object_id"])
                            for source_id in sources:
                                source = evidence_rows.get(source_id)
                                if source is None or source["derivation_class"] != "RAW_IMMUTABLE":
                                    fail("DERIVED_SOURCE", source_id)
                        evidence_rows[row["object_id"]] = row
                    elif row["object_type"] == "ARTIFACT" and row.get("closure_outcome"):
                        expected_rel = paths.object_relative(scope, "closures", row["object_id"], "json")
                        if row["object_relative_path"] != expected_rel or row["record_relative_path"] != expected_rel:
                            fail("CLOSURE_PATH", row["object_id"])
                        closure = strict_json_loads(record_raw)
                        if closure["identity"]["entity_id"] != row["object_id"] or closure["identity"]["entity_type"] != "ARTIFACT" or not self.schemas.validate(self.identity_schema.schema_id, self.identity_schema.version, closure["identity"]).valid:
                            fail("CLOSURE_ENVELOPE", row["object_id"])
                        if closure["closure_id"] != row["object_id"] or closure["run_id"] != scope.run_id or closure["attempt_id"] != scope.attempt_id:
                            fail("CLOSURE_IDENTITY", row["object_id"])
                        if closure["session_id"] != scope.session_id or closure["identity"].get("actor_id") != row.get("actor_id") or closure["evidence_ids"] != row.get("closure_evidence_ids"):
                            fail("CLOSURE_SCOPE_MANIFEST", row["object_id"])
                        if closure["outcome"] != row["closure_outcome"] or closure["outcome"] not in {"FAIL", "BLOCKED", "PASS"}:
                            fail("CLOSURE_OUTCOME", row["object_id"])
                        if closure["prior_manifest_sequence"] != index - 1 or closure["prior_manifest_sha256"] != prior_hash:
                            fail("CLOSURE_CHAIN", row["object_id"])
                        if scope.run_id in closure_runs:
                            fail("DUPLICATE_RUN_CLOSURE", scope.run_id)
                        closure_runs.add(scope.run_id)
                        classes = set()
                        for evidence_id in closure["evidence_ids"]:
                            source = evidence_rows.get(evidence_id)
                            if source is None or published.get(evidence_id) != 1:
                                fail("CLOSURE_MISSING_EVIDENCE", evidence_id)
                            elif source["scope"] != row["scope"]:
                                fail("CLOSURE_SCOPE", evidence_id)
                            else:
                                classes.add(source["evidence_class"])
                        if not set(closure["expected_evidence_classes"]) <= classes:
                            fail("INCOMPLETE_EVIDENCE", scope.run_id)
                    else:
                        fail("UNKNOWN_OBJECT_CLASS", row["object_id"])
                    rows.append(row)
                    prior_rows[row["object_id"]] = row
                    expected_files.add(manifest_path)
                    prior_hash = sha256_bytes(raw)
                except (OSError, ValueError, KeyError, TypeError, AttributeError, InvalidSignature, IndexError) as exc:
                    fail("MANIFEST_OR_OBJECT_INVALID", f"{relative_manifest}: {type(exc).__name__}: {exc}")
            for evidence_id in evidence_rows:
                if published.get(evidence_id) != 1:
                    fail("UNPUBLISHED_EVIDENCE", evidence_id)
            for relative, expected in expected_locators.items():
                try:
                    raw = self._read(paths, relative)
                    if raw != canonical_json(expected):
                        fail("LOCATOR_MUTATION", relative)
                    expected_files.add(paths.root / relative)
                except (OSError, ValueError, KeyError) as exc:
                    fail("LOCATOR_MISSING_OR_INVALID", f"{relative}: {exc}")
            for area in ("h", "records", "manifests", "registry", "staging"):
                for path in self._files_under(paths, paths.root / area):
                    if path not in expected_files:
                        fail("EXTRA_OR_PARTIAL", path.relative_to(paths.root).as_posix())
            allowed_roots = {"h", "records", "manifests", "registry", "staging", "store_header.json", "writer.lock"}
            with paths.guard_paths(paths.root / "_scan_") as pins:
                for name, attributes in native_ntfs.list_directory(pins.handle_for(paths.root)):
                    if attributes & 0x400:
                        fail("REPARSE_ROOT_ENTRY", name)
                    if name not in allowed_roots:
                        fail("FOREIGN_ROOT_ENTRY", name)
            checkpoint_status = "NOT_PROVIDED"
            if trusted_checkpoint is not None:
                checkpoint_status = "INVALID"
                if trusted_checkpoint_public_key_hex is None:
                    fail("CHECKPOINT_TRUST", "trusted public key not supplied externally")
                else:
                    payload = trusted_checkpoint["payload"]
                    signature = bytes.fromhex(trusted_checkpoint["signature_hex"])
                    trusted_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_checkpoint_public_key_hex))
                    trusted_key.verify(signature, checkpoint_payload(payload["store_id"], payload["lineage_id"], payload["sequence"], payload["manifest_sha256"]))
                    if payload != {"store_id": store_id, "lineage_id": lineage_id, "sequence": len(rows), "manifest_sha256": prior_hash}:
                        fail("CHECKPOINT_ROLLBACK_OR_MISMATCH", "trusted latest sequence/root differs")
                    else:
                        checkpoint_status = "VERIFIED"
            return {
                "result": "PASS" if not findings else "FAIL",
                "findings": sorted(findings, key=lambda item: (item["code"], item["detail"])),
                "store_id": store_id, "lineage_id": lineage_id,
                "manifest_count": len(rows), "object_count": len(seen_ids),
                "manifest_root_sha256": prior_hash,
                "checkpoint_status": checkpoint_status,
                "operational_admission": False,
                "checkpoint_custody_qualified": False,
            }
        except (OSError, ValueError, KeyError, TypeError, AttributeError, InvalidSignature, IndexError) as exc:
            fail("STORE_INVALID", f"{type(exc).__name__}: {exc}")
            return {
                "result": "FAIL", "findings": sorted(findings, key=lambda item: (item["code"], item["detail"])),
                "store_id": None, "lineage_id": None, "manifest_count": 0,
                "object_count": 0, "manifest_root_sha256": None,
                "checkpoint_status": "INVALID", "operational_admission": False,
                "checkpoint_custody_qualified": False,
            }
