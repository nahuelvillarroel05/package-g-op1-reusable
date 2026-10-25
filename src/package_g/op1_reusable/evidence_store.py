"""I1 synthetic evidence/event publication over the immutable object store."""
from __future__ import annotations

from copy import deepcopy
from typing import Any, Mapping

from .append_only import AppendOnlyStore, FaultHook, ObjectExists, StoreError, utc_now
from .identity import canonical_json, generate_id, sha256_bytes, validate_id
from .storage_paths import Scope


class EvidenceError(StoreError):
    """Frozen evidence shape or I1 provenance law failed closed."""


class EvidenceStore(AppendOnlyStore):
    """Storage foundation only; does not admit operational SESSION or RUN state."""

    @staticmethod
    def _scope_dict(scope: Scope) -> dict[str, str]:
        return {"project_id": scope.project_id, **{field: entity for field, _, _, entity in scope.items()}}

    def _by_id(self) -> dict[str, dict[str, Any]]:
        return {row["object_id"]: row for row in self.manifest_rows()}

    def _assert_fresh(self, entity_id: str, *, artifact_id: str | None = None) -> None:
        rows = self.manifest_rows()
        if any(row["object_id"] == entity_id for row in rows):
            raise ObjectExists("immutable object ID already committed")
        if artifact_id is not None and any(row.get("artifact_id") == artifact_id or row["object_id"] == artifact_id for row in rows):
            raise ObjectExists("artifact ID already committed")

    def _validate_event(self, record: Mapping[str, Any], scope: Scope, role: str, sequence: int) -> dict[str, Any]:
        value = deepcopy(dict(record))
        value["committed_sequence"] = sequence
        entry = self.schemas.find_document("OP1_EVENT_SCHEMA.json")
        result = self.schemas.validate(entry.schema_id, entry.version, value)
        if not result.valid:
            raise EvidenceError("frozen event schema rejected: " + "; ".join(result.errors))
        identity = value["identity"]
        if identity["schema_id"] != entry.schema_id or identity["schema_version"] != entry.version:
            raise EvidenceError("event identity schema binding mismatch")
        if identity["entity_type"] != "EVENT" or identity["entity_id"] != value["event_id"]:
            raise EvidenceError("event identity mismatch")
        if value["event_role"] != role or value["actor_id"] != identity["actor_id"]:
            raise EvidenceError("event role or actor mismatch")
        if value["session_id"] != scope.session_id or value.get("run_id") != scope.run_id or value.get("attempt_id") != scope.attempt_id:
            raise EvidenceError("event scope mismatch")
        for field in ("project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id"):
            if identity.get(field) != getattr(scope, field):
                raise EvidenceError(f"event envelope {field} mismatch")
        if value["writer_authentication_ref"] != self.writer_authentication_ref:
            raise EvidenceError("event writer authentication reference mismatch")
        validate_id(value["event_id"], "EVENT")
        return value

    def _commit_event_locked(self, record: Mapping[str, Any], scope: Scope, role: str, fault: FaultHook | None) -> dict[str, Any]:
        sequence = len(self.manifest_rows()) + 1
        event = self._validate_event(record, scope, role, sequence)
        self._assert_fresh(event["event_id"])
        prior = self._by_id()
        for reference in event["parent_ids"] + event["caused_by_ids"]:
            if reference["entity_id"] == event["event_id"] or reference["entity_id"] not in prior:
                raise EvidenceError("event causal reference is not prior committed")
            if prior[reference["entity_id"]]["object_type"] != reference["entity_type"]:
                raise EvidenceError("event causal reference type mismatch")
        if role == "PUBLICATION":
            if not event["evidence_ids"]:
                raise EvidenceError("publication event must cite committed evidence")
            for evidence_id in event["evidence_ids"]:
                if evidence_id not in prior or prior[evidence_id]["object_type"] != "EVIDENCE":
                    raise EvidenceError("publication cites missing evidence")
        elif event["evidence_ids"]:
            raise EvidenceError("pre-publication event cannot cite evidence")
        self.paths.reserve_scope(scope, self._write_locator)
        rel = self.paths.object_relative(scope, "events", event["event_id"], "json")
        data = canonical_json(event)
        object_meta = self._publish_bytes(rel, data, phase="event", fault=fault)
        body = {
            "object_type": "EVENT", "object_id": event["event_id"],
            "object_relative_path": rel, "object_byte_length": object_meta["byte_length"],
            "object_sha256": object_meta["sha256"],
            "record_relative_path": rel, "record_byte_length": object_meta["byte_length"],
            "record_sha256": object_meta["sha256"],
            "scope": self._scope_dict(scope), "event_role": role,
            "actor_id": event["actor_id"], "referenced_evidence_ids": event["evidence_ids"],
        }
        manifest = self._append_manifest(event["actor_id"], body, fault=fault)
        return {"event_id": event["event_id"], "manifest": manifest, "record": event}

    def _write_locator(self, relative: str, row: dict[str, Any]) -> None:
        self._publish_bytes(relative, canonical_json(row), phase="locator")

    def commit_action_event(self, record: Mapping[str, Any], scope: Scope, *, fault: FaultHook | None = None) -> dict[str, Any]:
        if record.get("event_role") not in {"ROOT", "ACTION", "OBSERVATION"}:
            raise EvidenceError("only pre-evidence action roles accepted here")
        with self.writer():
            return self._commit_event_locked(record, scope, record["event_role"], fault)

    def _validate_evidence(
        self,
        record: Mapping[str, Any],
        content: bytes,
        scope: Scope,
        producer_kind: str,
        prior: Mapping[str, dict[str, Any]],
    ) -> dict[str, Any]:
        if not isinstance(content, bytes):
            raise EvidenceError("exact evidence bytes required")
        value = deepcopy(dict(record))
        entry = self.schemas.find_document("OP1_EVIDENCE_SCHEMA.json")
        result = self.schemas.validate(entry.schema_id, entry.version, value)
        if not result.valid:
            raise EvidenceError("frozen evidence schema rejected: " + "; ".join(result.errors))
        identity = value["identity"]
        if identity["schema_id"] != entry.schema_id or identity["schema_version"] != entry.version:
            raise EvidenceError("evidence identity schema binding mismatch")
        if identity["entity_type"] != "EVIDENCE" or identity["entity_id"] != value["evidence_id"]:
            raise EvidenceError("evidence identity mismatch")
        if identity["actor_id"] != value["actor_id"]:
            raise EvidenceError("evidence actor mismatch")
        for field in ("project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id"):
            if identity.get(field) != getattr(scope, field):
                raise EvidenceError(f"evidence envelope {field} mismatch")
        if value["run_id"] != scope.run_id or value["attempt_id"] != scope.attempt_id:
            raise EvidenceError("evidence run/attempt mismatch")
        digest = sha256_bytes(content)
        if value["sha256"] != digest or identity.get("content_sha256") != digest or value["byte_length"] != len(content):
            raise EvidenceError("evidence exact content digest/length mismatch")
        if producer_kind not in {"ACTOR", "TOOL"}:
            raise EvidenceError("explicit I1 producer kind required")
        tool_fields = ("tool_id" in value, "tool_invocation_id" in value)
        if producer_kind == "TOOL" and tool_fields != (True, True):
            raise EvidenceError("tool-produced bytes require tool and invocation IDs")
        if producer_kind == "ACTOR" and tool_fields != (False, False):
            raise EvidenceError("direct actor observation cannot claim tool fields")
        klass = "raw" if value["derivation_class"] == "RAW_IMMUTABLE" else "derived"
        expected_path = self.paths.object_relative(scope, klass, value["evidence_id"], "bin")
        if value["relative_path"] != expected_path:
            raise EvidenceError("evidence relative path does not equal typed scope path")
        action = prior.get(value["event_id"])
        if action is None or action["object_type"] != "EVENT" or action["event_role"] not in {"ROOT", "ACTION", "OBSERVATION"}:
            raise EvidenceError("evidence requires prior committed action event")
        if action["scope"] != self._scope_dict(scope):
            raise EvidenceError("causing event scope mismatch")
        sources = value.get("source_evidence_ids", [])
        if klass == "raw" and sources:
            raise EvidenceError("raw evidence cannot derive from other evidence")
        if klass == "derived":
            if not sources:
                raise EvidenceError("derived evidence requires raw source IDs")
            for source_id in sources:
                source = prior.get(source_id)
                if source is None or source["object_type"] != "EVIDENCE" or source["derivation_class"] != "RAW_IMMUTABLE":
                    raise EvidenceError("derived source is not prior committed raw evidence")
        for reference in identity.get("caused_by_ids", []):
            target = prior.get(reference["entity_id"])
            if target is None or target["object_type"] != reference["entity_type"] or reference["entity_id"] == value["evidence_id"]:
                raise EvidenceError("evidence correction cause is not prior committed")
        if value["evidence_class"] == "CORRECTION":
            if klass != "derived" or not any(ref["entity_type"] == "EVIDENCE" for ref in identity.get("caused_by_ids", [])):
                raise EvidenceError("correction requires derived bytes and prior evidence cause")
        return value

    def _publish_evidence_locked(
        self,
        record: Mapping[str, Any],
        content: bytes,
        publication_event: Mapping[str, Any],
        scope: Scope,
        *,
        producer_kind: str,
        fault: FaultHook | None = None,
    ) -> dict[str, Any]:
        """Commit raw/derived bytes, frozen record, manifest, then publication event."""
        prior = self._by_id()
        evidence = self._validate_evidence(record, content, scope, producer_kind, prior)
        evidence_id = evidence["evidence_id"]
        self._assert_fresh(evidence_id, artifact_id=evidence.get("artifact_id"))
        provisional_event = self._validate_event(publication_event, scope, "PUBLICATION", len(prior) + 2)
        if provisional_event["evidence_ids"] != [evidence_id]:
            raise EvidenceError("publication event must cite this exact evidence ID")
        if "artifact_id" in evidence and evidence["artifact_id"] not in provisional_event["produced_artifact_ids"]:
            raise EvidenceError("publication event omitted artifact ID")
        if provisional_event["event_id"] in prior or provisional_event["event_id"] == evidence_id:
            raise ObjectExists("publication event ID already committed")
        self.paths.reserve_scope(scope, self._write_locator)
        rel = evidence["relative_path"]
        blob = self._publish_bytes(rel, content, phase="evidence_blob", fault=fault)
        self._fault(fault, "evidence.after_blob", self.root / rel)
        record_rel = f"records/evidence/{evidence_id}.json"
        record_bytes = canonical_json(evidence)
        record_meta = self._publish_bytes(record_rel, record_bytes, phase="evidence_record", fault=fault)
        self._fault(fault, "evidence.after_record", self.root / record_rel)
        body = {
            "object_type": "EVIDENCE", "object_id": evidence_id,
            "artifact_id": evidence.get("artifact_id"),
            "object_relative_path": rel, "object_byte_length": blob["byte_length"],
            "object_sha256": blob["sha256"],
            "record_relative_path": record_rel,
            "record_byte_length": record_meta["byte_length"], "record_sha256": record_meta["sha256"],
            "scope": self._scope_dict(scope), "event_id": evidence["event_id"],
            "actor_id": evidence["actor_id"], "producer_kind": producer_kind,
            "evidence_class": evidence["evidence_class"],
            "derivation_class": evidence["derivation_class"],
            "source_evidence_ids": evidence.get("source_evidence_ids", []),
        }
        manifest = self._append_manifest(evidence["actor_id"], body, fault=fault)
        self._fault(fault, "evidence.after_manifest", self.root / manifest["relative_path"])
        publication = self._commit_event_locked(publication_event, scope, "PUBLICATION", fault)
        self._fault(fault, "evidence.after_ack", self.root / publication["manifest"]["relative_path"])
        return {"evidence_id": evidence_id, "manifest": manifest, "publication_event_id": publication["event_id"], "publication_manifest": publication["manifest"]}

    def publish_evidence(
        self,
        record: Mapping[str, Any],
        content: bytes,
        publication_event: Mapping[str, Any],
        scope: Scope,
        *,
        producer_kind: str,
        fault: FaultHook | None = None,
    ) -> dict[str, Any]:
        """Commit one evidence publication under its own integrity-checked writer lock."""
        with self.writer():
            return self._publish_evidence_locked(
                record, content, publication_event, scope,
                producer_kind=producer_kind, fault=fault,
            )

    def publish_evidence_batch(
        self,
        entries: list[tuple[Mapping[str, Any], Mapping[str, Any], bytes, Mapping[str, Any]]],
        scope: Scope,
        *,
        producer_kind: str,
        fault: FaultHook | None = None,
    ) -> list[dict[str, Any]]:
        """Commit ordered ACTION/evidence/PUBLICATION triples under one writer lock.

        Each triple retains its own immutable objects and signed manifests. A failed
        batch has no success acknowledgement; the committed prefix stays immutable.
        """
        if not entries:
            raise EvidenceError("empty evidence batch")
        with self.writer() as lock_handle:
            receipts = []
            for action, evidence, content, publication in entries:
                if action.get("event_role") != "ACTION":
                    raise EvidenceError("batch requires an ACTION before each evidence")
                self._commit_event_locked(action, scope, "ACTION", fault)
                receipts.append(self._publish_evidence_locked(
                    evidence, content, publication, scope,
                    producer_kind=producer_kind, fault=fault,
                ))
            from .integrity import IntegrityVerifier
            verified = IntegrityVerifier(self.root).verify(
                _held_writer_lock_handle=lock_handle,
            )
            if verified["result"] != "PASS":
                raise EvidenceError("post-batch store integrity failed")
            return receipts

    def commit_synthetic_closure(
        self,
        scope: Scope,
        outcome: str,
        evidence_ids: list[str],
        expected_classes: list[str],
        *,
        fault: FaultHook | None = None,
    ) -> dict[str, Any]:
        """I1 fixture status only; never transitions an operational RUN."""
        if outcome not in {"FAIL", "BLOCKED", "PASS"} or not evidence_ids:
            raise EvidenceError("synthetic closure outcome/evidence invalid")
        with self.writer():
            prior = self._by_id()
            if any(row.get("closure_outcome") is not None and row["scope"]["run_id"] == scope.run_id for row in prior.values()):
                raise ObjectExists("synthetic RUN closure already committed")
            for evidence_id in evidence_ids:
                row = prior.get(evidence_id)
                if row is None or row["object_type"] != "EVIDENCE" or row["scope"] != self._scope_dict(scope):
                    raise EvidenceError("closure evidence missing or wrong scope")
                if not any(item["object_type"] == "EVENT" and item.get("event_role") == "PUBLICATION" and evidence_id in item["referenced_evidence_ids"] for item in prior.values()):
                    raise EvidenceError("closure evidence publication event missing")
            actual_classes = {prior[item]["evidence_class"] for item in evidence_ids}
            if not set(expected_classes) <= actual_classes:
                raise EvidenceError("required evidence class missing; INCOMPLETE_EVIDENCE")
            closure_id = generate_id("ARTIFACT")
            self._assert_fresh(closure_id)
            chain = self._manifest_chain()
            closure = {
                "identity": self._envelope(closure_id, "ARTIFACT", self.actor_id),
                "closure_id": closure_id, "session_id": scope.session_id,
                "run_id": scope.run_id, "attempt_id": scope.attempt_id,
                "outcome": outcome, "evidence_ids": evidence_ids,
                "expected_evidence_classes": expected_classes,
                "prior_manifest_sequence": len(chain),
                "prior_manifest_sha256": sha256_bytes(chain[-1][1]) if chain else None,
                "created_at_utc": utc_now(),
                "mode": "SYNTHETIC_I1_STORAGE_PROOF_ONLY",
            }
            rel = self.paths.object_relative(scope, "closures", closure_id, "json")
            data = canonical_json(closure)
            meta = self._publish_bytes(rel, data, phase="closure", fault=fault)
            body = {
                "object_type": "ARTIFACT", "object_id": closure_id,
                "object_relative_path": rel, "object_byte_length": meta["byte_length"], "object_sha256": meta["sha256"],
                "record_relative_path": rel, "record_byte_length": meta["byte_length"], "record_sha256": meta["sha256"],
                "scope": self._scope_dict(scope), "actor_id": self.actor_id,
                "closure_outcome": outcome, "closure_evidence_ids": evidence_ids,
            }
            manifest = self._append_manifest(self.actor_id, body, fault=fault)
            return {"closure_id": closure_id, "manifest": manifest, "record": closure}