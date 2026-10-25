"""I2 synthetic control journal on the unchanged I1 evidence publication API.

I1 PUBLICATION is the domain commit marker. A preceding ACTION or raw blob is
not authority. The sidecar lock coordinates I2 clients; all durable records
remain in the I1 signed, append-only store.
"""
from __future__ import annotations

import msvcrt
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .append_only import utc_now
from .evidence_store import EvidenceStore
from .i2_contract import I2ContractError, RUN_MACHINE
from .identity import canonical_json, generate_id, sha256_bytes, strict_json_loads, validate_id
from .integrity import IntegrityVerifier
from .storage_paths import Scope, check_ancestors, is_reparse


@dataclass(frozen=True)
class JournalRecord:
    payload: dict[str, Any]
    evidence_id: str
    event_id: str
    sequence: int
    scope: Scope


class I2Journal:
    """Synthetic I2 log. The caller supplies an I1 writer and external custody."""
    def __init__(self, store: EvidenceStore, *,
                 fault_hook: Callable[[str, str], None] | None = None) -> None:
        self.store = store
        self.fault_hook = fault_hook
        self._history_lock = threading.RLock()
        self._frontier_sequence = store._observed_sequence
        self._frontier_sha256 = store._observed_manifest_sha256
        self.lock_path = store.root.parent / ("." + store.root.name + ".i2-serial.lock")
        check_ancestors(self.lock_path, include_final=False)
        try:
            with self.lock_path.open("xb") as handle:
                handle.write(b"\x00")
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            if is_reparse(self.lock_path) or self.lock_path.read_bytes() != b"\x00":
                raise I2ContractError("I2 serialization lock invalid")

    def _fault(self, kind: str, stage: str) -> None:
        if self.fault_hook is not None:
            self.fault_hook(kind, stage)

    @contextmanager
    def serialized(self):
        """Process-safe boundary for replay, validation, publication, and readback."""
        check_ancestors(self.lock_path)
        with self.lock_path.open("r+b") as handle:
            deadline = time.monotonic() + 10
            while True:
                handle.seek(0)
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise I2ContractError("I2 serialization lock uncertain")
                    time.sleep(0.025)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

    def _event(self, scope: Scope, event_id: str, role: str, digest: str,
               evidence_ids: list[str], caused_by: list[dict[str, str]]) -> dict[str, Any]:
        entry = self.store.schemas.find_document("OP1_EVENT_SCHEMA.json")
        actor = self.store.actor_id
        identity = {
            "entity_id": event_id, "entity_type": "EVENT",
            "schema_id": entry.schema_id, "schema_version": entry.version,
            "actor_id": actor, "created_at_utc": utc_now(), "status": "COMMITTED",
            **{field: getattr(scope, field) for field in (
                "project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id")},
        }
        return {
            "identity": identity, "event_id": event_id, "event_kind": "I2_" + role,
            "session_id": scope.session_id, "run_id": scope.run_id,
            "attempt_id": scope.attempt_id, "actor_id": actor,
            "occurred_at_utc": utc_now(), "committed_sequence": 1,
            "parent_ids": [], "caused_by_ids": caused_by,
            "payload_sha256": digest, "produced_artifact_ids": [],
            "produced_finding_ids": [], "resolved_finding_ids": [],
            "triggered_decision_ids": [], "evidence_ids": evidence_ids,
            "writer_authentication_ref": self.store.writer_authentication_ref,
            "event_role": role,
        }

    def _evidence(self, scope: Scope, evidence_id: str, action_id: str,
                  content: bytes) -> dict[str, Any]:
        entry = self.store.schemas.find_document("OP1_EVIDENCE_SCHEMA.json")
        actor = self.store.actor_id
        identity = {
            "entity_id": evidence_id, "entity_type": "EVIDENCE",
            "schema_id": entry.schema_id, "schema_version": entry.version,
            "actor_id": actor, "created_at_utc": utc_now(), "status": "COMMITTED",
            "content_sha256": sha256_bytes(content),
            **{field: getattr(scope, field) for field in (
                "project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id")},
        }
        return {
            "identity": identity, "evidence_id": evidence_id,
            "run_id": scope.run_id, "event_id": action_id, "actor_id": actor,
            "relative_path": self.store.paths.object_relative(scope, "raw", evidence_id, "bin"),
            "byte_length": len(content), "sha256": sha256_bytes(content),
            "producer": "I2 synthetic control journal", "created_at_utc": utc_now(),
            "evidence_class": "I2_CONTROL", "derivation_class": "RAW_IMMUTABLE",
            "attempt_id": scope.attempt_id,
        }

    def _verified_rows(self) -> tuple[dict[str, Any], ...]:
        """Read one healthy I1 chain without allowing an observed prefix to roll back."""
        with self._history_lock:
            verdict = IntegrityVerifier(self.store.root).verify()
            if verdict["result"] != "PASS":
                raise I2ContractError("I1 evidence store unhealthy")
            chain = self.store._manifest_chain()
            if (len(chain) != verdict["manifest_count"]
                    or chain and sha256_bytes(chain[-1][1]) != verdict["manifest_root_sha256"]):
                raise I2ContractError("I1 evidence store changed during history read")
            for sequence, digest in (
                (self._frontier_sequence, self._frontier_sha256),
                (self.store._observed_sequence, self.store._observed_manifest_sha256),
            ):
                if (len(chain) < sequence
                        or sequence and sha256_bytes(chain[sequence - 1][1]) != digest):
                    raise I2ContractError("I1 observed manifest prefix rolled back")
            self._frontier_sequence = len(chain)
            self._frontier_sha256 = sha256_bytes(chain[-1][1]) if chain else None
            return tuple(row for row, _ in chain)

    def history(self) -> tuple[JournalRecord, ...]:
        rows = self._verified_rows()
        publications = {
            evidence_id: row
            for row in rows if row["object_type"] == "EVENT" and row.get("event_role") == "PUBLICATION"
            for evidence_id in row.get("referenced_evidence_ids", [])
        }
        records = []
        for row in rows:
            if row["object_type"] != "EVIDENCE" or row.get("evidence_class") != "I2_CONTROL":
                continue
            evidence_id = row["object_id"]
            publication = publications.get(evidence_id)
            if publication is None:
                raise I2ContractError("unpublished I2 control evidence")
            raw = self.store._readback(self.store.paths.checked_path(
                row["object_relative_path"], require_existing=True))
            payload = strict_json_loads(raw)
            if not isinstance(payload, dict):
                raise I2ContractError("I2 control payload is not an object")
            if payload.get("event_id") != publication["object_id"] or payload.get("evidence_id") != evidence_id:
                raise I2ContractError("I2 control publication binding mismatch")
            scope = Scope(**row["scope"])
            for field in ("session_id", "run_id", "attempt_id"):
                if payload.get("custody_" + field) != getattr(scope, field):
                    raise I2ContractError("I2 control custody scope mismatch")
            event_raw = self.store._readback(self.store.paths.checked_path(
                publication["object_relative_path"], require_existing=True))
            event = strict_json_loads(event_raw)
            if event["payload_sha256"] != sha256_bytes(raw):
                raise I2ContractError("I2 control event payload digest mismatch")
            if payload.get("audit_custody") is True:
                if payload.get("kind") != "REJECTION":
                    raise I2ContractError("audit custody outside rejection")
                if payload.get("candidate_run_id") != payload.get("subject_run_id"):
                    raise I2ContractError("rejection candidate Run mismatch")
                validate_id(payload.get("candidate_run_id"), "RUN")
                validate_id(payload.get("candidate_attempt_id"), "ATTEMPT")
                if scope.run_id == payload["candidate_run_id"] or scope.attempt_id == payload["candidate_attempt_id"]:
                    raise I2ContractError("rejection reused candidate custody")
            if payload.get("kind") == "RUN_ATOMIC_PATH":
                self._validate_atomic_path(payload, scope)
            elif "logical_events" in payload:
                raise I2ContractError("logical events outside atomic Run path")
            records.append(JournalRecord(payload, evidence_id, publication["object_id"],
                                         publication["sequence"], scope))
        records.sort(key=lambda item: item.sequence)
        return tuple(records)

    @staticmethod
    def _validate_atomic_path(payload: Mapping[str, Any], scope: Scope) -> None:
        events = payload.get("logical_events")
        if not isinstance(events, list) or len(events) != 2:
            raise I2ContractError("atomic Run path requires exactly two logical events")
        if payload.get("subject_session_id") != scope.session_id or payload.get("subject_run_id") != scope.run_id:
            raise I2ContractError("atomic Run path subject/custody mismatch")
        expected_predecessor = payload.get("causal_predecessor_event_id")
        seen = {payload.get("event_id"), payload.get("action_event_id")}
        authorities = None
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                raise I2ContractError("atomic Run logical event malformed")
            event_id = validate_id(event.get("event_id"), "EVENT")
            if event_id in seen or event.get("causal_predecessor_event_id") != expected_predecessor:
                raise I2ContractError("atomic Run event collision or causal gap")
            seen.add(event_id)
            expected_predecessor = event_id
            for field, expected in (("subject_session_id", scope.session_id),
                                    ("subject_run_id", scope.run_id),
                                    ("actor_id", payload.get("actor_id"))):
                if event.get(field) != expected:
                    raise I2ContractError(f"atomic Run event {field} mismatch")
            current_authorities = (
                validate_id(event.get("session_authority_id"), "AUTHORITY"),
                validate_id(event.get("run_authority_id"), "AUTHORITY"),
            )
            if authorities is not None and current_authorities != authorities:
                raise I2ContractError("atomic Run authority changed within transaction")
            authorities = current_authorities
            if not isinstance(event.get("occurred_at_utc"), str):
                raise I2ContractError("atomic Run event timestamp missing")
            evidence_ids = event.get("evidence_ids")
            if not isinstance(evidence_ids, list) or payload.get("evidence_id") not in evidence_ids:
                raise I2ContractError("atomic Run event evidence binding missing")
            if len(evidence_ids) != len(set(evidence_ids)):
                raise I2ContractError("atomic Run event evidence duplicated")
            for evidence_id in evidence_ids:
                validate_id(evidence_id, "EVIDENCE")
            previous, requested = event.get("previous_state"), event.get("requested_next_state")
            if requested != event.get("resulting_state"):
                raise I2ContractError("atomic Run requested/resulting state mismatch")
            RUN_MACHINE.require(previous, requested)
            if index == 0 and (previous, requested) != ("CREATED", "PRESTATE"):
                raise I2ContractError("atomic Run path has wrong first edge")
            if index == 1 and (previous != "PRESTATE" or requested not in {"CLAIMED", "BLOCKED_PRESTATE"}):
                raise I2ContractError("atomic Run path has wrong second edge")

    def transact(
        self, scope: Scope, build: Callable[[tuple[JournalRecord, ...]], dict[str, Any]],
    ) -> JournalRecord:
        """One replay-validated I2 decision, serialized across I2 processes."""
        with self.serialized():
            previous = self.history()
            payload = dict(build(previous))
            if "event_id" in payload or "evidence_id" in payload:
                raise I2ContractError("caller cannot choose I1 commit identities")
            audit_rejection = payload.pop("audit_rejection", False)
            if audit_rejection is True:
                if payload.get("kind") != "REJECTION":
                    raise I2ContractError("audit custody requires rejection")
                used_run_ids = {row.scope.run_id for row in previous}
                used_attempt_ids = {row.scope.attempt_id for row in previous}
                for _ in range(8):
                    audit_run_id, audit_attempt_id = generate_id("RUN"), generate_id("ATTEMPT")
                    if audit_run_id not in used_run_ids and audit_attempt_id not in used_attempt_ids:
                        break
                else:
                    raise I2ContractError("fresh audit custody unavailable")
                scope = Scope(
                    scope.project_id, scope.product_id, scope.lineage_id,
                    scope.version_id, scope.session_id, audit_run_id, audit_attempt_id,
                )
                payload["audit_custody"] = True
            elif audit_rejection is not False:
                raise I2ContractError("invalid audit custody request")
            action_id, event_id, evidence_id = (
                generate_id("EVENT"), generate_id("EVENT"), generate_id("EVIDENCE"))
            if payload.get("launch_intent_id") == "SELF_PUBLICATION":
                payload["launch_intent_id"] = event_id
            payload.update(
                event_id=event_id, evidence_id=evidence_id,
                action_event_id=action_id,
                custody_session_id=scope.session_id,
                custody_run_id=scope.run_id,
                custody_attempt_id=scope.attempt_id,
                actor_id=self.store.actor_id,
                occurred_at_utc=utc_now(),
                causal_predecessor_event_id=previous[-1].event_id if previous else None,
            )
            if payload.get("kind") == "RUN_ATOMIC_PATH":
                events = payload.get("logical_events")
                if not isinstance(events, list) or len(events) != 2:
                    raise I2ContractError("atomic Run path requires exactly two logical events")
                predecessor = payload["causal_predecessor_event_id"]
                filled = []
                for supplied in events:
                    if not isinstance(supplied, dict) or any(field in supplied for field in (
                        "event_id", "actor_id", "occurred_at_utc", "causal_predecessor_event_id")):
                        raise I2ContractError("caller cannot choose atomic Run event identities")
                    logical = dict(supplied)
                    logical_id = generate_id("EVENT")
                    logical.update(event_id=logical_id, actor_id=self.store.actor_id,
                                   occurred_at_utc=utc_now(),
                                   causal_predecessor_event_id=predecessor)
                    logical["evidence_ids"] = list(logical.get("evidence_ids", [])) + [evidence_id]
                    predecessor = logical_id
                    filled.append(logical)
                payload["logical_events"] = filled
                self._validate_atomic_path(payload, scope)
            elif "logical_events" in payload:
                raise I2ContractError("logical events outside atomic Run path")
            content = canonical_json(payload)
            digest = sha256_bytes(content)
            prior_ref = ([{"entity_type": "EVENT", "entity_id": previous[-1].event_id}]
                         if previous else [])
            action = self._event(scope, action_id, "ACTION", digest, [], prior_ref)
            publication = self._event(
                scope, event_id, "PUBLICATION", digest, [evidence_id],
                [{"entity_type": "EVENT", "entity_id": action_id}],
            )
            evidence = self._evidence(scope, evidence_id, action_id, content)
            kind = payload["kind"]
            self._fault(kind, "before_action")
            self.store.commit_action_event(action, scope)
            self._fault(kind, "after_action")
            self.store.publish_evidence(
                evidence, content, publication, scope, producer_kind="ACTOR",
                fault=lambda stage, _path: self._fault(kind, stage),
            )
            self._fault(kind, "after_publication_before_ack")
            current = self.history()
            if len(current) != len(previous) + 1 or current[-1].event_id != event_id:
                raise I2ContractError("I2 publication readback uncertain")
            return current[-1]
