"""I0 immutable identity registry with append-only synthetic registration receipts."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .identity import (
    HIERARCHY_TYPES, REQUIRED_HIERARCHY, IdentityError,
    canonical_json, generate_id, sha256_bytes, strict_json_loads, validate_id,
)
from .schema_registry import SchemaError, SchemaRegistry


class RegistryError(IdentityError):
    """Registration failed closed without changing the registry."""


class CollisionError(RegistryError):
    """An ID or semantic key was already registered."""


class RelationError(RegistryError):
    """A typed hierarchy or causal reference is invalid."""


@dataclass(frozen=True)
class IdentityRecord:
    entity_id: str
    entity_type: str
    logical_key: str
    record_sha256: str
    receipt_sha256: str
    sequence: int
    record_bytes: bytes

    @property
    def envelope(self) -> dict[str, Any]:
        record = strict_json_loads(self.record_bytes)
        return record.get("identity", record)


@dataclass(frozen=True)
class FailedInsertion:
    failure_id: str
    candidate_id: str | None
    attempted_envelope_sha256: str | None
    error_type: str
    error_message: str


class IdentityRegistry:
    """Synthetic, nonauthoritative I0 registry; I1 must supply durable storage."""

    def __init__(self, schemas: SchemaRegistry | None = None) -> None:
        self.schemas = schemas if schemas is not None else SchemaRegistry()
        self._records: dict[str, IdentityRecord] = {}
        self._logical_keys: dict[tuple[str, str], str] = {}
        self._receipts: list[bytes] = []
        self._receipt_ids: set[str] = set()
        self._failure_audits: list[bytes] = []
        self._audit_ids: set[str] = set()
        self._failure_ids: set[str] = set()
        self._abandoned_candidate_ids: set[str] = set()
        self._pending_failure: FailedInsertion | None = None
        self._identity_schema = self.schemas.find_document("OP1_IDENTITY_ENVELOPE_SCHEMA.json")

    @property
    def count(self) -> int:
        return len(self._records)

    @property
    def receipt_bytes(self) -> tuple[bytes, ...]:
        return tuple(self._receipts)

    @property
    def failure_audit_bytes(self) -> tuple[bytes, ...]:
        return tuple(self._failure_audits)

    @property
    def pending_failure(self) -> FailedInsertion | None:
        return self._pending_failure

    def lookup(self, entity_id: str, expected_type: str | None = None) -> IdentityRecord:
        validate_id(entity_id, expected_type)
        try:
            return self._records[entity_id]
        except KeyError as exc:
            raise RelationError("unknown immutable ID") from exc

    def retry_lookup(self, entity_id: str, expected_record_sha256: str, expected_type: str | None = None) -> IdentityRecord:
        """Read-only idempotent retry requires exact existing ID and record digest."""
        from .identity import validate_sha256
        validate_sha256(expected_record_sha256)
        record = self.lookup(entity_id, expected_type)
        if record.record_sha256 != expected_record_sha256:
            raise CollisionError("existing ID has different exact record digest")
        return record

    def abandon_failed_candidate(self, candidate_id: str | None, *, reason: str, actor_id: str | None = None) -> bytes:
        """Explicitly audit a failed insertion before allowing another allocation."""
        pending = self._pending_failure
        if pending is None or candidate_id != pending.candidate_id:
            raise RegistryError("no matching failed candidate to abandon")
        if not isinstance(reason, str) or not reason:
            raise RegistryError("abandonment reason required")
        if actor_id is None:
            raise RegistryError("registered actor required for abandonment")
        self.lookup(actor_id, "ACTOR")
        audit_id = generate_id("AUDIT")
        if audit_id in self._records or audit_id in self._receipt_ids or audit_id in self._audit_ids or audit_id in self._failure_ids or audit_id in self._abandoned_candidate_ids or audit_id == candidate_id:
            raise CollisionError("abandonment audit ID collision")
        audit = {
            "audit_id": audit_id, "actor_id": actor_id,
            "failure_id": pending.failure_id, "candidate_id": candidate_id,
            "attempted_envelope_sha256": pending.attempted_envelope_sha256,
            "error_type": pending.error_type, "error_message": pending.error_message,
            "reason": reason, "sequence": len(self._failure_audits) + 1,
            "previous_audit_sha256": sha256_bytes(self._failure_audits[-1]) if self._failure_audits else None,
        }
        raw = canonical_json(audit)
        self._failure_audits.append(raw)
        self._audit_ids.add(audit_id)
        if isinstance(candidate_id, str):
            self._abandoned_candidate_ids.add(candidate_id)
        self._pending_failure = None
        return raw

    def _check_scope(self, child: Mapping[str, Any], target: IdentityRecord) -> None:
        parent = target.envelope
        for field in HIERARCHY_TYPES:
            if field in child and field in parent and child[field] != parent[field]:
                raise RelationError(f"cross-boundary reference: {field}")

    def _check_hierarchy(self, envelope: Mapping[str, Any]) -> None:
        kind = envelope["entity_type"]
        for field in REQUIRED_HIERARCHY[kind]:
            if field not in envelope:
                raise RelationError(f"missing hierarchy field: {field}")
        for field, expected_type in HIERARCHY_TYPES.items():
            if field not in envelope:
                continue
            entity_id = validate_id(envelope[field], expected_type)
            if entity_id == envelope["entity_id"]:
                raise RelationError("self hierarchy reference")
            ancestor = self.lookup(entity_id, expected_type)
            self._check_scope(envelope, ancestor)

    def _check_reference(self, envelope: Mapping[str, Any], reference: Mapping[str, str], relation: str) -> IdentityRecord:
        kind, entity_id = reference["entity_type"], reference["entity_id"]
        validate_id(entity_id, kind)
        if entity_id == envelope["entity_id"]:
            raise RelationError("self parent or causal reference")
        target = self.lookup(entity_id, kind)
        self._check_scope(envelope, target)
        for field, hierarchy_type in HIERARCHY_TYPES.items():
            if kind == hierarchy_type and field in envelope and envelope[field] != entity_id:
                raise RelationError(f"reference conflicts with {field}")
        if relation == "supersedes":
            if kind != envelope["entity_type"]:
                raise RelationError("supersedes requires the same entity type")
            # I0 admits corrections only for bounded non-execution record classes.
            if kind not in {"ARTIFACT", "FINDING", "ERROR", "DECISION", "REPORT", "REVIEW"}:
                raise RelationError("supersedes unsupported for this type in I0")
            previous = target.envelope
            for field in HIERARCHY_TYPES:
                if envelope.get(field) != previous.get(field):
                    raise RelationError("supersedes crossed identity scope")
        return target

    def _validate(self, envelope: Mapping[str, Any], record: Mapping[str, Any] | None, content_bytes: bytes | None) -> bytes:
        shape = self.schemas.validate(self._identity_schema.schema_id, self._identity_schema.version, envelope)
        if not shape.valid:
            raise RegistryError("identity envelope schema rejected: " + "; ".join(shape.errors))
        kind, entity_id = envelope["entity_type"], envelope["entity_id"]
        validate_id(entity_id, kind)
        validate_id(envelope["actor_id"], "ACTOR")
        if not (kind == "ACTOR" and envelope["actor_id"] == entity_id and not any(r.entity_type == "ACTOR" for r in self._records.values())):
            self.lookup(envelope["actor_id"], "ACTOR")
        entry = self.schemas.lookup(envelope["schema_id"], envelope["schema_version"])
        if record is None:
            if entry.schema_id != self._identity_schema.schema_id:
                raise RegistryError("non-envelope schema requires its record")
            value: Mapping[str, Any] = envelope
        else:
            if record.get("identity") != envelope:
                raise RegistryError("record identity differs from envelope")
            result = self.schemas.validate(entry.schema_id, entry.version, record)
            if not result.valid:
                raise RegistryError("record schema rejected: " + "; ".join(result.errors))
            typed_key = kind.lower() + "_id"
            if typed_key not in record or record[typed_key] != entity_id:
                raise RegistryError("top-level typed ID differs from envelope")
            for field in HIERARCHY_TYPES:
                if field in record and record[field] != envelope.get(field):
                    raise RegistryError(f"top-level {field} differs from envelope")
            value = record
        if "content_sha256" in envelope:
            if content_bytes is None or sha256_bytes(content_bytes) != envelope["content_sha256"]:
                raise RegistryError("exact content bytes do not match content_sha256")
        elif content_bytes is not None:
            raise RegistryError("content bytes require content_sha256")
        self._check_hierarchy(envelope)
        for reference in envelope.get("parent_ids", ()):
            self._check_reference(envelope, reference, "parent")
        for reference in envelope.get("caused_by_ids", ()):
            self._check_reference(envelope, reference, "caused_by")
        if "supersedes_id" in envelope:
            self._check_reference(envelope, envelope["supersedes_id"], "supersedes")
        return canonical_json(value)

    def register(
        self,
        envelope: Mapping[str, Any],
        *,
        logical_key: str,
        record: Mapping[str, Any] | None = None,
        content_bytes: bytes | None = None,
    ) -> IdentityRecord:
        if self._pending_failure is not None:
            raise RegistryError("failed candidate requires explicit audited abandonment")
        try:
            return self._commit_registration(envelope, logical_key=logical_key, record=record, content_bytes=content_bytes)
        except (IdentityError, SchemaError, AttributeError, TypeError, KeyError) as exc:
            candidate_id = envelope.get("entity_id") if isinstance(envelope, Mapping) else None
            try:
                attempted_sha = sha256_bytes(canonical_json(envelope))
            except (TypeError, ValueError):
                attempted_sha = None
            failure_id = generate_id("ERROR")
            if failure_id == candidate_id or failure_id in self._records or failure_id in self._receipt_ids or failure_id in self._audit_ids or failure_id in self._failure_ids or failure_id in self._abandoned_candidate_ids:
                raise CollisionError("failure receipt ID collision") from exc
            self._failure_ids.add(failure_id)
            self._pending_failure = FailedInsertion(failure_id, candidate_id, attempted_sha, type(exc).__name__, str(exc))
            if isinstance(exc, (IdentityError, SchemaError)):
                raise
            raise RegistryError("malformed registration input") from exc

    def _commit_registration(
        self,
        envelope: Mapping[str, Any],
        *,
        logical_key: str,
        record: Mapping[str, Any] | None,
        content_bytes: bytes | None,
    ) -> IdentityRecord:
        if not isinstance(logical_key, str) or not logical_key:
            raise RegistryError("nonempty semantic logical_key required")
        entity_id = envelope.get("entity_id")
        kind = envelope.get("entity_type")
        if not isinstance(entity_id, str) or not isinstance(kind, str):
            raise RegistryError("string typed identity required")
        if entity_id in self._records or entity_id in self._receipt_ids or entity_id in self._audit_ids or entity_id in self._failure_ids or entity_id in self._abandoned_candidate_ids:
            raise CollisionError("ID already registered; read-only lookup is available")
        if (kind, logical_key) in self._logical_keys:
            raise CollisionError("semantic logical entity already registered")
        record_bytes = self._validate(envelope, record, content_bytes)
        previous = sha256_bytes(self._receipts[-1]) if self._receipts else None
        receipt = {
            "receipt_id": generate_id("ARTIFACT"),
            "sequence": len(self._receipts) + 1,
            "entity_id": entity_id,
            "entity_type": kind,
            "logical_key": logical_key,
            "record_sha256": sha256_bytes(record_bytes),
            "previous_receipt_sha256": previous,
        }
        if receipt["receipt_id"] == entity_id or receipt["receipt_id"] in self._records or receipt["receipt_id"] in self._receipt_ids or receipt["receipt_id"] in self._audit_ids or receipt["receipt_id"] in self._failure_ids or receipt["receipt_id"] in self._abandoned_candidate_ids:
            raise CollisionError("registration receipt ID collision")
        receipt_bytes = canonical_json(receipt)
        registered = IdentityRecord(entity_id, kind, logical_key, receipt["record_sha256"], sha256_bytes(receipt_bytes), receipt["sequence"], record_bytes)
        self._records[entity_id] = registered
        self._logical_keys[(kind, logical_key)] = entity_id
        self._receipts.append(receipt_bytes)
        self._receipt_ids.add(receipt["receipt_id"])
        return registered

    def create(
        self,
        entity_type: str,
        *,
        logical_key: str,
        actor_id: str | None = None,
        hierarchy: Mapping[str, str] | None = None,
        status: str = "CREATED",
        content_bytes: bytes | None = None,
        created_at_utc: str | None = None,
        entropy: bytes | None = None,
    ) -> IdentityRecord:
        if self._pending_failure is not None:
            raise RegistryError("failed candidate requires explicit audited abandonment before ID allocation")
        if hierarchy is not None and any(key not in HIERARCHY_TYPES for key in hierarchy):
            raise RegistryError("create hierarchy contains non-hierarchy fields")
        entity_id = generate_id(entity_type, entropy=entropy)
        identity = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "schema_id": self._identity_schema.schema_id,
            "schema_version": self._identity_schema.version,
            "actor_id": actor_id if actor_id is not None else entity_id if entity_type == "ACTOR" else None,
            "created_at_utc": created_at_utc or datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "status": status,
            **(dict(hierarchy) if hierarchy is not None else {}),
        }
        if content_bytes is not None:
            identity["content_sha256"] = sha256_bytes(content_bytes)
        return self.register(identity, logical_key=logical_key, content_bytes=content_bytes)
