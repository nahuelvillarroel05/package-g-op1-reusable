"""Synthetic I1 fixture builders; no operational session or run execution."""
from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from package_g.op1_reusable.append_only import utc_now
from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.identity import generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier, checkpoint_payload
from package_g.op1_reusable.storage_paths import Scope


_OWNERS: dict[Path, Ed25519PrivateKey] = {}


def _checkpoint(store_id, lineage_id, sequence, manifest_sha256, owner_key):
    payload = {"store_id": store_id, "lineage_id": lineage_id, "sequence": sequence, "manifest_sha256": manifest_sha256}
    checkpoint = {"payload": payload, "signature_hex": owner_key.sign(checkpoint_payload(**payload)).hex()}
    public = owner_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return checkpoint, public


def signed_checkpoint(store):
    report = IntegrityVerifier(store.root).verify()
    assert report["result"] == "PASS", report
    return _checkpoint(store.store_id, store.lineage_id, report["manifest_count"], report["manifest_root_sha256"], _OWNERS[store.root])


@contextmanager
def synthetic_store():
    with tempfile.TemporaryDirectory(prefix="i1-", dir=Path.home()) as temp:
        root = Path(temp) / "s"
        scope = Scope(*(generate_id(kind) for kind in ("PROJECT", "PRODUCT", "LINEAGE", "VERSION", "SESSION", "RUN", "ATTEMPT")))
        actor_id = generate_id("ACTOR")
        key = Ed25519PrivateKey.generate()
        owner_key = Ed25519PrivateKey.generate()
        store_id = generate_id("RESOURCE")
        genesis, public = _checkpoint(store_id, scope.lineage_id, 0, None, owner_key)
        store = EvidenceStore(
            root, create=True, store_id=store_id,
            lineage_id=scope.lineage_id, actor_id=actor_id,
            writer_private_key=key, trusted_checkpoint=genesis,
            trusted_checkpoint_public_key_hex=public,
        )
        _OWNERS[root] = owner_key
        try:
            yield store, scope, actor_id, key
        finally:
            _OWNERS.pop(root, None)


def sibling_scope(scope: Scope) -> Scope:
    return Scope(scope.project_id, scope.product_id, scope.lineage_id, scope.version_id, scope.session_id, generate_id("RUN"), generate_id("ATTEMPT"))


def event_record(store, scope, actor_id, role, evidence_ids=None, artifact_ids=None, *, event_id=None):
    event_id = event_id or generate_id("EVENT")
    entry = store.schemas.find_document("OP1_EVENT_SCHEMA.json")
    identity = {
        "entity_id": event_id, "entity_type": "EVENT",
        "schema_id": entry.schema_id, "schema_version": entry.version,
        "actor_id": actor_id, "created_at_utc": utc_now(), "status": "COMMITTED",
        **{field: getattr(scope, field) for field in ("project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id")},
    }
    return {
        "identity": identity, "event_id": event_id, "event_kind": role,
        "session_id": scope.session_id, "run_id": scope.run_id,
        "attempt_id": scope.attempt_id, "actor_id": actor_id,
        "occurred_at_utc": utc_now(), "committed_sequence": 1,
        "parent_ids": [], "caused_by_ids": [], "payload_sha256": sha256_bytes(b""),
        "produced_artifact_ids": list(artifact_ids or []),
        "produced_finding_ids": [], "resolved_finding_ids": [],
        "triggered_decision_ids": [], "evidence_ids": list(evidence_ids or []),
        "writer_authentication_ref": store.writer_authentication_ref,
        "event_role": role,
    }


def evidence_record(store, scope, actor_id, action_id, content, *, evidence_id=None, artifact_id=None, derivation="RAW_IMMUTABLE", sources=None, evidence_class="STDERR", caused_by=None, producer="synthetic observer", tool_id=None, invocation_id=None):
    evidence_id = evidence_id or generate_id("EVIDENCE")
    entry = store.schemas.find_document("OP1_EVIDENCE_SCHEMA.json")
    identity = {
        "entity_id": evidence_id, "entity_type": "EVIDENCE",
        "schema_id": entry.schema_id, "schema_version": entry.version,
        "actor_id": actor_id, "created_at_utc": utc_now(),
        "status": "COMMITTED", "content_sha256": sha256_bytes(content),
        **{field: getattr(scope, field) for field in ("project_id", "product_id", "lineage_id", "version_id", "session_id", "run_id")},
    }
    if caused_by is not None:
        identity["caused_by_ids"] = [{"entity_type": "EVIDENCE", "entity_id": caused_by}]
    klass = "raw" if derivation == "RAW_IMMUTABLE" else "derived"
    record = {
        "identity": identity, "evidence_id": evidence_id,
        "run_id": scope.run_id, "event_id": action_id,
        "actor_id": actor_id,
        "relative_path": store.paths.object_relative(scope, klass, evidence_id, "bin"),
        "byte_length": len(content), "sha256": sha256_bytes(content),
        "producer": producer, "created_at_utc": utc_now(),
        "evidence_class": evidence_class, "derivation_class": derivation,
        "attempt_id": scope.attempt_id,
    }
    if sources is not None:
        record["source_evidence_ids"] = list(sources)
    if artifact_id is not None:
        record["artifact_id"] = artifact_id
    if tool_id is not None:
        record["tool_id"] = tool_id
    if invocation_id is not None:
        record["tool_invocation_id"] = invocation_id
    return record


def publish(store, scope, actor_id, content, *, derivation="RAW_IMMUTABLE", sources=None, evidence_class="STDERR", caused_by=None, artifact_id=None, evidence_id=None, producer_kind="ACTOR", tool_id=None, invocation_id=None, fault=None):
    action = store.commit_action_event(event_record(store, scope, actor_id, "ACTION"), scope)
    record = evidence_record(
        store, scope, actor_id, action["event_id"], content,
        derivation=derivation, sources=sources, evidence_class=evidence_class,
        caused_by=caused_by, artifact_id=artifact_id, evidence_id=evidence_id,
        tool_id=tool_id, invocation_id=invocation_id,
    )
    publication = event_record(store, scope, actor_id, "PUBLICATION", [record["evidence_id"]], [artifact_id] if artifact_id else [])
    result = store.publish_evidence(record, content, publication, scope, producer_kind=producer_kind, fault=fault)
    return record, result