"""I0 identity properties and fail-closed synthetic registration cases."""
from __future__ import annotations

import copy
import json
import secrets

import pytest

from package_g.op1_reusable.identity import (
    HIERARCHY_TYPES, REQUIRED_HIERARCHY, TYPE_PREFIXES, IdentityError,
    canonical_json, generate_id, parse_id, sha256_bytes, validate_id,
)
from package_g.op1_reusable.registry import CollisionError, IdentityRegistry, RegistryError, RelationError


def seed_registry():
    registry = IdentityRegistry()
    actor = registry.create("ACTOR", logical_key="test-actor")
    project = registry.create("PROJECT", logical_key="project", actor_id=actor.entity_id)
    product = registry.create("PRODUCT", logical_key="product", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id})
    lineage = registry.create("LINEAGE", logical_key="lineage", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id, "product_id": product.entity_id})
    version = registry.create("VERSION", logical_key="version", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id, "product_id": product.entity_id, "lineage_id": lineage.entity_id})
    freeze = registry.create("FREEZE", logical_key="freeze", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id, "product_id": product.entity_id, "lineage_id": lineage.entity_id, "version_id": version.entity_id}, content_bytes=b"synthetic-freeze")
    session = registry.create("SESSION", logical_key="session", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id, "product_id": product.entity_id, "lineage_id": lineage.entity_id, "version_id": version.entity_id, "freeze_id": freeze.entity_id})
    run = registry.create("RUN", logical_key="run", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id, "product_id": product.entity_id, "lineage_id": lineage.entity_id, "version_id": version.entity_id, "session_id": session.entity_id})
    return registry, actor, project, product, lineage, version, freeze, session, run


def next_run_envelope(registry, run, **changes):
    envelope = copy.deepcopy(run.envelope)
    envelope["entity_id"] = generate_id("RUN")
    envelope.update(changes)
    return envelope


def assert_reject_unchanged(registry, envelope, *, logical_key, error=RegistryError, **kwargs):
    before = registry.receipt_bytes
    with pytest.raises(error):
        registry.register(envelope, logical_key=logical_key, **kwargs)
    assert registry.receipt_bytes == before
    assert registry.pending_failure is not None
    actor_id = next((record.entity_id for record in registry._records.values() if record.entity_type == "ACTOR"), None)
    audit = registry.abandon_failed_candidate(envelope.get("entity_id"), reason="synthetic rejected fixture", actor_id=actor_id)
    assert json.loads(audit)["candidate_id"] == envelope.get("entity_id")
    assert registry.pending_failure is None


def test_all_34_prefixes_and_random_component_properties():
    assert len(TYPE_PREFIXES) == 34 == len(REQUIRED_HIERARCHY)
    values = [generate_id(kind) for kind in TYPE_PREFIXES for _ in range(32)]
    assert len(values) == len(set(values))
    for kind in TYPE_PREFIXES:
        generated = generate_id(kind, entropy=b"\x42" * 16)
        assert generated == f"PG-{TYPE_PREFIXES[kind]}-" + "42" * 16
        assert parse_id(generated) == (kind, "42" * 16)
        assert validate_id(generated, kind) == generated
    assert all(len(value.rsplit("-", 1)[-1]) == 32 for value in values)


@pytest.mark.parametrize("bad", ["PG-RUN-" + "a" * 31, "PG-RUN-" + "A" * 32, "PG-RUN-" + "z" * 32, "PG-BOGUS-" + "a" * 32, "PG-RUN-" + "a" * 64, "a" * 64, "PG-RUN-" + "a" * 32 + "x"])
def test_malformed_prefix_entropy_and_hash_confusion_rejected(bad):
    with pytest.raises(IdentityError):
        parse_id(bad)


def test_wrong_prefix_entity_type_and_version_confusion_rejected():
    with pytest.raises(IdentityError):
        validate_id(generate_id("VERSION"), "RUN")
    with pytest.raises(IdentityError):
        validate_id(generate_id("RUN"), "VERSION")
    with pytest.raises(IdentityError):
        validate_id(sha256_bytes(b"content"), "RUN")
    with pytest.raises(IdentityError):
        generate_id("RUN", entropy=b"short")


def test_generation_is_not_clock_or_counter_based(monkeypatch):
    calls = []
    def fake_random(n):
        calls.append(n)
        return bytes([len(calls)]) * n
    monkeypatch.setattr(secrets, "token_bytes", fake_random)
    assert generate_id("RUN") != generate_id("RUN")
    assert calls == [16, 16]


def test_hierarchy_parent_child_and_append_only_receipts():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    attempt = registry.create("ATTEMPT", logical_key="attempt", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id, "product_id": product.entity_id, "lineage_id": lineage.entity_id, "version_id": version.entity_id, "session_id": session.entity_id, "run_id": run.entity_id})
    assert attempt.envelope["run_id"] == run.entity_id
    assert registry.count == 9 == len(registry.receipt_bytes)
    previous = None
    for index, raw in enumerate(registry.receipt_bytes, 1):
        receipt = json.loads(raw)
        assert receipt["sequence"] == index
        assert receipt["previous_receipt_sha256"] == previous
        validate_id(receipt["receipt_id"], "ARTIFACT")
        previous = sha256_bytes(raw)
    assert registry.lookup(run.entity_id, "RUN").record_bytes == canonical_json(run.envelope)


def test_collision_duplicate_semantic_key_and_mutable_id_replacement_rejected():
    registry, *_, run = seed_registry()
    first = run.envelope
    assert_reject_unchanged(registry, first, logical_key="run-reused", error=CollisionError)
    different_id = next_run_envelope(registry, run)
    assert_reject_unchanged(registry, different_id, logical_key="run", error=CollisionError)
    altered = copy.deepcopy(first)
    altered["status"] = "REPLACED"
    assert_reject_unchanged(registry, altered, logical_key="mutated", error=CollisionError)
    assert registry.lookup(run.entity_id).envelope["status"] == "CREATED"


def test_generated_id_collision_is_hard_error_without_silent_retry():
    registry = IdentityRegistry()
    actor = registry.create("ACTOR", logical_key="first", entropy=b"\x01" * 16)
    before = registry.receipt_bytes
    with pytest.raises(CollisionError):
        registry.create("ACTOR", logical_key="second", entropy=b"\x01" * 16)
    assert registry.receipt_bytes == before
    assert registry.lookup(actor.entity_id).logical_key == "first"
    with pytest.raises(RegistryError):
        registry.create("PROJECT", logical_key="blocked-until-abandon", actor_id=actor.entity_id)
    assert registry.pending_failure is not None
    registry.abandon_failed_candidate(actor.entity_id, reason="collision rejected", actor_id=actor.entity_id)
    assert registry.create("PROJECT", logical_key="fresh-after-abandon", actor_id=actor.entity_id).entity_type == "PROJECT"


def test_parent_self_unknown_wrong_type_and_caused_by_self_rejected():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    envelope = next_run_envelope(registry, run)
    envelope["parent_ids"] = [{"entity_type": "RUN", "entity_id": envelope["entity_id"]}]
    assert_reject_unchanged(registry, envelope, logical_key="self-parent", error=RelationError)
    envelope = next_run_envelope(registry, run, parent_ids=[{"entity_type": "SESSION", "entity_id": generate_id("SESSION")}])
    assert_reject_unchanged(registry, envelope, logical_key="unknown-parent", error=RelationError)
    envelope = next_run_envelope(registry, run, parent_ids=[{"entity_type": "SESSION", "entity_id": product.entity_id}])
    assert_reject_unchanged(registry, envelope, logical_key="wrong-parent", error=RegistryError)
    envelope = next_run_envelope(registry, run)
    envelope["caused_by_ids"] = [{"entity_type": "RUN", "entity_id": envelope["entity_id"]}]
    assert_reject_unchanged(registry, envelope, logical_key="causal-self", error=RelationError)
    envelope = next_run_envelope(registry, run, caused_by_ids=[{"entity_type": "EVENT", "entity_id": generate_id("EVENT")}])
    assert_reject_unchanged(registry, envelope, logical_key="causal-unknown", error=RelationError)
    envelope = next_run_envelope(registry, run, caused_by_ids=[{"entity_type": "PRODUCT", "entity_id": product.entity_id}])
    registry.register(envelope, logical_key="prior-cause")


def test_invalid_hierarchy_cross_lineage_and_illegal_supersedes_rejected():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    envelope = next_run_envelope(registry, run, product_id=generate_id("PRODUCT"))
    assert_reject_unchanged(registry, envelope, logical_key="unknown-product", error=RelationError)
    envelope = next_run_envelope(registry, run, project_id=run.envelope["product_id"])
    assert_reject_unchanged(registry, envelope, logical_key="wrong-hierarchy", error=RegistryError)
    envelope = next_run_envelope(registry, run, supersedes_id={"entity_type": "PRODUCT", "entity_id": product.entity_id})
    assert_reject_unchanged(registry, envelope, logical_key="wrong-supersedes", error=RelationError)
    envelope = next_run_envelope(registry, run, supersedes_id={"entity_type": "RUN", "entity_id": run.entity_id})
    envelope["session_id"] = generate_id("SESSION")
    assert_reject_unchanged(registry, envelope, logical_key="cross-session-supersedes", error=RelationError)


def test_content_hash_is_exact_byte_identity_separate_from_logical_id():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    assert freeze.envelope["content_sha256"] == sha256_bytes(b"synthetic-freeze")
    assert freeze.entity_id != freeze.envelope["content_sha256"]
    bad = copy.deepcopy(freeze.envelope)
    bad["entity_id"] = generate_id("FREEZE")
    assert_reject_unchanged(registry, bad, logical_key="new-freeze-bad-bytes", content_bytes=b"different")
    bad["entity_id"] = generate_id("FREEZE")
    bad["content_sha256"] = "ABC"
    assert_reject_unchanged(registry, bad, logical_key="new-freeze-bad-hash", content_bytes=b"synthetic-freeze")


def test_record_top_level_identity_and_envelope_must_agree():
    registry, actor, project, *_ = seed_registry()
    entry = registry.schemas.find_document("OP1_FINDING_SCHEMA.json")
    finding_id = generate_id("FINDING")
    envelope = {"entity_id": finding_id, "entity_type": "FINDING", "schema_id": entry.schema_id, "schema_version": entry.version, "actor_id": actor.entity_id, "created_at_utc": "2026-09-23T00:00:00Z", "status": "OPEN"}
    record = {"identity": envelope, "finding_id": finding_id, "subject_ids": [{"entity_type": "PROJECT", "entity_id": project.entity_id}], "observation": "synthetic", "severity": "INFO", "evidence_ids": [generate_id("EVIDENCE")], "initial_state": "OPEN"}
    result = registry.schemas.validate(entry.schema_id, entry.version, record)
    assert result.valid, result.errors
    registered = registry.register(envelope, logical_key="finding", record=record)
    assert registered.entity_id == finding_id
    bad = copy.deepcopy(record)
    bad["identity"] = dict(envelope, entity_id=generate_id("FINDING"))
    assert_reject_unchanged(registry, bad["identity"], logical_key="mismatched-finding", record=bad)


def test_unknown_actor_and_hierarchy_injection_rejected():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    candidate = next_run_envelope(registry, run, actor_id=generate_id("ACTOR"))
    assert_reject_unchanged(registry, candidate, logical_key="unknown-actor", error=RelationError)
    before = registry.receipt_bytes
    with pytest.raises(RegistryError):
        registry.create("PROJECT", logical_key="injection", actor_id=actor.entity_id, hierarchy={"entity_id": run.entity_id})
    assert registry.receipt_bytes == before


def test_sibling_session_parent_must_match_declared_session():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    sibling = registry.create("SESSION", logical_key="sibling", actor_id=actor.entity_id, hierarchy={k: session.envelope[k] for k in ("project_id", "product_id", "lineage_id", "version_id", "freeze_id")})
    envelope = next_run_envelope(registry, run, parent_ids=[{"entity_type": "SESSION", "entity_id": sibling.entity_id}])
    assert_reject_unchanged(registry, envelope, logical_key="sibling-parent", error=RelationError)


def test_execution_ids_cannot_be_superseded():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    candidate = next_run_envelope(registry, run, supersedes_id={"entity_type": "RUN", "entity_id": run.entity_id})
    assert_reject_unchanged(registry, candidate, logical_key="superseded-run", error=RelationError)


def test_receipt_id_collision_rejects_without_commit(monkeypatch):
    import package_g.op1_reusable.registry as registry_module
    registry = IdentityRegistry()
    actor = registry.create("ACTOR", logical_key="actor")
    first_receipt_id = json.loads(registry.receipt_bytes[0])["receipt_id"]
    original = registry_module.generate_id
    monkeypatch.setattr(registry_module, "generate_id", lambda kind, **kwargs: first_receipt_id if kind == "ARTIFACT" else original(kind, **kwargs))
    before = registry.receipt_bytes
    with pytest.raises(CollisionError):
        registry.create("PROJECT", logical_key="project", actor_id=actor.entity_id)
    assert registry.receipt_bytes == before
    assert registry.pending_failure is not None
    registry.abandon_failed_candidate(registry.pending_failure.candidate_id, reason="receipt collision", actor_id=actor.entity_id)


def test_causal_parent_can_be_same_scope_non_hierarchy_entity():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    event = registry.create("EVENT", logical_key="event", actor_id=actor.entity_id, hierarchy={"project_id": project.entity_id, "product_id": product.entity_id, "lineage_id": lineage.entity_id, "version_id": version.entity_id, "session_id": session.entity_id, "run_id": run.entity_id})
    candidate = next_run_envelope(registry, run, parent_ids=[{"entity_type": "EVENT", "entity_id": event.entity_id}])
    registered = registry.register(candidate, logical_key="causal-child")
    assert registered.envelope["parent_ids"][0]["entity_id"] == event.entity_id


@pytest.mark.parametrize("kind", list(TYPE_PREFIXES))
def test_frozen_envelope_accepts_exact_type_and_required_hierarchy(kind):
    from package_g.op1_reusable.schema_registry import SchemaRegistry
    schemas = SchemaRegistry()
    entry = schemas.find_document("OP1_IDENTITY_ENVELOPE_SCHEMA.json")
    envelope = {"entity_id": generate_id(kind), "entity_type": kind, "schema_id": entry.schema_id, "schema_version": entry.version, "actor_id": generate_id("ACTOR"), "created_at_utc": "2026-09-23T00:00:00Z", "status": "CREATED"}
    for field in REQUIRED_HIERARCHY[kind]:
        envelope[field] = "a" * 64 if field == "content_sha256" else generate_id(HIERARCHY_TYPES[field])
    assert schemas.validate(entry.schema_id, entry.version, envelope).valid, kind
    if REQUIRED_HIERARCHY[kind]:
        bad = dict(envelope)
        del bad[REQUIRED_HIERARCHY[kind][0]]
        assert not schemas.validate(entry.schema_id, entry.version, bad).valid, kind
    wrong = dict(envelope, entity_id=generate_id("PROJECT" if kind != "PROJECT" else "RUN"))
    assert not schemas.validate(entry.schema_id, entry.version, wrong).valid, kind


def test_claim_cannot_be_superseded_even_with_same_scope():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    hierarchy = {key: run.envelope[key] for key in ("project_id", "product_id", "lineage_id", "version_id", "session_id")}
    hierarchy["run_id"] = run.entity_id
    claim = registry.create("CLAIM", logical_key="claim", actor_id=actor.entity_id, hierarchy=hierarchy, content_bytes=b"synthetic-claim")
    candidate = copy.deepcopy(claim.envelope)
    candidate["entity_id"] = generate_id("CLAIM")
    candidate["supersedes_id"] = {"entity_type": "CLAIM", "entity_id": claim.entity_id}
    assert_reject_unchanged(registry, candidate, logical_key="new-claim", error=RelationError, content_bytes=b"synthetic-claim")


def test_bounded_finding_correction_appends_new_identity():
    registry, actor, *_ = seed_registry()
    first = registry.create("FINDING", logical_key="finding-original", actor_id=actor.entity_id)
    updated = copy.deepcopy(first.envelope)
    updated["entity_id"] = generate_id("FINDING")
    updated["supersedes_id"] = {"entity_type": "FINDING", "entity_id": first.entity_id}
    second = registry.register(updated, logical_key="finding-correction")
    assert second.entity_id != first.entity_id
    assert registry.lookup(first.entity_id).record_bytes == canonical_json(first.envelope)
    assert second.sequence == first.sequence + 1


def test_exact_digest_idempotent_retry_is_read_only_and_wrong_digest_rejected():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    before = registry.receipt_bytes
    assert registry.retry_lookup(run.entity_id, run.record_sha256, "RUN") == run
    assert registry.receipt_bytes == before
    with pytest.raises(CollisionError):
        registry.retry_lookup(run.entity_id, "0" * 64, "RUN")
    with pytest.raises(IdentityError):
        registry.retry_lookup(run.entity_id, run.entity_id, "RUN")


def test_abandonment_requires_exact_failed_candidate_and_actor():
    registry, actor, project, product, lineage, version, freeze, session, run = seed_registry()
    candidate = next_run_envelope(registry, run)
    candidate["parent_ids"] = [{"entity_type": "RUN", "entity_id": candidate["entity_id"]}]
    with pytest.raises(RegistryError):
        registry.register(candidate, logical_key="bad")
    with pytest.raises(RegistryError):
        registry.abandon_failed_candidate(generate_id("RUN"), reason="wrong", actor_id=actor.entity_id)
    with pytest.raises(RegistryError):
        registry.abandon_failed_candidate(candidate["entity_id"], reason="", actor_id=actor.entity_id)
    assert registry.pending_failure is not None
    first = registry.abandon_failed_candidate(candidate["entity_id"], reason="explicit rejection", actor_id=actor.entity_id)
    assert json.loads(first)["sequence"] == 1
    assert registry.pending_failure is None
    assert len(registry.receipt_bytes) == 8
    with pytest.raises(CollisionError):
        registry.register(candidate, logical_key="abandoned-reuse")
    registry.abandon_failed_candidate(candidate["entity_id"], reason="abandoned ID cannot be reused", actor_id=actor.entity_id)


def test_empty_registry_failure_cannot_be_abandoned_without_registered_actor(monkeypatch):
    registry = IdentityRegistry()
    invalid = {"entity_id": generate_id("ACTOR"), "entity_type": "ACTOR"}
    with pytest.raises(RegistryError):
        registry.register(invalid, logical_key="failed-bootstrap")
    assert registry.pending_failure is not None
    with pytest.raises(RegistryError):
        registry.abandon_failed_candidate(invalid["entity_id"], reason="bootstrap failed", actor_id=None)
    with pytest.raises(RelationError):
        registry.abandon_failed_candidate(invalid["entity_id"], reason="bootstrap failed", actor_id=generate_id("ACTOR"))
    assert registry.pending_failure is not None
    calls = []
    monkeypatch.setattr(secrets, "token_bytes", lambda count: calls.append(count) or b"0" * count)
    with pytest.raises(RegistryError):
        registry.create("ACTOR", logical_key="blocked-bootstrap")
    assert calls == []


def test_malformed_non_mapping_registration_fails_closed_with_audit_gate():
    registry, actor, *_ = seed_registry()
    with pytest.raises(RegistryError):
        registry.register(["invalid"], logical_key="malformed")
    assert registry.pending_failure is not None
    assert registry.pending_failure.candidate_id is None
    registry.abandon_failed_candidate(None, reason="invalid input", actor_id=actor.entity_id)
    assert registry.pending_failure is None
