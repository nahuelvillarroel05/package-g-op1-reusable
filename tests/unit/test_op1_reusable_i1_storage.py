"""I1 append-only storage, frozen evidence, and synthetic failure history."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from op1_reusable_i1_helpers import event_record, evidence_record, publish, sibling_scope, synthetic_store, signed_checkpoint
from package_g.op1_reusable.append_only import ObjectExists, StoreQuarantined
from package_g.op1_reusable.evidence_store import EvidenceError, EvidenceStore
from package_g.op1_reusable.identity import generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier


def test_raw_publication_readback_manifest_and_reopen():
    with synthetic_store() as (store, scope, actor, key):
        artifact_id = generate_id("ARTIFACT")
        raw = b"\x00native stderr\r\nfailed\xff"
        record, result = publish(store, scope, actor, raw, artifact_id=artifact_id)
        assert (store.root / record["relative_path"]).read_bytes() == raw
        assert record["sha256"] == sha256_bytes(raw)
        assert result["evidence_id"] == record["evidence_id"]
        rows = store.manifest_rows()
        assert [row["sequence"] for row in rows] == [1, 2, 3]
        assert rows[1]["artifact_id"] == artifact_id
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
        checkpoint, public = signed_checkpoint(store)
        reopened = EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)
        assert reopened.manifest_rows() == rows


def test_raw_and_derived_correction_are_separate_immutable_objects():
    with synthetic_store() as (store, scope, actor, key):
        raw_bytes = b"original observation\x00"
        original, _ = publish(store, scope, actor, raw_bytes, evidence_class="RAW_STDOUT")
        derived_bytes = b'{"interpretation":"corrected"}'
        corrected, _ = publish(
            store, scope, actor, derived_bytes,
            derivation="DERIVED_IMMUTABLE", sources=[original["evidence_id"]],
            caused_by=original["evidence_id"], evidence_class="CORRECTION",
        )
        assert corrected["evidence_id"] != original["evidence_id"]
        assert corrected["identity"]["caused_by_ids"][0]["entity_id"] == original["evidence_id"]
        assert (store.root / original["relative_path"]).read_bytes() == raw_bytes
        assert (store.root / corrected["relative_path"]).read_bytes() == derived_bytes
        assert original["relative_path"] != corrected["relative_path"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_derived_requires_prior_raw_and_raw_cannot_claim_sources():
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"derived"
        bad = evidence_record(store, scope, actor, action["event_id"], data, derivation="DERIVED_IMMUTABLE", sources=[generate_id("EVIDENCE")])
        publication = event_record(store, scope, actor, "PUBLICATION", [bad["evidence_id"]])
        with pytest.raises(EvidenceError):
            store.publish_evidence(bad, data, publication, scope, producer_kind="ACTOR")
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"raw"
        bad = evidence_record(store, scope, actor, action["event_id"], data, sources=[generate_id("EVIDENCE")])
        publication = event_record(store, scope, actor, "PUBLICATION", [bad["evidence_id"]])
        with pytest.raises(EvidenceError):
            store.publish_evidence(bad, data, publication, scope, producer_kind="ACTOR")
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_tool_attribution_is_explicit_and_frozen_schema_stays_closed():
    with synthetic_store() as (store, scope, actor, key):
        data = b"synthetic tool output"
        record, _ = publish(
            store, scope, actor, data, producer_kind="TOOL",
            tool_id=generate_id("TOOL"), invocation_id=generate_id("TOOL_INVOCATION"),
        )
        assert "tool_id" in record and "tool_invocation_id" in record
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        bad = evidence_record(store, scope, actor, action["event_id"], b"x", tool_id=generate_id("TOOL"))
        publication = event_record(store, scope, actor, "PUBLICATION", [bad["evidence_id"]])
        with pytest.raises(EvidenceError):
            store.publish_evidence(bad, b"x", publication, scope, producer_kind="TOOL")
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        bad = evidence_record(store, scope, actor, action["event_id"], b"x")
        bad["unexpected_field"] = True
        publication = event_record(store, scope, actor, "PUBLICATION", [bad["evidence_id"]])
        with pytest.raises(EvidenceError):
            store.publish_evidence(bad, b"x", publication, scope, producer_kind="ACTOR")


def test_duplicate_evidence_and_artifact_identity_never_replace():
    with synthetic_store() as (store, scope, actor, key):
        artifact_id = generate_id("ARTIFACT")
        evidence_id = generate_id("EVIDENCE")
        first, _ = publish(store, scope, actor, b"failed", artifact_id=artifact_id, evidence_id=evidence_id)
        original = (store.root / first["relative_path"]).read_bytes()
        with pytest.raises(ObjectExists):
            publish(store, scope, actor, b"success", artifact_id=artifact_id, evidence_id=evidence_id)
        assert (store.root / first["relative_path"]).read_bytes() == original
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_foreign_existing_final_path_rejects_without_mutation():
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"new bytes"
        record = evidence_record(store, scope, actor, action["event_id"], data)
        final = store.paths.ensure_parents(record["relative_path"])
        final.write_bytes(b"foreign existing")
        publication = event_record(store, scope, actor, "PUBLICATION", [record["evidence_id"]])
        with pytest.raises(StoreQuarantined):
            store.publish_evidence(record, data, publication, scope, producer_kind="ACTOR")
        assert final.read_bytes() == b"foreign existing"
        result = IntegrityVerifier(store.root).verify()
        assert result["result"] == "FAIL"
        assert any(item["code"] == "EXTRA_OR_PARTIAL" for item in result["findings"])


def test_manifest_rebuild_order_and_authentication_are_deterministic():
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"one")
        publish(store, scope, actor, b"two", evidence_class="STDOUT")
        first = store.manifest_rows()
        checkpoint, public = signed_checkpoint(store)
        second = EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public).manifest_rows()
        assert first == second
        assert [row["sequence"] for row in first] == list(range(1, len(first) + 1))
        assert all(len(row["writer_signature_hex"]) == 128 for row in first)
        assert IntegrityVerifier(store.root).verify() == IntegrityVerifier(store.root).verify()


def test_synthetic_fail_blocked_pass_histories_all_remain_addressable():
    with synthetic_store() as (store, first_scope, actor, key):
        scopes = [first_scope, sibling_scope(first_scope), sibling_scope(first_scope)]
        outcomes = ["FAIL", "BLOCKED", "PASS"]
        payloads = [b"failed stderr", b"blocked prestate", b"passing stdout"]
        classes = ["STDERR", "BLOCKER", "STDOUT"]
        records = []
        closures = []
        for scope, outcome, payload, evidence_class in zip(scopes, outcomes, payloads, classes):
            record, _ = publish(store, scope, actor, payload, evidence_class=evidence_class)
            closure = store.commit_synthetic_closure(scope, outcome, [record["evidence_id"]], [evidence_class])
            records.append(record)
            closures.append(closure)
        assert len({scope.run_id for scope in scopes}) == 3
        assert len({row["evidence_id"] for row in records}) == 3
        assert [item["record"]["outcome"] for item in closures] == outcomes
        for record, payload in zip(records, payloads):
            assert (store.root / record["relative_path"]).read_bytes() == payload
            assert sha256_bytes(payload) == record["sha256"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
        with pytest.raises(ObjectExists):
            store.commit_synthetic_closure(first_scope, "PASS", [records[0]["evidence_id"]], ["STDERR"])
        assert (store.root / records[0]["relative_path"]).read_bytes() == payloads[0]


def test_missing_required_evidence_class_cannot_seal_pass():
    with synthetic_store() as (store, scope, actor, key):
        record, _ = publish(store, scope, actor, b"only stdout", evidence_class="STDOUT")
        before = len(store.manifest_rows())
        with pytest.raises(EvidenceError, match="INCOMPLETE_EVIDENCE"):
            store.commit_synthetic_closure(scope, "PASS", [record["evidence_id"]], ["STDERR"])
        assert len(store.manifest_rows()) == before
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"