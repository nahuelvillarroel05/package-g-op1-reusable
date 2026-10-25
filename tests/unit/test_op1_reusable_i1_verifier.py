"""Read-only integrity verifier tests against synthetic I1 stores."""
from __future__ import annotations

import hashlib

import pytest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from op1_reusable_i1_helpers import event_record, publish, synthetic_store, signed_checkpoint
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier, checkpoint_payload
from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.append_only import StoreQuarantined


def _file_digests(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*") if path.is_file()
    }


def _signed_checkpoint(store):
    report = IntegrityVerifier(store.root).verify()
    key = Ed25519PrivateKey.generate()
    payload = {
        "store_id": store.store_id, "lineage_id": store.lineage_id,
        "sequence": report["manifest_count"],
        "manifest_sha256": report["manifest_root_sha256"],
    }
    checkpoint = {
        "payload": payload,
        "signature_hex": key.sign(checkpoint_payload(**payload)).hex(),
    }
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return checkpoint, public


def test_verifier_pass_is_deterministic_and_read_only():
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"observation")
        before = _file_digests(store.root)
        first = IntegrityVerifier(store.root).verify()
        second = IntegrityVerifier(store.root).verify()
        assert first == second
        assert first["result"] == "PASS"
        assert first["operational_admission"] is False
        assert first["checkpoint_custody_qualified"] is False
        assert _file_digests(store.root) == before


def test_mutated_and_missing_blob_are_detected_without_repair():
    with synthetic_store() as (store, scope, actor, key):
        record, _ = publish(store, scope, actor, b"original")
        path = store.root / record["relative_path"]
        path.write_bytes(b"mutated!")
        before = _file_digests(store.root)
        result = IntegrityVerifier(store.root).verify()
        assert result["result"] == "FAIL"
        assert any(item["code"] == "OBJECT_MUTATION" for item in result["findings"])
        assert _file_digests(store.root) == before
        path.unlink()
        assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"


def test_extra_file_and_partial_are_detected():
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"raw")
        stage = store.root / "staging" / f"{generate_id('ARTIFACT')}.partial"
        stage.write_bytes(b"incomplete")
        result = IntegrityVerifier(store.root).verify()
        assert result["result"] == "FAIL"
        assert any(item["code"] == "EXTRA_OR_PARTIAL" for item in result["findings"])
        assert stage.read_bytes() == b"incomplete"


def test_record_manifest_and_locator_mutations_are_detected():
    with synthetic_store() as (store, scope, actor, key):
        record, _ = publish(store, scope, actor, b"raw")
        record_path = store.root / "records" / "evidence" / f"{record['evidence_id']}.json"
        record_path.write_bytes(record_path.read_bytes() + b" ")
        assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"raw")
        locator = store.root / store.paths.locator_relative("v", scope.version_id)
        locator.write_bytes(b"{}")
        result = IntegrityVerifier(store.root).verify()
        assert result["result"] == "FAIL"
        assert any(item["code"] == "LOCATOR_MUTATION" for item in result["findings"])
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"raw")
        manifest = sorted((store.root / "manifests").iterdir())[0]
        manifest.write_bytes(manifest.read_bytes().replace(b'"sequence":1', b'"sequence":2'))
        assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"


def test_duplicate_identity_in_signed_manifest_is_detected():
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"raw")
        rows = store.manifest_rows()
        original = dict(rows[0])
        original["manifest_id"] = generate_id("ARTIFACT")
        original["identity"] = store._envelope(original["manifest_id"], "ARTIFACT", actor)
        original["sequence"] = len(rows) + 1
        last = sorted((store.root / "manifests").iterdir())[-1]
        original["previous_manifest_sha256"] = sha256_bytes(last.read_bytes())
        original.pop("writer_signature_hex")
        original["writer_signature_hex"] = key.sign(canonical_json(original)).hex()
        store._write_exclusive(
            f"manifests/{original['sequence']:012d}-{original['manifest_id']}.json",
            canonical_json(original),
        )
        result = IntegrityVerifier(store.root).verify()
        assert result["result"] == "FAIL"
        assert any(item["code"] == "DUPLICATE_ID" for item in result["findings"])


def test_external_checkpoint_verifies_and_detects_complete_prefix_rollback():
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        checkpoint, public = _signed_checkpoint(store)
        good = IntegrityVerifier(store.root).verify(
            trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        assert good["result"] == "PASS" and good["checkpoint_status"] == "VERIFIED"
        manifest = sorted((store.root / "manifests").iterdir())[0]
        event_path = store.root / store.paths.object_relative(scope, "events", action["event_id"], "json")
        manifest.unlink()
        event_path.unlink()
        for locator in store.paths.expected_locator_rows(scope):
            (store.root / locator["relative_path"]).unlink()
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
        after = IntegrityVerifier(store.root).verify(
            trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        assert after["result"] == "FAIL"
        assert any(item["code"] == "CHECKPOINT_ROLLBACK_OR_MISMATCH" for item in after["findings"])


def test_untrusted_or_forged_checkpoint_fails_closed():
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"raw")
        checkpoint, public = _signed_checkpoint(store)
        assert IntegrityVerifier(store.root).verify(trusted_checkpoint=checkpoint)["result"] == "FAIL"
        forged = {"payload": checkpoint["payload"], "signature_hex": "00" * 64}
        assert IntegrityVerifier(store.root).verify(
            trusted_checkpoint=forged,
            trusted_checkpoint_public_key_hex=public,
        )["result"] == "FAIL"



def test_malformed_manifest_shape_returns_fail_report():
    with synthetic_store() as (store, scope, actor, key):
        publish(store, scope, actor, b"raw")
        manifest = sorted((store.root / "manifests").iterdir())[0]
        manifest.write_bytes(b"[]")
        before = _file_digests(store.root)
        result = IntegrityVerifier(store.root).verify()
        assert result["result"] == "FAIL"
        assert result["findings"]
        assert _file_digests(store.root) == before


def test_writable_reopen_requires_external_latest_checkpoint_and_identity():
    with synthetic_store() as (store, scope, actor, key):
        store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        checkpoint, public = signed_checkpoint(store)
        with pytest.raises(StoreQuarantined):
            EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id)
        with pytest.raises(StoreQuarantined):
            EvidenceStore(store.root, writer_private_key=key, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)
        with pytest.raises(StoreQuarantined):
            EvidenceStore(store.root, writer_private_key=key, store_id=generate_id("RESOURCE"), lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)
        wrong_public = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        with pytest.raises(StoreQuarantined):
            EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=wrong_public)
        reopened = EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)
        assert reopened.manifest_rows() == store.manifest_rows()


def test_writable_reopen_rejects_older_checkpoint_and_complete_prefix_rollback():
    with synthetic_store() as (store, scope, actor, key):
        store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        pinned, public = signed_checkpoint(store)
        publish(store, scope, actor, b"later bytes")
        with pytest.raises(StoreQuarantined):
            EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=pinned, trusted_checkpoint_public_key_hex=public)
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        pinned, public = signed_checkpoint(store)
        manifest = sorted((store.root / "manifests").iterdir())[0]
        event_path = store.root / store.paths.object_relative(scope, "events", action["event_id"], "json")
        manifest.unlink()
        event_path.unlink()
        for locator in store.paths.expected_locator_rows(scope):
            (store.root / locator["relative_path"]).unlink()
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
        with pytest.raises(StoreQuarantined):
            EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=pinned, trusted_checkpoint_public_key_hex=public)


def test_missing_expected_store_and_unpinned_creation_fail_closed():
    with synthetic_store() as (store, scope, actor, key):
        missing = store.root.parent / "missing-store"
        checkpoint, public = signed_checkpoint(store)
        with pytest.raises(ValueError):
            EvidenceStore(missing, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)
        with pytest.raises(StoreQuarantined):
            EvidenceStore(missing, create=True, writer_private_key=key, store_id=generate_id("RESOURCE"), lineage_id=scope.lineage_id, actor_id=actor)
        assert not missing.exists()


def test_open_writer_rechecks_its_observed_prefix_under_lock():
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        pinned, public = signed_checkpoint(store)
        reopened = EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=pinned, trusted_checkpoint_public_key_hex=public)
        sorted((store.root / "manifests").iterdir())[0].unlink()
        (store.root / store.paths.object_relative(scope, "events", action["event_id"], "json")).unlink()
        for locator in store.paths.expected_locator_rows(scope):
            (store.root / locator["relative_path"]).unlink()
        with pytest.raises(StoreQuarantined):
            reopened.commit_action_event(event_record(reopened, scope, actor, "ACTION"), scope)
