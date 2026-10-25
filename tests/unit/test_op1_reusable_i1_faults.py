"""Synthetic crash, partial-write, and readback fault injection for I1."""
from __future__ import annotations

import errno

import pytest

from op1_reusable_i1_helpers import event_record, evidence_record, synthetic_store, signed_checkpoint
from package_g.op1_reusable.append_only import IntegrityFailure, ObjectExists, StoreQuarantined
from package_g.op1_reusable.evidence_store import EvidenceError, EvidenceStore
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.identity import generate_id


class InjectedInterruption(RuntimeError):
    pass


@pytest.mark.parametrize(
    "phase,verifier_result",
    [
        ("evidence_blob.before_create", "PASS"),
        ("evidence_blob.after_partial_create", "FAIL"),
        ("evidence_blob.mid_write", "FAIL"),
        ("evidence_blob.after_write", "FAIL"),
        ("evidence_blob.after_flush", "FAIL"),
        ("evidence_blob.before_publish", "FAIL"),
        ("evidence_blob.after_publish", "FAIL"),
        ("evidence.after_blob", "FAIL"),
        ("evidence_record.after_publish", "FAIL"),
        ("evidence.after_record", "FAIL"),
        ("evidence.after_manifest", "FAIL"),
        ("event.after_publish", "FAIL"),
        ("evidence.after_ack", "PASS"),
    ],
)
def test_interruption_boundary_never_promotes_incomplete_evidence(phase, verifier_result):
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"FAILED stderr before retry\r\n"
        checkpoint, public = signed_checkpoint(store)
        record = evidence_record(store, scope, actor, action["event_id"], data)
        publication = event_record(store, scope, actor, "PUBLICATION", [record["evidence_id"]])
        hits = []
        def fault(name, path):
            if name == phase:
                hits.append(name)
                raise InjectedInterruption(name)
        with pytest.raises(InjectedInterruption):
            store.publish_evidence(record, data, publication, scope, producer_kind="ACTOR", fault=fault)
        assert hits == [phase]
        verdict = IntegrityVerifier(store.root).verify()
        assert verdict["result"] == verifier_result, (phase, verdict["findings"])
        if phase == "evidence_blob.before_create":
            assert not (store.root / record["relative_path"]).exists()
        if phase == "evidence.after_ack":
            assert (store.root / record["relative_path"]).read_bytes() == data
            checkpoint, public = signed_checkpoint(store)
            reopened = EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)
            with pytest.raises(ObjectExists):
                reopened.publish_evidence(record, data, publication, scope, producer_kind="ACTOR")
            assert (store.root / record["relative_path"]).read_bytes() == data
        elif verifier_result == "FAIL":
            with pytest.raises(StoreQuarantined):
                EvidenceStore(store.root, writer_private_key=key, store_id=store.store_id, lineage_id=store.lineage_id, trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)


def test_disk_full_mid_write_leaves_partial_unreferenced():
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"streaming data" * 32
        record = evidence_record(store, scope, actor, action["event_id"], data)
        publication = event_record(store, scope, actor, "PUBLICATION", [record["evidence_id"]])
        def disk_full(name, path):
            if name == "evidence_blob.mid_write":
                raise OSError(errno.ENOSPC, "synthetic disk full")
        with pytest.raises(OSError) as exc:
            store.publish_evidence(record, data, publication, scope, producer_kind="ACTOR", fault=disk_full)
        assert exc.value.errno == errno.ENOSPC
        assert not (store.root / record["relative_path"]).exists()
        partials = tuple((store.root / "staging").iterdir())
        assert len(partials) == 1
        assert 0 < partials[0].stat().st_size < len(data)
        assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"


def test_staged_readback_mismatch_blocks_publication(monkeypatch):
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"readback check"
        record = evidence_record(store, scope, actor, action["event_id"], data)
        publication = event_record(store, scope, actor, "PUBLICATION", [record["evidence_id"]])
        original = store._readback
        monkeypatch.setattr(store, "_readback", lambda path: original(path) + b"!" if path.suffix == ".partial" else original(path))
        with pytest.raises(IntegrityFailure, match="staged readback"):
            store.publish_evidence(record, data, publication, scope, producer_kind="ACTOR")
        assert not (store.root / record["relative_path"]).exists()
        assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"


def test_record_hash_or_length_mismatch_rejects_before_any_blob_create():
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"exact raw"
        record = evidence_record(store, scope, actor, action["event_id"], data)
        record["sha256"] = "0" * 64
        publication = event_record(store, scope, actor, "PUBLICATION", [record["evidence_id"]])
        with pytest.raises(EvidenceError):
            store.publish_evidence(record, data, publication, scope, producer_kind="ACTOR")
        assert not (store.root / record["relative_path"]).exists()
        assert not tuple((store.root / "staging").iterdir())
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


@pytest.mark.parametrize("fault_phase", ["orphan.mid_write", "orphan.after_publish"])
def test_preopened_second_writer_quarantines_after_first_writer_leaves_crash_debris(fault_phase):
    with synthetic_store() as (first, scope, actor, key):
        checkpoint, public = signed_checkpoint(first)
        second = EvidenceStore(
            first.root, store_id=first.store_id, lineage_id=first.lineage_id,
            writer_private_key=key, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        relative = first.paths.object_relative(
            scope, "raw", generate_id("EVIDENCE"), "bin",
        )
        def fault(name, path):
            if name == fault_phase:
                raise InjectedInterruption(name)
        with pytest.raises(InjectedInterruption):
            with first.writer():
                first._publish_bytes(
                    relative, b"failed-first-writer", phase="orphan", fault=fault,
                )
        before = {
            p.relative_to(first.root).as_posix()
            for p in first.root.rglob("*") if p.is_file()
        }
        assert IntegrityVerifier(first.root).verify()["result"] == "FAIL"
        with pytest.raises(StoreQuarantined, match="pretransaction store integrity"):
            second.commit_action_event(
                event_record(second, scope, actor, "ACTION"), scope,
            )
        after = {
            p.relative_to(first.root).as_posix()
            for p in first.root.rglob("*") if p.is_file()
        }
        assert after == before
        assert second._quarantined is True
        assert second.manifest_rows() == ()


def test_preopened_writer_refuses_mutated_committed_object():
    with synthetic_store() as (first, scope, actor, key):
        first.commit_action_event(event_record(first, scope, actor, "ACTION"), scope)
        checkpoint, public = signed_checkpoint(first)
        second = EvidenceStore(
            first.root, store_id=first.store_id, lineage_id=first.lineage_id,
            writer_private_key=key, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        row = first.manifest_rows()[0]
        target = first.root / row["object_relative_path"]
        original = target.read_bytes()
        target.write_bytes(b"X" + original[1:])
        assert IntegrityVerifier(first.root).verify()["result"] == "FAIL"
        with pytest.raises(StoreQuarantined, match="pretransaction store integrity"):
            second.commit_action_event(
                event_record(second, scope, actor, "ACTION"), scope,
            )
        assert second._quarantined is True
        assert len(second.manifest_rows()) == 1


def test_writer_preflight_rejects_appended_lock_bytes():
    with synthetic_store() as (store, scope, actor, key):
        lock = store.root / "writer.lock"
        with lock.open("ab") as output:
            output.write(b"foreign")
        assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"
        with pytest.raises(StoreQuarantined, match="pretransaction store integrity"):
            store.commit_action_event(
                event_record(store, scope, actor, "ACTION"), scope,
            )
        assert lock.read_bytes() == bytes(1) + b"foreign"
        assert store.manifest_rows() == ()
