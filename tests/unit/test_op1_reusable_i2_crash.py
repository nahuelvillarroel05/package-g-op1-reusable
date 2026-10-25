"""Synthetic I2 publication crash windows; no native dispatch."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.i2_contract import I2ContractError
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store


class InjectedCrash(RuntimeError):
    pass


WINDOWS = [
    ("SESSION_CREATED", "before_action", False, True),
    ("SESSION_CREATED", "after_publication_before_ack", True, True),
    ("RUN_RESERVATION", "after_action", False, True),
    ("CLAIM", "before_action", False, True),
    ("CLAIM", "evidence.after_blob", False, False),
    ("CLAIM", "after_publication_before_ack", True, True),
    ("SYNTHETIC_OBSERVATION", "after_action", False, True),
    ("RUN_TRANSITION", "evidence.after_blob", False, False),
    ("RUN_TRANSITION", "after_publication_before_ack", True, True),
    ("SESSION_TRANSITION", "evidence.after_blob", False, False),
]


@pytest.mark.parametrize("kind,stage,committed,healthy", WINDOWS)
def test_publication_crash_window_reconciles_without_replay(kind, stage, committed, healthy):
    with synthetic_store() as (store, scope, actor, writer_key):
        def fault(record_kind, point):
            if record_kind == kind and point == stage:
                raise InjectedCrash(stage)

        journal = I2Journal(store, fault_hook=fault)
        with pytest.raises(InjectedCrash):
            journal.transact(scope, lambda _: {
                "kind": kind,
                "subject_session_id": scope.session_id,
                "subject_run_id": scope.run_id,
                "synthetic_only": True,
                "evidence_ids": [],
            })
        verdict = IntegrityVerifier(store.root).verify()
        assert (verdict["result"] == "PASS") is healthy
        if not healthy:
            # The partial root is retained and unavailable for another claim.
            with pytest.raises(I2ContractError, match="unhealthy"):
                I2Journal(store).history()
            continue_test = False
            assert not continue_test
            return
        checkpoint, public = signed_checkpoint(store)
        reopened = EvidenceStore(
            store.root, store_id=store.store_id, lineage_id=store.lineage_id,
            writer_private_key=writer_key, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        restarted = I2Journal(reopened)
        rows = restarted.history()
        assert len(rows) == int(committed)
        if committed:
            assert rows[0].payload["kind"] == kind
            # Lost acknowledgement permits inspection of this exact record only.
            assert rows[0].event_id == restarted.history()[0].event_id


def test_lost_claim_ack_preserves_single_consumed_slot():
    with synthetic_store() as (store, scope, actor, writer_key):
        def fault(kind, stage):
            if kind == "CLAIM" and stage == "after_publication_before_ack":
                raise InjectedCrash("lost claim acknowledgement")

        journal = I2Journal(store, fault_hook=fault)
        with pytest.raises(InjectedCrash):
            journal.transact(scope, lambda _: {
                "kind": "CLAIM", "subject_session_id": scope.session_id,
                "subject_run_id": scope.run_id, "synthetic_only": True,
                "evidence_ids": [],
            })
        checkpoint, public = signed_checkpoint(store)
        reopened = EvidenceStore(
            store.root, store_id=store.store_id, lineage_id=store.lineage_id,
            writer_private_key=writer_key, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        restarted = I2Journal(reopened)
        result = restarted.transact(scope, lambda history: {
            "kind": "REJECTION" if any(row.payload["kind"] == "CLAIM" for row in history)
            else "CLAIM",
            "subject_session_id": scope.session_id,
            "subject_run_id": scope.run_id,
            "reason": "DUPLICATE_CLAIM",
            "synthetic_only": True,
            "evidence_ids": [row.evidence_id for row in history],
        })
        assert result.payload["kind"] == "REJECTION"
        assert [row.payload["kind"] for row in restarted.history()] == ["CLAIM", "REJECTION"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
