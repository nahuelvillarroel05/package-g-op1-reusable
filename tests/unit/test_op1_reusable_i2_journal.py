"""I2 publication and claim-serialization tests on the unchanged I1 store."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import generate_id
from package_g.op1_reusable.integrity import IntegrityVerifier

from op1_reusable_i1_helpers import synthetic_store


def test_session_and_run_history_commit_through_i1_publication():
    with synthetic_store() as (store, scope, actor, key):
        journal = I2Journal(store)
        first = journal.transact(scope, lambda history: {
            "kind": "SESSION_CREATED", "subject_session_id": scope.session_id,
            "previous_state": None, "requested_next_state": "CREATED",
            "resulting_state": "CREATED", "evidence_ids": [],
        })
        second = journal.transact(scope, lambda history: {
            "kind": "SESSION_TRANSITION", "subject_session_id": scope.session_id,
            "previous_state": history[-1].payload["resulting_state"],
            "requested_next_state": "ACTIVE", "resulting_state": "ACTIVE",
            "evidence_ids": [history[-1].evidence_id],
        })
        records = journal.history()
        assert [item.event_id for item in records] == [first.event_id, second.event_id]
        assert records[1].payload["causal_predecessor_event_id"] == first.event_id
        assert records[1].payload["evidence_ids"] == [first.evidence_id]
        assert records[0].payload["custody_run_id"] == scope.run_id
        assert records[0].payload["subject_session_id"] == scope.session_id
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_concurrent_claim_attempts_publish_one_claim_and_preserve_rejection():
    with synthetic_store() as (store, scope, actor, key):
        journal = I2Journal(store)
        run_id = scope.run_id

        def attempt(_):
            return journal.transact(scope, lambda history: {
                "kind": ("CLAIM" if not any(item.payload["kind"] == "CLAIM"
                                            and item.payload.get("subject_run_id") == run_id
                                            for item in history) else "REJECTION"),
                "subject_session_id": scope.session_id,
                "subject_run_id": run_id,
                "claim_id": generate_id("CLAIM"),
                "reason": "DUPLICATE_CLAIM" if any(
                    item.payload["kind"] == "CLAIM" and item.payload.get("subject_run_id") == run_id
                    for item in history) else None,
                "evidence_ids": [item.evidence_id for item in history],
            })

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        history = journal.history()
        assert len(results) == len(history) == 2
        assert [item.payload["kind"] for item in history] == ["CLAIM", "REJECTION"]
        assert history[0].payload["claim_id"] != history[1].payload["claim_id"]
        assert history[1].payload["evidence_ids"] == [history[0].evidence_id]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
