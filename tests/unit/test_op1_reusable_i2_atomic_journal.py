"""One I1 publication commits both synthetic Run transition events or neither."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.i2_contract import I2ContractError
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import generate_id, validate_id
from package_g.op1_reusable.integrity import IntegrityVerifier

from op1_reusable_i1_helpers import synthetic_store


class _InjectedCrash(RuntimeError):
    pass


def _path(scope, session_authority_id, run_authority_id, prior_evidence_id, terminal):
    return {
        "kind": "RUN_ATOMIC_PATH",
        "subject_session_id": scope.session_id,
        "subject_run_id": scope.run_id,
        "logical_events": [
            {"subject_session_id": scope.session_id, "subject_run_id": scope.run_id,
             "session_authority_id": session_authority_id,
             "run_authority_id": run_authority_id,
             "previous_state": "CREATED", "requested_next_state": "PRESTATE",
             "resulting_state": "PRESTATE", "evidence_ids": [prior_evidence_id]},
            {"subject_session_id": scope.session_id, "subject_run_id": scope.run_id,
             "session_authority_id": session_authority_id,
             "run_authority_id": run_authority_id,
             "previous_state": "PRESTATE", "requested_next_state": terminal,
             "resulting_state": terminal, "evidence_ids": [prior_evidence_id]},
        ],
        "evidence_ids": [prior_evidence_id],
    }


@pytest.mark.parametrize("terminal", ["CLAIMED", "BLOCKED_PRESTATE"])
def test_atomic_path_has_two_ordered_events_under_one_publication(terminal):
    with synthetic_store() as (store, scope, actor, writer_key):
        journal = I2Journal(store)
        prior = journal.transact(scope, lambda _: {
            "kind": "RUN_ADMITTED", "subject_session_id": scope.session_id,
            "subject_run_id": scope.run_id, "evidence_ids": [],
        })
        batch = journal.transact(scope, lambda _: _path(
            scope, generate_id("AUTHORITY"), generate_id("AUTHORITY"),
            prior.evidence_id, terminal))
        events = batch.payload["logical_events"]
        assert len(events) == 2
        assert all(validate_id(event["event_id"], "EVENT") for event in events)
        assert len({event["event_id"] for event in events}) == 2
        assert events[0]["causal_predecessor_event_id"] == prior.event_id
        assert events[1]["causal_predecessor_event_id"] == events[0]["event_id"]
        assert all(batch.evidence_id in event["evidence_ids"] for event in events)
        assert [event["resulting_state"] for event in events] == ["PRESTATE", terminal]
        assert [item.payload["kind"] for item in journal.history()] == [
            "RUN_ADMITTED", "RUN_ATOMIC_PATH"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


@pytest.mark.parametrize("stage,committed,healthy", [
    ("before_action", False, True),
    ("evidence.after_blob", False, False),
    ("after_publication_before_ack", True, True),
])
def test_atomic_path_fault_never_exposes_standalone_prestate(stage, committed, healthy):
    with synthetic_store() as (store, scope, actor, writer_key):
        journal = I2Journal(store)
        prior = journal.transact(scope, lambda _: {
            "kind": "RUN_ADMITTED", "subject_session_id": scope.session_id,
            "subject_run_id": scope.run_id, "evidence_ids": [],
        })
        def fault(kind, point):
            if kind == "RUN_ATOMIC_PATH" and point == stage:
                raise _InjectedCrash(point)
        faulted = I2Journal(store, fault_hook=fault)
        with pytest.raises(_InjectedCrash):
            faulted.transact(scope, lambda _: _path(
                scope, generate_id("AUTHORITY"), generate_id("AUTHORITY"),
                prior.evidence_id, "BLOCKED_PRESTATE"))
        assert (IntegrityVerifier(store.root).verify()["result"] == "PASS") is healthy
        if not healthy:
            with pytest.raises(I2ContractError, match="unhealthy"):
                I2Journal(store).history()
        else:
            rows = I2Journal(store).history()
            assert len(rows) == 1 + int(committed)
            if committed:
                assert rows[-1].payload["logical_events"][1]["resulting_state"] == "BLOCKED_PRESTATE"
            assert not any(row.payload.get("kind") == "RUN_TRANSITION"
                           and row.payload.get("resulting_state") == "PRESTATE" for row in rows)


def test_atomic_path_rejects_authority_switch_without_publication():
    with synthetic_store() as (store, scope, actor, writer_key):
        journal = I2Journal(store)
        prior = journal.transact(scope, lambda _: {
            "kind": "RUN_ADMITTED", "subject_session_id": scope.session_id,
            "subject_run_id": scope.run_id, "evidence_ids": [],
        })
        proposed = _path(scope, generate_id("AUTHORITY"), generate_id("AUTHORITY"),
                         prior.evidence_id, "CLAIMED")
        proposed["logical_events"][1]["run_authority_id"] = generate_id("AUTHORITY")
        with pytest.raises(I2ContractError, match="authority changed"):
            journal.transact(scope, lambda _: proposed)
        assert [row.payload["kind"] for row in journal.history()] == ["RUN_ADMITTED"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
