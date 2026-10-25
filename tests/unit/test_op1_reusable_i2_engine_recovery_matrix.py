"""Engine recovery around synthetic execution, closure, and Session decisions."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _stamp
from test_op1_reusable_i2_dispatch_recovery import _claimed_engine


class _InjectedCrash(RuntimeError):
    pass


def _restart(store, writer_key, trusted, exact):
    checkpoint, public = signed_checkpoint(store)
    reopened = EvidenceStore(
        store.root, store_id=store.store_id, lineage_id=store.lineage_id,
        writer_private_key=writer_key, trusted_checkpoint=checkpoint,
        trusted_checkpoint_public_key_hex=public,
    )
    return I2Engine(I2Journal(reopened), trusted, lambda _: exact)


@pytest.mark.parametrize("target,stage", [
    ("SYNTHETIC_OBSERVATION", "after_action"),
    ("SYNTHETIC_OBSERVATION", "after_publication_before_ack"),
    ("RUN_TRANSITION", "after_publication_before_ack"),
    ("BUDGET_RELEASE", "after_publication_before_ack"),
])
def test_recovery_does_not_reexecute_or_mutate_terminal_history(target, stage):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        armed = {"kind": None}
        def fault(kind, point):
            if armed["kind"] == kind and point == stage:
                raise _InjectedCrash(f"{kind}:{point}")

        engine, ids, exact, trusted = _claimed_engine(store, base_scope, fault_hook=fault)
        launch = engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                                       _stamp(2), dispatch_ack=True)
        assert launch.payload["resulting_state"] == "EXECUTING"
        observation = None
        if target != "SYNTHETIC_OBSERVATION":
            observation = engine.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
        if target == "BUDGET_RELEASE":
            terminal = engine.transition_run(ids["session"], ids["run"], "PASS", _stamp(2),
                                             evidence_ids=[observation.evidence_id], cleanup_proven=True)
            assert terminal.payload["resulting_state"] == "PASS"
        armed["kind"] = target
        with pytest.raises(_InjectedCrash):
            if target == "SYNTHETIC_OBSERVATION":
                engine.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
            elif target == "RUN_TRANSITION":
                engine.transition_run(ids["session"], ids["run"], "PASS", _stamp(2),
                                      evidence_ids=[observation.evidence_id], cleanup_proven=True)
            else:
                engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
        restarted = _restart(store, writer_key, trusted, exact)
        run = restarted.replay()[ids["session"]].runs[ids["run"]]
        if target == "SYNTHETIC_OBSERVATION":
            assert run.state == "EXECUTING"
            expected = int(stage == "after_publication_before_ack")
            assert len(run.observation_evidence_ids) == expected
            again = restarted.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
            assert again.payload["kind"] == "REJECTION"
            if expected:
                terminal = restarted.transition_run(
                    ids["session"], ids["run"], "PASS", _stamp(2),
                    evidence_ids=run.observation_evidence_ids, cleanup_proven=True)
                assert terminal.payload["resulting_state"] == "PASS"
            else:
                closed = restarted.transition_run(ids["session"], ids["run"], "UNKNOWN", _stamp(2))
                assert closed.payload["resulting_state"] == "UNKNOWN"
        else:
            assert run.state == "PASS"
            if target == "RUN_TRANSITION":
                duplicate = restarted.transition_run(ids["session"], ids["run"], "FAIL", _stamp(2),
                                                     evidence_ids=[observation.evidence_id])
                assert duplicate.payload["kind"] == "REJECTION"
            else:
                assert ids["run"] in restarted.replay()[ids["session"]].reservations
                duplicate = restarted.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
                assert duplicate.payload["kind"] == "REJECTION"
                assert restarted.continue_after_run(ids["session"], ids["run"],
                                                    _stamp(2)).payload["resulting_state"] == "ACTIVE"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_quarantine_publication_lost_ack_remains_terminal_after_restart():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        armed = {"enabled": False}
        def fault(kind, point):
            if armed["enabled"] and kind == "SESSION_TRANSITION" and point == "after_publication_before_ack":
                raise _InjectedCrash(point)

        engine, ids, exact, trusted = _claimed_engine(store, base_scope, fault_hook=fault)
        engine.transition_run(ids["session"], ids["run"], "EXECUTING", _stamp(2), dispatch_ack=True)
        observed = engine.observe_synthetic(ids["session"], ids["run"], "UNKNOWN", _stamp(2))
        closed = engine.transition_run(ids["session"], ids["run"], "UNKNOWN", _stamp(2),
                                       evidence_ids=[observed.evidence_id], cleanup_proven=False)
        assert closed.payload["resulting_state"] == "UNKNOWN"
        armed["enabled"] = True
        with pytest.raises(_InjectedCrash):
            engine.continue_after_run(ids["session"], ids["run"], _stamp(2))
        restarted = _restart(store, writer_key, trusted, exact)
        assert restarted.replay()[ids["session"]].state == "QUARANTINED"
        assert restarted.continue_after_run(ids["session"], ids["run"],
                                            _stamp(2)).payload["kind"] == "REJECTION"
        assert restarted.activate_session(ids["session"], _stamp(2)).payload["kind"] == "REJECTION"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
