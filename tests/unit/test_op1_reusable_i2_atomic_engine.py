"""Fresh synthetic Runs use frozen atomic prestate paths."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


@pytest.mark.parametrize("prestate,expected", [
    (True, "CLAIMED"), (False, "BLOCKED_PRESTATE"), (None, "BLOCKED_PRESTATE"),
])
def test_atomic_resolution_never_commits_standalone_prestate(prestate, expected):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        run = _run_record(ids, session, auth, reserved.event_id)
        engine.admit_run(run, auth, proof, scope, _stamp(2))
        observed = engine.observe_prestate(ids["session"], ids["run"], prestate, _stamp(2))
        assert observed.payload["kind"] == "PRESTATE_OBSERVATION"
        for forbidden in ("PRESTATE", "CLAIMED", "BLOCKED_PRESTATE", "REJECTED_AUTHORITY"):
            bypass = engine.transition_run(ids["session"], ids["run"], forbidden, _stamp(2))
            assert bypass.payload["kind"] == "REJECTION"
            assert "atomic resolution" in bypass.payload["reason"]
        assert engine.replay()[ids["session"]].runs[ids["run"]].state == "CREATED"
        claim = _claim(ids, session, auth, reserved.event_id) if prestate else None
        result = engine.resolve_prestate(ids["session"], ids["run"], _stamp(2), claim=claim)
        assert result.payload["kind"] == "RUN_ATOMIC_PATH"
        assert [event["resulting_state"] for event in result.payload["logical_events"]] == [
            "PRESTATE", expected]
        view = engine.replay()[ids["session"]].runs[ids["run"]]
        assert view.state == expected
        assert view.prestate_evidence_id == observed.evidence_id
        assert not any(item.payload.get("kind") == "RUN_TRANSITION" and
                       item.payload.get("resulting_state") == "PRESTATE"
                       for item in engine.journal.history())
        if prestate:
            assert view.claim == claim
            assert view.claim_event_id == result.payload["logical_events"][1]["event_id"]
            dispatched = engine.transition_run(ids["session"], ids["run"],
                                               "EXECUTING", _stamp(2), dispatch_ack=True)
            assert dispatched.payload["resulting_state"] == "EXECUTING"
        else:
            assert view.terminal_event_id == result.payload["logical_events"][1]["event_id"]
            engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
            assert engine.continue_after_run(ids["session"], ids["run"],
                                             _stamp(2)).payload["resulting_state"] == "ACTIVE"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_preclaim_binding_mismatch_closes_created_run_without_missing_edge():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        current_exact = [exact]
        engine = I2Engine(I2Journal(store), trusted, lambda _: current_exact[0])
        engine.create_session(session, session_proof, _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        run = _run_record(ids, session, auth, reserved.event_id)
        engine.admit_run(run, auth, proof, scope, _stamp(2))
        engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2))
        current_exact[0] = exact + b" "
        result = engine.resolve_prestate(ids["session"], ids["run"], _stamp(2),
                                         claim=_claim(ids, session, auth, reserved.event_id))
        assert result.payload["kind"] == "RUN_TRANSITION"
        assert (result.payload["previous_state"], result.payload["resulting_state"]) == (
            "CREATED", "REJECTED_AUTHORITY")
        view = engine.replay()[ids["session"]].runs[ids["run"]]
        assert view.state == "REJECTED_AUTHORITY" and view.claim is None
        engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
        assert engine.continue_after_run(ids["session"], ids["run"],
                                         _stamp(2)).payload["resulting_state"] == "QUARANTINED"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
