"""Budget release must agree with immutable terminal cleanup evidence."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.i2_contract import I2ContractError, replay_budget
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _run_record


def test_caller_cleanup_boolean_cannot_release_unproven_terminal_run():
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
        engine.admit_run(_run_record(ids, session, auth, reserved.event_id),
                         auth, proof, scope, _stamp(2))
        closed = engine.transition_run(ids["session"], ids["run"], "ABORTED_OWNER",
                                       _stamp(2), owner_abort=True)
        assert closed.payload["resulting_state"] == "ABORTED_OWNER"
        assert engine.replay()[ids["session"]].runs[ids["run"]].cleanup_proven is False
        release = engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
        assert release.payload["kind"] == "REJECTION"
        view = engine.replay()[ids["session"]]
        budget = replay_budget(session["resource_ceilings"], session["max_runs"],
                               view.budget_events)
        assert budget.active_runs == 1 and ids["run"] not in budget.released
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_replay_rejects_forged_release_after_unproven_cleanup():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        journal = I2Journal(store)
        engine = I2Engine(journal, trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        engine.admit_run(_run_record(ids, session, auth, reserved.event_id),
                         auth, proof, scope, _stamp(2))
        closed = engine.transition_run(ids["session"], ids["run"], "ABORTED_OWNER",
                                       _stamp(2), owner_abort=True)
        journal.transact(scope, lambda _: {
            "kind": "BUDGET_RELEASE", "subject_session_id": ids["session"],
            "subject_run_id": ids["run"],
            "durable_terminal_event_id": closed.event_id,
            "cleanup_proven": True, "observed_at_utc": _stamp(2),
            "evidence_ids": [],
        })
        with pytest.raises(I2ContractError, match="terminal Run cleanup proof"):
            engine.replay()
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
