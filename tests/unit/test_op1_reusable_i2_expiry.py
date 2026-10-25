"""Synthetic Session activation, clock, and between-Run expiry boundaries."""
from __future__ import annotations

from copy import deepcopy

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record
from test_op1_reusable_i2_dispatch_recovery import _claimed_engine


def test_preactivation_clock_rollback_and_expiry_preserve_prior_run():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, _, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["expires_at_utc"] = _stamp(4)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        auth["expires_at_utc"] = _stamp(3)
        auth["session_authority_sha256"] = sha256_bytes(canonical_json(session))
        proof = _signed(auth, "proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        before_activation = engine.reserve_run(scope, auth, proof, _stamp(1))
        assert before_activation.payload["kind"] == "REJECTION"
        assert "inactive Session" in before_activation.payload["reason"]
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        rollback = engine.reserve_run(scope, auth, proof, _stamp(1))
        assert rollback.payload["kind"] == "REJECTION"
        assert "clock moved backward" in rollback.payload["reason"]
        reservation = engine.reserve_run(scope, auth, proof, _stamp(2))
        assert reservation.payload["kind"] == "RUN_RESERVATION"
        run = _run_record(ids, session, auth, reservation.event_id)
        assert engine.admit_run(run, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED"
        assert engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2)).payload["kind"] == "PRESTATE_OBSERVATION"
        claim = _claim(ids, session, auth, reservation.event_id)
        assert engine.resolve_prestate(ids["session"], ids["run"], _stamp(2),
                                       claim=claim).payload["logical_events"][1]["resulting_state"] == "CLAIMED"
        assert engine.transition_run(ids["session"], ids["run"], "EXECUTING", _stamp(2),
                                     dispatch_ack=True).payload["resulting_state"] == "EXECUTING"
        observed = engine.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
        closed = engine.transition_run(ids["session"], ids["run"], "PASS", _stamp(2),
                                       evidence_ids=[observed.evidence_id], cleanup_proven=True)
        assert closed.payload["resulting_state"] == "PASS"
        assert engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2)).payload["kind"] == "BUDGET_RELEASE"
        assert engine.continue_after_run(ids["session"], ids["run"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        next_ids = deepcopy(ids)
        for name in ("run", "attempt", "claim", "namespace", "operation"):
            next_ids[name] = generate_id(name.upper())
        next_ids["run_authority"] = generate_id("AUTHORITY")
        next_auth = deepcopy(auth)
        next_auth.update(
            authority_id=next_ids["run_authority"], run_id=next_ids["run"],
            attempt_id=next_ids["attempt"], claim_id=next_ids["claim"],
            namespace_id=next_ids["namespace"], operation_id=next_ids["operation"],
            expires_at_utc=_stamp(4),
            exact_binding_manifest_relative_path="bindings/" + next_ids["run"] + ".json",
        )
        next_auth["identity"]["entity_id"] = next_ids["run_authority"]
        next_auth["identity"]["run_id"] = next_ids["run"]
        next_proof = _signed(next_auth, "proof_sha256", issuer_key)
        next_scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                           ids["session"], next_ids["run"], next_ids["attempt"])
        expired_proposal = engine.reserve_run(next_scope, next_auth, next_proof, _stamp(4))
        assert expired_proposal.payload["kind"] == "REJECTION"
        assert "not currently valid" in expired_proposal.payload["reason"]
        assert engine.transition_session(ids["session"], "EXPIRED", _stamp(4),
                                         reason="expiry").payload["resulting_state"] == "EXPIRED"
        view = engine.replay()[ids["session"]]
        assert view.state == "EXPIRED"
        assert list(view.runs) == [ids["run"]]
        assert view.runs[ids["run"]].state == "PASS"
        assert view.runs[ids["run"]].claim == claim
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_expiry_after_consumed_claim_blocks_launch_and_preserves_run():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        expiry = engine.replay()[ids["session"]].authority["expires_at_utc"]
        rejected = engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                                         expiry, dispatch_ack=True)
        assert rejected.payload["kind"] == "REJECTION"
        assert "not currently valid" in rejected.payload["reason"]
        run = engine.replay()[ids["session"]].runs[ids["run"]]
        assert run.state == "CLAIMED" and run.claim["state"] == "CONSUMED"
        closed = engine.transition_run(ids["session"], ids["run"], "CONSUMED_FAILED",
                                       expiry, dispatch_proven=False, cleanup_proven=True)
        assert closed.payload["resulting_state"] == "CONSUMED_FAILED"
        engine.release_run_budget(ids["session"], ids["run"], True, expiry)
        expired = engine.continue_after_run(ids["session"], ids["run"], expiry)
        assert expired.payload["resulting_state"] == "EXPIRED"
        assert engine.replay()[ids["session"]].runs[ids["run"]].claim["state"] == "CONSUMED"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
