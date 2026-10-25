"""A restarted synthetic controller cannot launch a consumed claim."""
from __future__ import annotations

from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


def test_claimed_run_cannot_dispatch_after_controller_restart():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        run = _run_record(ids, session, auth, reserved.event_id)
        assert engine.admit_run(run, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED"
        assert engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2)).payload["kind"] == "PRESTATE_OBSERVATION"
        claim = _claim(ids, session, auth, reserved.event_id)
        claimed = engine.resolve_prestate(ids["session"], ids["run"], _stamp(2), claim=claim)
        assert claimed.payload["logical_events"][1]["resulting_state"] == "CLAIMED"
        checkpoint, public = signed_checkpoint(store)
        reopened = EvidenceStore(
            store.root, store_id=store.store_id, lineage_id=store.lineage_id,
            writer_private_key=writer_key, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        restarted = I2Engine(I2Journal(reopened), trusted, lambda _: exact)
        replay = restarted.replay()[ids["session"]].runs[ids["run"]]
        assert replay.state == "CLAIMED" and replay.claim == claim
        relaunch = restarted.transition_run(ids["session"], ids["run"], "EXECUTING",
                                            _stamp(2), dispatch_ack=True)
        assert relaunch.payload["kind"] == "REJECTION"
        assert "launch permit" in relaunch.payload["reason"]
        assert restarted.replay()[ids["session"]].runs[ids["run"]].state == "CLAIMED"
        closed = restarted.transition_run(ids["session"], ids["run"], "CONSUMED_FAILED",
                                           _stamp(2), dispatch_proven=False,
                                           cleanup_proven=True)
        assert closed.payload["resulting_state"] == "CONSUMED_FAILED"
        assert restarted.release_run_budget(ids["session"], ids["run"], True,
                                            _stamp(2)).payload["kind"] == "BUDGET_RELEASE"
        assert restarted.continue_after_run(ids["session"], ids["run"],
                                            _stamp(2)).payload["resulting_state"] == "ACTIVE"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


class _LostClaimAck(RuntimeError):
    pass


def test_lost_claim_ack_does_not_grant_local_launch_permit():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        def fault(kind, stage):
            if kind == "RUN_ATOMIC_PATH" and stage == "after_publication_before_ack":
                raise _LostClaimAck("durable claim ack lost")

        engine = I2Engine(I2Journal(store, fault_hook=fault), trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        run = _run_record(ids, session, auth, reserved.event_id)
        engine.admit_run(run, auth, proof, scope, _stamp(2))
        engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2))
        claim = _claim(ids, session, auth, reserved.event_id)
        try:
            engine.resolve_prestate(ids["session"], ids["run"], _stamp(2), claim=claim)
        except _LostClaimAck:
            pass
        else:
            raise AssertionError("claim acknowledgement fault did not fire")
        assert engine.replay()[ids["session"]].runs[ids["run"]].state == "CLAIMED"
        attempt = engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                                        _stamp(2), dispatch_ack=True)
        assert attempt.payload["kind"] == "REJECTION"
        assert "launch permit" in attempt.payload["reason"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
