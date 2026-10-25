"""Engine reconciliation across synthetic atomic claim and prestate-block crashes."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.i2_contract import I2ContractError
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


class _InjectedCrash(RuntimeError):
    pass


@pytest.mark.parametrize("passed", [True, False])
@pytest.mark.parametrize("stage,committed,healthy", [
    ("before_action", False, True),
    ("after_action", False, True),
    ("evidence.after_blob", False, False),
    ("after_publication_before_ack", True, True),
])
def test_atomic_run_resolution_reconciles_after_crash(passed, stage, committed, healthy):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])

        def fault(kind, point):
            if kind == "RUN_ATOMIC_PATH" and point == stage:
                raise _InjectedCrash(point)

        engine = I2Engine(I2Journal(store, fault_hook=fault), trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        engine.admit_run(_run_record(ids, session, auth, reserved.event_id),
                         auth, proof, scope, _stamp(2))
        observed = engine.observe_prestate(ids["session"], ids["run"], passed, _stamp(2))
        claim = _claim(ids, session, auth, reserved.event_id) if passed else None
        with pytest.raises(_InjectedCrash):
            engine.resolve_prestate(ids["session"], ids["run"], _stamp(2), claim=claim)

        assert (IntegrityVerifier(store.root).verify()["result"] == "PASS") is healthy
        if not healthy:
            with pytest.raises(I2ContractError, match="unhealthy"):
                I2Journal(store).history()
            return

        checkpoint, public = signed_checkpoint(store)
        reopened = EvidenceStore(
            store.root, store_id=store.store_id, lineage_id=store.lineage_id,
            writer_private_key=writer_key, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        restarted = I2Engine(I2Journal(reopened), trusted, lambda _: exact)
        run = restarted.replay()[ids["session"]].runs[ids["run"]]
        expected = "CLAIMED" if passed else "BLOCKED_PRESTATE"
        assert run.state == (expected if committed else "CREATED")
        assert run.prestate_evidence_id == observed.evidence_id
        assert not any(item.payload.get("kind") == "RUN_TRANSITION" and
                       item.payload.get("resulting_state") == "PRESTATE"
                       for item in restarted.journal.history())

        if committed:
            assert (run.claim is not None) is passed
            again = restarted.resolve_prestate(ids["session"], ids["run"],
                                                _stamp(2), claim=claim)
            assert again.payload["kind"] == "REJECTION"
            if passed:
                dispatch = restarted.transition_run(ids["session"], ids["run"],
                                                    "EXECUTING", _stamp(2), dispatch_ack=True)
                assert dispatch.payload["kind"] == "REJECTION"
                assert "launch permit" in dispatch.payload["reason"]
                closed = restarted.transition_run(ids["session"], ids["run"],
                                                  "CONSUMED_FAILED", _stamp(2),
                                                  dispatch_proven=False, cleanup_proven=True)
                assert closed.payload["resulting_state"] == "CONSUMED_FAILED"
        else:
            resolved = restarted.resolve_prestate(ids["session"], ids["run"],
                                                  _stamp(2), claim=claim)
            assert resolved.payload["kind"] == "RUN_ATOMIC_PATH"
            assert resolved.payload["logical_events"][1]["resulting_state"] == expected
            if passed:
                restarted.transition_run(ids["session"], ids["run"], "EXECUTING",
                                         _stamp(2), dispatch_ack=True)

        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
