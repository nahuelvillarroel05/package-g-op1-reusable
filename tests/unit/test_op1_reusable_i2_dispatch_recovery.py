"""A durable launch intent alone cannot authorize another synthetic execution."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


class _LostLaunchAcknowledgement(RuntimeError):
    pass


def _claimed_engine(store, base_scope, *, fault_hook=None):
    ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
        evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
    scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                  ids["session"], ids["run"], ids["attempt"])
    engine = I2Engine(I2Journal(store, fault_hook=fault_hook), trusted, lambda _: exact)
    engine.create_session(session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
    engine.activate_session(ids["session"], _stamp(2))
    reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
    engine.admit_run(_run_record(ids, session, auth, reserved.event_id),
                     auth, proof, scope, _stamp(2))
    engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2))
    result = engine.resolve_prestate(ids["session"], ids["run"], _stamp(2),
                                     claim=_claim(ids, session, auth, reserved.event_id))
    assert result.payload["logical_events"][1]["resulting_state"] == "CLAIMED"
    return engine, ids, exact, trusted


def test_lost_launch_ack_cannot_restart_synthetic_execution():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        def fault(kind, stage):
            if kind == "RUN_TRANSITION" and stage == "after_publication_before_ack":
                raise _LostLaunchAcknowledgement(stage)

        engine, ids, exact, trusted = _claimed_engine(store, base_scope, fault_hook=fault)
        with pytest.raises(_LostLaunchAcknowledgement):
            engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                                  _stamp(2), dispatch_ack=True)
        checkpoint, public = signed_checkpoint(store)
        reopened = EvidenceStore(
            store.root, store_id=store.store_id, lineage_id=store.lineage_id,
            writer_private_key=writer_key, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=public,
        )
        restarted = I2Engine(I2Journal(reopened), trusted, lambda _: exact)
        assert restarted.replay()[ids["session"]].runs[ids["run"]].state == "EXECUTING"
        attempted = restarted.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
        assert attempted.payload["kind"] == "REJECTION"
        assert "execution permit" in attempted.payload["reason"]
        assert not any(item.payload.get("kind") == "SYNTHETIC_OBSERVATION"
                       for item in restarted.journal.history())
        closed = restarted.transition_run(ids["session"], ids["run"], "UNKNOWN", _stamp(2))
        assert closed.payload["resulting_state"] == "UNKNOWN"
        assert restarted.continue_after_run(ids["session"], ids["run"],
                                            _stamp(2)).payload["resulting_state"] == "QUARANTINED"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_two_synthetic_observations_can_execute_only_once():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        launched = engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                                         _stamp(2), dispatch_ack=True)
        assert launched.payload["resulting_state"] == "EXECUTING"
        with ThreadPoolExecutor(max_workers=2) as pool:
            rows = list(pool.map(lambda _: engine.observe_synthetic(
                ids["session"], ids["run"], "PASS", _stamp(2)), range(2)))
        assert sorted(row.payload["kind"] for row in rows) == ["REJECTION", "SYNTHETIC_OBSERVATION"]
        assert len([item for item in engine.journal.history()
                    if item.payload.get("kind") == "SYNTHETIC_OBSERVATION"]) == 1
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_incomplete_evidence_requires_prior_synthetic_provenance():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                              _stamp(2), dispatch_ack=True)
        observed = engine.observe_synthetic(ids["session"], ids["run"],
                                            "INCOMPLETE_EVIDENCE", _stamp(2))
        assert observed.payload["outcome"] == "INCOMPLETE_EVIDENCE"
        missing = engine.transition_run(ids["session"], ids["run"],
                                        "INCOMPLETE_EVIDENCE", _stamp(2))
        assert missing.payload["kind"] == "REJECTION"
        closed = engine.transition_run(ids["session"], ids["run"],
                                       "INCOMPLETE_EVIDENCE", _stamp(2),
                                       evidence_ids=[observed.evidence_id])
        assert closed.payload["resulting_state"] == "INCOMPLETE_EVIDENCE"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
