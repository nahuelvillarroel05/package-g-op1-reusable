"""Adversarial semantic replay checks beyond the frozen graph's bare edges."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from package_g.op1_reusable.i2_contract import I2ContractError
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_dispatch_recovery import _claimed_engine


def test_duplicate_session_id_is_preserved_as_rejection():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        signature = _signed(session, "authority_proof_sha256", issuer_key)
        first = engine.create_session(session, signature, _stamp(1))
        second = engine.create_session(session, signature, _stamp(1))
        assert first.payload["kind"] == "SESSION_CREATED"
        assert second.payload["kind"] == "REJECTION"
        assert [row.payload["kind"] for row in engine.journal.history()] == [
            "SESSION_CREATED", "REJECTION"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_terminal_outcome_must_match_prior_synthetic_observation():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                              _stamp(2), dispatch_ack=True)
        observed = engine.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
        wrong = engine.transition_run(ids["session"], ids["run"], "FAIL", _stamp(2),
                                      evidence_ids=[observed.evidence_id], cleanup_proven=True)
        assert wrong.payload["kind"] == "REJECTION"
        correct = engine.transition_run(ids["session"], ids["run"], "PASS", _stamp(2),
                                        evidence_ids=[observed.evidence_id], cleanup_proven=True)
        assert correct.payload["resulting_state"] == "PASS"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_replay_rejects_forged_terminal_label_and_authority_id():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                              _stamp(2), dispatch_ack=True)
        observed = engine.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
        terminal = engine.transition_run(ids["session"], ids["run"], "PASS", _stamp(2),
                                         evidence_ids=[observed.evidence_id], cleanup_proven=True)
        history = engine.journal.history()
        assert history[-1].event_id == terminal.event_id
        for edits in (
            {"requested_next_state": "FAIL", "resulting_state": "FAIL"},
            {"session_authority_id": "PG-AUTH-" + "0" * 32},
        ):
            forged = list(history)
            payload = deepcopy(forged[-1].payload)
            payload.update(edits)
            forged[-1] = replace(forged[-1], payload=payload)
            with pytest.raises(I2ContractError):
                engine.replay(tuple(forged))
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_replay_rejects_invented_active_quarantine_reason_and_rollback():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        quarantined = engine.transition_session(ids["session"], "QUARANTINED", _stamp(2),
                                                reason="session_invariant_violation")
        assert quarantined.payload["resulting_state"] == "QUARANTINED"
        history = engine.journal.history()
        for edits in (
            {"reason": "invented_quarantine_bypass"},
            {"previous_state": "CREATED"},
        ):
            forged = list(history)
            payload = deepcopy(forged[-1].payload)
            payload.update(edits)
            forged[-1] = replace(forged[-1], payload=payload)
            with pytest.raises(I2ContractError):
                engine.replay(tuple(forged))
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_replay_cannot_continue_crashed_run_as_healthy_session():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                              _stamp(2), dispatch_ack=True)
        observed = engine.observe_synthetic(ids["session"], ids["run"], "CRASHED", _stamp(2))
        closed = engine.transition_run(ids["session"], ids["run"], "CRASHED", _stamp(2),
                                       evidence_ids=[observed.evidence_id], cleanup_proven=True)
        assert closed.payload["resulting_state"] == "CRASHED"
        engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
        quarantined = engine.continue_after_run(ids["session"], ids["run"], _stamp(2))
        assert quarantined.payload["resulting_state"] == "QUARANTINED"
        history = list(engine.journal.history())
        payload = deepcopy(history[-1].payload)
        payload.update(requested_next_state="ACTIVE", resulting_state="ACTIVE",
                       applicable_findings=[])
        history[-1] = replace(history[-1], payload=payload)
        with pytest.raises(I2ContractError, match="continuation"):
            engine.replay(tuple(history))


@pytest.mark.parametrize("state,reason", [
    ("EXPIRED", "expiry"),
    ("TERMINATED", "MAX_RUNS"),
    ("TERMINATED", "OWNER_TERMINATION"),
])
def test_replay_rejects_premature_or_unauthorized_administrative_closure(state, reason):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        engine.transition_session(ids["session"], "QUARANTINED", _stamp(2),
                                  reason="session_invariant_violation")
        history = list(engine.journal.history())
        payload = deepcopy(history[-1].payload)
        payload.update(requested_next_state=state, resulting_state=state,
                       reason=reason, owner_authorized=False)
        history[-1] = replace(history[-1], payload=payload)
        with pytest.raises(I2ContractError):
            engine.replay(tuple(history))


def test_replay_rejects_activation_after_exact_session_expiry():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        history = list(engine.journal.history())
        payload = deepcopy(history[-1].payload)
        payload["observed_at_utc"] = session["expires_at_utc"]
        history[-1] = replace(history[-1], payload=payload)
        with pytest.raises(I2ContractError):
            engine.replay(tuple(history))


def test_replay_rejects_forged_run_continuation_termination():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        engine.transition_run(ids["session"], ids["run"], "EXECUTING",
                              _stamp(2), dispatch_ack=True)
        observed = engine.observe_synthetic(ids["session"], ids["run"], "PASS", _stamp(2))
        engine.transition_run(ids["session"], ids["run"], "PASS", _stamp(2),
                              evidence_ids=[observed.evidence_id], cleanup_proven=True)
        engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
        continued = engine.continue_after_run(ids["session"], ids["run"], _stamp(2))
        assert continued.payload["resulting_state"] == "ACTIVE"
        history = list(engine.journal.history())
        payload = deepcopy(history[-1].payload)
        payload.update(requested_next_state="TERMINATED", resulting_state="TERMINATED")
        history[-1] = replace(history[-1], payload=payload)
        with pytest.raises(I2ContractError):
            engine.replay(tuple(history))
