"""Administrative Session guards honor the frozen edge-specific reasons."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp


@pytest.mark.parametrize("reason", [
    "session_invariant_violation",
    "foreign_ownership_mutation",
    "host_exclusivity_compromise",
])
def test_created_session_quarantine_rejects_active_only_reasons(reason):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        rejected = engine.transition_session(ids["session"], "QUARANTINED", _stamp(1),
                                             reason=reason)
        assert rejected.payload["kind"] == "REJECTION"
        assert engine.replay()[ids["session"]].state == "CREATED"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


@pytest.mark.parametrize("reason", [
    "authority_integrity_failure",
    "protected_source_mismatch",
    "session_policy_mismatch",
])
def test_created_session_quarantine_accepts_exact_frozen_reasons(reason):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        closed = engine.transition_session(ids["session"], "QUARANTINED", _stamp(1),
                                           reason=reason)
        assert closed.payload["resulting_state"] == "QUARANTINED"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
