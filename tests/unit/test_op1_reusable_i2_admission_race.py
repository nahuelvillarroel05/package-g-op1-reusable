"""A prepared Run cannot be admitted after Session closure."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _run_record


@pytest.mark.parametrize("terminal,reason,owner_authorized", [
    ("TERMINATED", "OWNER_TERMINATION", True),
    ("QUARANTINED", "session_invariant_violation", False),
])
def test_session_closure_between_reservation_and_admission_rejects_run(
        terminal, reason, owner_authorized):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        reservation = engine.reserve_run(scope, auth, proof, _stamp(2))
        assert reservation.payload["kind"] == "RUN_RESERVATION"
        closed = engine.transition_session(ids["session"], terminal, _stamp(2),
                                           reason=reason, owner_authorized=owner_authorized)
        assert closed.payload["resulting_state"] == terminal
        run = _run_record(ids, session, auth, reservation.event_id)
        admission = engine.admit_run(run, auth, proof, scope, _stamp(2))
        assert admission.payload["kind"] == "REJECTION"
        assert "inactive Session" in admission.payload["reason"]
        view = engine.replay()[ids["session"]]
        assert view.state == terminal
        assert ids["run"] in view.reservations and ids["run"] not in view.runs
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
