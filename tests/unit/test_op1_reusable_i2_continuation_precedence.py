"""Uncontained Run ambiguity quarantines before ordinary Session expiry/exhaustion."""
from __future__ import annotations

import pytest

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


@pytest.mark.parametrize("boundary", ["expiry", "max_runs"])
def test_uncontained_unknown_quarantines_before_ordinary_boundary(boundary):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        if boundary == "expiry":
            session["expires_at_utc"] = _stamp(3)
            auth["expires_at_utc"] = _stamp(3)
        else:
            session["max_runs"] = 1
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        auth["session_authority_sha256"] = sha256_bytes(canonical_json(session))
        proof = _signed(auth, "proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        engine.admit_run(_run_record(ids, session, auth, reserved.event_id),
                         auth, proof, scope, _stamp(2))
        engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2))
        claim = _claim(ids, session, auth, reserved.event_id)
        engine.resolve_prestate(ids["session"], ids["run"], _stamp(2), claim=claim)
        engine.transition_run(ids["session"], ids["run"], "EXECUTING", _stamp(2),
                              dispatch_ack=True)
        observed = engine.observe_synthetic(ids["session"], ids["run"], "UNKNOWN", _stamp(2))
        engine.transition_run(ids["session"], ids["run"], "UNKNOWN", _stamp(2),
                              evidence_ids=[observed.evidence_id], cleanup_proven=True)
        engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
        now = _stamp(3) if boundary == "expiry" else _stamp(2)
        decision = engine.continue_after_run(ids["session"], ids["run"], now)
        assert decision.payload["resulting_state"] == "QUARANTINED"
        assert "UNCONTAINED_RUN_UNCERTAINTY" in decision.payload["applicable_findings"]
        assert ("EXPIRY" if boundary == "expiry" else "MAX_RUNS") in decision.payload["applicable_findings"]
        assert engine.replay()[ids["session"]].runs[ids["run"]].state == "UNKNOWN"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
