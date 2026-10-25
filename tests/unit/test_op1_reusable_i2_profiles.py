"""Both frozen Session profiles remain reusable in synthetic engineering."""
from __future__ import annotations

from copy import deepcopy

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _run_record


def test_operational_reusable_session_preserves_two_distinct_blocked_runs():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, base_auth, _, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["profile"] = "OPERATIONAL_REUSABLE"
        for name in ("output_bytes", "cpu_ms", "elapsed_ms"):
            session["resource_ceilings"][name] *= 2
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        run_ids = []
        for index in range(2):
            current_ids = deepcopy(ids)
            if index:
                for name in ("run", "attempt", "claim", "namespace", "operation"):
                    current_ids[name] = generate_id(name.upper())
                current_ids["run_authority"] = generate_id("AUTHORITY")
            auth = deepcopy(base_auth)
            auth.update(
                authority_id=current_ids["run_authority"],
                session_authority_sha256=sha256_bytes(canonical_json(session)),
                run_id=current_ids["run"], attempt_id=current_ids["attempt"],
                claim_id=current_ids["claim"], namespace_id=current_ids["namespace"],
                operation_id=current_ids["operation"],
                exact_binding_manifest_relative_path="bindings/" + current_ids["run"] + ".json",
            )
            auth["identity"]["entity_id"] = auth["authority_id"]
            auth["identity"]["run_id"] = current_ids["run"]
            proof = _signed(auth, "proof_sha256", issuer_key)
            scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                          ids["session"], current_ids["run"], current_ids["attempt"])
            reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
            assert reserved.payload["kind"] == "RUN_RESERVATION"
            run = _run_record(current_ids, session, auth, reserved.event_id)
            assert engine.admit_run(run, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED"
            engine.observe_prestate(ids["session"], current_ids["run"], False, _stamp(2))
            closed = engine.resolve_prestate(ids["session"], current_ids["run"], _stamp(2))
            assert closed.payload["logical_events"][1]["resulting_state"] == "BLOCKED_PRESTATE"
            engine.release_run_budget(ids["session"], current_ids["run"], True, _stamp(2))
            expected = "ACTIVE" if index == 0 else "TERMINATED"
            assert engine.continue_after_run(ids["session"], current_ids["run"],
                                             _stamp(2)).payload["resulting_state"] == expected
            run_ids.append(current_ids["run"])
        view = engine.replay()[ids["session"]]
        assert view.authority["profile"] == "OPERATIONAL_REUSABLE"
        assert view.state == "TERMINATED" and len(set(run_ids)) == 2
        assert [view.runs[run_id].state for run_id in run_ids] == [
            "BLOCKED_PRESTATE", "BLOCKED_PRESTATE"]
        assert all(view.runs[run_id].claim is None for run_id in run_ids)
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_operational_profile_rejects_fault_injection_operation_class():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["profile"] = "OPERATIONAL_REUSABLE"
        session["allowed_operation_classes"] = ["CONTROLLED_FAULT_INJECTION"]
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        proposal = engine.create_session(session, session_proof, _stamp(1))
        assert proposal.payload["kind"] == "REJECTION"
        assert "outside frozen profile" in proposal.payload["reason"]
        assert ids["session"] not in engine.replay()
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
