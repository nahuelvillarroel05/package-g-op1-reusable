"""Synthetic overlapping Run reservations retain cumulative resource debits."""
from __future__ import annotations

from copy import deepcopy

from package_g.op1_reusable.i2_contract import replay_budget
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _run_record


def test_active_run_limit_reopens_after_cleanup_without_refunding_sum():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, base_auth, _, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["max_runs"] = 3
        for name in ("output_bytes", "cpu_ms", "elapsed_ms"):
            session["resource_ceilings"][name] *= 3
        session["resource_ceilings"]["memory_peak_bytes"] = 30
        session["resource_ceilings"]["max_concurrent_runs"] = 2
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"

        candidates = []
        for index in range(3):
            run_ids = deepcopy(ids)
            if index:
                for name in ("run", "attempt", "claim", "namespace", "operation"):
                    run_ids[name] = generate_id(name.upper())
                run_ids["run_authority"] = generate_id("AUTHORITY")
            auth = deepcopy(base_auth)
            auth.update(
                authority_id=run_ids["run_authority"],
                session_authority_sha256=sha256_bytes(canonical_json(session)),
                run_id=run_ids["run"], attempt_id=run_ids["attempt"],
                claim_id=run_ids["claim"], namespace_id=run_ids["namespace"],
                operation_id=run_ids["operation"],
                exact_binding_manifest_relative_path="bindings/" + run_ids["run"] + ".json",
            )
            auth["identity"]["entity_id"] = auth["authority_id"]
            auth["identity"]["run_id"] = run_ids["run"]
            proof = _signed(auth, "proof_sha256", issuer_key)
            scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                          ids["session"], run_ids["run"], run_ids["attempt"])
            candidates.append((run_ids, auth, proof, scope))

        for run_ids, auth, proof, scope in candidates[:2]:
            reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
            assert reserved.payload["kind"] == "RUN_RESERVATION"
            run = _run_record(run_ids, session, auth, reserved.event_id)
            assert engine.admit_run(run, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED"
            assert engine.observe_prestate(ids["session"], run_ids["run"], False, _stamp(2)).payload["kind"] == "PRESTATE_OBSERVATION"
        third_ids, third_auth, third_proof, third_scope = candidates[2]
        over = engine.reserve_run(third_scope, third_auth, third_proof, _stamp(2))
        assert over.payload["kind"] == "REJECTION"
        assert "concurrent Run budget exceeded" in over.payload["reason"]
        first_id = candidates[0][0]["run"]
        closed = engine.resolve_prestate(ids["session"], first_id, _stamp(2))
        assert closed.payload["logical_events"][1]["resulting_state"] == "BLOCKED_PRESTATE"
        assert engine.release_run_budget(ids["session"], first_id, True, _stamp(2)).payload["kind"] == "BUDGET_RELEASE"
        assert engine.continue_after_run(ids["session"], first_id, _stamp(2)).payload["resulting_state"] == "ACTIVE"
        accepted = engine.reserve_run(third_scope, third_auth, third_proof, _stamp(2))
        assert accepted.payload["kind"] == "RUN_RESERVATION"
        view = engine.replay()[ids["session"]]
        budget = replay_budget(session["resource_ceilings"], session["max_runs"], view.budget_events)
        assert budget.runs_reserved == 3
        assert budget.active_runs == 2
        assert budget.active_memory == 20
        assert budget.cumulative["output_bytes"] == 600
        assert first_id in budget.released
        assert view.runs[first_id].state == "BLOCKED_PRESTATE"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
