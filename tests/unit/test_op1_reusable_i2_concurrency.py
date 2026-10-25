"""Synthetic engine races share one append-only I1-backed decision ledger."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


def test_max_runs_claim_and_terminal_races_commit_one_winner_each():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, base_auth, _, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["max_runs"] = 1
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"

        candidates = []
        for index in range(2):
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
        with ThreadPoolExecutor(max_workers=2) as pool:
            proposals = list(pool.map(lambda item: engine.reserve_run(item[3], item[1], item[2], _stamp(2)),
                                      candidates))
        assert sorted(item.payload["kind"] for item in proposals) == ["REJECTION", "RUN_RESERVATION"]
        winner = next(item for item in proposals if item.payload["kind"] == "RUN_RESERVATION")
        run_ids, auth, proof, scope = next(item for item in candidates if item[0]["run"] == winner.payload["subject_run_id"])
        run_id = run_ids["run"]
        run_record = _run_record(run_ids, session, auth, winner.event_id)
        assert engine.admit_run(run_record, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED"
        assert engine.observe_prestate(ids["session"], run_id, True, _stamp(2)).payload["kind"] == "PRESTATE_OBSERVATION"
        claim = _claim(run_ids, session, auth, winner.event_id)
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda _: engine.resolve_prestate(
                ids["session"], run_id, _stamp(2), claim=claim), range(2)))
        assert sorted(item.payload["kind"] for item in claims) == ["REJECTION", "RUN_ATOMIC_PATH"]
        assert engine.transition_run(ids["session"], run_id, "EXECUTING", _stamp(2),
                                     dispatch_ack=True).payload["resulting_state"] == "EXECUTING"
        observed = engine.observe_synthetic(ids["session"], run_id, "PASS", _stamp(2))
        with ThreadPoolExecutor(max_workers=2) as pool:
            terminals = list(pool.map(lambda _: engine.transition_run(
                ids["session"], run_id, "PASS", _stamp(2),
                evidence_ids=[observed.evidence_id], cleanup_proven=True), range(2)))
        assert sorted(item.payload["kind"] for item in terminals) == ["REJECTION", "RUN_TRANSITION"]
        view = engine.replay()[ids["session"]]
        assert len(view.reservations) == 1
        assert len(view.runs) == 1
        assert view.runs[run_id].state == "PASS"
        assert view.runs[run_id].claim == claim
        assert view.runs[run_id].terminal_event_id == next(
            item.event_id for item in terminals if item.payload["kind"] == "RUN_TRANSITION")
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
