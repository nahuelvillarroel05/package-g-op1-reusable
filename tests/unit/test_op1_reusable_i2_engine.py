"""End-to-end synthetic Session reuse over I1 append-only evidence."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from package_g.op1_reusable.i2_contract import I2ContractError
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _identity, _seal_claim, _signed, _stamp


def _run_record(ids, session, auth, reservation_id):
    return {
        "identity": _identity(
            "RUN", ids["run"], session["owner_actor_id"], "OP1_RUN_SCHEMA.json",
            project_id=ids["project"], product_id=ids["product"],
            lineage_id=ids["lineage"], version_id=ids["version"],
            session_id=ids["session"], run_id=ids["run"],
        ),
        "run_id": ids["run"], "session_id": ids["session"],
        "run_authority_id": ids["run_authority"], "operation_id": ids["operation"],
        "namespace_id": ids["namespace"], "claim_id": ids["claim"],
        "claim_slot": ids["run"], "attempt_ids": [ids["attempt"]],
        "source_freeze_id": ids["freeze"], "policy_ids": [ids["policy"]],
        "target_resource_ids": [], "authorized_command_sha256": auth["command_sha256"],
        "budget_reservation_event_id": reservation_id, "opened_at_utc": _stamp(2),
    }


def _claim(ids, session, auth, reservation_id):
    return _seal_claim({
        "identity": _identity(
            "CLAIM", ids["claim"], session["owner_actor_id"],
            "OP1_RUN_CLAIM_SCHEMA.json",
            project_id=ids["project"], product_id=ids["product"],
            lineage_id=ids["lineage"], version_id=ids["version"],
            session_id=ids["session"], run_id=ids["run"], content_sha256="8" * 64,
        ),
        "claim_id": ids["claim"], "run_id": ids["run"], "session_id": ids["session"],
        "run_authority_id": ids["run_authority"], "claim_slot": ids["run"],
        "claim_operation_id": ids["operation"], "claimer_actor_id": session["owner_actor_id"],
        "namespace_id": ids["namespace"],
        "authorization_exact_sha256": sha256_bytes(canonical_json(auth)),
        "created_at_utc": _stamp(2), "durable_readback_sha256": "9" * 64,
        "reservation_event_id": reservation_id, "state": "CONSUMED",
    })


def test_reusable_session_preserves_failed_then_blocked_runs():
    with synthetic_store() as (store, initial_scope, actor, writer_key):
        ids, session, session_bytes, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=initial_scope, return_signer=True)
        session["resource_ceilings"]["output_bytes"] = 400
        session["resource_ceilings"]["cpu_ms"] = 200
        session["resource_ceilings"]["elapsed_ms"] = 200
        session["resource_ceilings"]["memory_peak_bytes"] = 20
        session["resource_ceilings"]["max_concurrent_runs"] = 2
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        auth["session_authority_sha256"] = sha256_bytes(canonical_json(session))
        proof = _signed(auth, "proof_sha256", issuer_key)

        journal = I2Journal(store)
        engine = I2Engine(journal, trusted, lambda _: exact)
        created = engine.create_session(session, session_proof, _stamp(1))
        assert created.payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"

        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        assert reserved.payload["kind"] == "RUN_RESERVATION", reserved.payload.get("reason")
        run = _run_record(ids, session, auth, reserved.event_id)
        assert engine.admit_run(run, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED", reserved.payload
        committed = journal.history()
        forged_prestate = replace(
            committed[-1], event_id=generate_id("EVENT"),
            sequence=committed[-1].sequence + 1,
            payload={"kind": "RUN_TRANSITION", "subject_session_id": ids["session"],
                     "subject_run_id": ids["run"], "previous_state": "CREATED",
                     "requested_next_state": "PRESTATE", "resulting_state": "PRESTATE",
                     "session_authority_id": session["authority_id"],
                     "run_authority_id": auth["authority_id"]},
        )
        with pytest.raises(I2ContractError, match="standalone fresh Run"):
            engine.replay(committed + (forged_prestate,))
        assert engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2)).payload["kind"] == "PRESTATE_OBSERVATION"
        claim = _claim(ids, session, auth, reserved.event_id)
        assert engine.resolve_prestate(ids["session"], ids["run"], _stamp(2),
                                       claim=claim).payload["logical_events"][1]["resulting_state"] == "CLAIMED"
        committed = journal.history()
        atomic_index = next(index for index, item in enumerate(committed)
                            if item.payload.get("kind") == "RUN_ATOMIC_PATH")
        forged = list(committed)
        forged_payload = deepcopy(forged[atomic_index].payload)
        forged_payload["claim_slot_preimage_hex"] = "00"
        forged[atomic_index] = replace(forged[atomic_index], payload=forged_payload)
        with pytest.raises(I2ContractError, match="claim slot readback bytes"):
            engine.replay(tuple(forged))
        replay = engine.resolve_prestate(ids["session"], ids["run"], _stamp(2), claim=claim)
        assert replay.payload["kind"] == "REJECTION"
        assert engine.transition_run(ids["session"], ids["run"], "EXECUTING", _stamp(2),
                                     dispatch_ack=True).payload["resulting_state"] == "EXECUTING"
        observed = engine.observe_synthetic(ids["session"], ids["run"], "FAIL", _stamp(2))
        assert engine.transition_run(
            ids["session"], ids["run"], "FAIL", _stamp(2),
            evidence_ids=[observed.evidence_id], cleanup_proven=True,
        ).payload["resulting_state"] == "FAIL"
        assert engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2)).payload["kind"] == "BUDGET_RELEASE"
        assert engine.continue_after_run(ids["session"], ids["run"], _stamp(2)).payload["resulting_state"] == "ACTIVE"

        second_ids = deepcopy(ids)
        for name in ("run", "attempt", "claim", "namespace", "operation"):
            second_ids[name] = generate_id(name.upper())
        second_ids["run_authority"] = generate_id("AUTHORITY")
        second_auth = deepcopy(auth)
        second_auth.update(
            authority_id=second_ids["run_authority"], run_id=second_ids["run"],
            claim_id=second_ids["claim"], attempt_id=second_ids["attempt"],
            namespace_id=second_ids["namespace"], operation_id=second_ids["operation"],
            exact_binding_manifest_relative_path="bindings/" + second_ids["run"] + ".json",
        )
        second_auth["identity"]["entity_id"] = second_ids["run_authority"]
        second_auth["identity"]["run_id"] = second_ids["run"]
        second_proof = _signed(second_auth, "proof_sha256", issuer_key)
        second_scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                             ids["session"], second_ids["run"], second_ids["attempt"])
        second_reserved = engine.reserve_run(second_scope, second_auth, second_proof, _stamp(3))
        assert second_reserved.payload["kind"] == "RUN_RESERVATION"
        second_run = _run_record(second_ids, session, second_auth, second_reserved.event_id)
        assert engine.admit_run(second_run, second_auth, second_proof,
                                second_scope, _stamp(3)).payload["kind"] == "RUN_ADMITTED"
        engine.observe_prestate(ids["session"], second_ids["run"], False, _stamp(3))
        blocked = engine.resolve_prestate(ids["session"], second_ids["run"], _stamp(3))
        assert blocked.payload["logical_events"][1]["resulting_state"] == "BLOCKED_PRESTATE"
        engine.release_run_budget(ids["session"], second_ids["run"], True, _stamp(3))
        assert engine.continue_after_run(ids["session"], second_ids["run"], _stamp(3)).payload["resulting_state"] == "TERMINATED"

        view = engine.replay()[ids["session"]]
        assert [view.runs[run_id].state for run_id in (ids["run"], second_ids["run"])] == [
            "FAIL", "BLOCKED_PRESTATE"]
        assert len(view.reservations) == 2
        assert view.state == "TERMINATED"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
