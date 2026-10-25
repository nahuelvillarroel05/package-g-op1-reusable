"""Synthetic five-Run Session history, with immutable earlier failures."""
from __future__ import annotations

from copy import deepcopy
import os
import shutil
from pathlib import Path

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


def test_five_runs_preserve_fail_block_timeout_and_later_pass():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, base_auth, _, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["max_runs"] = 5
        for name in ("output_bytes", "cpu_ms", "elapsed_ms"):
            session["resource_ceilings"][name] *= 5
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"

        outcomes = ("PASS", "FAIL", "BLOCKED_PRESTATE", "TIMEOUT", "PASS")
        run_ids = []
        for index, outcome in enumerate(outcomes):
            run_ids_for_iteration = deepcopy(ids)
            if index:
                for name in ("run", "attempt", "claim", "namespace", "operation"):
                    run_ids_for_iteration[name] = generate_id(name.upper())
                run_ids_for_iteration["run_authority"] = generate_id("AUTHORITY")
            run_id = run_ids_for_iteration["run"]
            auth = deepcopy(base_auth)
            auth.update(
                authority_id=run_ids_for_iteration["run_authority"],
                session_authority_sha256=sha256_bytes(canonical_json(session)),
                run_id=run_id, attempt_id=run_ids_for_iteration["attempt"],
                claim_id=run_ids_for_iteration["claim"],
                namespace_id=run_ids_for_iteration["namespace"],
                operation_id=run_ids_for_iteration["operation"],
                exact_binding_manifest_relative_path="bindings/" + run_id + ".json",
            )
            auth["identity"]["entity_id"] = auth["authority_id"]
            auth["identity"]["run_id"] = run_id
            proof = _signed(auth, "proof_sha256", issuer_key)
            scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                          ids["session"], run_id, run_ids_for_iteration["attempt"])
            now = _stamp(index + 2)
            reserved = engine.reserve_run(scope, auth, proof, now)
            assert reserved.payload["kind"] == "RUN_RESERVATION"
            run_record = _run_record(run_ids_for_iteration, session, auth, reserved.event_id)
            assert engine.admit_run(run_record, auth, proof, scope, now).payload["kind"] == "RUN_ADMITTED"
            assert engine.observe_prestate(ids["session"], run_id, outcome != "BLOCKED_PRESTATE", now).payload["kind"] == "PRESTATE_OBSERVATION"
            if outcome == "BLOCKED_PRESTATE":
                closed = engine.resolve_prestate(ids["session"], run_id, now)
            else:
                claim = _claim(run_ids_for_iteration, session, auth, reserved.event_id)
                assert engine.resolve_prestate(ids["session"], run_id, now,
                                               claim=claim).payload["logical_events"][1]["resulting_state"] == "CLAIMED"
                assert engine.transition_run(ids["session"], run_id, "EXECUTING", now,
                                             dispatch_ack=True).payload["resulting_state"] == "EXECUTING"
                observation = engine.observe_synthetic(ids["session"], run_id, outcome, now)
                closed = engine.transition_run(ids["session"], run_id, outcome, now,
                                               evidence_ids=[observation.evidence_id],
                                               effect_classified=True, cleanup_proven=True)
            if outcome == "BLOCKED_PRESTATE":
                assert closed.payload["logical_events"][1]["resulting_state"] == outcome
            else:
                assert closed.payload["resulting_state"] == outcome
            assert engine.release_run_budget(ids["session"], run_id, True, now).payload["kind"] == "BUDGET_RELEASE"
            expected_session = "TERMINATED" if index == 4 else "ACTIVE"
            assert engine.continue_after_run(ids["session"], run_id, now).payload["resulting_state"] == expected_session
            run_ids.append(run_id)

        view = engine.replay()[ids["session"]]
        assert [view.runs[run_id].state for run_id in run_ids] == list(outcomes)
        assert len(set(run_ids)) == len(outcomes)
        assert len({view.runs[run_id].terminal_event_id for run_id in run_ids}) == len(outcomes)
        assert {run_id for run_id in run_ids if view.runs[run_id].claim is not None} == {
            run_id for run_id, outcome in zip(run_ids, outcomes) if outcome != "BLOCKED_PRESTATE"
        }
        assert len(view.reservations) == 5
        assert view.state == "TERMINATED"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
        export = os.environ.get("I2_HISTORY_EXPORT_DIR")
        if export:
            destination = Path(export).resolve(strict=False)
            if destination.exists():
                raise AssertionError("engineering history export target already exists")
            destination.parent.mkdir(parents=True, exist_ok=True)
            checkpoint, public_key = signed_checkpoint(store)
            shutil.copytree(store.root, destination)
            assert IntegrityVerifier(destination).verify(
                trusted_checkpoint=checkpoint,
                trusted_checkpoint_public_key_hex=public_key,
            )["result"] == "PASS"
            receipt = {
                "schema": "package-g-op1-reusable-i2-synthetic-history-export@1",
                "campaign_id": os.environ["I2_ENGINEERING_CAMPAIGN_ID"],
                "engineering_attempt_id": os.environ["I2_ENGINEERING_ATTEMPT_ID"],
                "session_id": ids["session"],
                "session_authority_id": session["authority_id"],
                "profile": session["profile"],
                "original_evidence_root": str(store.root),
                "exported_evidence_root": str(destination),
                "states": list(outcomes),
                "runs": [
                    {
                        "run_id": run_id,
                        "attempt_id": view.runs[run_id].authority["attempt_id"],
                        "run_authority_id": view.runs[run_id].authority["authority_id"],
                        "claim_id": view.runs[run_id].authority["claim_id"],
                        "namespace_id": view.runs[run_id].authority["namespace_id"],
                        "terminal_event_id": view.runs[run_id].terminal_event_id,
                        "observation_evidence_ids": view.runs[run_id].observation_evidence_ids,
                        "resulting_state": view.runs[run_id].state,
                    }
                    for run_id in run_ids
                ],
                "checkpoint": checkpoint,
                "checkpoint_public_key_hex": public_key,
                "manifest_rows": len(store.manifest_rows()),
                "integrity_result": "PASS",
                "physical_c2_executed": False,
            }
            destination.with_suffix(".receipt.json").write_bytes(canonical_json(receipt))
