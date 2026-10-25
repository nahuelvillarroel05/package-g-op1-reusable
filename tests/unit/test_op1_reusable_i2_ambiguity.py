"""Unproven isolation cannot resume an uncertain synthetic Run."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from package_g.op1_reusable import i2_engine as engine_module
from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.i2_contract import I2ContractError
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_isolation import signed_report
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_engine import _claim, _run_record


def test_unknown_run_caller_isolation_assertion_cannot_continue_session():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        run = _run_record(ids, session, auth, reserved.event_id)
        assert engine.admit_run(run, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED", reserved.payload
        engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2))
        claim = _claim(ids, session, auth, reserved.event_id)
        assert engine.resolve_prestate(ids["session"], ids["run"], _stamp(2),
                                       claim=claim).payload["logical_events"][1]["resulting_state"] == "CLAIMED"
        assert engine.transition_run(ids["session"], ids["run"], "EXECUTING", _stamp(2),
                                     dispatch_ack=True).payload["resulting_state"] == "EXECUTING"
        observed = engine.observe_synthetic(ids["session"], ids["run"], "UNKNOWN", _stamp(2))
        assert engine.transition_run(ids["session"], ids["run"], "UNKNOWN", _stamp(2),
                                     evidence_ids=[observed.evidence_id],
                                     cleanup_proven=True).payload["resulting_state"] == "UNKNOWN"
        denied = engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2))
        assert denied.payload["kind"] == "REJECTION"
        continued = engine.continue_after_run(ids["session"], ids["run"], _stamp(2),
                                              isolation_proven=True)
        assert continued.payload["resulting_state"] == "QUARANTINED"
        assert engine.replay()[ids["session"]].runs[ids["run"]].state == "UNKNOWN"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_independent_synthetic_isolation_preserves_unknown_run_and_allows_fresh_run():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["resource_ceilings"].update(
            output_bytes=400, cpu_ms=200, elapsed_ms=200, memory_peak_bytes=20)
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        auth["session_authority_sha256"] = sha256_bytes(canonical_json(session))
        proof = _signed(auth, "proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        observer_actor = generate_id("ACTOR")
        observer_key = Ed25519PrivateKey.generate()
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact,
                          {observer_actor: observer_key.public_key()})
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        reserved = engine.reserve_run(scope, auth, proof, _stamp(2))
        run = _run_record(ids, session, auth, reserved.event_id)
        assert engine.admit_run(run, auth, proof, scope, _stamp(2)).payload["kind"] == "RUN_ADMITTED", reserved.payload
        engine.observe_prestate(ids["session"], ids["run"], True, _stamp(2))
        claim = _claim(ids, session, auth, reserved.event_id)
        assert engine.resolve_prestate(ids["session"], ids["run"], _stamp(2),
                                       claim=claim).payload["logical_events"][1]["resulting_state"] == "CLAIMED"
        assert engine.transition_run(ids["session"], ids["run"], "EXECUTING", _stamp(2),
                                     dispatch_ack=True).payload["resulting_state"] == "EXECUTING"
        side_effects = []
        original_evaluate = engine_module.evaluate
        def substituted(outcome):
            side_effects.append(outcome)
            return outcome
        engine_module.evaluate = substituted
        try:
            denied = engine.observe_synthetic(ids["session"], ids["run"], "UNKNOWN", _stamp(2))
        finally:
            engine_module.evaluate = original_evaluate
        assert denied.payload["kind"] == "REJECTION"
        assert side_effects == []
        observed = engine.observe_synthetic(ids["session"], ids["run"], "UNKNOWN", _stamp(2))
        assert engine.transition_run(ids["session"], ids["run"], "UNKNOWN", _stamp(2),
                                     evidence_ids=[observed.evidence_id],
                                     cleanup_proven=False).payload["resulting_state"] == "UNKNOWN"
        checkpoint, owner_public = signed_checkpoint(store)
        read_only_store = EvidenceStore(
            store.root, store_id=store.store_id, lineage_id=store.lineage_id,
            actor_id=store.actor_id, trusted_checkpoint=checkpoint,
            trusted_checkpoint_public_key_hex=owner_public)
        observer = I2Engine(I2Journal(read_only_store), trusted, lambda _: exact)
        report = signed_report(observer, ids["session"], ids["run"],
                               observer_actor, observer_key, _stamp(2))
        forged = dict(report)
        forged["signature_hex"] = "00" * 64
        assert engine.record_isolation_report(ids["session"], ids["run"], forged,
                                              _stamp(2)).payload["kind"] == "REJECTION"
        assert engine.record_isolation_report(ids["session"], ids["run"], report,
                                              _stamp(2)).payload["kind"] == "REJECTION"
        report = signed_report(observer, ids["session"], ids["run"],
                               observer_actor, observer_key, _stamp(2))
        wrong_namespace = dict(report)
        wrong_namespace["namespace_id"] = generate_id("NAMESPACE")
        unsigned = dict(wrong_namespace)
        unsigned.pop("signature_hex")
        wrong_namespace["signature_hex"] = observer_key.sign(canonical_json(unsigned)).hex()
        assert engine.record_isolation_report(ids["session"], ids["run"],
                                              wrong_namespace, _stamp(2)).payload["kind"] == "REJECTION"
        report = signed_report(observer, ids["session"], ids["run"],
                               observer_actor, observer_key, _stamp(2))
        imported = engine.record_isolation_report(ids["session"], ids["run"], report, _stamp(2))
        assert imported.payload["kind"] == "ISOLATION_OBSERVATION"
        assert engine.release_run_budget(ids["session"], ids["run"], True, _stamp(2)).payload["kind"] == "BUDGET_RELEASE"
        continued = engine.continue_after_run(ids["session"], ids["run"], _stamp(2))
        assert continued.payload["resulting_state"] == "ACTIVE"
        assert continued.payload["independent_isolation_proven"] is True
        view = engine.replay()[ids["session"]]
        assert view.runs[ids["run"]].state == "UNKNOWN"
        assert view.runs[ids["run"]].claim["state"] == "CONSUMED"
        assert view.runs[ids["run"]].isolation_report == report
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
        second_reservation = engine.reserve_run(second_scope, second_auth, second_proof, _stamp(3))
        assert second_reservation.payload["kind"] == "RUN_RESERVATION", second_reservation.payload
        second_run = _run_record(second_ids, session, second_auth, second_reservation.event_id)
        assert engine.admit_run(second_run, second_auth, second_proof, second_scope,
                                _stamp(3)).payload["kind"] == "RUN_ADMITTED"
        view = engine.replay()[ids["session"]]
        assert view.runs[ids["run"]].state == "UNKNOWN"
        assert view.runs[second_ids["run"]].state == "CREATED"
        history = engine.journal.history()
        continuation_index = next(index for index, item in enumerate(history)
                                  if item.payload.get("independent_isolation_proven") is True)
        forged = list(history)
        forged_payload = dict(forged[continuation_index].payload)
        forged_payload["budget_release_event_id"] = generate_id("EVENT")
        forged[continuation_index] = replace(forged[continuation_index], payload=forged_payload)
        with pytest.raises(I2ContractError):
            engine.replay(tuple(forged))
        engine.read_exact_binding = lambda _: b"changed-external-binding"
        assert engine.replay()[ids["session"]].state == "ACTIVE"
        quarantined = engine.transition_session(ids["session"], "QUARANTINED",
                                                _stamp(4), reason="protected_source_mismatch")
        assert quarantined.payload["resulting_state"] == "QUARANTINED"
        assert engine.replay()[ids["session"]].runs[ids["run"]].state == "UNKNOWN"
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
