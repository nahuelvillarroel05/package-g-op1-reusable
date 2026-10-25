"""Fresh Run identities reject collisions before an authoritative reservation."""
from __future__ import annotations

from copy import deepcopy

import pytest

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp


@pytest.mark.parametrize("reused", ["claim", "namespace", "attempt", "run_authority"])
def test_collision_rejected_before_run_reservation_publication(reused):
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, base_auth, base_proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["max_runs"] = 2
        for name in ("output_bytes", "cpu_ms", "elapsed_ms"):
            session["resource_ceilings"][name] *= 2
        session["resource_ceilings"]["memory_peak_bytes"] *= 2
        session["resource_ceilings"]["max_concurrent_runs"] = 2
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, session_proof, _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        first_scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                            ids["session"], ids["run"], ids["attempt"])
        first_auth = deepcopy(base_auth)
        first_auth["session_authority_sha256"] = sha256_bytes(canonical_json(session))
        first_proof = _signed(first_auth, "proof_sha256", issuer_key)
        first = engine.reserve_run(first_scope, first_auth, first_proof, _stamp(2))
        assert first.payload["kind"] == "RUN_RESERVATION"

        second_ids = deepcopy(ids)
        for name in ("run", "attempt", "claim", "namespace", "operation"):
            second_ids[name] = generate_id(name.upper())
        second_ids["run_authority"] = generate_id("AUTHORITY")
        second_ids[reused] = ids[reused]
        auth = deepcopy(base_auth)
        auth.update(
            authority_id=second_ids["run_authority"],
            session_authority_sha256=sha256_bytes(canonical_json(session)),
            run_id=second_ids["run"], attempt_id=second_ids["attempt"],
            claim_id=second_ids["claim"], namespace_id=second_ids["namespace"],
            operation_id=second_ids["operation"],
            exact_binding_manifest_relative_path="bindings/" + second_ids["run"] + ".json",
        )
        auth["identity"]["entity_id"] = auth["authority_id"]
        auth["identity"]["run_id"] = second_ids["run"]
        proof = _signed(auth, "proof_sha256", issuer_key)
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], second_ids["run"], second_ids["attempt"])
        collision = engine.reserve_run(scope, auth, proof, _stamp(2))
        assert collision.payload["kind"] == "REJECTION"
        assert "reused" in collision.payload["reason"]
        assert list(engine.replay()[ids["session"]].reservations) == [ids["run"]]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_global_run_id_collision_between_sessions_is_rejected_before_publication():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        a = _fixture(evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        b = _fixture(evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        ids_a, session_a, _, auth_a, proof_a, exact_a, trusted_a, signer_a = a
        ids_b, session_b, _, auth_b, proof_b, exact_b, trusted_b, signer_b = b
        bindings = {
            auth_a["exact_binding_manifest_relative_path"]: exact_a,
            auth_b["exact_binding_manifest_relative_path"]: exact_b,
        }
        engine = I2Engine(I2Journal(store), trusted_a | trusted_b, bindings.__getitem__)
        for ids, session, signer in (
            (ids_a, session_a, signer_a), (ids_b, session_b, signer_b),
        ):
            engine.create_session(session, _signed(session, "authority_proof_sha256", signer),
                                  _stamp(1))
            engine.activate_session(ids["session"], _stamp(2))
        scope_a = Scope(ids_a["project"], ids_a["product"], ids_a["lineage"],
                        ids_a["version"], ids_a["session"], ids_a["run"], ids_a["attempt"])
        assert engine.reserve_run(scope_a, auth_a, proof_a, _stamp(2)).payload["kind"] == "RUN_RESERVATION"

        auth_b = deepcopy(auth_b)
        auth_b["run_id"] = ids_a["run"]
        auth_b["identity"]["run_id"] = ids_a["run"]
        proof_b = _signed(auth_b, "proof_sha256", signer_b)
        scope_b = Scope(ids_b["project"], ids_b["product"], ids_b["lineage"],
                        ids_b["version"], ids_b["session"], ids_a["run"], ids_b["attempt"])
        duplicate = engine.reserve_run(scope_b, auth_b, proof_b, _stamp(2))
        assert duplicate.payload["kind"] == "REJECTION"
        assert "reused RUN_ID" in duplicate.payload["reason"]
        views = engine.replay()
        assert list(views[ids_a["session"]].reservations) == [ids_a["run"]]
        assert views[ids_b["session"]].reservations == {}
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_cross_session_run_authority_is_rejected_without_reservation():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        a = _fixture(evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        b = _fixture(evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        ids_a, session_a, _, auth_a, proof_a, exact_a, trusted_a, signer_a = a
        ids_b, session_b, _, auth_b, proof_b, exact_b, trusted_b, signer_b = b
        bindings = {
            auth_a["exact_binding_manifest_relative_path"]: exact_a,
            auth_b["exact_binding_manifest_relative_path"]: exact_b,
        }
        engine = I2Engine(I2Journal(store), trusted_a | trusted_b, bindings.__getitem__)
        for ids, session, signer in (
            (ids_a, session_a, signer_a), (ids_b, session_b, signer_b),
        ):
            engine.create_session(session, _signed(session, "authority_proof_sha256", signer),
                                  _stamp(1))
            engine.activate_session(ids["session"], _stamp(2))
        scope_b = Scope(ids_b["project"], ids_b["product"], ids_b["lineage"],
                        ids_b["version"], ids_b["session"], ids_a["run"], ids_b["attempt"])
        wrong_parent = deepcopy(auth_a)
        wrong_parent["session_id"] = ids_b["session"]
        wrong_parent["attempt_id"] = ids_b["attempt"]
        wrong_parent["identity"]["session_id"] = ids_b["session"]
        wrong_parent["identity"]["freeze_id"] = ids_b["freeze"]
        wrong_parent_proof = _signed(wrong_parent, "proof_sha256", signer_a)
        attempt = engine.reserve_run(scope_b, wrong_parent, wrong_parent_proof, _stamp(2))
        assert attempt.payload["kind"] == "REJECTION"
        assert "wrong parent Session authority" in attempt.payload["reason"]
        assert engine.replay()[ids_b["session"]].reservations == {}
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
