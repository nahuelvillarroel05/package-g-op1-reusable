"""Synthetic authority fixtures exercise exact frozen schema and child bindings."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from package_g.op1_reusable.i2_authority import (
    verify_session_authority, verify_run_authority, verify_run_record,
    claim_content_sha256, claim_slot_preimage, verify_claim_record,
)
from package_g.op1_reusable.i2_contract import I2ContractError
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.schema_registry import SchemaRegistry


def _stamp(offset: int) -> str:
    base = datetime(2026, 9, 24, 17, 0, tzinfo=timezone.utc)
    return (base + timedelta(minutes=offset)).isoformat().replace("+00:00", "Z")


def _identity(kind: str, entity_id: str, actor: str, doc: str, **scope):
    entry = SchemaRegistry().find_document(doc)
    return {
        "entity_id": entity_id, "entity_type": kind,
        "schema_id": entry.schema_id, "schema_version": entry.version,
        "actor_id": actor, "created_at_utc": _stamp(0), "status": "SYNTHETIC_I2",
        **scope,
    }


def _signed(record, field, key):
    unsigned = dict(record)
    unsigned.pop(field, None)
    proof = key.sign(canonical_json(unsigned))
    record[field] = sha256_bytes(proof)
    return proof


def _seal_claim(claim):
    claim["durable_readback_sha256"] = sha256_bytes(claim_slot_preimage(claim))
    claim["identity"]["content_sha256"] = claim_content_sha256(claim)
    return claim


def _budget(**changes):
    value = {
        "http_transactions": 0, "tcp_calibrations": 0, "udp_calibrations": 0,
        "pktmon_starts": 0, "channel_e_starts": 0, "job_starts": 0,
        "output_bytes": 200, "cpu_ms": 100, "elapsed_ms": 100,
        "memory_peak_bytes": 10, "max_concurrent_runs": 1,
    }
    value.update(changes)
    return value


def _fixture(*, evidence_root=None, base_scope=None, return_signer=False):
    issuer = generate_id("ACTOR")
    owner = generate_id("ACTOR")
    key = Ed25519PrivateKey.generate()
    trusted = {issuer: key.public_key()}
    ids = {name: generate_id(name.upper()) for name in (
        "project", "product", "lineage", "version", "freeze", "session",
        "run", "attempt", "claim", "namespace", "operation", "policy", "tool",
    )}
    if base_scope is not None:
        for name in ("project", "product", "lineage", "version"):
            ids[name] = getattr(base_scope, name + "_id")
    ids["session_authority"] = generate_id("AUTHORITY")
    ids["run_authority"] = generate_id("AUTHORITY")
    scope = {name + "_id": ids[name] for name in ("project", "product", "lineage", "version", "freeze")}
    policy = [{"policy_id": ids["policy"], "sha256": "1" * 64}]
    session = {
        "identity": _identity("AUTHORITY", ids["session_authority"], issuer,
                              "OP1_SESSION_AUTHORITY_SCHEMA.json", **scope,
                              session_id=ids["session"]),
        "session_id": ids["session"], "authority_id": ids["session_authority"],
        "issuer_actor_id": issuer, "owner_actor_id": owner,
        "product_id": ids["product"], "lineage_id": ids["lineage"],
        "version_id": ids["version"], "freeze_id": ids["freeze"],
        "freeze_manifest_sha256": "2" * 64, "profile": "EXPERIMENTAL_REUSABLE",
        "allowed_operation_classes": ["READ_ONLY_RECONCILIATION"],
        "policy_bindings": policy, "target_class": "SYNTHETIC_READ_ONLY",
        "resource_ceilings": _budget(), "max_runs": 2,
        "issued_at_utc": _stamp(0), "expires_at_utc": _stamp(60),
        "evidence_root": evidence_root or "C:/synthetic-i2-only", "allowed_tool_ids": [ids["tool"]],
        "network_boundary": "NO_NETWORK", "mutation_boundary": "SYNTHETIC_ONLY",
        "authority_proof_sha256": "0" * 64, "run_authorization_required": True,
    }
    session_proof = _signed(session, "authority_proof_sha256", key)
    session_bytes = verify_session_authority(session, session_proof, trusted, _stamp(1))
    command_hash = "3" * 64
    manifest = {
        "operation_class": "READ_ONLY_RECONCILIATION", "target_class": "SYNTHETIC_READ_ONLY",
        "target_literal": "synthetic://fixture", "port_map": {}, "resource_names": {},
        "command_request_sha256": command_hash, "command_graph_sha256": "4" * 64,
        "entrypoint_sha256": "5" * 64, "wrapper_sha256": "6" * 64,
        "source_commit": "a" * 40, "source_tree": "b" * 40,
        "source_fingerprint_sha256": "7" * 64, "freeze_id": ids["freeze"],
        "policy_ids": [ids["policy"]], "tool_ids": [ids["tool"]],
    }
    manifest_bytes = canonical_json(manifest)
    path = "bindings/" + ids["run"] + ".json"
    run_auth = {
        "identity": _identity("AUTHORITY", ids["run_authority"], issuer,
                              "OP1_RUN_AUTHORITY_SCHEMA.json", **scope,
                              session_id=ids["session"], run_id=ids["run"]),
        "authority_id": ids["run_authority"], "session_id": ids["session"],
        "run_id": ids["run"], "claim_id": ids["claim"], "attempt_id": ids["attempt"],
        "namespace_id": ids["namespace"], "operation_id": ids["operation"],
        "owner_actor_id": owner, "issuer_actor_id": issuer,
        "issued_at_utc": _stamp(1), "expires_at_utc": _stamp(30),
        "session_authority_sha256": sha256_bytes(session_bytes),
        "freeze_manifest_sha256": session["freeze_manifest_sha256"],
        "policy_manifest_sha256": sha256_bytes(canonical_json(policy)),
        "command_sha256": command_hash, "operation_class": "READ_ONLY_RECONCILIATION",
        "target_class": "SYNTHETIC_READ_ONLY", "resource_ceilings": _budget(),
        "proof_sha256": "0" * 64, "one_shot": True,
        "exact_binding_manifest_sha256": sha256_bytes(manifest_bytes),
        "exact_binding_manifest_relative_path": path,
        "exact_binding_manifest": manifest,
    }
    run_proof = _signed(run_auth, "proof_sha256", key)
    result = (ids, session, session_bytes, run_auth, run_proof, manifest_bytes, trusted)
    return result + (key,) if return_signer else result


def test_signed_child_authority_and_run_record_bind_every_identity():
    ids, session, session_bytes, auth, proof, exact, trusted = _fixture()
    authority_bytes = verify_run_authority(
        auth, proof, trusted, session, session_bytes, _stamp(2), lambda _: exact)
    reservation = generate_id("EVENT")
    run = {
        "identity": _identity("RUN", ids["run"], session["owner_actor_id"],
                              "OP1_RUN_SCHEMA.json",
                              project_id=ids["project"], product_id=ids["product"],
                              lineage_id=ids["lineage"], version_id=ids["version"],
                              session_id=ids["session"], run_id=ids["run"]),
        "run_id": ids["run"], "session_id": ids["session"],
        "run_authority_id": ids["run_authority"], "operation_id": ids["operation"],
        "namespace_id": ids["namespace"], "claim_id": ids["claim"],
        "claim_slot": ids["run"], "attempt_ids": [ids["attempt"]],
        "source_freeze_id": ids["freeze"], "policy_ids": [ids["policy"]],
        "target_resource_ids": [], "authorized_command_sha256": auth["command_sha256"],
        "budget_reservation_event_id": reservation, "opened_at_utc": _stamp(2),
    }
    verify_run_record(run, auth, session, reservation)
    claim = {
        "identity": _identity("CLAIM", ids["claim"], session["owner_actor_id"],
                              "OP1_RUN_CLAIM_SCHEMA.json",
                              project_id=ids["project"], product_id=ids["product"],
                              lineage_id=ids["lineage"], version_id=ids["version"],
                              session_id=ids["session"], run_id=ids["run"],
                              content_sha256="8" * 64),
        "claim_id": ids["claim"], "run_id": ids["run"], "session_id": ids["session"],
        "run_authority_id": ids["run_authority"], "claim_slot": ids["run"],
        "claim_operation_id": ids["operation"], "claimer_actor_id": session["owner_actor_id"],
        "namespace_id": ids["namespace"], "authorization_exact_sha256": sha256_bytes(authority_bytes),
        "created_at_utc": _stamp(2), "durable_readback_sha256": "9" * 64,
        "reservation_event_id": reservation, "state": "CONSUMED",
    }
    _seal_claim(claim)
    verify_claim_record(claim, run, auth, authority_bytes, reservation)
    wrong_readback = deepcopy(claim)
    wrong_readback["durable_readback_sha256"] = "0" * 64
    with pytest.raises(I2ContractError, match="durable readback digest"):
        verify_claim_record(wrong_readback, run, auth, authority_bytes, reservation)
    wrong_content = deepcopy(claim)
    wrong_content["identity"]["content_sha256"] = "0" * 64
    with pytest.raises(I2ContractError, match="identity content digest"):
        verify_claim_record(wrong_content, run, auth, authority_bytes, reservation)
    wrong = deepcopy(claim)
    wrong["run_id"] = generate_id("RUN")
    with pytest.raises(I2ContractError, match="differs"):
        verify_claim_record(wrong, run, auth, authority_bytes, reservation)


def test_authority_rejects_cross_session_binding_and_exact_byte_mutation():
    ids, session, session_bytes, auth, proof, exact, trusted = _fixture()
    with pytest.raises(I2ContractError, match="exact binding bytes"):
        verify_run_authority(auth, proof, trusted, session, session_bytes, _stamp(2),
                             lambda _: exact + b" ")
    other_session = {**session, "session_id": generate_id("SESSION")}
    with pytest.raises(I2ContractError, match="session_id mismatch"):
        verify_run_authority(auth, proof, trusted, other_session,
                             canonical_json(other_session), _stamp(2), lambda _: exact)


def test_expiry_and_clock_rollback_block_new_authority_use():
    ids, session, session_bytes, auth, proof, exact, trusted = _fixture()
    with pytest.raises(I2ContractError, match="not currently valid"):
        verify_run_authority(auth, proof, trusted, session, session_bytes, _stamp(31),
                             lambda _: exact)
    with pytest.raises(I2ContractError, match="clock moved backward"):
        verify_run_authority(auth, proof, trusted, session, session_bytes, _stamp(2),
                             lambda _: exact, prior_observed=_stamp(3))


@pytest.mark.parametrize("field, replacement, expected", [
    ("claim_slot", lambda _: generate_id("RUN"), "Claim slot"),
    ("claim_operation_id", lambda _: generate_id("OPERATION"), "Claim operation"),
    ("claimer_actor_id", lambda _: generate_id("ACTOR"), "Claim owner"),
])
def test_claim_rejects_substituted_slot_operation_or_actor(field, replacement, expected):
    ids, session, session_bytes, auth, proof, exact, trusted = _fixture()
    reservation = generate_id("EVENT")
    run = {
        "identity": _identity("RUN", ids["run"], session["owner_actor_id"],
                              "OP1_RUN_SCHEMA.json", project_id=ids["project"],
                              product_id=ids["product"], lineage_id=ids["lineage"],
                              version_id=ids["version"], session_id=ids["session"],
                              run_id=ids["run"]),
        "run_id": ids["run"], "session_id": ids["session"],
        "namespace_id": ids["namespace"], "claim_id": ids["claim"],
        "claim_slot": ids["run"], "operation_id": ids["operation"],
    }
    claim = {
        "identity": _identity("CLAIM", ids["claim"], session["owner_actor_id"],
                              "OP1_RUN_CLAIM_SCHEMA.json", project_id=ids["project"],
                              product_id=ids["product"], lineage_id=ids["lineage"],
                              version_id=ids["version"], session_id=ids["session"],
                              run_id=ids["run"], content_sha256="8" * 64),
        "claim_id": ids["claim"], "run_id": ids["run"], "session_id": ids["session"],
        "run_authority_id": ids["run_authority"], "claim_slot": ids["run"],
        "claim_operation_id": ids["operation"],
        "claimer_actor_id": session["owner_actor_id"],
        "namespace_id": ids["namespace"],
        "authorization_exact_sha256": sha256_bytes(canonical_json(auth)),
        "created_at_utc": _stamp(2), "durable_readback_sha256": "9" * 64,
        "reservation_event_id": reservation, "state": "CONSUMED",
    }
    _seal_claim(claim)
    claim[field] = replacement(ids)
    with pytest.raises(I2ContractError, match=expected):
        verify_claim_record(claim, run, auth, canonical_json(auth), reservation)


def test_child_authority_rejects_parent_outside_time_window():
    ids, session, session_bytes, auth, proof, exact, trusted, issuer_key = _fixture(return_signer=True)
    session["issued_at_utc"] = _stamp(4)
    auth["session_authority_sha256"] = sha256_bytes(canonical_json(session))
    proof = _signed(auth, "proof_sha256", issuer_key)
    with pytest.raises(I2ContractError, match="not currently valid"):
        verify_run_authority(auth, proof, trusted, session, canonical_json(session),
                             _stamp(2), lambda _: exact)
