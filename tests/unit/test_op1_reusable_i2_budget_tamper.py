"""I2 adversarial budget and I1 custody tamper checks in synthetic stores."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace

import pytest

from package_g.op1_reusable.i2_contract import I2ContractError, replay_budget
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.identity import generate_id
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp
from test_op1_reusable_i2_dispatch_recovery import _claimed_engine


def test_reserved_budget_cannot_roll_down_before_or_after_admission():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        engine, ids, exact, trusted = _claimed_engine(store, base_scope)
        history = engine.journal.history()
        index = next(i for i, row in enumerate(history)
                     if row.payload.get("kind") == "RUN_RESERVATION")
        forged = list(history)
        payload = deepcopy(forged[index].payload)
        payload["budget"]["cpu_ms"] -= 1
        forged[index] = replace(forged[index], payload=payload)
        with pytest.raises(I2ContractError, match="reservation budget"):
            engine.replay(tuple(forged))
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_same_session_duplicate_run_id_is_preserved_as_rejection():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        scope = Scope(ids["project"], ids["product"], ids["lineage"], ids["version"],
                      ids["session"], ids["run"], ids["attempt"])
        first = engine.reserve_run(scope, auth, proof, _stamp(2))
        again = engine.reserve_run(scope, auth, proof, _stamp(2))
        assert first.payload["kind"] == "RUN_RESERVATION"
        assert again.payload["kind"] == "REJECTION"
        assert "reused RUN_ID" in again.payload["reason"]
        assert IntegrityVerifier(store.root).verify()["result"] == "PASS"


def test_deleted_i2_evidence_blob_blocks_replay():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
        row = next(row for row in store.manifest_rows()
                   if row["object_type"] == "EVIDENCE" and row.get("evidence_class") == "I2_CONTROL")
        target = store.paths.checked_path(row["object_relative_path"], require_existing=True)
        target.unlink()
        assert IntegrityVerifier(store.root).verify()["result"] == "FAIL"
        with pytest.raises(I2ContractError, match="I1 evidence store unhealthy"):
            engine.replay()


def test_truncated_published_transition_history_blocks_replay():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        engine.create_session(session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
        engine.activate_session(ids["session"], _stamp(2))
        checkpoint, public = signed_checkpoint(store)
        latest_manifest = sorted((store.root / "manifests").iterdir())[-1]
        latest_manifest.unlink()
        verdict = IntegrityVerifier(store.root).verify(
            trusted_checkpoint=checkpoint, trusted_checkpoint_public_key_hex=public)
        assert verdict["result"] == "FAIL"
        with pytest.raises(I2ContractError, match="I1 evidence store unhealthy"):
            engine.replay()


def test_active_sum_memory_exhaustion_blocks_with_spare_run_count():
    session_ceiling = {
        "http_transactions": 4, "tcp_calibrations": 0, "udp_calibrations": 0,
        "pktmon_starts": 0, "channel_e_starts": 0, "job_starts": 0,
        "output_bytes": 400, "cpu_ms": 100, "elapsed_ms": 100,
        "memory_peak_bytes": 20, "max_concurrent_runs": 2,
    }
    run_budget = {**session_ceiling, "http_transactions": 1, "output_bytes": 10,
                  "cpu_ms": 10, "elapsed_ms": 10, "memory_peak_bytes": 11}
    first, second = generate_id("RUN"), generate_id("RUN")
    first_event = {"kind": "RESERVE", "event_id": generate_id("EVENT"),
                   "run_id": first, "budget": run_budget}
    second_event = {"kind": "RESERVE", "event_id": generate_id("EVENT"),
                    "run_id": second, "budget": run_budget}
    assert replay_budget(session_ceiling, 3, [first_event]).active_memory == 11
    with pytest.raises(I2ContractError, match="active memory"):
        replay_budget(session_ceiling, 3, [first_event, second_event])


def test_complete_prefix_rollback_is_rejected_by_open_i2_reader():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, auth, proof, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        root = store.root.resolve()
        before = {path.relative_to(root) for path in root.rglob("*") if path.is_file()}
        created = engine.create_session(
            session, _signed(session, "authority_proof_sha256", issuer_key), _stamp(1))
        assert created.payload["kind"] == "SESSION_CREATED"
        assert ids["session"] in engine.replay()
        new_files = [path for path in root.rglob("*")
                     if path.is_file() and path.relative_to(root) not in before]
        assert new_files
        for path in new_files:
            assert path.resolve().is_relative_to(root)
            path.unlink()
        # The remaining empty I1 root is a valid prefix without external custody.
        assert IntegrityVerifier(root).verify()["result"] == "PASS"
        with pytest.raises(I2ContractError, match="observed manifest prefix"):
            engine.replay()
