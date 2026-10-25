"""Two synthetic I2 processes compete for one Session run ceiling."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.identity import canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.integrity import IntegrityVerifier
from package_g.op1_reusable.storage_paths import Scope

from op1_reusable_i1_helpers import signed_checkpoint, synthetic_store
from test_op1_reusable_i2_authority import _fixture, _signed, _stamp


WORKER = Path(__file__).resolve().parents[1] / "support/op1_reusable_i2_reserve_worker.py"


def test_separate_processes_commit_one_max_runs_reservation():
    with synthetic_store() as (store, base_scope, actor, writer_key):
        ids, session, _, base_auth, _, exact, trusted, issuer_key = _fixture(
            evidence_root=str(store.root), base_scope=base_scope, return_signer=True)
        session["max_runs"] = 1
        session_proof = _signed(session, "authority_proof_sha256", issuer_key)
        engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
        assert engine.create_session(session, session_proof, _stamp(1)).payload["kind"] == "SESSION_CREATED"
        assert engine.activate_session(ids["session"], _stamp(2)).payload["resulting_state"] == "ACTIVE"
        checkpoint, checkpoint_public = signed_checkpoint(store)
        shared = {
            "store_id": store.store_id, "lineage_id": store.lineage_id,
            "actor_id": actor, "writer_key_hex": writer_key.private_bytes(
                Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
            "checkpoint": checkpoint, "checkpoint_public_hex": checkpoint_public,
            "issuer_actor_id": base_auth["issuer_actor_id"],
            "issuer_public_hex": issuer_key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw).hex(),
            "exact_hex": exact.hex(), "now": _stamp(2),
        }
        parent = store.root.parent
        gate = parent / "i2-go"
        workers = []
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(("src", "tests/unit"))
        try:
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
                fixture = parent / f"i2-fixture-{index}.json"
                fixture.write_text(json.dumps({**shared, "scope": vars(scope),
                                               "authority": auth, "proof_hex": proof.hex()}), encoding="utf-8")
                ready = parent / f"i2-ready-{index}"
                process = subprocess.Popen(
                    [sys.executable, str(WORKER), str(store.root), str(fixture), str(gate), str(ready)],
                    cwd=Path(__file__).resolve().parents[2], env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                workers.append((process, ready))
            deadline = time.monotonic() + 15
            while not all(ready.exists() for _, ready in workers):
                if time.monotonic() >= deadline or any(process.poll() is not None for process, ready in workers if not ready.exists()):
                    raise AssertionError("I2 process worker failed before race gate")
                time.sleep(0.02)
            gate.write_text("GO", encoding="ascii")
            results = []
            for process, _ in workers:
                stdout, stderr = process.communicate(timeout=30)
                assert process.returncode == 0, stderr
                results.append(json.loads(stdout))
            assert sorted(item["kind"] for item in results) == ["REJECTION", "RUN_RESERVATION"]
            view = engine.replay()[ids["session"]]
            assert len(view.reservations) == 1
            assert next(iter(view.reservations)) == next(
                item["run_id"] for item in results if item["kind"] == "RUN_RESERVATION")
            assert IntegrityVerifier(store.root).verify()["result"] == "PASS"
        finally:
            for process, _ in workers:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
