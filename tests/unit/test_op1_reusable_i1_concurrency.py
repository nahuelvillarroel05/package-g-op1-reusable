"""Bounded separate-process I1 writer races on immutable slots."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from op1_reusable_i1_helpers import event_record, evidence_record, synthetic_store, signed_checkpoint
from package_g.op1_reusable.identity import generate_id
from package_g.op1_reusable.integrity import IntegrityVerifier


WORKER = Path(__file__).resolve().parents[1] / "support/op1_reusable_i1_publish_worker.py"


def contend(store, scope, actor, key, fixtures):
    parent = store.root.parent
    gate = parent / "go"
    processes = []
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join(("src", "tests/unit"))
    environment["I1_SYNTHETIC_WRITER_KEY_HEX"] = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    checkpoint, public = signed_checkpoint(store)
    environment["I1_SYNTHETIC_CHECKPOINT"] = json.dumps(checkpoint)
    environment["I1_SYNTHETIC_OWNER_PUBLIC_KEY_HEX"] = public
    environment["I1_SYNTHETIC_STORE_ID"] = store.store_id
    environment["I1_SYNTHETIC_LINEAGE_ID"] = store.lineage_id
    try:
        for index, fixture in enumerate(fixtures):
            path = parent / f"fixture-{index}.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            ready = parent / f"ready-{index}"
            process = subprocess.Popen(
                [sys.executable, str(WORKER), str(store.root), str(path), str(gate), str(ready)],
                cwd=Path(__file__).resolve().parents[2],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            processes.append((process, ready))
        deadline = time.monotonic() + 15
        while not all(ready.exists() for _, ready in processes):
            if time.monotonic() >= deadline or any(process.poll() is not None for process, ready in processes if not ready.exists()):
                raise AssertionError("worker failed before race gate")
            time.sleep(0.02)
        gate.write_text("GO", encoding="ascii")
        results = []
        for process, _ in processes:
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stderr
            results.append(json.loads(stdout))
        return results
    finally:
        for process, _ in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def fixture(store, scope, actor, action_id, data, *, evidence_id=None, artifact_id=None, publication_event_id=None):
    record = evidence_record(store, scope, actor, action_id, data, evidence_id=evidence_id, artifact_id=artifact_id)
    event = event_record(
        store, scope, actor, "PUBLICATION", [record["evidence_id"]],
        [artifact_id] if artifact_id else [], event_id=publication_event_id,
    )
    return {"fixture_id": generate_id("ARTIFACT"), "source_freeze_id": "PG-FRZ-e55f2e60890261eb8452d9168f776552", "scope": vars(scope), "record": record, "publication_event": event, "content_hex": data.hex()}


@pytest.mark.parametrize("scenario", ["same_evidence_id_and_path", "same_artifact_id", "different_objects", "conflicting_publication_id"])
def test_two_processes_never_last_writer_win(scenario):
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        if scenario == "same_evidence_id_and_path":
            shared = generate_id("EVIDENCE")
            fixtures = [
                fixture(store, scope, actor, action["event_id"], b"first contender", evidence_id=shared),
                fixture(store, scope, actor, action["event_id"], b"second contender", evidence_id=shared),
            ]
        elif scenario == "same_artifact_id":
            artifact = generate_id("ARTIFACT")
            fixtures = [
                fixture(store, scope, actor, action["event_id"], b"first", artifact_id=artifact),
                fixture(store, scope, actor, action["event_id"], b"second", artifact_id=artifact),
            ]
        elif scenario == "conflicting_publication_id":
            publication_id = generate_id("EVENT")
            fixtures = [
                fixture(store, scope, actor, action["event_id"], b"first", publication_event_id=publication_id),
                fixture(store, scope, actor, action["event_id"], b"second", publication_event_id=publication_id),
            ]
        else:
            fixtures = [
                fixture(store, scope, actor, action["event_id"], b"first", artifact_id=generate_id("ARTIFACT")),
                fixture(store, scope, actor, action["event_id"], b"second", artifact_id=generate_id("ARTIFACT")),
            ]
        results = contend(store, scope, actor, key, fixtures)
        statuses = [result["status"] for result in results]
        if scenario == "different_objects":
            assert statuses.count("PASS") == 2, results
        else:
            assert statuses.count("PASS") == 1 and statuses.count("ObjectExists") == 1, results
        verdict = IntegrityVerifier(store.root).verify()
        assert verdict["result"] == "PASS", (scenario, results, verdict["findings"])
        evidence_rows = [row for row in store.manifest_rows() if row["object_type"] == "EVIDENCE"]
        assert len(evidence_rows) == (2 if scenario == "different_objects" else 1)
        for row in evidence_rows:
            content = (store.root / row["object_relative_path"]).read_bytes()
            assert content in {b"first", b"second", b"first contender", b"second contender"}