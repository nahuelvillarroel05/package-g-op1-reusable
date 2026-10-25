"""Separate-process synthetic I2 reservation contender; no runtime adapter."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.i2_engine import I2Engine
from package_g.op1_reusable.i2_journal import I2Journal
from package_g.op1_reusable.storage_paths import Scope


def main() -> None:
    root, fixture_path, gate, ready = map(Path, sys.argv[1:5])
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    store = EvidenceStore(
        root, store_id=fixture["store_id"], lineage_id=fixture["lineage_id"],
        actor_id=fixture["actor_id"],
        writer_private_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fixture["writer_key_hex"])),
        trusted_checkpoint=fixture["checkpoint"],
        trusted_checkpoint_public_key_hex=fixture["checkpoint_public_hex"],
    )
    issuer = fixture["issuer_actor_id"]
    trusted = {issuer: Ed25519PublicKey.from_public_bytes(bytes.fromhex(fixture["issuer_public_hex"]))}
    exact = bytes.fromhex(fixture["exact_hex"])
    engine = I2Engine(I2Journal(store), trusted, lambda _: exact)
    ready.write_text("READY", encoding="ascii")
    deadline = time.monotonic() + 15
    while not gate.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("I2 race gate timeout")
        time.sleep(0.02)
    result = engine.reserve_run(Scope(**fixture["scope"]), fixture["authority"],
                                bytes.fromhex(fixture["proof_hex"]), fixture["now"])
    print(json.dumps({"kind": result.payload["kind"], "event_id": result.event_id,
                      "run_id": result.payload["subject_run_id"],
                      "reason": result.payload.get("reason")}))


if __name__ == "__main__":
    main()
