"""Separate-process I1 synthetic publication contender."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from package_g.op1_reusable.evidence_store import EvidenceStore
from package_g.op1_reusable.storage_paths import Scope


def main() -> int:
    root, fixture_path, gate_path, ready_path = map(Path, sys.argv[1:5])
    fixture = json.loads(fixture_path.read_bytes())
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(os.environ["I1_SYNTHETIC_WRITER_KEY_HEX"]))
    store = EvidenceStore(
        root, writer_private_key=key,
        store_id=os.environ["I1_SYNTHETIC_STORE_ID"],
        lineage_id=os.environ["I1_SYNTHETIC_LINEAGE_ID"],
        trusted_checkpoint=json.loads(os.environ["I1_SYNTHETIC_CHECKPOINT"]),
        trusted_checkpoint_public_key_hex=os.environ["I1_SYNTHETIC_OWNER_PUBLIC_KEY_HEX"],
    )
    ready_path.write_text("READY", encoding="ascii")
    deadline = time.monotonic() + 15
    while not gate_path.exists():
        if time.monotonic() >= deadline:
            print(json.dumps({"status": "TIMEOUT"}))
            return 2
        time.sleep(0.01)
    try:
        result = store.publish_evidence(
            fixture["record"], bytes.fromhex(fixture["content_hex"]),
            fixture["publication_event"], Scope(**fixture["scope"]),
            producer_kind="ACTOR",
        )
        print(json.dumps({"status": "PASS", "evidence_id": result["evidence_id"]}))
    except Exception as exc:
        print(json.dumps({"status": type(exc).__name__, "message": str(exc)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())