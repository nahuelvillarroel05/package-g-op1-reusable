#!/usr/bin/env python3
"""Freeze prior PGOP1 BFCL structural decisions before official regrade scoring."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "Engineering" / "PGOP1_REAL_BENCHMARK_EVALUATION_001" / "PGOP1_AUDIT_RESULTS.json"
OUTPUT = Path(__file__).resolve().parent / "PGOP1_PRIOR_DECISIONS_FREEZE.json"
IDS = [f"simple_python_{index}" for index in range(20)]
FIELDS = (
    "family",
    "task_id",
    "engine_task_id",
    "observation_ids",
    "pgop1_verdict",
    "reason",
    "predicate",
    "comparison",
    "auditor_scope",
    "independent_semantic_label",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    if OUTPUT.exists():
        raise FileExistsError(f"Refusing to overwrite prior decision freeze: {OUTPUT}")
    raw = SOURCE.read_bytes()
    report = json.loads(raw.decode("utf-8-sig"))
    matching = {
        row["task_id"]: row
        for row in report["cases"]
        if row.get("family") == "bfcl_v4" and row.get("task_id") in IDS
    }
    if sorted(matching) != sorted(IDS):
        raise RuntimeError("Prior PGOP1 BFCL decisions do not exactly cover the fixed 20-ID selection")
    cases = [{field: matching[task_id].get(field) for field in FIELDS} for task_id in IDS]
    if any(row["pgop1_verdict"] != "ABSTAIN" for row in cases):
        raise RuntimeError("Expected all pre-existing selected PGOP1 decisions to remain ABSTAIN")
    document = {
        "schema": "pgop1.bfcl.prior-decisions-freeze.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "status": "FROZEN_BEFORE_OFFICIAL_REGRADE",
        "selection": {
            "family": "bfcl_v4",
            "category": "simple_python",
            "task_ids": IDS,
            "rule": "historical fixed prefix simple_python_0..19; no selection by output or score",
        },
        "source": {"path": str(SOURCE), "sha256": digest(raw), "bytes": len(raw)},
        "official_score_loaded_before_freeze": False,
        "cases": cases,
        "decision_hashes": {
            row["task_id"]: digest(json.dumps(row, sort_keys=True, ensure_ascii=False).encode("utf-8"))
            for row in cases
        },
        "boundary": "Prior PGOP1 structural abstentions are frozen; official BFCL result does not alter them or establish independent semantic truth.",
    }
    payload = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    OUTPUT.write_bytes(payload)
    print(json.dumps({"status": document["status"], "cases": len(cases), "source_sha256": document["source"]["sha256"], "freeze_sha256": digest(payload), "output": str(OUTPUT)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
