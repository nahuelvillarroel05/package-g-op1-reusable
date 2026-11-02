"""Fresh-process storage/recovery checks for explicit attribution v2 selection."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.generalized import audit_evidence
from runtime.candidate.swebench_claim_audit.generalized_bridge import (
    bind_generalized_audit, recover_generalized_audit,
)

CONTRACT = "pgop1.swebench.attribution-ambiguity.v2"


def _source(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _result(root: Path) -> dict[str, object]:
    root.mkdir(parents=True, exist_ok=True)
    trajectory = _source(root, "trajectory.json", {
        "instance_id": "example__repo-1",
        "messages": [{"role": "assistant", "content": "I resolved the task."}],
    }, "AGENT_TRAJECTORY", "pgop1.swebench.trajectory.miniswe_json.v1")
    report = _source(root, "report.json", {"example__repo-1": {"resolved": True}},
                     "EVALUATOR_REPORT", "pgop1.swebench.evaluator_report.resolved_map_json.v1")
    return audit_evidence(root, {"run_id": "v2-recovery-run", "instance_id": "example__repo-1",
        "claim_attribution_contract": CONTRACT, "evidence": [trajectory, report]})


def test_v2_selector_survives_fresh_process_derivation_and_recovery(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    context_root = tmp_path / "context"
    audit = _result(data_root)
    assert audit["claim_attribution_contract"] == CONTRACT

    bound = bind_generalized_audit(audit, data_root, context_root)
    assert bound["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert bound["context_engine"]["fresh_process_readback"]["status"] == "PASS"

    for name in ("trajectory.json", "report.json"):
        (data_root / name).unlink()
    recovered = recover_generalized_audit(context_root)
    assert recovered["status"] == "PASS"
    assert recovered["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert recovered["source_reread"] == "NOT_PERFORMED"
    assert recovered["producer_redispatch"] == "NOT_PERFORMED"
    assert recovered["semantic_claim_validation"] == "SEMANTIC_VALIDATION_NOT_PROVEN"


def test_v2_recovery_rejects_tampered_receipt_commitment(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    context_root = tmp_path / "context"
    audit = _result(data_root)
    bind_generalized_audit(audit, data_root, context_root)
    receipt_path = context_root / "generalized-bridge-receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["manifest"]["graph_sha256"] = "0" * 64
    receipt_path.write_bytes(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())

    with pytest.raises(AuditError, match="manifest differs"):
        recover_generalized_audit(context_root)
