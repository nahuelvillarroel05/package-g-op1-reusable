"""Context Engine persistence and recovery for A010 versioned audits."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import audit_evidence
from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.generalized_bridge import (
    bind_generalized_audit,
    recover_generalized_audit,
)

CONTRACT = "pgop1.swebench.attribution-ambiguity.v1"
RUN = "a010-recovery-run"
INSTANCE = "example__repo-1"


def _put(root: Path, name: str, value: object, role: str, parser_id: str) -> tuple[dict[str, object], bytes]:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return ({"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
             "role": role, "parser_id": parser_id}, raw)


def _case(data_root: Path) -> tuple[dict[str, object], dict[str, bytes]]:
    data_root.mkdir(parents=True, exist_ok=True)
    trajectory, trajectory_raw = _put(data_root, "trajectory.json", {
        "instance_id": INSTANCE,
        "messages": [{"role": "assistant", "content":
            "Résumé 🧪 — The reviewer wrote: 'Keep movin'; I did not resolve the task. "
            "I used the literal 'x'; I resolved the task.'"}],
    }, "AGENT_TRAJECTORY", "pgop1.swebench.trajectory.miniswe_json.v1")
    evaluator, evaluator_raw = _put(data_root, "report.json", {INSTANCE: {"resolved": True}},
        "EVALUATOR_REPORT", "pgop1.swebench.evaluator_report.resolved_map_json.v1")
    result = audit_evidence(data_root, {"run_id": RUN, "instance_id": INSTANCE,
        "claim_attribution_contract": CONTRACT, "evidence": [trajectory, evaluator]})
    return result, {"trajectory.json": trajectory_raw, "report.json": evaluator_raw}


def _retraction_case(data_root: Path) -> tuple[dict[str, object], dict[str, bytes]]:
    data_root.mkdir(parents=True, exist_ok=True)
    trajectory, trajectory_raw = _put(data_root, "trajectory.json", {
        "instance_id": INSTANCE,
        "messages": [
            {"role": "assistant", "content": "I resolved the task."},
            {"role": "assistant", "content": "I retract my previous claim."},
        ],
    }, "AGENT_TRAJECTORY", "pgop1.swebench.trajectory.miniswe_json.v1")
    evaluator, evaluator_raw = _put(data_root, "report.json", {INSTANCE: {"resolved": True}},
        "EVALUATOR_REPORT", "pgop1.swebench.evaluator_report.resolved_map_json.v1")
    result = audit_evidence(data_root, {"run_id": RUN, "instance_id": INSTANCE,
        "claim_attribution_contract": CONTRACT, "evidence": [trajectory, evaluator]})
    return result, {"trajectory.json": trajectory_raw, "report.json": evaluator_raw}


def test_new_contract_survives_context_commit_and_fresh_process_recovery(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    context_root = tmp_path / "context"
    audit, original_sources = _case(data_root)
    bound = bind_generalized_audit(audit, data_root, context_root)

    assert bound["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert bound["bridge_qualifiers"]["logic_status"] == "SEMANTIC_VALIDATION_NOT_PROVEN"
    assert bound["bridge_qualifiers"]["evaluator_authentication_status"] == "UNAUTHENTICATED"
    assert bound["context_engine"]["fresh_process_readback"]["status"] == "PASS"
    assert bound["context_engine"]["fresh_process_readback"]["derivation"]["status"] == "DERIVATION_VERIFIED"

    receipt = json.loads((context_root / "generalized-bridge-receipt.json").read_bytes())
    capsule_source = receipt["capsule"]
    capsule_raw = (context_root / "normalized-audit-capsule.json").read_bytes()
    assert len(capsule_raw) == capsule_source["bytes"]
    assert hashlib.sha256(capsule_raw).hexdigest() == capsule_source["sha256"]
    capsule = json.loads(capsule_raw)
    assert capsule["audit_result"] == audit
    assert capsule["audit_result"]["claim_attribution_contract"] == CONTRACT
    assert capsule["bridge_qualifiers"] == bound["bridge_qualifiers"]

    # Remove producer-side inputs so recovery must use the exact bytes committed in Engine.
    for source_name in original_sources:
        (data_root / source_name).unlink()
    local_recovery = recover_generalized_audit(context_root)
    assert local_recovery["status"] == "PASS"
    assert local_recovery["source_reread"] == "NOT_PERFORMED"
    assert local_recovery["adapter_rerun"] == "PERFORMED_FROM_ENGINE_BYTES"
    assert local_recovery["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert local_recovery["bridge_qualifiers"] == bound["bridge_qualifiers"]

    repo_root = Path(__file__).resolve().parents[1]
    child_code = (
        "import hashlib,json,sys; from pathlib import Path; "
        "sys.path.insert(0,sys.argv[1]); "
        "from runtime.candidate.context_engine import Engine; "
        "from runtime.candidate.swebench_claim_audit.generalized_bridge import recover_generalized_audit; "
        "root=Path(sys.argv[2]); recovery=recover_generalized_audit(root); engine=Engine(root); "
        "receipt=json.loads((root/'generalized-bridge-receipt.json').read_bytes()); "
        "capsule_raw=engine.read_source(receipt['capsule']['source_id']); "
        "capsule=json.loads(capsule_raw); "
        "sources=[{'path':r['path'],'bytes':len(engine.read_source(r['source_id'])),'sha256':"
        "hashlib.sha256(engine.read_source(r['source_id'])).hexdigest()} for r in capsule['source_refs']]; "
        "print(json.dumps({'recovery':recovery,'capsule_sha256':hashlib.sha256(capsule_raw).hexdigest(),"
        "'capsule_bytes':len(capsule_raw),'sources':sources},sort_keys=True))"
    )
    child = subprocess.run([sys.executable, "-I", "-B", "-c", child_code,
                            str(repo_root), str(context_root)],
                           capture_output=True, text=True, timeout=45, check=False)
    assert child.returncode == 0, child.stderr
    recovered = json.loads(child.stdout)
    assert recovered["recovery"]["status"] == "PASS"
    assert recovered["recovery"]["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert recovered["recovery"]["bridge_qualifiers"]["logic_status"] == "SEMANTIC_VALIDATION_NOT_PROVEN"
    assert recovered["recovery"]["bridge_qualifiers"]["evaluator_authentication_status"] == "UNAUTHENTICATED"
    assert recovered["recovery"]["producer_redispatch"] == "NOT_PERFORMED"
    assert recovered["capsule_sha256"] == capsule_source["sha256"]
    assert recovered["capsule_bytes"] == capsule_source["bytes"]
    assert {row["path"]: (row["bytes"], row["sha256"]) for row in recovered["sources"]} == {
        name: (len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in original_sources.items()
    }


def test_versioned_contract_recovery_rejects_identity_tampering(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    context_root = tmp_path / "context"
    audit, _ = _case(data_root)
    bind_generalized_audit(audit, data_root, context_root)

    receipt_path = context_root / "generalized-bridge-receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["identity"] = "another__repo-2"
    receipt_path.write_bytes(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())

    with pytest.raises(AuditError, match="(?i)receipt|identity|capsule|metadata"):
        recover_generalized_audit(context_root)


def test_standalone_retraction_observation_recovers_from_committed_source_bytes(
        tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    context_root = tmp_path / "context"
    audit, source_bytes = _retraction_case(data_root)
    assert len(audit["CLAIM_RETRACTIONS"]) == 1
    event = audit["CLAIM_RETRACTIONS"][0]
    bound = bind_generalized_audit(audit, data_root, context_root)
    assert bound["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert bound["context_engine"]["fresh_process_readback"]["status"] == "PASS"

    for name in source_bytes:
        (data_root / name).unlink()
    recovery = recover_generalized_audit(context_root)
    assert recovery["status"] == "PASS"
    assert recovery["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert recovery["bridge_qualifiers"]["evaluator_authentication_status"] == "UNAUTHENTICATED"

    repo_root = Path(__file__).resolve().parents[1]
    child_code = (
        "import hashlib,json,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
        "from runtime.candidate.context_engine import Engine; "
        "from runtime.candidate.swebench_claim_audit.generalized_bridge import recover_generalized_audit; "
        "root=Path(sys.argv[2]); recovery=recover_generalized_audit(root); engine=Engine(root); "
        "receipt=json.loads((root/'generalized-bridge-receipt.json').read_bytes()); "
        "capsule=json.loads(engine.read_source(receipt['capsule']['source_id'])); "
        "rows=engine.query(task_id='INSTANCE:example__repo-1',kind='claim_retraction',limit=10); "
        "sources=[{'path':r['path'],'bytes':len(engine.read_source(r['source_id'])),'sha256':"
        "hashlib.sha256(engine.read_source(r['source_id'])).hexdigest()} for r in capsule['source_refs']]; "
        "print(json.dumps({'recovery':recovery,'rows':rows,'sources':sources},sort_keys=True))"
    )
    child = subprocess.run([sys.executable, "-I", "-B", "-c", child_code,
                            str(repo_root), str(context_root)],
                           capture_output=True, text=True, timeout=45, check=False)
    assert child.returncode == 0, child.stderr
    fresh = json.loads(child.stdout)
    assert fresh["recovery"]["status"] == "PASS"
    assert fresh["recovery"]["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert len(fresh["rows"]) == 1
    recovered_event = fresh["rows"][0]["value"]["value"]
    assert {key: recovered_event[key] for key in event} == event
    assert recovered_event["target_claim_id"] == event["target_claim_id"]
    assert recovered_event["source_pointer"] == event["source_pointer"]
    assert {row["path"]: (row["bytes"], row["sha256"]) for row in fresh["sources"]} == {
        name: (len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in source_bytes.items()
    }


def test_versioned_contract_source_commitment_mismatch_fails_before_context_creation(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    audit, _ = _case(data_root)
    (data_root / "trajectory.json").write_bytes(b"tampered source bytes")

    with pytest.raises(AuditError, match="source differs from adapter commitment"):
        bind_generalized_audit(audit, data_root, tmp_path / "context")
    assert not (tmp_path / "context").exists()
