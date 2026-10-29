from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.generalized_bridge import (
    bind_generalized_audit,
    recover_generalized_audit,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _audit(data_root: Path, *, verdict: str = "SUPPORTED") -> dict:
    raw = json.dumps({"opaque": "source bytes", "claim": "adapter-owned"}, sort_keys=True).encode()
    (data_root / "evidence.json").write_bytes(raw)
    return {
        "schema": "pgop1.swebench.generalized-audit.v1",
        "instance_id": "example__repo-1",
        "run_id": "run-a",
        "AUDIT_VERDICT": verdict,
        "AGENT_STATEMENT": [{"text": "I resolved the issue", "predicate": "TASK_RESOLVED"}],
        "PREDICTION": [],
        "EVALUATOR_RESULT": [],
        "observations": [
            {"observation_id": "claim-1", "kind": "agent_statement", "predicate": "TASK_RESOLVED",
             "claim_id": "claim-1", "value": True, "run_id": "run-a", "instance_id": "example__repo-1",
             "source_ref": {"path": "evidence.json", "sha256": _sha(raw), "pointer": "/claim"},
             "parser_id": "json-v1", "parser_version": "1"},
            {"observation_id": "result-1", "kind": "evaluator_result", "predicate": "TASK_RESOLVED",
             "value": False, "run_id": "run-a", "instance_id": "example__repo-1",
             "source_ref": {"path": "evidence.json", "sha256": _sha(raw), "pointer": "/opaque"},
             "parser_id": "json-v1", "parser_version": "1"},
        ],
        "relationships": [
            {"relationship_id": "comparison-1", "from": "claim-1", "to": "result-1",
             "relation": "PREDICATE_VALUE_COMPARISON", "predicate": "TASK_RESOLVED",
             "asserted_value": True, "observed_value": False,
             "evidence_bindings": [
                 {"path": "evidence.json", "sha256": _sha(raw), "pointer": "/claim"},
                 {"path": "evidence.json", "sha256": _sha(raw), "pointer": "/opaque"},
             ]},
        ],
        "SOURCE_PROVENANCE": {
            "evidence_references": [
                {"path": "evidence.json", "sha256": _sha(raw), "bytes": len(raw),
                 "role": "agent_trajectory", "parser_id": "json-v1", "parser_version": "1"},
            ],
        },
        "EXECUTION_EVIDENCE": [],
    }


def test_generalized_bind_commits_source_and_recovers_without_adapter(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    context_root = tmp_path / "context"

    bound = bind_generalized_audit(result, data_root, context_root)

    assert bound["schema"] == "pgop1.swebench.generalized-context-bridge.v2"
    assert bound["adapter_verdict"] == "SUPPORTED"
    assert bound["context_engine"]["status"] == "PASS"
    assert bound["context_engine"]["semantic_claim_validation"] == "SEMANTIC_VALIDATION_NOT_PROVEN"
    assert bound["derivation"]["status"] == "DERIVATION_NOT_VERIFIED"
    assert bound["fixed_i7_provider_dispatch"] == "NOT_PERFORMED"
    assert bound["context_engine"]["fresh_process_readback"]["status"] == "PASS"

    # Recovery relies on the committed context store; original data are absent.
    (data_root / "evidence.json").unlink()
    recovered = recover_generalized_audit(context_root)
    assert recovered["status"] == "PASS"
    assert recovered["source_objects_verified"] == 1
    assert recovered["source_reread"] == "NOT_PERFORMED"
    assert recovered["adapter_rerun"] == "NOT_PERFORMED"
    assert recovered["producer_redispatch"] == "NOT_PERFORMED"


def test_adapter_relationship_is_bound_as_derived_engine_edge(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    context_root = tmp_path / "context"

    bound = bind_generalized_audit(result, data_root, context_root)

    manifest = bound["context_engine"]["manifest"]
    graph_path = context_root / "versions" / f"{manifest['version']:08d}-{manifest['graph_sha256']}" / "graph.json"
    graph = json.loads(graph_path.read_bytes())
    edges = [edge for edge in graph["edges"] if edge.get("relation_type") == "PREDICATE_VALUE_COMPARISON"]
    assert len(edges) == 1
    assert edges[0]["relationship"] == "DERIVED_ASSOCIATION"
    assert edges[0]["asserted_value"] is True
    assert edges[0]["observed_value"] is False


def test_generalized_bridge_rejects_changed_source_bytes(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    (data_root / "evidence.json").write_text("changed", encoding="utf-8")

    with pytest.raises(AuditError, match="source differs from adapter commitment"):
        bind_generalized_audit(result, data_root, tmp_path / "context")


def test_generalized_bridge_rejects_path_traversal(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    ref = result["SOURCE_PROVENANCE"]["evidence_references"][0]
    ref["path"] = "../outside.json"

    with pytest.raises(AuditError, match="normalized relative path"):
        bind_generalized_audit(result, data_root, tmp_path / "context")


@pytest.mark.parametrize(
    "unsafe_path",
    ["container.txt:hidden", "visible.txt.", "visible.txt ", "CON.txt", "NUL", "COM1.log",
     "LPT¹.data", r"folder\evidence.json"],
)
def test_direct_bridge_rejects_windows_path_aliases(tmp_path: Path, unsafe_path: str) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    result["SOURCE_PROVENANCE"]["evidence_references"][0]["path"] = unsafe_path

    with pytest.raises(AuditError):
        bind_generalized_audit(result, data_root, tmp_path / "context")


def test_direct_bridge_rejects_casefold_source_aliases_on_windows(tmp_path: Path) -> None:
    import os

    if os.name != "nt":
        pytest.skip("case-fold collision rule is specific to Windows path identity")
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    original = result["SOURCE_PROVENANCE"]["evidence_references"][0]
    result["SOURCE_PROVENANCE"]["evidence_references"].append(dict(original, path="Evidence.json"))

    with pytest.raises(AuditError, match="case folding"):
        bind_generalized_audit(result, data_root, tmp_path / "context")


def test_output_root_guard_detects_reparse_component_without_is_junction(tmp_path: Path, monkeypatch) -> None:
    from runtime.candidate.swebench_claim_audit import generalized_bridge

    junction = tmp_path / "junction"
    monkeypatch.setattr(generalized_bridge, "_reparse", lambda path: path == junction)

    with pytest.raises(AuditError, match="reparse component"):
        generalized_bridge._assert_new_root(junction / "context")


@pytest.mark.parametrize(
    "unsafe_path",
    ["container.txt:hidden", "visible.txt.", "visible.txt ", "CON.txt", "NUL", "COM1.log",
     "LPT¹.data", r"folder\evidence.json"],
)
def test_direct_bridge_rejects_windows_path_aliases(tmp_path: Path, unsafe_path: str) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    result["SOURCE_PROVENANCE"]["evidence_references"][0]["path"] = unsafe_path

    with pytest.raises(AuditError):
        bind_generalized_audit(result, data_root, tmp_path / "context")


def test_direct_bridge_rejects_casefold_source_aliases_on_windows(tmp_path: Path) -> None:
    import os

    if os.name != "nt":
        pytest.skip("case-fold collision rule is specific to Windows path identity")
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    original = result["SOURCE_PROVENANCE"]["evidence_references"][0]
    alias = dict(original, path="Evidence.json")
    result["SOURCE_PROVENANCE"]["evidence_references"].append(alias)

    with pytest.raises(AuditError, match="case folding"):
        bind_generalized_audit(result, data_root, tmp_path / "context")


def test_output_root_guard_detects_reparse_component_without_is_junction(tmp_path: Path, monkeypatch) -> None:
    from runtime.candidate.swebench_claim_audit import generalized_bridge

    junction = tmp_path / "junction"
    monkeypatch.setattr(generalized_bridge, "_reparse", lambda path: path == junction)

    with pytest.raises(AuditError, match="reparse component"):
        generalized_bridge._assert_new_root(junction / "context")


def test_recovery_rejects_tampered_receipt(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    context_root = tmp_path / "context"
    bind_generalized_audit(result, data_root, context_root)
    receipt_path = context_root / "generalized-bridge-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["manifest"]["graph_sha256"] = "0" * 64
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(AuditError, match="manifest differs"):
        recover_generalized_audit(context_root)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("identity", "another__repo-99"),
        ("run_id", "another-run"),
        ("task_id", "INSTANCE:another__repo-99"),
        ("adapter_verdict", "CONTRADICTED"),
        ("expected_observation_ids", ["attacker-selected-observation"]),
    ],
)
def test_recovery_rejects_receipt_metadata_not_bound_to_capsule(
    tmp_path: Path, field: str, value: object,
) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    context_root = tmp_path / "context"
    bind_generalized_audit(result, data_root, context_root)
    receipt_path = context_root / "generalized-bridge-receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt[field] = value
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="utf-8")

    with pytest.raises(AuditError):
        recover_generalized_audit(context_root)


def test_run_only_sources_and_unknown_instance_observations_stay_run_scoped(tmp_path: Path) -> None:
    from runtime.candidate.context_engine import Engine

    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    ref = result["SOURCE_PROVENANCE"]["evidence_references"][0]
    ref["instance_binding"] = "RUN_ONLY"
    result["EXECUTION_EVIDENCE"] = [dict(ref)]
    result["relationships"] = []
    for observation in result["observations"]:
        observation["instance_id"] = "UNKNOWN"
    context_root = tmp_path / "context"

    bind_generalized_audit(result, data_root, context_root)

    engine = Engine(context_root)
    run_rows = engine.query(task_id="RUN:run-a", limit=1000)
    instance_rows = engine.query(task_id="INSTANCE:example__repo-1", limit=1000)
    assert any(row["kind"] == "source_artifact" for row in run_rows)
    assert not any(row["kind"] == "source_artifact" for row in instance_rows)
    assert all(row["kind"] != "agent_statement" for row in instance_rows)


def test_batch_aggregate_requires_explicit_batch_scope(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    result = _audit(data_root)
    result.pop("instance_id")
    result["batch_id"] = "batch-0001"
    result["result_scope"] = "BATCH_AGGREGATE"

    bound = bind_generalized_audit(result, data_root, tmp_path / "context")

    assert bound["identity_kind"] == "BATCH_AGGREGATE"
    assert bound["identity"] == "batch-0001"
