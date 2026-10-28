"""Prospective evidence bridge to PGOP1's immutable Context Engine.

The bridge stores exact hashes/bytes for selected inputs, binds normalized
claim/result/verdict observations to a small JSON capsule, then verifies and
queries the store in a separate Python process. The Context Engine verifies
storage, graph and I5-NEXT bindings; the claim verdict remains adapter-owned.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import Any

from runtime.candidate.context_engine import Engine, canonical_json, pointer, sha256_bytes, strict_json_loads

from .adapter import AuditError, _checked_root, _read_bytes, _safe_path, _sha


BRIDGE_SCHEMA = "pgop1.swebench.context-bridge.v1"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_CAPSULE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_REFERENCES = 64


def _stable_id(prefix: str, value: str) -> str:
    return prefix + "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _source_limit(path: str) -> int:
    if path.endswith(".traj.json"):
        return 16 * 1024 * 1024
    if path.endswith(".gz"):
        return 32 * 1024 * 1024
    if path.endswith(".diff"):
        return 16 * 1024 * 1024
    if path.endswith(".jsonl"):
        return 16 * 1024 * 1024
    return 8 * 1024 * 1024


def _references(audit_result: dict[str, Any]) -> list[dict[str, Any]]:
    provenance = audit_result.get("SOURCE_PROVENANCE")
    if not isinstance(provenance, dict):
        raise AuditError("BRIDGE_PROVENANCE_MISSING", "adapter result lacks source provenance")
    refs: list[dict[str, Any]] = []
    for key in ("EXECUTION_EVIDENCE",):
        values = audit_result.get(key)
        if not isinstance(values, list):
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "execution evidence must be an array")
        refs.extend(values)
    values = provenance.get("evidence_references", [])
    if not isinstance(values, list):
        raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "provenance references must be an array")
    refs.extend(values)
    unique: dict[str, dict[str, Any]] = {}
    for item in refs:
        if (not isinstance(item, dict) or not isinstance(item.get("path"), str)
                or not isinstance(item.get("sha256"), str) or type(item.get("bytes")) is not int):
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "evidence reference lacks a path, digest or byte count")
        current = unique.get(item["path"])
        if current is not None and (current["sha256"] != item["sha256"] or current["bytes"] != item["bytes"]):
            raise AuditError("BRIDGE_EVIDENCE_CONFLICT", "one evidence path has conflicting commitments")
        unique[item["path"]] = item
    if not unique or len(unique) > MAX_SOURCE_REFERENCES:
        raise AuditError("BRIDGE_SOURCE_COUNT", "source reference count is empty or exceeds its bound")
    return [unique[key] for key in sorted(unique)]


def _direct_json_pointer(path: str, instance_id: str, claim: dict[str, Any] | None) -> str | None:
    escaped_id = _escape_pointer(instance_id)
    if path == f"logs/logs/{instance_id}/report.json":
        return "/" + escaped_id
    if path == f"logs/trajs/{instance_id}.traj.json":
        return str(claim["source_pointer"]) if claim else "/instance_id"
    if path.endswith("/per_instance_details.json"):
        return "/" + escaped_id
    if path.endswith("/results/results.json"):
        return "/resolved"
    return None


def _assert_new_root(path: Path) -> Path:
    candidate = path.absolute()
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink() or (hasattr(cursor, "is_junction") and cursor.is_junction()):
            raise AuditError("BRIDGE_REPARSE_POINT", "Context Engine output path has a reparse component")
    if candidate.exists():
        raise AuditError("BRIDGE_CONTEXT_ROOT_EXISTS", "Context Engine integration requires a fresh output root")
    return candidate


def _fresh_process_verify(
    context_root: Path,
    instance_id: str,
    expected_manifest: dict[str, Any],
    expected_observations: list[str],
) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[3]
    code = (
        "import json,sys; from pathlib import Path; "
        "sys.path.insert(0,sys.argv[1]); "
        "from runtime.candidate.context_engine import Engine; "
        "root=Path(sys.argv[2]); instance=sys.argv[3]; "
        "expected_version=int(sys.argv[4]); expected_graph=sys.argv[5]; "
        "expected_ids=set(json.loads(sys.argv[6])); e=Engine(root); "
        "v=e.verify(); m=e.latest(); rows=e.query(task_id=instance,limit=1000); "
        "found={r['id'] for r in rows}; "
        "ok=(v['status']=='PASS' and m['version']==expected_version and "
        "m['graph_sha256']==expected_graph and expected_ids.issubset(found)); "
        "print(json.dumps({'status':'PASS' if ok else 'NOT_PROVEN',"
        "'versions':v['versions'],'graph_version':m['version'],"
        "'graph_sha256':m['graph_sha256'],'query_count':len(rows),"
        "'expected_observations_found':len(expected_ids & found),"
        "'read_only_api_operations':True,'filesystem_mutation_status':'NOT_PROVEN',"
        "'index_reconstruction':'POSSIBLE','dispatch':'NOT_PERFORMED',"
        "'redispatch':'NOT_APPLICABLE_NO_PROVIDER_OPERATION'},sort_keys=True)); "
        "sys.exit(0 if ok else 3)"
    )
    args = [sys.executable, "-I", "-B", "-c", code, str(repo_root), str(context_root),
            instance_id, str(expected_manifest["version"]), expected_manifest["graph_sha256"],
            json.dumps(expected_observations, separators=(",", ":"))]
    try:
        completed = subprocess.run(args, shell=False, capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_UNAVAILABLE",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_APPLICABLE_NO_PROVIDER_OPERATION"}
    if completed.returncode != 0:
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_VERIFY_FAILED",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_APPLICABLE_NO_PROVIDER_OPERATION"}
    try:
        value = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_OUTPUT_INVALID",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_APPLICABLE_NO_PROVIDER_OPERATION"}
    if not isinstance(value, dict) or value.get("status") != "PASS":
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_VERIFY_FAILED",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_APPLICABLE_NO_PROVIDER_OPERATION"}
    return value


def bind_to_context_engine(
    audit_result: dict[str, Any],
    data_root: str | os.PathLike[str],
    context_root: str | os.PathLike[str],
) -> dict[str, Any]:
    """Bind one adapter result and its cited source bytes to a new I4/I5-NEXT store.

    This records and verifies provenance/graph bindings only. It does not rerun
    the evaluator, infer claim semantics, invoke a fixed I7 provider, or create
    an operational execution/recovery record.
    """
    if (not isinstance(audit_result, dict)
            or audit_result.get("schema") != "pgop1.swebench.claim-audit.v1"
            or audit_result.get("AUDIT_VERDICT") not in {
                "SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE",
                "INTEGRITY_FAILURE", "VERIFICATION_ERROR",
            }):
        raise AuditError("BRIDGE_AUDIT_RESULT_INVALID", "bridge requires a versioned adapter result")
    instance_id = audit_result.get("instance_id")
    if not isinstance(instance_id, str) or instance_id == "UNBOUND":
        raise AuditError("BRIDGE_INSTANCE_UNBOUND", "bridge requires a bound instance identity")
    claim = audit_result.get("AGENT_STATEMENT")
    if claim is not None and (not isinstance(claim, dict) or not isinstance(claim.get("text"), str)
                              or len(claim["text"].encode("utf-8")) > 64 * 1024):
        raise AuditError("BRIDGE_CLAIM_INVALID", "claim must be a bounded explicit statement object")

    root = _checked_root(data_root)
    output_root = _assert_new_root(Path(context_root))
    refs = _references(audit_result)
    admitted: list[dict[str, Any]] = []
    grants = []
    for item in refs:
        path = _safe_path(root, item["path"])
        raw, measured = _read_bytes(root, item["path"], min(MAX_SOURCE_BYTES, _source_limit(item["path"])))
        if len(raw) != item["bytes"] or measured["sha256"] != item["sha256"]:
            raise AuditError("BRIDGE_SOURCE_COMMITMENT_MISMATCH", "current source differs from adapter evidence reference")
        source_id = _stable_id("source", item["path"] + "\0" + item["sha256"])
        source = {"path": item["path"], "absolute_path": str(path), "sha256": item["sha256"],
                  "bytes": item["bytes"], "source_id": source_id,
                  "scope": "ENGINEERING_RESULT", "raw_bytes_retained": True}
        admitted.append(source)
        grants.append({"path": str(path), "sha256": item["sha256"], "scope": "ENGINEERING_RESULT"})

    source_by_path = {row["path"]: row for row in admitted}
    capsule_observations = {
        "AGENT_STATEMENT": claim,
        "PREDICTION": audit_result.get("PREDICTION"),
        "EVALUATOR_RESULT": audit_result.get("EVALUATOR_RESULT"),
        "AUDIT_VERDICT": {"value": audit_result["AUDIT_VERDICT"],
                           "reason_codes": audit_result.get("reason_codes", []),
                           "authority": "ADVISORY_ENGINEERING_ONLY"},
        "SOURCE_PROVENANCE": audit_result.get("SOURCE_PROVENANCE"),
    }
    comparison = {
        "from": "AGENT_STATEMENT", "to": "EVALUATOR_RESULT",
        "relationship": "DERIVED_ASSOCIATION", "predicate": "TASK_RESOLVED",
        "asserted_value": True if claim else "UNKNOWN",
        "observed_value": (audit_result.get("EVALUATOR_RESULT") or {}).get("observed_value", "UNKNOWN"),
        "adapter_verdict": audit_result["AUDIT_VERDICT"],
        "source_ids": [row["source_id"] for row in admitted],
    }
    result_edge = {
        "from": "EVALUATOR_RESULT", "to": "AUDIT_VERDICT",
        "relationship": "DERIVED_ASSOCIATION", "predicate": "LOCAL_RESULT_COMPARISON",
        "source_ids": [row["source_id"] for row in admitted],
    }
    patch_path = f"logs/logs/{instance_id}/patch.diff"
    patch_source = source_by_path.get(patch_path)
    if audit_result.get("PREDICTION") is not None and patch_source is None:
        raise AuditError("BRIDGE_PATCH_SOURCE_MISSING", "prediction result has no committed patch source")
    prediction_edge = {
        "from": "PREDICTION", "to": "PATCH_ARTIFACT",
        "relationship": "DERIVED_ASSOCIATION", "predicate": "PATCH_BYTES_EQUAL",
        "observed_value": True if audit_result.get("PREDICTION", {}).get("patch_equal_to_prediction") else "UNKNOWN",
        "source_ids": [source_by_path[path]["source_id"] for path in
                       ("logs/all_preds.jsonl", patch_path) if path in source_by_path],
    }
    capsule = {
        "schema": "pgop1.swebench.context-source-capsule.v1",
        "instance_id": instance_id,
        "run_identity": (audit_result.get("SOURCE_PROVENANCE") or {}).get("run_identity", "UNKNOWN"),
        "observations": capsule_observations,
        "source_refs": admitted,
        "relationships": [comparison, result_edge, prediction_edge],
        "limitations": {
            "semantic_claim_verification_by_context_engine": "NOT_PERFORMED",
            "upstream_run_authentication": "NOT_PROVEN",
            "provider_identity": "NOT_CRYPTOGRAPHICALLY_ATTESTED",
            "independent_custody": "NOT_PROVEN",
            "operational_authority": "NONE",
        },
    }
    capsule_raw = canonical_json(capsule)
    if len(capsule_raw) > MAX_CAPSULE_BYTES:
        raise AuditError("BRIDGE_CAPSULE_TOO_LARGE", "derived context capsule exceeds its byte bound")
    capsule_path = output_root / "adapter-capsule.json"
    capsule_path.parent.mkdir(parents=True, exist_ok=False)
    with capsule_path.open("xb") as stream:
        stream.write(capsule_raw)
        stream.flush()
        os.fsync(stream.fileno())
    capsule_hash = sha256_bytes(capsule_raw)
    capsule_source_id = "source-capsule-" + capsule_hash

    # This is a new local store. The exact per-file grants are scoped to the
    # adapter-cited path/hash and are used only to copy bytes into ContextEngine.
    engine = Engine(output_root, grants=grants)
    for source in admitted:
        descriptor = engine.admit_source(source["absolute_path"], source["sha256"],
                                         scope=source["scope"], source_id=source["source_id"])
        if descriptor.get("sha256") != source["sha256"] or descriptor.get("byte_length") != source["bytes"]:
            raise AuditError("BRIDGE_SOURCE_ADMISSION_MISMATCH", "Context Engine admitted different source bytes")
    capsule_descriptor = engine.admit_source(capsule_path, capsule_hash, scope="ENGINEERING_RESULT",
                                             source_id=capsule_source_id)
    if capsule_descriptor.get("sha256") != capsule_hash:
        raise AuditError("BRIDGE_CAPSULE_ADMISSION_MISMATCH", "Context Engine admitted a different capsule")

    observations: list[dict[str, Any]] = []
    source_node_ids: dict[str, str] = {}
    for index, source in enumerate(admitted):
        pointer_path = _direct_json_pointer(source["path"], instance_id, claim)
        if pointer_path is not None:
            raw = engine.read_source(source["source_id"])
            parsed = strict_json_loads(raw)
            value = pointer(parsed, pointer_path)
            binding = {"source_id": source["source_id"], "pointer": pointer_path}
        else:
            pointer_path = f"/source_refs/{index}"
            value = capsule["source_refs"][index]
            binding = {"source_id": capsule_source_id, "pointer": pointer_path}
        node_id = _stable_id("source-observation", instance_id + "\0" + source["source_id"])
        source_node_ids[source["source_id"]] = node_id
        observations.append({"id": node_id, "kind": "source_artifact", "task_id": instance_id,
                             "artifact_id": source["source_id"], "source_id": binding["source_id"],
                             "evidence_pointer": binding["pointer"], "value": value})

    statement_pointer = str(claim["source_pointer"]) if claim else None
    trajectory_path = f"logs/trajs/{instance_id}.traj.json"
    trajectory_source = source_by_path.get(trajectory_path)
    if claim and trajectory_source:
        statement_binding = {"source_id": trajectory_source["source_id"], "pointer": statement_pointer}
        statement_value = claim["text"]
    else:
        statement_binding = {"source_id": capsule_source_id, "pointer": "/observations/AGENT_STATEMENT"}
        statement_value = claim
    statement_id = _stable_id("observation-agent-statement", instance_id)
    prediction_id = _stable_id("observation-prediction", instance_id)
    evaluator_id = _stable_id("observation-evaluator-result", instance_id)
    verdict_id = _stable_id("observation-audit-verdict", instance_id)
    provenance_id = _stable_id("observation-source-provenance", instance_id)
    observations.extend([
        {"id": statement_id, "kind": "agent_statement", "task_id": instance_id,
         "run_id": capsule["run_identity"], "source_id": statement_binding["source_id"],
         "evidence_pointer": statement_binding["pointer"], "value": statement_value},
        {"id": prediction_id, "kind": "prediction", "task_id": instance_id,
         "run_id": capsule["run_identity"], "source_id": capsule_source_id,
         "evidence_pointer": "/observations/PREDICTION",
         "value": capsule_observations["PREDICTION"]},
        {"id": evaluator_id, "kind": "evaluator_result", "task_id": instance_id,
         "run_id": capsule["run_identity"], "source_id": capsule_source_id,
         "evidence_pointer": "/observations/EVALUATOR_RESULT",
         "value": capsule_observations["EVALUATOR_RESULT"]},
        {"id": verdict_id, "kind": "audit_verdict", "task_id": instance_id,
         "run_id": capsule["run_identity"], "source_id": capsule_source_id,
         "evidence_pointer": "/observations/AUDIT_VERDICT",
         "value": capsule_observations["AUDIT_VERDICT"]},
        {"id": provenance_id, "kind": "source_provenance", "task_id": instance_id,
         "run_id": capsule["run_identity"], "source_id": capsule_source_id,
         "evidence_pointer": "/observations/SOURCE_PROVENANCE",
         "value": capsule_observations["SOURCE_PROVENANCE"]},
    ])

    edges: list[dict[str, Any]] = []
    for relation_index, (start, end) in enumerate(((statement_id, evaluator_id), (evaluator_id, verdict_id))):
        relation = capsule["relationships"][relation_index]
        edges.append({"id": _stable_id("edge-derived", instance_id + f"\0{relation_index}"),
                      "from": start, "to": end, "relationship": "DERIVED_ASSOCIATION",
                      "evidence_bindings": [{"source_id": capsule_source_id,
                                              "pointer": f"/relationships/{relation_index}"}]})
    if patch_source is not None:
        edges.append({"id": _stable_id("edge-prediction-patch", instance_id),
                      "from": prediction_id, "to": source_node_ids[patch_source["source_id"]],
                      "relationship": "DERIVED_ASSOCIATION",
                      "evidence_bindings": [{"source_id": capsule_source_id, "pointer": "/relationships/2"}]})
    for source_id, node_id in source_node_ids.items():
        edges.append({"id": _stable_id("edge-source", instance_id + "\0" + source_id),
                      "from": node_id, "to": verdict_id, "relationship": "DERIVED_ASSOCIATION",
                      "evidence_bindings": [{"source_id": capsule_source_id,
                                              "pointer": "/source_refs/" + str(next(i for i, r in enumerate(admitted) if r["source_id"] == source_id))}]})

    manifest = engine.ingest(observations, edges, provenance={
        "tool_identity": "PGOP1_SWEBENCH_CLAIM_AUDIT_CONTEXT_BRIDGE",
        "declared_actor_identity": "UNKNOWN",
        "provider_identity": "UNKNOWN",
        "process_identity": "UNKNOWN",
        "invocation_evidence": "LOCAL_ENGINEERING_BRIDGE_CALL",
    })
    verification = engine.verify()
    rows = engine.query(task_id=instance_id, limit=1000)
    expected_ids = [statement_id, prediction_id, evaluator_id, verdict_id, provenance_id]
    if verification.get("status") != "PASS" or not set(expected_ids).issubset({row["id"] for row in rows}):
        fresh = {"status": "NOT_PROVEN", "reason_code": "IN_PROCESS_GRAPH_VERIFY_FAILED",
                 "dispatch": "NOT_PERFORMED", "redispatch": "NOT_APPLICABLE_NO_PROVIDER_OPERATION"}
    else:
        fresh = _fresh_process_verify(output_root, instance_id, manifest, expected_ids)
    return {
        "schema": BRIDGE_SCHEMA,
        "instance_id": instance_id,
        "adapter_verdict": audit_result["AUDIT_VERDICT"],
        "context_engine": {
            "status": "PASS" if verification.get("status") == "PASS" else "NOT_PROVEN",
            "manifest": manifest,
            "verification": verification,
            "queried_observations": len(rows),
            "observation_ids": [row["id"] for row in rows],
            "source_objects_admitted": len(admitted),
            "source_bytes_admitted": sum(row["bytes"] for row in admitted),
            "capsule_sha256": capsule_hash,
            "semantic_claim_verification_by_context_engine": "NOT_PERFORMED",
            "fresh_process_readback": fresh,
        },
        "fixed_i7_provider_dispatch": "NOT_PERFORMED",
        "provider_recovery": "NOT_APPLICABLE_NO_PROVIDER_OPERATION_CREATED",
        "redispatch": "NOT_APPLICABLE_NO_PROVIDER_OPERATION_CREATED",
        "authority": "ADVISORY_ENGINEERING_ONLY; NO_OP1_AUTHORITY_EFFECT",
    }
