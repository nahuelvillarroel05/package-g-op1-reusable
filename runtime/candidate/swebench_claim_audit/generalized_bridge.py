"""Generalized adapter-to-Context-Engine binding for PGOP1 SWE-bench audits.

This module commits adapter-normalized results and source bytes to the real
I4/I5-NEXT Context Engine. It does not interpret claim semantics or execute
the agent, evaluator, patch, or any code present in evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import subprocess
import sys
from typing import Any

from runtime.candidate.context_engine import Engine, canonical_json, strict_json_loads

from .adapter import AuditError, _checked_root, _read_bytes, _safe_path, _sha


BRIDGE_SCHEMA = "pgop1.swebench.generalized-context-bridge.v1"
AUDIT_SCHEMA = "pgop1.swebench.generalized-audit.v1"
MAX_SOURCE_REFERENCES = 64
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_CAPSULE_BYTES = 8 * 1024 * 1024
MAX_AUDIT_BYTES = 4 * 1024 * 1024
MAX_OBSERVATIONS = 1000
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")


def _stable_id(prefix: str, value: str) -> str:
    return prefix + "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


def _safe_relative(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise AuditError("BRIDGE_PATH_INVALID", "source path must be a normalized relative POSIX path")
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    parts = value.split("/")
    if (posix.is_absolute() or windows.is_absolute() or windows.drive
            or any(part in {"", ".", ".."} for part in parts)):
        raise AuditError("BRIDGE_PATH_INVALID", "source path must be a normalized relative path")
    reserved = re.compile(r"(?i)^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])$")
    for part in parts:
        stem = part.split(".", 1)[0]
        if ":" in part or part.endswith((".", " ")) or reserved.fullmatch(stem):
            raise AuditError("BRIDGE_PATH_INVALID", "source path component uses a Windows alias, device name, or ADS syntax")
    return value


def _reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _identity(audit_result: dict[str, Any]) -> tuple[str, str, str]:
    instance = audit_result.get("instance_id")
    run = audit_result.get("run_id")
    batch = audit_result.get("batch_id")
    if isinstance(instance, str) and instance and instance != "UNBOUND":
        kind, value = "INSTANCE", instance
    elif (audit_result.get("result_scope") == "BATCH_AGGREGATE"
          and isinstance(batch, str) and batch):
        kind, value = "BATCH_AGGREGATE", batch
    else:
        raise AuditError("BRIDGE_IDENTITY_UNBOUND", "audit result must bind an instance or explicit batch aggregate")
    if not _ID_RE.fullmatch(value):
        raise AuditError("BRIDGE_IDENTITY_INVALID", "audit identity is not a bounded stable identifier")
    if not isinstance(run, str) or not run:
        run = "UNKNOWN"
    return kind, value, run


def _source_references(audit_result: dict[str, Any]) -> list[dict[str, Any]]:
    provenance = audit_result.get("SOURCE_PROVENANCE")
    if not isinstance(provenance, dict):
        raise AuditError("BRIDGE_PROVENANCE_MISSING", "audit result lacks source provenance")
    candidates: list[Any] = []
    refs = provenance.get("evidence_references", [])
    if not isinstance(refs, list):
        raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "provenance evidence_references must be an array")
    candidates.extend(refs)
    execution = audit_result.get("EXECUTION_EVIDENCE", [])
    if not isinstance(execution, list):
        raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "EXECUTION_EVIDENCE must be an array")
    candidates.extend(execution)

    by_path: dict[str, dict[str, Any]] = {}
    for item in candidates:
        if not isinstance(item, dict):
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "evidence reference must be an object")
        raw_path = item.get("path")
        digest = item.get("sha256")
        size = item.get("bytes")
        if (not isinstance(raw_path, str) or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or type(size) is not int or size < 0 or size > MAX_SOURCE_BYTES):
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "evidence reference needs bounded path, sha256, and byte count")
        path = _safe_relative(raw_path)
        role = item.get("role", "UNKNOWN")
        parser_id = item.get("parser_id", "UNKNOWN")
        parser_version = item.get("parser_version", "UNKNOWN")
        instance_binding = item.get("instance_binding", "INSTANCE_BOUND")
        if not isinstance(role, str) or not role or len(role) > 128:
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "evidence role must be a bounded string")
        if not isinstance(parser_id, str) or not parser_id or len(parser_id) > 256:
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "parser identity must be a bounded string")
        if not isinstance(parser_version, str) or not parser_version or len(parser_version) > 128:
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "parser version must be a bounded string")
        if instance_binding not in {"INSTANCE_BOUND", "RUN_ONLY"}:
            raise AuditError("BRIDGE_EVIDENCE_MALFORMED", "instance_binding must be INSTANCE_BOUND or RUN_ONLY")
        normalized = {"path": path, "sha256": digest, "bytes": size,
                      "role": role, "parser_id": parser_id, "parser_version": parser_version,
                      "instance_binding": instance_binding}
        path_key = path.casefold() if os.name == "nt" else path
        old = by_path.get(path_key)
        if old is not None and old["path"] != path:
            raise AuditError("BRIDGE_EVIDENCE_PATH_ALIAS", "source paths collide under Windows case folding")
        if old is not None and (old["sha256"], old["bytes"]) != (digest, size):
            raise AuditError("BRIDGE_EVIDENCE_CONFLICT", "same source path has conflicting byte commitments")
        if old is not None:
            old_roles = set(old["roles"])
            old_roles.add(role)
            old_parsers = set(old["parser_ids"])
            old_parsers.add(parser_id)
            old["roles"] = sorted(old_roles)
            old["parser_ids"] = sorted(old_parsers)
            old_versions = set(old["parser_versions"])
            old_versions.add(parser_version)
            old["parser_versions"] = sorted(old_versions)
            bindings = set(old["instance_bindings"])
            bindings.add(instance_binding)
            old["instance_bindings"] = sorted(bindings)
        else:
            by_path[path_key] = {**normalized, "roles": [role], "parser_ids": [parser_id],
                                 "parser_versions": [parser_version],
                                 "instance_bindings": [instance_binding]}
    if not by_path or len(by_path) > MAX_SOURCE_REFERENCES:
        raise AuditError("BRIDGE_SOURCE_COUNT", "source reference count is empty or exceeds the limit of 64")
    return [by_path[path] for path in sorted(by_path)]


def _validate_audit(audit_result: dict[str, Any]) -> tuple[str, str, str]:
    if (not isinstance(audit_result, dict) or audit_result.get("schema") != AUDIT_SCHEMA
            or audit_result.get("AUDIT_VERDICT") not in {
                "SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE",
                "INTEGRITY_FAILURE", "VERIFICATION_ERROR",
            }):
        raise AuditError("BRIDGE_AUDIT_RESULT_INVALID", "bridge requires a versioned generalized audit result")
    identity = _identity(audit_result)
    encoded = canonical_json(audit_result)
    if len(encoded) > MAX_AUDIT_BYTES:
        raise AuditError("BRIDGE_AUDIT_TOO_LARGE", "normalized audit result exceeds its byte bound")
    return identity


def _is_run_only(source_ref: dict[str, Any]) -> bool:
    bindings = source_ref.get("instance_bindings", [])
    return "RUN_ONLY" in bindings


def _source_task_id(source_ref: dict[str, Any], identity_kind: str,
                    identity_value: str, run_id: str) -> str:
    if _is_run_only(source_ref) or identity_kind == "BATCH_AGGREGATE":
        return "RUN:" + run_id
    return f"INSTANCE:{identity_value}"


def _observation_task_id(item: dict[str, Any], identity_kind: str,
                         identity_value: str, run_id: str) -> str:
    instance = item.get("instance_id")
    if isinstance(instance, str) and instance not in {"", "UNKNOWN", "UNBOUND"}:
        return f"INSTANCE:{instance}"
    return "RUN:" + str(item.get("run_id", run_id))


def _expected_observation_tasks(audit_result: dict[str, Any], identity_kind: str,
                                identity_value: str, run_id: str,
                                source_refs: list[dict[str, Any]], capsule_hash: str
                                ) -> dict[str, str]:
    """Recompute graph observation identities and scopes from capsule contents."""
    task_id = f"{identity_kind}:{identity_value}"
    expected: dict[str, str] = {}
    for source in source_refs:
        source_id = _stable_id("source", source["path"] + "\0" + source["sha256"])
        source_task = _source_task_id(source, identity_kind, identity_value, run_id)
        expected[_stable_id("source-artifact", source_task + "\0" + source_id)] = source_task
    normalized = audit_result.get("observations")
    if not isinstance(normalized, list):
        raise AuditError("BRIDGE_RECOVERY_AUDIT_INVALID", "capsule audit observations are unavailable")
    seen: set[str] = set()
    for item in normalized:
        if not isinstance(item, dict) or not isinstance(item.get("observation_id"), str):
            raise AuditError("BRIDGE_RECOVERY_AUDIT_INVALID", "capsule observation identity is invalid")
        observation_run = item.get("run_id", run_id)
        unique_key = "\0".join((str(observation_run), str(item.get("instance_id") or ""), item["observation_id"]))
        if unique_key in seen:
            raise AuditError("BRIDGE_RECOVERY_AUDIT_INVALID", "capsule contains duplicate observation identities")
        seen.add(unique_key)
        observation_task = _observation_task_id(item, identity_kind, identity_value, run_id)
        graph_id = _stable_id("normalized-observation", task_id + "\0" + unique_key)
        expected[graph_id] = observation_task
    result_id = _stable_id("normalized-audit", task_id + "\0" + capsule_hash)
    expected[result_id] = task_id
    if len(expected) > MAX_OBSERVATIONS:
        raise AuditError("BRIDGE_RECOVERY_OBSERVATION_LIMIT", "capsule graph observation count exceeds bound")
    return expected


def _assert_new_root(path: Path) -> Path:
    candidate = path.absolute()
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor = cursor / part
        if _reparse(cursor):
            raise AuditError("BRIDGE_REPARSE_POINT", "Context Engine output path has a reparse component")
    if candidate.exists():
        raise AuditError("BRIDGE_CONTEXT_ROOT_EXISTS", "new integration requires a fresh output root")
    return candidate


def _receipt_path(context_root: Path) -> Path:
    return context_root / "generalized-bridge-receipt.json"


def _write_receipt(context_root: Path, receipt: dict[str, Any]) -> None:
    path = _receipt_path(context_root)
    raw = canonical_json(receipt)
    try:
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise AuditError("BRIDGE_RECEIPT_EXISTS", "bridge receipt already exists") from exc


def _fresh_process_readback(context_root: Path, expected_manifest: dict[str, Any],
                            expected_by_task: dict[str, list[str]]) -> dict[str, Any]:
    repo_root = Path(__file__).resolve().parents[3]
    code = (
        "import json,sys; from pathlib import Path; sys.path.insert(0,sys.argv[1]); "
        "from runtime.candidate.context_engine import Engine; "
        "e=Engine(Path(sys.argv[2])); v=e.verify(); m=e.latest(); "
        "expected_map=json.loads(sys.argv[4]); found=set(); "
        "[(found.update(r['id'] for r in e.query(task_id=t,limit=1000))) for t in expected_map]; "
        "expected={i for ids in expected_map.values() for i in ids}; "
        "ok=(v['status']=='PASS' and m==json.loads(sys.argv[3]) and expected.issubset(found)); "
        "print(json.dumps({'status':'PASS' if ok else 'NOT_PROVEN','verification':v,"
        "'manifest':m,'expected_observations_found':len(expected & found),"
        "'dispatch':'NOT_PERFORMED','redispatch':'NOT_PERFORMED',"
        "'index_reconstruction':'POSSIBLE'},sort_keys=True)); sys.exit(0 if ok else 3)"
    )
    args = [sys.executable, "-I", "-B", "-c", code, str(repo_root), str(context_root),
            json.dumps(expected_manifest, sort_keys=True, separators=(",", ":")),
            json.dumps(expected_by_task, sort_keys=True, separators=(",", ":"))]
    try:
        result = subprocess.run(args, shell=False, capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_UNAVAILABLE",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_PERFORMED"}
    if result.returncode != 0:
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_VERIFY_FAILED",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_PERFORMED"}
    try:
        value = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_OUTPUT_INVALID",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_PERFORMED"}
    if not isinstance(value, dict) or value.get("status") != "PASS":
        return {"status": "NOT_PROVEN", "reason_code": "FRESH_PROCESS_VERIFY_FAILED",
                "dispatch": "NOT_PERFORMED", "redispatch": "NOT_PERFORMED"}
    return value


def bind_generalized_audit(
    audit_result: dict[str, Any],
    data_root: str | os.PathLike[str],
    context_root: str | os.PathLike[str],
) -> dict[str, Any]:
    """Bind one normalized audit result and its cited bytes to a fresh Engine.

    This function validates storage commitments only. The adapter remains the
    owner of parsing, statement attribution, predicate matching, and verdict
    semantics. Evidence paths are treated as untrusted data and never executed.
    """
    identity_kind, identity_value, run_id = _validate_audit(audit_result)
    root = _checked_root(data_root)
    output_root = _assert_new_root(Path(context_root))
    references = _source_references(audit_result)
    normalized = audit_result.get("observations")
    if not isinstance(normalized, list) or len(normalized) > MAX_OBSERVATIONS - MAX_SOURCE_REFERENCES - 1:
        raise AuditError("BRIDGE_NORMALIZED_OBSERVATIONS_INVALID", "audit observations must be a bounded array")

    admitted: list[dict[str, Any]] = []
    grants: list[dict[str, str]] = []
    for ref in references:
        source_path = _safe_path(root, ref["path"])
        raw, measured = _read_bytes(root, ref["path"], MAX_SOURCE_BYTES)
        if len(raw) != ref["bytes"] or measured["sha256"] != ref["sha256"]:
            raise AuditError("BRIDGE_SOURCE_COMMITMENT_MISMATCH", "current source differs from adapter commitment")
        source_id = _stable_id("source", ref["path"] + "\0" + ref["sha256"])
        row = {**ref, "source_id": source_id, "absolute_path": str(source_path),
               "scope": "ENGINEERING_RESULT"}
        admitted.append(row)
        grants.append({"path": str(source_path), "sha256": ref["sha256"], "scope": "ENGINEERING_RESULT"})

    capsule = {
        "schema": "pgop1.swebench.generalized-audit-capsule.v1",
        "identity_kind": identity_kind,
        "identity": identity_value,
        "run_id": run_id,
        "audit_result": audit_result,
        "source_refs": [{key: row[key] for key in
                         ("path", "sha256", "bytes", "roles", "parser_ids", "parser_versions",
                          "instance_bindings", "source_id", "scope")}
                        for row in admitted],
        "responsibility": {
            "semantic_claim_validation": "ADAPTER_OWNED",
            "storage_and_graph_binding": "CONTEXT_ENGINE_OWNED",
            "upstream_actor_provider_authentication": "NOT_PROVEN",
            "producer_execution_or_redispatch": "NOT_PERFORMED",
            "operational_authority": "NONE",
        },
    }
    capsule_raw = canonical_json(capsule)
    if len(capsule_raw) > MAX_CAPSULE_BYTES:
        raise AuditError("BRIDGE_CAPSULE_TOO_LARGE", "capsule exceeds its configured byte bound")

    output_root.mkdir(parents=True, exist_ok=False)
    capsule_path = output_root / "normalized-audit-capsule.json"
    with capsule_path.open("xb") as stream:
        stream.write(capsule_raw)
        stream.flush()
        os.fsync(stream.fileno())
    capsule_hash = _sha(capsule_raw)
    capsule_id = "source-capsule-" + capsule_hash

    engine = Engine(output_root, grants=grants)
    for row in admitted:
        descriptor = engine.admit_source(row["absolute_path"], row["sha256"],
                                         scope=row["scope"], source_id=row["source_id"])
        if descriptor.get("sha256") != row["sha256"] or descriptor.get("byte_length") != row["bytes"]:
            raise AuditError("BRIDGE_SOURCE_ADMISSION_MISMATCH", "Context Engine admitted different source bytes")
    descriptor = engine.admit_source(capsule_path, capsule_hash, scope="ENGINEERING_RESULT", source_id=capsule_id)
    if descriptor.get("sha256") != capsule_hash or descriptor.get("byte_length") != len(capsule_raw):
        raise AuditError("BRIDGE_CAPSULE_ADMISSION_MISMATCH", "Context Engine admitted a different capsule")

    task_id = f"{identity_kind}:{identity_value}"
    observations: list[dict[str, Any]] = []
    source_graph_ids: dict[str, str] = {}
    capsule_pointer = "/source_refs"
    for index, row in enumerate(admitted):
        value = capsule["source_refs"][index]
        pointer = f"{capsule_pointer}/{index}"
        source_task = _source_task_id(row, identity_kind, identity_value, run_id)
        source_graph_id = _stable_id("source-artifact", source_task + "\0" + row["source_id"])
        source_graph_ids[row["source_id"]] = source_graph_id
        observations.append({
            "id": source_graph_id,
            "kind": "source_artifact", "task_id": source_task, "run_id": run_id,
            "artifact_id": row["source_id"], "source_id": capsule_id,
            "evidence_pointer": pointer, "value": value,
        })
    source_by_commitment = {(row["path"], row["sha256"]): row for row in admitted}
    edges: list[dict[str, Any]] = []
    normalized_keys: set[str] = set()
    observation_graph_ids: dict[str, str] = {}
    for index, item in enumerate(normalized):
        if not isinstance(item, dict):
            raise AuditError("BRIDGE_NORMALIZED_OBSERVATIONS_INVALID", "normalized observation must be an object")
        observation_key = item.get("observation_id")
        kind = item.get("kind")
        source_ref = item.get("source_ref")
        if (not isinstance(observation_key, str) or not observation_key or len(observation_key) > 512
                or not isinstance(kind, str) or not kind
                or len(kind) > 128 or not isinstance(source_ref, dict)):
            raise AuditError("BRIDGE_NORMALIZED_OBSERVATIONS_INVALID", "observation identity, kind, or source binding is invalid")
        observation_run = item.get("run_id", run_id)
        observation_instance = item.get("instance_id")
        if not isinstance(observation_run, str) or not observation_run:
            raise AuditError("BRIDGE_NORMALIZED_OBSERVATIONS_INVALID", "observation run identity is invalid")
        if identity_kind != "BATCH_AGGREGATE" and observation_run != run_id:
            raise AuditError("BRIDGE_OBSERVATION_RUN_MISMATCH", "observation run differs from audit result")
        if identity_kind == "INSTANCE" and item.get("instance_id") != identity_value:
            if item.get("instance_id") not in {"UNKNOWN", "UNBOUND", None}:
                raise AuditError("BRIDGE_OBSERVATION_INSTANCE_MISMATCH", "observation instance differs from audit result")
        unique_key = "\0".join((observation_run, str(observation_instance or ""), observation_key))
        if unique_key in normalized_keys:
            raise AuditError("BRIDGE_NORMALIZED_OBSERVATIONS_INVALID", "duplicate normalized observation identity")
        normalized_keys.add(unique_key)
        source_key = (source_ref.get("path"), source_ref.get("sha256"))
        source = source_by_commitment.get(source_key)
        if source is None:
            raise AuditError("BRIDGE_OBSERVATION_SOURCE_UNBOUND", "observation source is not among committed evidence refs")
        observation_task = _observation_task_id(item, identity_kind, identity_value, run_id)
        if observation_task.startswith("INSTANCE:") and _is_run_only(source):
            raise AuditError("BRIDGE_OBSERVATION_SOURCE_SCOPE_MISMATCH", "run-only source cannot bind an instance observation")
        graph_id = _stable_id("normalized-observation", task_id + "\0" + unique_key)
        graph_observation = {
            "id": graph_id, "kind": kind, "task_id": observation_task, "run_id": observation_run,
            "finding_id": observation_key, "source_id": capsule_id,
            "evidence_pointer": f"/audit_result/observations/{index}", "value": item,
        }
        if isinstance(observation_instance, str) and observation_instance:
            graph_observation["instance_id"] = observation_instance
        observations.append(graph_observation)
        old_observation_id = observation_graph_ids.get(observation_key)
        if old_observation_id is not None and old_observation_id != graph_id:
            raise AuditError("BRIDGE_NORMALIZED_OBSERVATIONS_INVALID", "duplicate graph observation key")
        observation_graph_ids[observation_key] = graph_id
        claim_id = item.get("claim_id")
        if isinstance(claim_id, str) and claim_id:
            old_claim_id = observation_graph_ids.get(claim_id)
            if old_claim_id is not None and old_claim_id != graph_id:
                raise AuditError("BRIDGE_NORMALIZED_OBSERVATIONS_INVALID", "duplicate claim identity")
            observation_graph_ids[claim_id] = graph_id
        edges.append({
            "id": _stable_id("edge-observation-source", task_id + "\0" + unique_key),
            "from": source_graph_ids[source["source_id"]], "to": graph_id,
            "relationship": "DERIVED_ASSOCIATION",
            "evidence_bindings": [{"source_id": capsule_id,
                                   "pointer": f"/audit_result/observations/{index}/source_ref"}],
        })
    relationships = audit_result.get("relationships", [])
    if not isinstance(relationships, list) or len(relationships) > MAX_OBSERVATIONS:
        raise AuditError("BRIDGE_RELATIONSHIPS_INVALID", "relationships must be a bounded array")
    relationship_ids: set[str] = set()
    for index, item in enumerate(relationships):
        if not isinstance(item, dict):
            raise AuditError("BRIDGE_RELATIONSHIPS_INVALID", "relationship must be an object")
        relationship_id = item.get("relationship_id")
        start = item.get("from")
        end = item.get("to")
        bindings = item.get("evidence_bindings")
        if (not isinstance(relationship_id, str) or not relationship_id
                or relationship_id in relationship_ids or not isinstance(start, str)
                or not isinstance(end, str) or start not in observation_graph_ids
                or end not in observation_graph_ids
                or item.get("relation") != "PREDICATE_VALUE_COMPARISON"
                or not isinstance(item.get("predicate"), str)
                or type(item.get("asserted_value")) is not bool
                or type(item.get("observed_value")) is not bool
                or not isinstance(bindings, list) or not bindings):
            raise AuditError("BRIDGE_RELATIONSHIPS_INVALID", "relationship endpoints or predicate/value bindings are invalid")
        relationship_ids.add(relationship_id)
        for binding in bindings:
            if (not isinstance(binding, dict) or not isinstance(binding.get("path"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("sha256", "")))
                    or not isinstance(binding.get("pointer"), str)):
                raise AuditError("BRIDGE_RELATIONSHIPS_INVALID", "relationship evidence binding is malformed")
            source = source_by_commitment.get((_safe_relative(binding["path"]), binding["sha256"]))
            if source is None:
                raise AuditError("BRIDGE_RELATIONSHIP_SOURCE_UNBOUND", "relationship source is not among committed evidence refs")
            if _is_run_only(source):
                raise AuditError("BRIDGE_RELATIONSHIP_SOURCE_SCOPE_MISMATCH", "run-only source cannot support an instance relationship")
        edges.append({
            "id": _stable_id("edge-claim-comparison", task_id + "\0" + relationship_id),
            "from": observation_graph_ids[start],
            "to": observation_graph_ids[end],
            "relationship": "DERIVED_ASSOCIATION",
            "relation_type": item["relation"],
            "predicate": item["predicate"],
            "asserted_value": item["asserted_value"],
            "observed_value": item["observed_value"],
            "evidence_bindings": [{"source_id": capsule_id,
                                   "pointer": f"/audit_result/relationships/{index}"}],
        })
    result_id = _stable_id("normalized-audit", task_id + "\0" + capsule_hash)
    observations.append({
        "id": result_id, "kind": "audit_result", "task_id": task_id, "run_id": run_id,
        "finding_id": identity_value, "source_id": capsule_id,
        "evidence_pointer": "/audit_result", "value": audit_result,
    })
    if len(observations) > MAX_OBSERVATIONS:
        raise AuditError("BRIDGE_OBSERVATION_LIMIT", "derived graph exceeds its observation bound")

    for index, row in enumerate(admitted):
        if _is_run_only(row):
            continue
        edges.append({
            "id": _stable_id("edge-source-audit", task_id + "\0" + row["source_id"]),
            "from": source_graph_ids[row["source_id"]], "to": result_id,
            "relationship": "DERIVED_ASSOCIATION",
            "evidence_bindings": [{"source_id": capsule_id,
                                   "pointer": f"/source_refs/{index}"}],
        })

    manifest = engine.ingest(observations, edges, provenance={
        "tool_identity": "PGOP1_SWEBENCH_GENERALIZED_CONTEXT_BRIDGE",
        "declared_actor_identity": "UNKNOWN", "provider_identity": "UNKNOWN",
        "process_identity": "UNKNOWN", "invocation_evidence": "LOCAL_ENGINEERING_BRIDGE_CALL",
    })
    verification = engine.verify()
    rows = engine.query(task_id=task_id, limit=1000)
    expected_by_task = _expected_observation_tasks(
        audit_result, identity_kind, identity_value, run_id, admitted, capsule_hash)
    expected_ids = sorted(expected_by_task)
    queried_by_task: dict[str, set[str]] = {}
    for expected_task in sorted(set(expected_by_task.values())):
        queried_by_task[expected_task] = {
            row["id"] for row in engine.query(task_id=expected_task, limit=1000)
        }
    found_ids = set().union(*queried_by_task.values()) if queried_by_task else set()
    if verification.get("status") != "PASS" or not set(expected_ids).issubset(found_ids):
        raise AuditError("BRIDGE_ENGINE_READBACK_FAILED", "Context Engine verify/query did not recover expected observations")
    if engine.latest() != manifest:
        raise AuditError("BRIDGE_MANIFEST_READBACK_FAILED", "latest Context Engine manifest differs from ingest receipt")
    expected_by_task_lists: dict[str, list[str]] = {}
    for observation_id, expected_task in expected_by_task.items():
        expected_by_task_lists.setdefault(expected_task, []).append(observation_id)
    fresh = _fresh_process_readback(output_root, manifest, expected_by_task_lists)
    if fresh.get("status") != "PASS":
        raise AuditError("BRIDGE_FRESH_PROCESS_READBACK_FAILED", "fresh process did not verify graph and query bindings")

    receipt = {
        "schema": "pgop1.swebench.generalized-bridge-receipt.v1",
        "bridge_schema": BRIDGE_SCHEMA,
        "identity_kind": identity_kind,
        "identity": identity_value,
        "task_id": task_id,
        "run_id": run_id,
        "manifest": manifest,
        "capsule": {"source_id": capsule_id, "sha256": capsule_hash, "bytes": len(capsule_raw)},
        "source_refs": [{"source_id": row["source_id"], "sha256": row["sha256"],
                         "bytes": row["bytes"]} for row in admitted],
        "expected_observation_ids": expected_ids,
        "adapter_verdict": audit_result["AUDIT_VERDICT"],
        "semantic_claim_validation": "ADAPTER_OWNED",
        "engine_status": "PASS",
        "dispatch": "NOT_PERFORMED",
        "redispatch": "NOT_PERFORMED",
    }
    _write_receipt(output_root, receipt)
    return {
        "schema": BRIDGE_SCHEMA,
        "identity_kind": identity_kind,
        "identity": identity_value,
        "adapter_verdict": audit_result["AUDIT_VERDICT"],
        "context_engine": {"status": "PASS", "manifest": manifest,
                           "verification": verification, "queried_observations": len(found_ids),
                           "observation_ids": expected_ids, "source_objects_admitted": len(admitted),
                           "source_bytes_admitted": sum(row["bytes"] for row in admitted),
                           "capsule_sha256": capsule_hash,
                           "semantic_claim_validation": "ADAPTER_OWNED",
                           "index_reconstruction": bool(engine.metrics.get("RECONSTRUCTION_REQUIRED")),
                           "fresh_process_readback": fresh},
        "fixed_i7_provider_dispatch": "NOT_PERFORMED",
        "provider_recovery": "NOT_APPLICABLE_NO_PROVIDER_OPERATION_CREATED",
        "redispatch": "NOT_PERFORMED",
        "authority": "ADVISORY_ENGINEERING_ONLY; NO_OP1_AUTHORITY_EFFECT",
    }


def recover_generalized_audit(context_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Verify a committed bridge receipt and graph without source rereads.

    Engine initialization may reconstruct its disposable SQLite index. This
    routine does not run the adapter, read the original data root, or dispatch
    a producer/evaluator.
    """
    root = Path(context_root).resolve(strict=True)
    receipt_path = root / "generalized-bridge-receipt.json"
    try:
        raw = receipt_path.read_bytes()
        receipt = strict_json_loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuditError("BRIDGE_RECEIPT_UNAVAILABLE", "saved bridge receipt cannot be read") from exc
    if canonical_json(receipt) != raw:
        raise AuditError("BRIDGE_RECEIPT_INVALID", "saved receipt is not canonical JSON")
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != "pgop1.swebench.generalized-bridge-receipt.v1"
            or receipt.get("bridge_schema") != BRIDGE_SCHEMA):
        raise AuditError("BRIDGE_RECEIPT_INVALID", "saved bridge receipt has an unsupported schema")
    engine = Engine(root)
    verification = engine.verify()
    latest = engine.latest()
    capsule_commitment = receipt.get("capsule")
    if not isinstance(capsule_commitment, dict):
        raise AuditError("BRIDGE_RECEIPT_INVALID", "saved receipt lacks capsule commitment")
    capsule_raw = None
    capsule_source_id = capsule_commitment.get("source_id")
    try:
        capsule_raw = engine.read_source(capsule_source_id)
    except Exception as exc:
        raise AuditError("BRIDGE_RECOVERY_CAPSULE_MISSING", "stored capsule source is unavailable") from exc
    if (len(capsule_raw) != capsule_commitment.get("bytes")
            or _sha(capsule_raw) != capsule_commitment.get("sha256")):
        raise AuditError("BRIDGE_RECOVERY_CAPSULE_MISMATCH", "stored capsule differs from receipt commitment")
    try:
        capsule = strict_json_loads(capsule_raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuditError("BRIDGE_RECOVERY_CAPSULE_INVALID", "stored capsule is not valid JSON") from exc
    if (canonical_json(capsule) != capsule_raw or not isinstance(capsule, dict)
            or capsule.get("schema") != "pgop1.swebench.generalized-audit-capsule.v1"):
        raise AuditError("BRIDGE_RECOVERY_CAPSULE_INVALID", "stored capsule has an unsupported schema")

    audit_result = capsule.get("audit_result")
    identity_kind, identity_value, run_id = _validate_audit(audit_result)
    task_id = f"{identity_kind}:{identity_value}"
    if (capsule.get("identity_kind") != identity_kind
            or capsule.get("identity") != identity_value
            or capsule.get("run_id") != run_id):
        raise AuditError("BRIDGE_RECOVERY_CAPSULE_IDENTITY_MISMATCH", "capsule identity metadata differs from its audit result")
    receipt_checks = {
        "identity_kind": identity_kind,
        "identity": identity_value,
        "task_id": task_id,
        "run_id": run_id,
        "adapter_verdict": audit_result["AUDIT_VERDICT"],
        "semantic_claim_validation": "ADAPTER_OWNED",
        "engine_status": "PASS",
        "dispatch": "NOT_PERFORMED",
        "redispatch": "NOT_PERFORMED",
    }
    if any(receipt.get(key) != value for key, value in receipt_checks.items()):
        raise AuditError("BRIDGE_RECOVERY_RECEIPT_MISMATCH", "receipt identity or verdict metadata differs from immutable capsule")

    capsule_source_refs = capsule.get("source_refs")
    if not isinstance(capsule_source_refs, list):
        raise AuditError("BRIDGE_RECOVERY_SOURCES_MISMATCH", "capsule source list is invalid")
    source_refs = _source_references(audit_result)
    expected_capsule_refs = []
    expected_receipt_refs = []
    for ref in source_refs:
        source_id = _stable_id("source", ref["path"] + "\0" + ref["sha256"])
        expected_capsule_refs.append({
            "path": ref["path"], "sha256": ref["sha256"], "bytes": ref["bytes"],
            "roles": ref["roles"], "parser_ids": ref["parser_ids"],
            "parser_versions": ref["parser_versions"], "instance_bindings": ref["instance_bindings"],
            "source_id": source_id, "scope": "ENGINEERING_RESULT",
        })
        expected_receipt_refs.append({"source_id": source_id, "sha256": ref["sha256"], "bytes": ref["bytes"]})
    if capsule_source_refs != expected_capsule_refs or receipt.get("source_refs") != expected_receipt_refs:
        raise AuditError("BRIDGE_RECOVERY_SOURCES_MISMATCH", "source commitments differ from immutable audit result")
    if capsule_source_id != "source-capsule-" + _sha(capsule_raw):
        raise AuditError("BRIDGE_RECOVERY_CAPSULE_ID_MISMATCH", "capsule source identity is not derived from its bytes")
    for expected in expected_receipt_refs:
        try:
            source_raw = engine.read_source(expected["source_id"])
        except Exception as exc:
            raise AuditError("BRIDGE_RECOVERY_SOURCE_MISSING", "admitted source object is unavailable") from exc
        if len(source_raw) != expected["bytes"] or _sha(source_raw) != expected["sha256"]:
            raise AuditError("BRIDGE_RECOVERY_SOURCE_MISMATCH", "admitted source object differs from immutable audit commitment")

    expected_by_id = _expected_observation_tasks(
        audit_result, identity_kind, identity_value, run_id, source_refs, _sha(capsule_raw))
    expected_ids = sorted(expected_by_id)
    if receipt.get("expected_observation_ids") != expected_ids:
        raise AuditError("BRIDGE_RECOVERY_OBSERVATION_COMMITMENT_MISMATCH", "receipt observation IDs differ from immutable capsule")
    if receipt.get("manifest") != latest:
        raise AuditError("BRIDGE_RECOVERY_MANIFEST_MISMATCH", "stored latest manifest differs from saved receipt")
    by_task: dict[str, set[str]] = {}
    for observation_id, expected_task in expected_by_id.items():
        by_task.setdefault(expected_task, set()).add(observation_id)
    found: set[str] = set()
    for expected_task, expected_task_ids in by_task.items():
        task_rows = engine.query(task_id=expected_task, limit=1000)
        task_found = {row["id"] for row in task_rows}
        if not expected_task_ids.issubset(task_found):
            raise AuditError("BRIDGE_RECOVERY_OBSERVATIONS_MISSING", "verified graph lacks capsule-derived observation identities")
        found.update(task_found)
    return {
        "schema": "pgop1.swebench.generalized-bridge-recovery.v1",
        "status": "PASS" if verification.get("status") == "PASS" else "NOT_PROVEN",
        "identity_kind": identity_kind,
        "identity": identity_value,
        "manifest": latest,
        "verification": verification,
        "expected_observations_found": len(set(expected_ids) & found),
        "capsule_sha256": _sha(capsule_raw),
        "source_objects_verified": len(expected_receipt_refs),
        "source_reread": "NOT_PERFORMED",
        "adapter_rerun": "NOT_PERFORMED",
        "producer_redispatch": "NOT_PERFORMED",
        "index_reconstruction": bool(engine.metrics.get("RECONSTRUCTION_REQUIRED")),
        "authority": "ADVISORY_ENGINEERING_ONLY; NO_OP1_AUTHORITY_EFFECT",
    }
