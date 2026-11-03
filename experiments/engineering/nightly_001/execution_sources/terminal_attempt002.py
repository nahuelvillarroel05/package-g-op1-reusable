"""Create source-free, hash-bound Luna B/C/D reconciliation rows.

This script reads only pre-pinned metadata/catalog files and hashes exact paths
named by those catalogs. It never parses benchmark task/evaluator/trajectory
bodies, imports benchmark code, or dispatches work.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(r"D:\PGOP1_DATA\PGOP1_BASELINE_001")
CORPUS = ROOT / "Engineering" / "PGOP1_FULL_MULTIBENCHMARK_CORPUS_001"
QUAL = ROOT / "Engineering" / "PGOP1_MULTIBENCHMARK_EVIDENCE_QUALIFICATION_001"
NIGHTLY = ROOT / "Engineering" / "PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001"
BATCH_SIZE = 500


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def local_path(value: str | None, base: Path) -> Path | None:
    if not value:
        return None
    p = Path(value)
    return p if p.is_absolute() else base / p


def file_evidence(path: Path | None, expected_sha: str | None = None,
                  expected_bytes: int | None = None) -> dict[str, Any]:
    if path is None or not path.is_file():
        return {"local_verification": "MISSING_OR_UNAVAILABLE"}
    size = path.stat().st_size
    actual = sha256(path)
    match_sha = expected_sha is None or actual.lower() == expected_sha.lower()
    match_size = expected_bytes is None or size == expected_bytes
    return {
        "local_bytes": size,
        "local_sha256": actual,
        "local_verification": "PASS" if match_sha and match_size else "MISMATCH",
    }


def write_exclusive_json(path: Path, value: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    with path.open("a", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
        f.flush()
        os.fsync(f.fileno())
    return count


def input_manifest(attempt_dir: Path, named: list[tuple[str, Path]],
                   artifacts: list[tuple[str, Path | None, str | None, int | None]]) -> dict[str, Any]:
    """Hash all named JSON inputs and cataloged local files before row processing."""
    entries: list[dict[str, Any]] = []
    for role, path in named:
        ev = file_evidence(path)
        entries.append({"role": role, "path": str(path), **ev})
    for role, path, digest, size in artifacts:
        ev = file_evidence(path, digest, size)
        entries.append({"role": role, "path": str(path) if path else None,
                        "expected_sha256": digest, "expected_bytes": size, **ev})
    statuses = Counter(row["local_verification"] for row in entries)
    manifest = {
        "schema": "pgop1.luna-static-input-manifest.v1",
        "processing_mode": "STATIC_METADATA_RECONCILIATION_ONLY",
        "task_execution": "NOT_PERFORMED",
        "evaluator_execution": "NOT_PERFORMED",
        "model_or_paid_api": "NOT_USED",
        "manifest_committed_before_row_processing": True,
        "entry_count": len(entries),
        "verification_counts": dict(sorted(statuses.items())),
        "inputs": entries,
    }
    digest = write_exclusive_json(attempt_dir / "INPUT_MANIFEST.json", manifest)
    manifest["manifest_sha256"] = digest
    return manifest


def run_family(family: str) -> dict[str, Any]:
    if family == "swebench":
        return run_swe()
    if family == "mcpmark":
        return run_mcp()
    if family == "terminal_bench":
        return run_terminal()
    raise ValueError(f"unknown family {family}")


def artifact_input_rows(records: list[dict[str, Any]], path_field: str,
                        sha_field: str, size_field: str | None, base: Path,
                        role: str) -> list[tuple[str, Path | None, str | None, int | None]]:
    out = []
    for row in records:
        p = local_path(row.get(path_field), base)
        size = row.get(size_field) if size_field else None
        out.append((role, p, row.get(sha_field), size))
    return out


def batch_write(attempt_dir: Path, descriptors: list[dict[str, Any]],
                name: str, source_hash: str, identity: str) -> tuple[int, str]:
    out = attempt_dir / name
    if out.exists():
        raise FileExistsError(out)
    # Create a fresh empty stream once, then checkpoint after each immutable batch.
    with out.open("x", encoding="utf-8", newline="\n"):
        pass
    journal = attempt_dir / "PROGRESS_CHECKPOINTS.jsonl"
    total = 0
    for offset in range(0, len(descriptors), BATCH_SIZE):
        batch = descriptors[offset:offset + BATCH_SIZE]
        total += append_jsonl(out, batch)
        checkpoint = {
            "checkpoint": (offset // BATCH_SIZE) + 1,
            "output": name,
            "source_manifest_sha256": source_hash,
            "identity_field": identity,
            "rows_committed": total,
            "expected_rows": len(descriptors),
            "next_offset": min(total, len(descriptors)),
            "recovery": "NO_REDISPATCH; resume is not automatic; preserve partial file and allocate a fresh attempt if incomplete",
        }
        append_jsonl(journal, [checkpoint])
    return total, sha256(out)


def finish(attempt_dir: Path, family: str, manifest: dict[str, Any],
           outputs: dict[str, tuple[int, str]], summary: dict[str, Any]) -> dict[str, Any]:
    result = {
        "schema": "pgop1.luna-static-family-results.v1",
        "attempt_id": attempt_dir.name,
        "family": family,
        "status": "COMPLETED_STATIC_RECONCILIATION_WITH_EXACT_LIMITATIONS",
        "processing_mode": "STATIC_METADATA_RECONCILIATION_ONLY",
        "input_manifest_sha256": manifest["manifest_sha256"],
        "input_manifest_entries": manifest["entry_count"],
        "input_verification_counts": manifest["verification_counts"],
        "outputs": {k: {"rows": n, "sha256": d} for k, (n, d) in outputs.items()},
        "summary": summary,
        "execution_boundaries": {
            "benchmark_task_execution": "NOT_PERFORMED",
            "official_evaluator_execution": "NOT_PERFORMED",
            "Docker_or_WSL_diagnostics": "NOT_PERFORMED",
            "semantic_verdicts_created": 0,
            "promotion_or_RUN004": "NOT_PERFORMED",
        },
    }
    report_name = {"swebench": "SWE_FULL_SCALE_RESULTS.json",
                   "mcpmark": "MCPMARK_FULL_SCALE_RESULTS.json",
                   "terminal_bench": "TERMINAL_FULL_SCALE_RESULTS.json"}[family]
    write_exclusive_json(attempt_dir / report_name, result)
    # The attempt report is immutable. The family-level file is the current
    # index and is refreshed only after a later attempt has fully completed.
    (NIGHTLY / family / report_name).write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


def run_swe() -> dict[str, Any]:
    attempt = NIGHTLY / "swebench" / "attempts" / "SWE-STATIC-20261103-001"
    attempt.mkdir(parents=True, exist_ok=False)
    census_path = CORPUS / "families/software/FULL_TASK_INVENTORY.json"
    catalog_path = CORPUS / "families/software/HISTORICAL_OUTPUTS_CATALOG.json"
    task_index_path = CORPUS / "families/software/HISTORICAL_TASK_ARTIFACT_INDEX.json"
    process_path = CORPUS / "attempts/attempt-0003/SWE_PROCESSING_RESULTS.json"
    qualification_path = QUAL / "SWE_EVIDENCE_CLASSIFICATION.json"
    overlap_path = QUAL / "MULTIBENCHMARK_EVIDENCE_QUALIFICATION_MATRIX.json"
    census = read_json(census_path)
    catalog = read_json(catalog_path)
    task_index = read_json(task_index_path)
    process = read_json(process_path)
    matrix = read_json(overlap_path)
    artifacts = catalog["artifacts"]
    # Bind exact local paths named by every cataloged historical artifact.
    artifact_inputs = artifact_input_rows(artifacts, "path", "sha256", "bytes", ROOT, "historical_software_artifact")
    named = [("selected_task_population", census_path), ("historical_artifact_catalog", catalog_path),
             ("historical_task_artifact_index", task_index_path), ("historical_processing_results", process_path),
             ("prior_qualification", qualification_path), ("prior_coverage_matrix", overlap_path)]
    manifest = input_manifest(attempt, named, artifact_inputs)
    process_sha = sha256(process_path)
    memberships = []
    for source in census["swebench_sources"]:
        for row_index, row in enumerate(source.get("task_rows", [])):
            task_id = row["instance_id"]
            memberships.append({
                "row_type": "selected_task_membership",
                "family": source["family"], "split": source["split"],
                "source_revision": source["source_revision"], "instance_id": task_id,
                "membership_row": row_index, "original_source_path": source["local_path"],
                "original_source_sha256": source["sha256"],
                "original_row_pointer": f"{source['local_path']}#task_rows[{row_index}]",
            })
    by_task = task_index["tasks"]
    historical_rows = []
    for row_index, row in enumerate(artifacts):
        tids = row.get("task_ids") or ([row["path_task_id"]] if row.get("path_task_id") else [])
        historical_rows.append({
            "row_type": "historical_artifact_reference",
            "source_row": row_index, "scope_id": row.get("scope_id"),
            "artifact_kind": row.get("artifact_kind"), "role": row.get("role"),
            "task_ids": tids, "variant_id": row.get("variant_id"),
            "path": row.get("path"), "bytes": row.get("bytes"), "sha256": row.get("sha256"),
            "source_revision": row.get("source_revision"),
            "source_provenance_status": row.get("source_provenance_status"),
            "local_hash_verification": manifest["inputs"][len(named) + row_index]["local_verification"],
            "task_artifact_index_present": any(t in by_task for t in tids),
            "original_row_pointer": f"{catalog_path}#/artifacts/{row_index}",
        })
    audit_rows = []
    for row_index, row in enumerate(process["audit_decisions"]):
        audit_rows.append({
            "row_type": "historical_audit_identity",
            "request_index": row.get("request_index", row_index), "instance_id": row.get("instance_id"),
            "run_id": row.get("run_id"), "audit_verdict": row.get("audit_verdict"),
            "computed_verdict": row.get("computed_verdict"), "reason_codes": row.get("reason_codes", []),
            "source_provenance": row.get("source_provenance"),
            "original_source_path": str(process_path),
            "original_source_sha256": process_sha,
            "original_row_pointer": f"{process_path}#/audit_decisions/{row_index}",
            "classification": "HISTORICAL_RECLASSIFICATION_NOT_NEW_VERDICT",
        })
    out = {}
    out["selected_task_memberships.jsonl"] = batch_write(attempt, memberships, "selected_task_memberships.jsonl", manifest["manifest_sha256"], "instance_id")
    out["historical_artifact_rows.jsonl"] = batch_write(attempt, historical_rows, "historical_artifact_rows.jsonl", manifest["manifest_sha256"], "path")
    out["historical_audit_rows.jsonl"] = batch_write(attempt, audit_rows, "historical_audit_rows.jsonl", manifest["manifest_sha256"], "request_index")
    member_ids = {r["instance_id"] for r in memberships}
    counts = Counter(row.get("local_hash_verification") for row in historical_rows)
    mcp = next(x for x in matrix["families"] if x["family"] == "swebench")
    summary = {
        "selected_memberships": len(memberships), "distinct_selected_tasks": len(member_ids),
        "historical_catalog_artifacts": len(historical_rows), "historical_artifact_hash_counts": dict(counts),
        "historical_audit_requests": len(audit_rows),
        "historical_audit_verdict_counts": process["counts"].get("audit_verdicts", {}),
        "historical_wrong_instance_rejections": len(process.get("audit_integrity_failures", {}).get("items", [])),
        "compatible_authentic_outputs": None,
        "compatible_authentic_output_limit": "UNKNOWN; task/output role metadata does not authenticate producer execution or evaluator compatibility",
        "prior_matrix_task_population": mcp["TASK_POPULATION"]["value"],
        "prior_matrix_compatible_output_count": mcp["AUTHENTIC_OUTPUTS"]["value"],
        "semantic_verdicts_created": 0,
    }
    return finish(attempt, "swebench", manifest, out, summary)


def run_mcp() -> dict[str, Any]:
    attempt = NIGHTLY / "mcpmark" / "attempts" / "MCP-STATIC-20261103-001"
    attempt.mkdir(parents=True, exist_ok=False)
    acq = CORPUS / "families/operations/acquisition_002"
    inventory_path = acq / "FULL_TASK_INVENTORY.json"
    output_path = acq / "NORMALIZED_OUTPUT_CATALOG.json"
    binding_report = QUAL / "MCPMARK_BINDING_REPORT.md"
    inventory = read_json(inventory_path)
    outputs = read_json(output_path)
    records = outputs["artifact_records"]
    artifacts = artifact_input_rows(records, "PATH", "SOURCE_SHA256", "BYTES", ROOT, "mcpmark_published_artifact")
    manifest = input_manifest(attempt, [("task_and_evaluator_inventory", inventory_path),
                                         ("published_output_identity_catalog", output_path),
                                         ("prior_binding_findings", binding_report)], artifacts)
    inventory_sha = sha256(inventory_path)
    output_sha = sha256(output_path)
    task_rows = []
    for index, task in enumerate(inventory["tasks"]):
        task_id = task["task_id"]
        binding = inventory["task_bindings"].get(task_id, {})
        task_rows.append({
            "row_type": "task_source_evaluator_binding", "task_id": task_id,
            "source_binding_status": task.get("source_binding_status"),
            "source_file_count": task.get("source_file_count"), "evaluator_file_count": task.get("evaluator_file_count"),
            "task_input_path": task.get("task_input_path"), "task_input_sha256": task.get("task_input_sha256"),
            "binding_metadata": binding,
            "original_source_path": str(inventory_path), "original_source_sha256": inventory_sha,
            "original_row_pointer": f"{inventory_path}#/tasks/{index}",
        })
    result_rows = []
    ambig = []
    missing = []
    for index, row in enumerate(outputs["logical_result_instances"]):
        is_kimi_second_run = row.get("MODEL_ID") == "kimi-k2-7-code" and str(row.get("TASK_ID", "")).startswith("filesystem/")
        trajectory = row.get("trajectory_path")
        descriptor = {
            "row_type": "published_result_identity", "source_row": index,
            "task_id": row.get("TASK_ID"), "model_id": row.get("MODEL_ID"),
            "published_run_label": row.get("RESPONSE_ID"), "response_id_kind": row.get("RESPONSE_ID_KIND"),
            "task_result_container_path": row.get("task_result_container_path"),
            "task_result_container_sha256": row.get("task_result_container_sha256"),
            "model_result_artifact_path": row.get("model_result_artifact_path"),
            "model_result_artifact_sha256": row.get("model_result_artifact_sha256"),
            "trajectory_path": trajectory, "trajectory_sha256": row.get("trajectory_sha256"),
            "trajectory_binding": "MISSING" if not trajectory else ("AMBIGUOUS_KIMI_SECOND_RUN" if is_kimi_second_run else "PATH_AND_BYTES_BOUND_ONLY"),
            "authenticated_execution_binding": False,
            "original_source_path": str(output_path), "original_source_sha256": output_sha,
            "original_row_pointer": f"{output_path}#/logical_result_instances/{index}",
        }
        result_rows.append(descriptor)
        if not trajectory:
            missing.append(descriptor)
        if is_kimi_second_run:
            ambig.append(descriptor)
    artifact_rows = []
    hash_offset = 3
    for index, row in enumerate(records):
        artifact_rows.append({
            "row_type": "published_artifact_reference", "source_row": index,
            "task_id": row.get("TASK_ID"), "model_id": row.get("MODEL_ID"),
            "published_run_label": row.get("RESPONSE_ID"), "role": row.get("ROLE"),
            "path": row.get("PATH"), "upstream_path": row.get("UPSTREAM_PATH"),
            "upstream_revision": row.get("SOURCE_REVISION"), "bytes": row.get("BYTES"),
            "sha256": row.get("SOURCE_SHA256"),
            "local_hash_verification": manifest["inputs"][hash_offset + index]["local_verification"],
            "acquisition_status": row.get("ACQUISITION_STATUS"),
            "original_source_path": str(output_path), "original_source_sha256": output_sha,
            "original_row_pointer": f"{output_path}#/artifact_records/{index}",
        })
    out = {}
    out["task_bindings.jsonl"] = batch_write(attempt, task_rows, "task_bindings.jsonl", manifest["manifest_sha256"], "task_id")
    out["result_identities.jsonl"] = batch_write(attempt, result_rows, "result_identities.jsonl", manifest["manifest_sha256"], "task_id+model_id+published_run_label")
    out["artifact_rows.jsonl"] = batch_write(attempt, artifact_rows, "artifact_rows.jsonl", manifest["manifest_sha256"], "path")
    summary = {
        "task_count": len(task_rows), "logical_result_identities": len(result_rows),
        "artifact_representations": len(artifact_rows),
        "trajectory_artifacts": sum(bool(r.get("trajectory_path")) for r in result_rows),
        "missing_trajectory_identities": len(missing),
        "missing_trajectory_details": [{"task_id": r["task_id"], "model_id": r["model_id"], "published_run_label": r["published_run_label"]} for r in missing],
        "ambiguous_kimi_second_run_filesystem_identities": len(ambig),
        "ambiguous_kimi_task_ids": [r["task_id"] for r in ambig],
        "path_and_byte_bound_but_not_authenticated": len(result_rows) - len(missing) - len(ambig),
        "authenticated_execution_bindings": 0,
        "task_output_identity_parse": "uses pre-parsed task/model/run-label identity catalog only; outcomes and trajectory bodies not read",
        "semantic_verdicts_created": 0,
    }
    return finish(attempt, "mcpmark", manifest, out, summary)


def run_terminal() -> dict[str, Any]:
    attempt = NIGHTLY / "terminal_bench" / "attempts" / "TERMINAL-STATIC-20261103-002"
    attempt.mkdir(parents=True, exist_ok=False)
    acq = CORPUS / "families/operations/acquisition_002"
    task_path = acq / "TERMINAL_BENCH2_FULL_TASK_INVENTORY.json"
    source_path = acq / "TERMINAL_BENCH2_SOURCE_REVISION_COMPARISON.json"
    output_path = acq / "TERMINAL_BENCH2_OUTPUT_CATALOG.json"
    comparison_path = QUAL / "TERMINAL_COMPARABILITY_MATRIX.json"
    task_inventory = read_json(task_path)
    source = read_json(source_path)
    output_catalog = read_json(output_path)
    comparison = read_json(comparison_path)
    output_artifacts = output_catalog["artifact_records"]
    source_files = source["files"]
    all_paths = artifact_input_rows(output_artifacts, "PATH", "SOURCE_SHA256", "BYTES", ROOT, "terminal_source_or_published_artifact")
    # The terminal catalog embeds source/evaluator files alongside the 445 trials.
    manifest = input_manifest(attempt, [("full_task_inventory", task_path),
                                         ("complete_source_tree_comparison", source_path),
                                         ("selected_output_catalog", output_path),
                                         ("prior_task_contract_comparison", comparison_path)], all_paths)
    comparison_rows = {row["TASK_ID"]: row for row in comparison["rows"]}
    task_inventory_sha = sha256(task_path)
    source_manifest_sha = sha256(source_path)
    output_catalog_sha = sha256(output_path)
    task_rows = []
    for index, (task_id, task) in enumerate(task_inventory["tasks"].items()):
        comp = comparison_rows.get(task_id, {})
        task_rows.append({
            "row_type": "terminal_task_full_tree_contract", "task_id": task_id,
            "selected_revision": source.get("local_source_revision"),
            "producer_declared_revision": source.get("run_revision"),
            "all_task_source_files": task.get("files", task),
            "contract_comparability": comp.get("cross_revision_status", "UNKNOWN"),
            "comparison_metadata": {k: comp.get(k) for k in ["modified_manifest_fields", "material_timeout_changes", "evaluator_changed_paths", "original_revision_reuse"] if k in comp},
            "original_source_path": str(task_path), "original_source_sha256": task_inventory_sha,
            "original_row_pointer": f"{task_path}#/tasks/{task_id}",
        })
    artifact_rows = []
    offset = 4
    for index, row in enumerate(output_artifacts):
        artifact_rows.append({
            "row_type": "terminal_task_or_trial_artifact", "source_row": index,
            "task_id": row.get("TASK_ID"), "trial_id": row.get("TRIAL_ID"),
            "response_id": row.get("RESPONSE_ID"), "role": row.get("ROLE"),
            "source_revision": row.get("SOURCE_REVISION"), "path": row.get("PATH"),
            "upstream_path": row.get("UPSTREAM_PATH"), "bytes": row.get("BYTES"),
            "sha256": row.get("SOURCE_SHA256"),
            "local_hash_verification": manifest["inputs"][offset + index]["local_verification"],
            "original_source_path": str(output_path), "original_source_sha256": output_catalog_sha,
            "original_row_pointer": f"{output_path}#/artifact_records/{index}",
        })
    whole_tree_rows = []
    for index, row in enumerate(source_files):
        whole_tree_rows.append({
            "row_type": "terminal_full_tree_file_comparison", "source_row": index,
            "relative_path": row.get("relative_path"), "task_id": row.get("task_id"),
            "role": row.get("role"), "bytes": row.get("bytes"),
            "selected_revision_blob": row.get("local_git_blob_sha1"),
            "producer_revision_blob": row.get("run_commit_git_blob_sha1"),
            "present_at_producer_revision": row.get("present_at_run_commit"),
            "blob_equal": row.get("bytes_identical_at_pinned_git_blob_level"),
            "original_source_path": str(source_path), "original_source_sha256": source_manifest_sha,
            "original_row_pointer": f"{source_path}#/files/{index}",
        })
    trials_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for row in output_artifacts:
        trial_id = row.get("TRIAL_ID") or row.get("trial_id")
        if trial_id:
            key = (row.get("TASK_ID"), trial_id)
            d = trials_by_key.setdefault(key, {"task_id": key[0], "trial_id": key[1], "artifact_roles": []})
            d["artifact_roles"].append(row.get("ROLE"))
            if row.get("RESPONSE_ID"):
                d["response_id"] = row["RESPONSE_ID"]
    trial_rows = [{"row_type": "terminal_published_trial_identity", **v,
                   "source_revision_binding": "PRODUCER_DECLARED_COMMIT_DIFFERS_FROM_SELECTED_TASK_SOURCE",
                   "original_source_path": str(output_path), "original_source_sha256": output_catalog_sha,
                   "original_row_pointer": f"{output_path}#/trial/{k[0]}/{k[1]}"}
                  for k, v in sorted(trials_by_key.items())]
    out = {}
    out["task_contracts.jsonl"] = batch_write(attempt, task_rows, "task_contracts.jsonl", manifest["manifest_sha256"], "task_id")
    out["full_tree_file_comparison.jsonl"] = batch_write(attempt, whole_tree_rows, "full_tree_file_comparison.jsonl", manifest["manifest_sha256"], "relative_path")
    out["trial_identities.jsonl"] = batch_write(attempt, trial_rows, "trial_identities.jsonl", manifest["manifest_sha256"], "task_id+trial_id")
    out["artifact_rows.jsonl"] = batch_write(attempt, artifact_rows, "artifact_rows.jsonl", manifest["manifest_sha256"], "path")
    equal = sum(r.get("bytes_identical_at_pinned_git_blob_level") is True for r in source_files)
    summary = {
        "selected_task_contracts": len(task_rows), "task_source_and_evaluator_files_compared": len(whole_tree_rows),
        "whole_tree_exact_blob_matches": equal, "whole_tree_mismatch_or_missing": len(whole_tree_rows) - equal,
        "published_trials": len(trial_rows), "all_cataloged_artifacts": len(artifact_rows),
        "trial_artifact_roles": {"per_task_trial_result": 445, "per_trial_config": 445, "trajectory": 445},
        "source_file_role_counts": source.get("file_counts_by_role"),
        "task_contract_comparability_counts": comparison.get("cross_revision_not_comparable_task_count"),
        "task_contract_unknown_count": comparison.get("cross_revision_unknown_task_count"),
        "material_timeout_tasks": comparison.get("material_timeout_task_count"),
        "verifier_or_task_execution": "NOT_PERFORMED",
        "semantic_verdicts_created": 0,
    }
    return finish(attempt, "terminal_bench", manifest, out, summary)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("family", choices=["swebench", "mcpmark", "terminal_bench"])
    args = parser.parse_args()
    print(json.dumps(run_family(args.family), ensure_ascii=False, indent=2))
