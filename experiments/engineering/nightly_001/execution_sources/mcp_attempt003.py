"""Source-bound JSON shape scan of MCPMark results and trajectories."""
from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(r"D:\PGOP1_DATA\PGOP1_BASELINE_001")
CORPUS = ROOT / "Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/families/operations/acquisition_002"
QUAL = ROOT / "Engineering/PGOP1_MULTIBENCHMARK_EVIDENCE_QUALIFICATION_001"
NIGHTLY = ROOT / "Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/mcpmark"
OUT = NIGHTLY / "attempts/MCP-STRUCT-20261103-003"
BATCH = 250


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_exclusive(path: Path, value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    with path.open("x", encoding="utf-8", newline="\n") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())
    return hashlib.sha256(payload.encode()).hexdigest()


def checkpoint_write(path: Path, rows: list[dict[str, Any]], journal: Path,
                     manifest_sha: str) -> tuple[int, str]:
    with path.open("x", encoding="utf-8", newline="\n"):
        pass
    count = 0
    for start in range(0, len(rows), BATCH):
        batch = rows[start:start + BATCH]
        with path.open("a", encoding="utf-8", newline="\n") as f:
            for row in batch:
                f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        count += len(batch)
        with journal.open("a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"output": path.name, "rows_committed": count,
                                "expected_rows": len(rows), "input_manifest_sha256": manifest_sha,
                                "no_redispatch": True}) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return count, sha(path)


def safe_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, type(exc).__name__


def field_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=False)
    driver_path = Path(__file__).resolve()
    driver_bytes = driver_path.read_bytes()
    driver_sha = hashlib.sha256(driver_bytes).hexdigest()
    with (OUT / "DRIVER_SNAPSHOT.py").open("xb") as f:
        f.write(driver_bytes)
        f.flush()
        os.fsync(f.fileno())
    inventory_path = CORPUS / "FULL_TASK_INVENTORY.json"
    catalog_path = CORPUS / "NORMALIZED_OUTPUT_CATALOG.json"
    binding_path = QUAL / "MCPMARK_BINDING_REPORT.md"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    artifacts = catalog["artifact_records"]
    catalog_sha = sha(catalog_path)

    input_rows = []
    named = [("task_inventory", inventory_path), ("normalized_output_catalog", catalog_path)]
    for role, path in named:
        input_rows.append({"role": role, "path": str(path), "sha256": sha(path), "bytes": path.stat().st_size})
    for index, row in enumerate(artifacts):
        path = Path(row["PATH"])
        if not path.is_file():
            actual, size, status = None, None, "MISSING_OR_UNAVAILABLE"
        else:
            actual, size = sha(path), path.stat().st_size
            status = "PASS" if actual == row["SOURCE_SHA256"] and size == row["BYTES"] else "MISMATCH"
        input_rows.append({"role": "cataloged_artifact", "index": index, "path": str(path),
                           "expected_sha256": row["SOURCE_SHA256"], "expected_bytes": row["BYTES"],
                           "actual_sha256": actual, "actual_bytes": size, "status": status})
    manifest = {
        "schema": "pgop1.mcpmark.structural-input-manifest.v1", "attempt_id": OUT.name,
        "processing_mode": "JSON_STRUCTURE_ONLY_NO_BENCHMARK_EXECUTION",
        "manifest_committed_before_parsing": True, "task_inventory_path": str(inventory_path),
        "output_catalog_path": str(catalog_path), "artifact_count": len(artifacts),
        "driver_snapshot_path": str(OUT / "DRIVER_SNAPSHOT.py"), "driver_sha256": driver_sha,
        "verification_counts": dict(Counter(r.get("status", "PASS") for r in input_rows)),
        "inputs": input_rows, "payload_values_exported": False,
    }
    manifest_sha = write_exclusive(OUT / "INPUT_MANIFEST.json", manifest)
    journal = OUT / "PROGRESS_CHECKPOINTS.jsonl"
    with journal.open("x", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"checkpoint": 0, "phase": "INPUT_MANIFEST_COMMITTED",
                            "input_manifest_sha256": manifest_sha, "artifact_count": len(artifacts)}) + "\n")

    logical_rows = catalog["logical_result_instances"]
    results_by_key = {(r.get("TASK_ID"), r.get("MODEL_ID"), r.get("RESPONSE_ID")): r for r in logical_rows}
    task_leaves = {r["task_id"]: (r.get("category_id", "") + "__" + r.get("task_leaf_id", ""))
                   for r in inventory["tasks"]}
    expected_models_by_task: dict[str, set[str]] = {}
    for item in logical_rows:
        expected_models_by_task.setdefault(item["TASK_ID"], set()).add(item["MODEL_ID"])
    structural_rows: list[dict[str, Any]] = []
    result_parse_counts = Counter()
    result_field_presence = Counter()
    result_identity_mismatches = []
    run_value_types = Counter()
    trajectory_parse_counts = Counter()
    trajectory_role_counts = Counter()
    trajectory_schema_errors = Counter()
    representation_variants = Counter()
    trajectory_types = Counter()
    function_call_count = 0
    function_output_count = 0
    matched_call_output_pairs = 0
    unmatched_call_count = 0
    orphan_output_count = 0
    duplicate_call_id_count = 0
    duplicate_output_id_count = 0
    out_of_order_output_count = 0
    explicit_tool_metadata_messages = 0
    explicit_tool_role_messages = 0
    trajectory_message_total = 0
    nested_run_value_types = Counter()
    nested_run_field_presence = Counter()
    outcome_value_fields = {"success", "score", "metrics", "summary", "error_message", "token_usage", "execution_time", "turn_count"}

    for index, source in enumerate(artifacts):
        role = source.get("ROLE")
        if role not in {"per_task_model_result", "per_task_result_container", "trajectory"}:
            continue
        path = Path(source["PATH"])
        obj, error = safe_json(path)
        task_id, model_id, run_label = source.get("TASK_ID"), source.get("MODEL_ID"), source.get("RESPONSE_ID")
        row: dict[str, Any] = {
            "row_type": "mcp_json_structural_observation", "catalog_row": index,
            "artifact_role": role, "task_id": task_id, "model_id": model_id,
            "published_run_label": run_label, "path": source.get("PATH"),
            "sha256": source.get("SOURCE_SHA256"), "bytes": source.get("BYTES"),
            "upstream_path": source.get("UPSTREAM_PATH"),
            "original_source_path": str(catalog_path), "original_source_sha256": catalog_sha,
            "original_row_pointer": f"{catalog_path}#/artifact_records/{index}",
            "payload_exported": False,
        }
        if error:
            structural_rows.append({**row, "parse_status": "JSON_PARSE_ERROR", "error_class": error})
            if role == "trajectory":
                trajectory_parse_counts["JSON_PARSE_ERROR"] += 1
            else:
                result_parse_counts["JSON_PARSE_ERROR"] += 1
            continue
        if role == "trajectory":
            trajectory_parse_counts["JSON_PARSE_PASS"] += 1
            valid_top = isinstance(obj, list)
            messages = obj if valid_top else []
            role_counts = Counter()
            type_counts = Counter()
            schema_errors = Counter()
            explicit_calls = 0
            explicit_tool_roles = 0
            calls: dict[str, list[int]] = {}
            outputs: dict[str, list[int]] = {}
            for message_index, message in enumerate(messages):
                if not isinstance(message, dict):
                    schema_errors["message_not_object"] += 1
                    continue
                mrole = message.get("role")
                role_counts[str(mrole)] += 1
                mtype = message.get("type")
                type_counts[str(mtype)] += 1
                if mrole in {"tool", "function"}:
                    explicit_tool_roles += 1
                if mtype == "function_call":
                    explicit_calls += 1
                    call_id = message.get("call_id")
                    if not isinstance(call_id, str) or not call_id:
                        schema_errors["function_call_missing_call_id"] += 1
                    else:
                        calls.setdefault(call_id, []).append(message_index)
                    if not isinstance(message.get("name"), str) or "arguments" not in message:
                        schema_errors["function_call_required_fields_missing"] += 1
                elif mtype == "function_call_output":
                    call_id = message.get("call_id")
                    if not isinstance(call_id, str) or not call_id or "output" not in message:
                        schema_errors["function_call_output_required_fields_missing"] += 1
                    else:
                        outputs.setdefault(call_id, []).append(message_index)
                elif mtype == "message" or (mtype is None and mrole in {"system", "developer", "user", "assistant"}):
                    if mtype is None:
                        representation_variants[f"typeless_role_{mrole}"] += 1
                    if mrole not in {"system", "developer", "user", "assistant"}:
                        schema_errors["message_role_invalid"] += 1
                    if "content" not in message or not isinstance(message.get("content"), (str, list)):
                        schema_errors["message_content_invalid_shape"] += 1
                else:
                    schema_errors["message_type_unknown_or_missing"] += 1
            trajectory_message_total += len(messages)
            trajectory_role_counts.update(role_counts)
            trajectory_types.update(type_counts)
            trajectory_schema_errors.update(schema_errors)
            explicit_tool_metadata_messages += explicit_calls
            explicit_tool_role_messages += explicit_tool_roles
            calls_local = sum(len(v) for v in calls.values())
            outputs_local = sum(len(v) for v in outputs.values())
            function_call_count += calls_local
            function_output_count += outputs_local
            duplicate_call_id_count += sum(len(v) > 1 for v in calls.values())
            duplicate_output_id_count += sum(len(v) > 1 for v in outputs.values())
            unmatched_call_count += sum(call_id not in outputs for call_id in calls)
            orphan_output_count += sum(call_id not in calls for call_id in outputs)
            matched_call_output_pairs += sum(1 for call_id in calls if call_id in outputs and len(calls[call_id]) == len(outputs[call_id]) == 1)
            out_of_order_output_count += sum(1 for call_id in calls if call_id in outputs and min(outputs[call_id]) < min(calls[call_id]))
            row.update({"parse_status": "JSON_PARSE_PASS", "top_level_type": "array" if valid_top else field_type(obj),
                        "message_count": len(messages), "message_role_counts": dict(role_counts),
                        "message_type_counts": dict(type_counts),
                        "message_schema_error_counts": dict(schema_errors),
                        "representation_variant_counts": {"typeless_user_message": sum(1 for m in messages if isinstance(m, dict) and m.get("type") is None and m.get("role") == "user")},
                        "function_call_count": calls_local, "function_call_output_count": outputs_local,
                        "matched_call_output_pairs": sum(1 for call_id in calls if call_id in outputs and len(calls[call_id]) == len(outputs[call_id]) == 1),
                        "unmatched_call_count": sum(call_id not in outputs for call_id in calls),
                        "orphan_output_count": sum(call_id not in calls for call_id in outputs),
                        "tool_call_binding_status": "STRUCTURALLY_VALID" if not schema_errors and all(len(calls[k]) == len(outputs.get(k, [])) == 1 for k in calls) and not any(k not in calls for k in outputs) else "STRUCTURAL_ANOMALY_OR_UNSUPPORTED_MESSAGE_TYPE"})
            structural_rows.append(row)
            continue

        result_parse_counts["JSON_PARSE_PASS"] += 1
        keys = set(obj) if isinstance(obj, dict) else set()
        for key in outcome_value_fields:
            if key in keys:
                result_field_presence[key] += 1
                if key in obj:
                    run_value_types[f"{key}:{field_type(obj[key])}"] += 1
        if role == "per_task_model_result":
            valid_shape = isinstance(obj, dict) and {"task", "model", "runs"}.issubset(keys) and isinstance(obj.get("runs"), dict)
            actual_task = obj.get("task") if isinstance(obj, dict) else None
            actual_model = obj.get("model") if isinstance(obj, dict) else None
            actual_runs = sorted(obj["runs"]) if valid_shape else []
            expected_task_leaf = task_leaves.get(task_id)
            identity_ok = actual_task == expected_task_leaf and actual_model == model_id and run_label in actual_runs
            run_fields = sorted(set().union(*(set(v) for v in obj["runs"].values() if isinstance(v, dict)))) if valid_shape else []
            run_field_types = {}
            if valid_shape:
                for run in obj["runs"].values():
                    if isinstance(run, dict):
                        for key, value in run.items():
                            nested_run_field_presence[key] += 1
                            nested_run_value_types[f"{key}:{field_type(value)}"] += 1
                            run_field_types[key] = field_type(value)
            if not valid_shape or not identity_ok:
                result_identity_mismatches.append({"task_id": task_id, "model_id": model_id,
                                                   "published_run_label": run_label, "path": str(path),
                                                   "valid_shape": valid_shape, "identity_matches_catalog": identity_ok,
                                                   "task_leaf_id_match": actual_task == expected_task_leaf})
            row.update({"parse_status": "JSON_PARSE_PASS", "shape_valid": valid_shape,
                        "top_level_keys": sorted(keys), "task_leaf_id_matches_catalog": actual_task == expected_task_leaf,
                        "task_id": task_id, "task_leaf_id": expected_task_leaf,
                        "model_identity_matches_catalog": actual_model == model_id,
                        "published_run_label_present": run_label in actual_runs,
                        "run_labels": actual_runs, "run_field_names": run_fields,
                        "run_field_types": run_field_types,
                        "outcome_value_fields_exported": False})
        else:
            models = obj.get("models") if isinstance(obj, dict) else None
            valid_shape = isinstance(obj, dict) and isinstance(models, dict) and isinstance(obj.get("task"), str)
            expected_leaf = task_leaves.get(task_id)
            actual_models = set(models) if isinstance(models, dict) else set()
            expected_models = expected_models_by_task.get(task_id, set())
            task_match = isinstance(obj, dict) and obj.get("task") == expected_leaf
            model_set_match = actual_models == expected_models
            if not valid_shape or not task_match or not model_set_match:
                result_identity_mismatches.append({"task_id": task_id, "path": str(path),
                                                   "result_container": True, "valid_shape": valid_shape,
                                                   "task_leaf_match": task_match, "model_set_match": model_set_match})
            row.update({"parse_status": "JSON_PARSE_PASS", "shape_valid": valid_shape,
                        "top_level_keys": sorted(keys), "task_identity_matches_catalog": isinstance(obj, dict) and obj.get("task") == task_id,
                        "task_leaf_matches_catalog": task_match, "model_set_matches_catalog": model_set_match,
                        "model_entry_count": len(models) if isinstance(models, dict) else None,
                        "model_ids": sorted(models) if isinstance(models, dict) else [],
                        "result_container_payload_exported": False})
        structural_rows.append(row)

    output_path = OUT / "structural_rows.jsonl"
    row_count, row_sha = checkpoint_write(output_path, structural_rows, journal, manifest_sha)
    summary = {
        "task_count": inventory["task_count"],
        "logical_result_identities": catalog["logical_result_instance_count"],
        "artifact_records": catalog["artifact_record_count"],
        "structural_rows_processed": row_count,
        "result_json_files_parsed": dict(result_parse_counts),
        "result_identity_or_shape_mismatches": len(result_identity_mismatches),
        "result_identity_mismatch_details": result_identity_mismatches,
        "result_structural_field_presence_counts": dict(result_field_presence),
        "outcome_field_type_counts_values_not_recorded": dict(run_value_types + nested_run_value_types),
        "nested_run_field_presence_counts": dict(nested_run_field_presence),
        "trajectory_files_parsed": dict(trajectory_parse_counts),
        "trajectory_messages": trajectory_message_total,
        "trajectory_role_counts": dict(trajectory_role_counts),
        "trajectory_message_type_counts": dict(trajectory_types),
        "trajectory_schema_error_counts": dict(trajectory_schema_errors),
        "representation_variants_observed": dict(representation_variants),
        "function_calls": function_call_count, "function_call_outputs": function_output_count,
        "matched_call_output_pairs": matched_call_output_pairs,
        "unmatched_call_count": unmatched_call_count, "orphan_output_count": orphan_output_count,
        "duplicate_call_id_count": duplicate_call_id_count, "duplicate_output_id_count": duplicate_output_id_count,
        "out_of_order_output_count": out_of_order_output_count,
        "tool_call_pair_validity": "STRUCTURAL_CALL_ID_PAIRING_ONLY; no tool execution or tool-result semantic validation",
        "missing_trajectory_identities": catalog["logical_result_instance_count"] - catalog["trajectory_artifacts"],
        "authenticated_execution_bindings": 0,
        "semantic_verdicts_created": 0,
    }
    report = {
        "schema": "pgop1.mcpmark.structural-results.v1", "attempt_id": OUT.name,
        "status": "COMPLETED_STRUCTURAL_PARSE_WITH_EXACT_LIMITATIONS",
        "input_manifest_sha256": manifest_sha, "input_manifest_entries": len(input_rows),
        "input_verification_counts": manifest["verification_counts"],
        "outputs": {"structural_rows.jsonl": {"rows": row_count, "sha256": row_sha}},
        "summary": summary,
        "execution_boundaries": {"benchmark_task_execution": "NOT_PERFORMED",
                                  "verifier_or_evaluator_execution": "NOT_PERFORMED",
                                  "trajectory_body_export": "NOT_PERFORMED",
                                  "model_or_paid_api": "NOT_USED"},
    }
    write_exclusive(OUT / "MCPMARK_STRUCTURAL_RESULTS.json", report)
    (NIGHTLY / "MCPMARK_STRUCTURAL_RESULTS.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["task_count", "logical_result_identities", "artifact_records",
                                              "structural_rows_processed", "result_json_files_parsed",
                                              "result_identity_or_shape_mismatches", "trajectory_files_parsed",
                                              "trajectory_messages", "trajectory_role_counts",
                                              "trajectory_message_type_counts", "trajectory_schema_error_counts",
                                              "function_calls", "function_call_outputs", "matched_call_output_pairs",
                                              "unmatched_call_count", "orphan_output_count", "authenticated_execution_bindings"]}, indent=2))


if __name__ == "__main__":
    main()
