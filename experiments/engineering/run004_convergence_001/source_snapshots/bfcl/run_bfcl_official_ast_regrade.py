#!/usr/bin/env python3
"""Bounded official BFCL AST function-path regrade on the frozen historical 20.

Only exact source function/class spans from the pinned upstream revision are
compiled. The standard BFCL CLI and its multi-turn imports are not loaded. Model
responses are consumed as JSON data and are never executed as code.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]
TASK = ROOT / "baseline/BENCHMARK_CORPUS_001/calling/gorilla/berkeley-function-call-leaderboard/bfcl_eval/data/BFCL_v4_simple_python.json"
REFERENCE = ROOT / "baseline/BENCHMARK_CORPUS_001/calling/gorilla/berkeley-function-call-leaderboard/bfcl_eval/data/possible_answer/BFCL_v4_simple_python.json"
RESPONSE = ROOT / "Engineering/PGOP1_MULTIBENCHMARK_EXECUTION_PILOT_001/bfcl-public-response-candidate-001/BFCL_v4_simple_python_result.json"
OLD_RUN = ROOT / "Engineering/PGOP1_REAL_BENCHMARK_EVALUATION_001"
OLD_RECEIPT = OLD_RUN / "OFFICIAL_EVALUATOR_RECEIPTS.json"
OLD_RESULTS = OLD_RUN / "bfcl-run-002/per_case_results.json"
FROZEN_DECISIONS = Path(__file__).resolve().parent / "PGOP1_PRIOR_DECISIONS_FREEZE.json"
PINNED_MODEL_HANDLER = (
    Path(__file__).resolve().parents[1]
    / "evaluator_dependencies/bfcl/official-6ea57973c7a6097fd7c5915698c54c17c5b1b6c8-source/berkeley-function-call-leaderboard/bfcl_eval/model_handler/local_inference/falcon_fc.py"
)
PINNED_UTILS = (
    Path(__file__).resolve().parents[1]
    / "evaluator_dependencies/bfcl/official-6ea57973c7a6097fd7c5915698c54c17c5b1b6c8-source/berkeley-function-call-leaderboard/bfcl_eval/utils.py"
)
BFCL = ROOT / "baseline/BENCHMARK_CORPUS_001/calling/gorilla/berkeley-function-call-leaderboard/bfcl_eval"
ATTEMPT = Path(__file__).resolve().parent / "attempts/official-result-regrade-007"
PIN = "6ea57973c7a6097fd7c5915698c54c17c5b1b6c8"
MODEL = "tiiuae/Falcon3-1B-Instruct-FC"
IDS = [f"simple_python_{index}" for index in range(20)]


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_hash(value) -> str:
    return sha(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def source_span(path: Path, name: str, class_name: str | None = None):
    raw = path.read_bytes()
    tree = ast.parse(raw)
    lines = raw.decode("utf-8-sig").splitlines(keepends=True)
    nodes = tree.body
    if class_name:
        nodes = next(node for node in nodes if isinstance(node, ast.ClassDef) and node.name == class_name).body
    node = next(
        node
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    )
    text = "".join(lines[node.lineno - 1 : node.end_lineno])
    return node, text, sha(text.encode("utf-8"))


def load_exact(path: Path, select=None, allow_assign=False, method_class=None, expected_span_hashes=None, namespace=None):
    raw = path.read_bytes()
    tree = ast.parse(raw)
    lines = raw.decode("utf-8-sig").splitlines(keepends=True)
    nodes = tree.body
    if method_class:
        nodes = next(node for node in nodes if isinstance(node, ast.ClassDef) and node.name == method_class).body
    loaded = []
    for node in nodes:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (select is None or node.name in select):
            text = "".join(lines[node.lineno - 1 : node.end_lineno])
            span_sha = sha(text.encode("utf-8"))
            expected = (expected_span_hashes or {}).get(node.name)
            if expected and span_sha != expected:
                raise RuntimeError(f"Official source span changed for {path}:{node.name}: {span_sha}")
            if method_class:
                text = textwrap.dedent(text)
            # `exec` compiles only the exact, hash-checked official span. No
            # model response text is passed to compile/exec/eval.
            code = "from __future__ import annotations\n" + text
            exec(compile(code, f"{path}:{node.lineno}", "exec"), namespace)
            loaded.append({"path": str(path), "symbol": node.name, "start_line": node.lineno, "end_line": node.end_lineno, "source_span_sha256": span_sha})
        elif allow_assign and isinstance(node, (ast.Assign, ast.AnnAssign)):
            code = compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec")
            exec(code, namespace)
    return loaded


def dangerous_calls(tree: ast.AST):
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"eval", "exec", "__import__", "compile"}:
            found.append(func.id)
    return found


def main() -> int:
    if ATTEMPT.exists():
        raise FileExistsError(f"Refusing to overwrite attempt directory: {ATTEMPT}")
    ATTEMPT.mkdir(parents=True)

    closure_manifest = ROOT / "Engineering/PGOP1_RUN004_FULL_PREPARATION_001/RUN004_EVALUATOR_MANIFEST.json"
    evaluator_manifest = read_json(closure_manifest)
    family_manifest = next(row for row in evaluator_manifest["families"] if row.get("family") == "bfcl_v4")
    if family_manifest.get("source_commit") != PIN:
        raise RuntimeError("RUN004 evaluator manifest did not bind the selected official source pin")
    if evaluator_manifest.get("run004") != "NOT_EXECUTED":
        raise RuntimeError("Expected RUN004 to remain unexecuted")

    freeze_raw = FROZEN_DECISIONS.read_bytes()
    freeze = json.loads(freeze_raw.decode("utf-8-sig"))
    if freeze.get("status") != "FROZEN_BEFORE_OFFICIAL_REGRADE" or len(freeze.get("cases", [])) != len(IDS):
        raise RuntimeError("PGOP1 structural decisions were not frozen before official regrade")
    if [row["task_id"] for row in freeze["cases"]] != IDS:
        raise RuntimeError("Frozen PGOP1 decision IDs differ from the fixed historical selection")

    prior_receipt = read_json(OLD_RECEIPT)
    if prior_receipt.get("evaluator_commit") != PIN:
        raise RuntimeError("Prior historical evaluator receipt does not match the pinned source commit")
    expected_files = prior_receipt["source_files"]
    for path_text, record in expected_files.items():
        path = Path(path_text)
        if not path.is_file() or sha(path.read_bytes()) != record["sha256"]:
            raise RuntimeError(f"Historical official source hash mismatch: {path}")

    task_rows = jsonl(TASK)
    reference_rows = jsonl(REFERENCE)
    response_rows = jsonl(RESPONSE)
    source_hashes = {
        "tasks": {"path": str(TASK), "sha256": sha(TASK.read_bytes()), "bytes": TASK.stat().st_size},
        "references": {"path": str(REFERENCE), "sha256": sha(REFERENCE.read_bytes()), "bytes": REFERENCE.stat().st_size},
        "responses": {"path": str(RESPONSE), "sha256": sha(RESPONSE.read_bytes()), "bytes": RESPONSE.stat().st_size},
    }
    if source_hashes != prior_receipt["inputs"]:
        raise RuntimeError("Historical input file identities differ from the prior official receipt")
    if len({row["id"] for row in response_rows}) != len(response_rows):
        raise RuntimeError("Response file contains duplicate IDs")
    response_map = {row["id"]: row for row in response_rows}
    if any(task_id not in response_map for task_id in IDS):
        raise RuntimeError("Fixed historical selection is incomplete in the original response file")
    selected_responses = [response_map[task_id] for task_id in IDS]
    if any(not isinstance(row.get("result"), str) for row in selected_responses):
        raise RuntimeError("Selected outputs are not strings for official Falcon JSON decode path")

    # Inspect only task function names and decode response content with JSON.
    task_map = {row["id"]: row for row in task_rows}
    reference_map = {row["id"]: row for row in reference_rows}
    if any(task_id not in task_map or task_id not in reference_map for task_id in IDS):
        raise RuntimeError("Pinned task/reference files lack selected IDs")
    function_names = []
    for task_id in IDS:
        functions = task_map[task_id]["function"]
        names = [function["name"] for function in functions]
        function_names.extend(names)

    # The official checker consults only `underscore_to_dot` for dotted task
    # function names. Project that literal from the exact pinned model_config
    # rather than importing the module (which eagerly imports every model
    # handler and its API clients).
    model_config_path = BFCL / "constants/model_config.py"
    if sha(model_config_path.read_bytes()) != expected_files[str(model_config_path)]["sha256"]:
        raise RuntimeError("Pinned model_config file hash differs from historical official receipt")
    model_config_tree = ast.parse(model_config_path.read_bytes())
    mapping_node = next(
        node.value
        for node in model_config_tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "local_inference_model_map" for target in node.targets)
    )
    model_call = next(
        value
        for key, value in zip(mapping_node.keys, mapping_node.values)
        if isinstance(key, ast.Constant) and key.value == MODEL
    )
    underscore_to_dot = ast.literal_eval(next(keyword.value for keyword in model_call.keywords if keyword.arg == "underscore_to_dot"))
    if type(underscore_to_dot) is not bool:
        raise RuntimeError("Pinned model_config underscore_to_dot is not a literal boolean")

    decoder_node, decoder_text, decoder_hash = source_span(PINNED_MODEL_HANDLER, "decode_ast", "Falcon3FCHandler")
    prior_spans = {
        (Path(row["path"]).name, row["symbol"]): row["source_span_sha256"]
        for row in prior_receipt.get("executed_source_spans", [])
    }
    if prior_spans.get(("falcon_fc.py", "decode_ast")) != decoder_hash:
        raise RuntimeError("Pinned Falcon decode_ast differs from the prior source-slice receipt")
    checker_path = BFCL / "eval_checker/ast_eval/ast_checker.py"
    checker_source = checker_path.read_bytes()
    if sha(checker_source) != expected_files[str(checker_path)]["sha256"]:
        raise RuntimeError("Pinned AST checker file hash differs from historical official receipt")
    runner_path = BFCL / "eval_checker/eval_runner.py"
    runner_source = runner_path.read_bytes()
    if sha(runner_source) != expected_files[str(runner_path)]["sha256"]:
        raise RuntimeError("Pinned eval_runner file hash differs from historical official receipt")

    # Static safety checks of the exact called source only. The full CLI, its
    # multi-turn module, and `model_handler/utils.py` are intentionally excluded.
    decoder_tree = ast.parse(textwrap.dedent(decoder_text))
    checker_tree = ast.parse(checker_source)
    utils_node, utils_text, utils_hash = source_span(PINNED_UTILS, "is_function_calling_format_output")
    if prior_spans.get(("utils.py", "is_function_calling_format_output")) != utils_hash:
        raise RuntimeError("Pinned output-format helper differs from the prior source-slice receipt")
    utils_tree = ast.parse(utils_text)
    runner_tree = ast.parse(runner_source)
    _subset_node, _subset_text, subset_hash = source_span(runner_path, "_subset_entries_by_model_ids")
    _entry_node, _entry_text, entry_hash = source_span(runner_path, "_evaluate_single_ast_entry")
    if prior_spans.get(("eval_runner.py", "_subset_entries_by_model_ids")) != subset_hash:
        raise RuntimeError("Pinned official alignment function differs from the prior source-slice receipt")
    if prior_spans.get(("eval_runner.py", "_evaluate_single_ast_entry")) != entry_hash:
        raise RuntimeError("Pinned official AST entry function differs from the prior source-slice receipt")
    executed_trees = [decoder_tree, checker_tree, utils_tree, ast.parse(_subset_text), ast.parse(_entry_text)]
    source_call_names = [name for tree in executed_trees for name in dangerous_calls(tree)]
    if source_call_names:
        raise RuntimeError(f"A forbidden dynamic call is reachable in the selected function path: {source_call_names}")
    full_runner_imports_multiturn = any(
        isinstance(node, ast.ImportFrom)
        and (node.module or "").startswith("bfcl_eval.eval_checker.multi_turn_eval")
        for node in runner_tree.body
    )
    if not full_runner_imports_multiturn:
        raise RuntimeError("Expected full official CLI multi-turn import boundary was not observed")

    # The exact Falcon decoder uses json.loads. Validate all 20 payloads with
    # that official decoder before invoking the official checker path.
    ns = {"json": json, "re": re}
    decoder_loaded = load_exact(
        PINNED_MODEL_HANDLER,
        select={"decode_ast"},
        method_class="Falcon3FCHandler",
        expected_span_hashes={"decode_ast": decoder_hash},
        namespace=ns,
    )
    decoded = []
    decode_precheck_errors = []
    for response in selected_responses:
        try:
            decoded.append(ns["decode_ast"](None, response["result"], None, False))
        except Exception as exc:
            # The official entry function captures decode exceptions and turns
            # them into ordinary case results. Keep only the exception type;
            # response text remains opaque and is not emitted.
            decoded.append(None)
            decode_precheck_errors.append({"task_id": response["id"], "exception_type": type(exc).__name__})
    decoded_calls = [name for result in decoded if result is not None for call in result for name in call]
    if any(not isinstance(name, str) for name in decoded_calls):
        raise RuntimeError("Decoded response function names are not strings")

    # The remaining exact checker dependencies are loaded by source span from
    # pinned files, without importing package initializers or model handlers.
    from enum import Enum

    ns["Enum"] = Enum
    loaded = list(decoder_loaded)
    loaded += load_exact(BFCL / "constants/enums.py", select={"Language", "ReturnFormat"}, namespace=ns)
    loaded += load_exact(BFCL / "constants/type_mappings.py", select=set(), allow_assign=True, namespace=ns)
    for lang in ("java", "js"):
        loaded += load_exact(BFCL / f"eval_checker/ast_eval/type_convertor/{lang}_type_converter.py", namespace=ns)
    # This is an exact data projection of the single official config field used
    # by convert_func_name; no handler or evaluator behavior is stubbed.
    ns["MODEL_CONFIG_MAPPING"] = {MODEL: SimpleNamespace(underscore_to_dot=underscore_to_dot)}
    loaded += load_exact(checker_path, allow_assign=True, namespace=ns)
    loaded += load_exact(PINNED_UTILS, select={"is_function_calling_format_output"}, expected_span_hashes={"is_function_calling_format_output": utils_hash}, namespace=ns)
    loaded += load_exact(runner_path, select={"_subset_entries_by_model_ids", "_evaluate_single_ast_entry"}, expected_span_hashes={"_subset_entries_by_model_ids": subset_hash, "_evaluate_single_ast_entry": entry_hash}, namespace=ns)

    # Handler adapter delegates only to the exact official decode_ast method;
    # no inference, model loading, tool invocation, or response-code execution.
    handler = SimpleNamespace(decode_ast=lambda result, fmt, tag: ns["decode_ast"](None, result, fmt, tag))
    selected_tasks = [task_map[task_id] for task_id in IDS]
    selected_refs = [reference_map[task_id] for task_id in IDS]
    prompts, answers = ns["_subset_entries_by_model_ids"](selected_responses, task_rows, reference_rows, allow_missing=True)
    if [row["id"] for row in prompts] != IDS or [row["id"] for row in answers] != IDS:
        raise RuntimeError("Official alignment function did not preserve the frozen fixed-prefix order")

    historical_rows = read_json(OLD_RESULTS)
    historical = {row["task_id"]: row["official_result"] for row in historical_rows}
    if set(historical) != set(IDS):
        raise RuntimeError("Prior official results do not match the frozen fixed-prefix task IDs")
    result_rows = []
    for response, prompt, reference in zip(selected_responses, prompts, answers):
        if response["id"] != prompt["id"]:
            raise RuntimeError("Response and prompt identity mismatch")
        result = ns["_evaluate_single_ast_entry"](
            handler,
            prompt["id"],
            response["result"],
            reference["ground_truth"],
            prompt,
            MODEL,
            "simple_python",
            ns["Language"].PYTHON,
            ns["ReturnFormat"].PYTHON,
            has_tool_call_tag=False,
        )
        match = canonical_hash(result) == canonical_hash(historical[prompt["id"]])
        result_rows.append(
            {
                "task_id": prompt["id"],
                "official_valid": result.get("valid"),
                "official_error_type": result.get("error_type"),
                "official_result_sha256": canonical_hash(result),
                "historical_official_result_sha256": canonical_hash(historical[prompt["id"]]),
                "matches_historical_official_result": match,
                "task_source_row_sha256": sha(json.dumps(prompt, sort_keys=True, ensure_ascii=False).encode("utf-8")),
                "response_source_row_sha256": sha(json.dumps(response, sort_keys=True, ensure_ascii=False).encode("utf-8")),
                "reference_source_row_sha256": sha(json.dumps(reference, sort_keys=True, ensure_ascii=False).encode("utf-8")),
            }
        )

    passed = sum(1 for row in result_rows if row["official_valid"] is True)
    source_inventory = []
    for source_path in [PINNED_MODEL_HANDLER, PINNED_UTILS, checker_path, runner_path]:
        source_inventory.append({"path": str(source_path), "bytes": source_path.stat().st_size, "sha256": sha(source_path.read_bytes())})
    summary = {
        "schema": "pgop1.bfcl.official-execution-results.v1",
        "status": "OFFICIAL_RESULT_REGRADE_PARTIAL_FUNCTION_PATH",
        "benchmark": "BFCL V4",
        "source_commit": PIN,
        "population": {"category": "simple_python", "selected_case_count": len(result_rows), "selection_rule": "historical fixed prefix simple_python_0..19; no outcome filtering", "new_task_cases": 0},
        "counts": {"official_function_slice_evaluations": len(result_rows), "passed": passed, "failed": len(result_rows) - passed, "historical_result_matches": sum(row["matches_historical_official_result"] for row in result_rows), "fresh_model_generations": 0, "tool_or_function_calls": 0, "response_derived_eval_or_exec_calls": 0, "full_official_cli_executions": 0, "RUN004_executions": 0},
        "runtime": {"python": sys.version, "environment": "existing Windows Python; no package installation; no Docker/WSL; function-source slice only", "dependency_closure_validated": False, "pinned_model_handler_source_acquired": True, "pinned_model_handler_imported": False, "model_loaded": False, "network_used_during_evaluation": False},
        "security": {"status": "PASS_SCOPED_FUNCTION_PATH_STATIC_GUARDS", "response_input_decoder": "official Falcon3FCHandler.decode_ast using json.loads", "called_official_sources_checked_for_eval_exec": True, "dangerous_call_names_in_called_sources": source_call_names, "full_cli_imports_multiturn": full_runner_imports_multiturn, "full_cli_imported_or_invoked": False, "model_handler_utils_eval_path_reached": False, "model_config_imported": False, "model_config_data_projection": {"source_path": str(model_config_path), "source_sha256": sha(model_config_path.read_bytes()), "field": "underscore_to_dot", "value": underscore_to_dot}, "task_function_names_with_dot": sum("." in name for name in function_names)},
        "input_hashes": source_hashes,
        "frozen_pgop1_decisions": {"path": str(FROZEN_DECISIONS), "sha256": sha(freeze_raw), "cases": len(freeze["cases"]), "verdicts": {"ABSTAIN": len(freeze["cases"])}},
        "official_source_files": source_inventory,
        "loaded_official_source_spans": loaded,
        "decoder_precheck_errors": decode_precheck_errors,
        "limitations": ["This is an exact official function-path regrade, not the BFCL CLI, not full dependency-closure validation, not a full category/leaderboard score, not fresh model generation, and not independent semantic qualification.", "The 87,200 exact prompt identities and 292,584 remaining unresolved rows in the six-family binding report are outside this 20-case historical regrade.", "Original PGOP1 structural decisions remain frozen and unchanged; official validity does not replace ABSTAIN or UNKNOWN independent labels."],
    }
    (ATTEMPT / "official_case_results.json").write_text(json.dumps(result_rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (ATTEMPT / "regrade_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": summary["status"], "evaluated": len(result_rows), "passed": passed, "failed": len(result_rows) - passed, "historical_result_matches": summary["counts"]["historical_result_matches"], "output": str(ATTEMPT)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
