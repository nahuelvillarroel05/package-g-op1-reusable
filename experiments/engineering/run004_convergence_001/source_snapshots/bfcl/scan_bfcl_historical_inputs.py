#!/usr/bin/env python3
"""Inert smoke scan for the fixed historical BFCL result slice.

Runs only the hash-bound official Falcon JSON decoder on stored response data.
It does not call an evaluator/scorer, execute tool calls, or print response text.
"""

from __future__ import annotations

import ast
import hashlib
import json
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BFCL = ROOT / "baseline/BENCHMARK_CORPUS_001/calling/gorilla/berkeley-function-call-leaderboard/bfcl_eval"
OLD = ROOT / "Engineering/PGOP1_REAL_BENCHMARK_EVALUATION_001"
PINNED = ROOT / "Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/evaluator_dependencies/bfcl/official-6ea57973c7a6097fd7c5915698c54c17c5b1b6c8-source/berkeley-function-call-leaderboard/bfcl_eval"
FALCON = PINNED / "model_handler/local_inference/falcon_fc.py"
PIN = "6ea57973c7a6097fd7c5915698c54c17c5b1b6c8"
IDS = [f"simple_python_{index}" for index in range(20)]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_span(path: Path, symbol: str, class_name: str | None = None):
    raw = path.read_bytes()
    tree = ast.parse(raw)
    body = tree.body
    if class_name:
        body = next(node for node in body if isinstance(node, ast.ClassDef) and node.name == class_name).body
    node = next(node for node in body if isinstance(node, ast.FunctionDef) and node.name == symbol)
    lines = raw.decode("utf-8-sig").splitlines(keepends=True)
    text = "".join(lines[node.lineno - 1 : node.end_lineno])
    return text, sha(text.encode("utf-8")), node.lineno, node.end_lineno


def call_names(node: ast.AST):
    found = []
    for item in ast.walk(node):
        if isinstance(item, ast.Call):
            if isinstance(item.func, ast.Name):
                found.append(item.func.id)
            elif isinstance(item.func, ast.Attribute):
                found.append(ast.unparse(item.func))
    return sorted(set(found))


def main() -> int:
    receipt = json.loads((OLD / "OFFICIAL_EVALUATOR_RECEIPTS.json").read_text(encoding="utf-8-sig"))
    if receipt.get("evaluator_commit") != PIN:
        raise RuntimeError("Historical receipt pin mismatch")
    response_meta = receipt["inputs"]["responses"]
    response_path = Path(response_meta["path"])
    response_raw = response_path.read_bytes()
    if sha(response_raw) != response_meta["sha256"]:
        raise RuntimeError("Historical response file hash mismatch")
    rows = [json.loads(line) for line in response_raw.decode("utf-8-sig").splitlines() if line.strip()]
    selected = {row["id"]: row for row in rows if row.get("id") in IDS}
    if list(sorted(selected)) != sorted(IDS):
        raise RuntimeError("Historical fixed-prefix selection incomplete")

    decoder_source, decoder_sha, decoder_start, decoder_end = source_span(FALCON, "decode_ast", "Falcon3FCHandler")
    previous_span = next(
        row["source_span_sha256"]
        for row in receipt["executed_source_spans"]
        if Path(row["path"]).name == "falcon_fc.py" and row["symbol"] == "decode_ast"
    )
    if decoder_sha != previous_span:
        raise RuntimeError("Pinned official decoder source span mismatch")
    method_tree = ast.parse(textwrap.dedent(decoder_source))
    method_calls = call_names(method_tree)
    if "eval" in method_calls or "exec" in method_calls:
        raise RuntimeError("Pinned decoder contains a direct dynamic execution call")
    namespace = {"json": json}
    exec(compile("from __future__ import annotations\n" + textwrap.dedent(decoder_source), f"{FALCON}:{decoder_start}", "exec"), namespace)
    decode = namespace["decode_ast"]

    decoder_results = []
    for task_id in IDS:
        try:
            parsed = decode(None, selected[task_id]["result"], None, False)
            if not isinstance(parsed, list) or any(not isinstance(item, dict) for item in parsed):
                raise TypeError("official decoder returned unexpected container type")
            decoder_results.append({"task_id": task_id, "status": "DECODED_JSON", "call_count": len(parsed), "call_name_count": sum(len(item) for item in parsed)})
        except Exception as exc:
            decoder_results.append({"task_id": task_id, "status": "DECODE_ERROR_CAPTURED_BY_OFFICIAL_ENTRY", "exception_type": type(exc).__name__})

    runner_path = BFCL / "eval_checker/eval_runner.py"
    checker_path = BFCL / "eval_checker/ast_eval/ast_checker.py"
    runner_tree = ast.parse(runner_path.read_bytes())
    checker_tree = ast.parse(checker_path.read_bytes())
    runner_defs = {node.name: node for node in runner_tree.body if isinstance(node, ast.FunctionDef)}
    checker_defs = {node.name: node for node in checker_tree.body if isinstance(node, ast.FunctionDef)}
    evaluate_calls = call_names(runner_defs["_evaluate_single_ast_entry"])
    subset_calls = call_names(runner_defs["_subset_entries_by_model_ids"])
    ast_calls = {
        name: call_names(checker_defs[name])
        for name in ["ast_checker", "simple_function_checker", "type_checker", "convert_func_name", "string_checker", "list_checker", "dict_checker", "list_dict_checker", "standardize_string"]
    }
    executed_source_calls = evaluate_calls + sum(ast_calls.values(), []) + method_calls
    forbidden = sorted(set(executed_source_calls) & {"eval", "exec", "compile", "__import__", "open", "system", "popen", "run"})
    if forbidden:
        raise RuntimeError(f"Forbidden dynamic or external calls found in scoped route: {forbidden}")
    full_runner_multiturn_import = any(
        isinstance(node, ast.ImportFrom) and (node.module or "").startswith("bfcl_eval.eval_checker.multi_turn_eval")
        for node in runner_tree.body
    )
    output = {
        "schema": "pgop1.bfcl.inert-input-scan.v1",
        "status": "SMOKE_SCAN_COMPLETE_NO_SCORE",
        "source_commit": PIN,
        "selection": {"category": "simple_python", "ids": IDS, "rule": "historical fixed prefix; no output filtering"},
        "response_input": {"path": str(response_path), "sha256": sha(response_raw), "bytes": len(response_raw), "selected_rows": len(IDS)},
        "official_decoder": {"source_path": str(FALCON), "source_sha256": sha(FALCON.read_bytes()), "method_span_sha256": decoder_sha, "span_lines": [decoder_start, decoder_end], "direct_calls": method_calls},
        "decoder_results": decoder_results,
        "scorer_was_called": False,
        "route_static_review": {"entry_direct_calls": evaluate_calls, "alignment_direct_calls": subset_calls, "simple_python_ast_calls": ast_calls, "dangerous_calls_in_scoped_source": forbidden, "full_cli_imports_multiturn": full_runner_multiturn_import, "full_cli_imported": False, "model_handler_utils_eval_path_reached": False},
        "limits": ["This scan invokes only the pinned JSON decoder on opaque archived responses; it creates no official scores.", "A captured decoder error means the pinned official entry function will produce a normal failed case result for that row.", "No response body is included in this artifact."],
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
