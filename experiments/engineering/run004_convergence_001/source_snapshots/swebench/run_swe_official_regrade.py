"""Regrade one new original SWE Multilingual recorded log with pinned _grade."""
import gzip
import hashlib
import json
import os
import sys
import types
from pathlib import Path

import pyarrow.parquet as pq

ROOT = Path(r"D:\PGOP1_DATA\PGOP1_BASELINE_001")
OUT = ROOT / "Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/execution_receipts/swebench/SWE_OFFICIAL_REGRADE_001"
BENCH = ROOT / "Engineering/PGOP1_REAL_BENCHMARK_EVALUATION_001"
BASE = ROOT
SOURCE = ROOT / "SWE-bench-main"
HISTORY = ROOT / "Engineering/Legacy_Root_Workspaces/PGOP1_V1_OFFICIAL_REGRADE_NETWORK_RECOVERY_20261028T053443Z"
PYTHON_EXE = HISTORY / "venv/Scripts/python.exe"
EXPECTED_REVISION = "02e7a74ffd0b707aab73d203fe87bdc7c76afc8e"
EXPECTED_PARQUET_SHA256 = "92abca7cb527b41a9f66d03a26ce441ff7319e3a49f985998fd56be4bb9b08b2"
RUN_ID = "SWE_OFFICIAL_REGRADE_001"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def main() -> int:
    if OUT.exists():
        raise FileExistsError(f"fresh output path already exists: {OUT}")
    OUT.mkdir(parents=True)
    os.environ.update(
        HF_HUB_OFFLINE="1",
        HF_DATASETS_OFFLINE="1",
        PYTHON_DOTENV_DISABLED="1",
        HF_HOME=str(OUT / "offline-cache"),
    )
    identity_path = HISTORY / "UPSTREAM_SOURCE_IDENTITY.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    assert identity["resolved_commit_sha"] == EXPECTED_REVISION
    bindings = []
    for item in identity["files"]:
        path = SOURCE / item["relative_path"]
        observed = sha(path)
        assert observed == item["checkout_sha256"], item["relative_path"]
        bindings.append({"relative_path": item["relative_path"], "sha256": observed})
    package_path = SOURCE / "swebench/submit/package.py"
    assert sha(package_path) == "83423d149c51d01a9eb526ac4bc2f9418b2428528cd24d5f6d9998f3d77dcc85"

    # Verify the complete preserved source identity before importing official grader code.
    sys.path.insert(0, str(SOURCE))
    harness = types.ModuleType("swebench.harness")
    harness.__path__ = [str(SOURCE / "swebench/harness")]
    sys.modules["swebench.harness"] = harness
    from swebench.submit.package import _grade

    parquet = BASE / "multilingual/data/test-00000-of-00001.parquet"
    predictions_path = BASE / "logs/all_preds.jsonl"
    assert sha(parquet) == EXPECTED_PARQUET_SHA256
    tasks = {row["instance_id"]: row for row in pq.read_table(parquet).to_pylist()}
    predictions = {
        row["instance_id"]: row
        for row in map(json.loads, predictions_path.read_text(encoding="utf-8").splitlines())
        if row.get("instance_id")
    }
    old_ids = set()
    for name in ("swe-regrade-001", "swe-regrade-002"):
        selection = json.loads((BENCH / name / "selection.json").read_text(encoding="utf-8"))
        old_ids.update(selection["ids"])
    candidates = []
    for instance_id in sorted(set(tasks) & set(predictions) - old_ids):
        original = BASE / "logs/logs" / instance_id
        patch = original / "patch.diff"
        execution_log = original / "test_output.txt.gz"
        report = original / "report.json"
        if all(path.is_file() for path in (patch, execution_log, report)):
            candidates.append((instance_id, original, patch, execution_log, report))
    assert candidates, "no fresh task/prediction/patch/log/report intersection outside the prior 15-case sample"
    instance_id, original, patch, compressed_log, report_path = candidates[0]
    preselection = json.loads((ROOT / "Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/swebench/SWE_OFFICIAL_REGRADE_001_SELECTION.json").read_text(encoding="utf-8"))
    assert preselection["run_id"] == RUN_ID and preselection["selected_before_outcome_read"] is True
    assert preselection["task_id"] == instance_id
    structural = json.loads((ROOT / "Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/swebench/SWE_OFFICIAL_REGRADE_001_PGOP1_STRUCTURAL_PREREGISTRATION.json").read_text(encoding="utf-8"))
    assert structural["run_id"] == RUN_ID and structural["decision_time"] == "PRE_EVALUATOR_INVOCATION"
    assert structural["predicate"]["name"] == "TASK_RESOLVED"
    bound = preselection["input_bindings"]
    assert bound["task_parquet"]["sha256"] == sha(parquet)
    assert bound["all_predictions"]["sha256"] == sha(predictions_path)
    assert bound["patch"]["sha256"] == sha(patch)
    assert bound["compressed_original_test_log"]["sha256"] == sha(compressed_log)
    assert bound["archived_report"]["sha256"] == sha(report_path)
    assert bound["grader_source"]["sha256"] == sha(SOURCE / "swebench/submit/package.py")
    prediction = predictions[instance_id]
    assert patch.read_text(encoding="utf-8") == prediction["model_patch"]
    raw_log = gzip.decompress(compressed_log.read_bytes())
    assert len(raw_log) < 20 * 1024 * 1024
    log_path = OUT / f"{instance_id}.test_output.txt"
    log_path.write_bytes(raw_log)
    task = tasks[instance_id]
    archived = json.loads(report_path.read_text(encoding="utf-8"))[instance_id]["resolved"]

    # This is the official pinned function path used by the prior recorded-log regrade.
    resolved = _grade(task, patch, log_path, prediction["model_name_or_path"])
    result = {
        "run_id": RUN_ID,
        "benchmark_variant": "SWE-BENCH_MULTILINGUAL",
        "task_id": instance_id,
        "official_result": {"resolved": resolved},
        "archived_result": {"resolved": archived},
        "matches_archived": resolved == archived,
        "evaluator": "swebench.submit.package._grade",
        "source_revision": EXPECTED_REVISION,
        "source_package_sha256": sha(package_path),
        "dataset_parquet_sha256": sha(parquet),
        "prediction_sha256": sha(predictions_path),
        "patch_sha256": sha(patch),
        "compressed_log_sha256": sha(compressed_log),
        "decompressed_log_sha256": hashlib.sha256(raw_log).hexdigest(),
        "report_sha256": sha(report_path),
        "previous_sample_ids_excluded": len(old_ids),
        "selection_rule": "lexicographically first task/prediction/patch/log/report intersection after excluding the prior 15 IDs; no outcome filtering",
        "patches_applied": 0,
        "tests_reexecuted": 0,
        "network_requests": 0,
        "result_scope": "one offline original-log regrade; no CLI parity or campaign score claim",
    }
    write(OUT / "per_case_result.json", result)
    write(OUT / "source_bindings.json", bindings)
    receipt = {
        "run_id": RUN_ID,
        "interpreter": sys.version,
        "interpreter_path": sys.executable,
        "source_revision": EXPECTED_REVISION,
        "official_entrypoint": "swebench.submit.package._grade",
        "source_file_count_verified": len(bindings),
        "source_package_sha256": sha(package_path),
        "dataset": {"path": str(parquet), "sha256": sha(parquet)},
        "prediction_file": {"path": str(predictions_path), "sha256": sha(predictions_path)},
        "prior_sample_ids_excluded": len(old_ids),
        "new_task_id": instance_id,
        "resolved": resolved,
        "matches_archived": resolved == archived,
        "patches_applied": 0,
        "tests_reexecuted": 0,
        "network_requests": 0,
        "dotenv_disabled": True,
        "docker_used": False,
        "mode": "OFFICIAL_RECORDED_LOG_RESULT_REGRADE_NOT_TASK_EXECUTION",
    }
    write(OUT / "execution_receipt.json", receipt)
    print(json.dumps({"run_id": RUN_ID, "cases": 1, "task_id": instance_id, "resolved": resolved, "matches_archived": resolved == archived}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
