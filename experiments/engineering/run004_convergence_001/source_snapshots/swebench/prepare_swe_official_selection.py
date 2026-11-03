"""Select and hash-bind one fresh recorded-log input before reading its outcome."""
import hashlib
import json
from pathlib import Path

import pyarrow.parquet as pq

ROOT = Path(r"D:\PGOP1_DATA\PGOP1_BASELINE_001")
BASE = ROOT / "Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001"
BENCH = ROOT / "Engineering/PGOP1_REAL_BENCHMARK_EVALUATION_001"
HISTORY = ROOT / "Engineering/Legacy_Root_Workspaces/PGOP1_V1_OFFICIAL_REGRADE_NETWORK_RECOVERY_20261028T053443Z"
SOURCE = ROOT / "SWE-bench-main"
OUTPUT = BASE / "swebench/SWE_OFFICIAL_REGRADE_001_SELECTION.json"
EXPECTED_PARQUET_SHA256 = "92abca7cb527b41a9f66d03a26ce441ff7319e3a49f985998fd56be4bb9b08b2"
EXPECTED_PREDICTIONS_SHA256 = "f59500bc9a1961d2fd0230f81a712f5f420dfbad88c48cbaedb4756207f4df36"
EXPECTED_REVISION = "02e7a74ffd0b707aab73d203fe87bdc7c76afc8e"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    if OUTPUT.exists():
        raise FileExistsError(f"selection already exists: {OUTPUT}")
    identity = json.loads((HISTORY / "UPSTREAM_SOURCE_IDENTITY.json").read_text(encoding="utf-8"))
    assert identity["resolved_commit_sha"] == EXPECTED_REVISION
    package = SOURCE / "swebench/submit/package.py"
    assert sha(package) == "83423d149c51d01a9eb526ac4bc2f9418b2428528cd24d5f6d9998f3d77dcc85"
    source_bindings = []
    for item in identity["files"]:
        path = SOURCE / item["relative_path"]
        observed = sha(path)
        assert observed == item["checkout_sha256"], item["relative_path"]
        source_bindings.append({"relative_path": item["relative_path"], "sha256": observed})

    parquet = ROOT / "multilingual/data/test-00000-of-00001.parquet"
    predictions_path = ROOT / "logs/all_preds.jsonl"
    assert sha(parquet) == EXPECTED_PARQUET_SHA256
    assert sha(predictions_path) == EXPECTED_PREDICTIONS_SHA256
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

    selected = None
    for instance_id in sorted((set(tasks) & set(predictions)) - old_ids):
        original = ROOT / "logs/logs" / instance_id
        files = {name: original / name for name in ("patch.diff", "test_output.txt.gz", "report.json")}
        if all(path.is_file() for path in files.values()):
            selected = (instance_id, original, files)
            break
    assert selected is not None, "no fresh task/prediction/patch/log/report intersection outside prior sample"
    instance_id, original, files = selected
    prediction = predictions[instance_id]
    patch = files["patch.diff"]
    assert patch.read_text(encoding="utf-8") == prediction["model_patch"]
    result = {
        "schema": "pgop1.swe-recorded-log-selection.v1",
        "run_id": "SWE_OFFICIAL_REGRADE_001",
        "selected_before_outcome_read": True,
        "benchmark_variant": "SWE-BENCH_MULTILINGUAL",
        "task_id": instance_id,
        "selection_rule": "lexicographically first task/prediction/patch/log/report intersection excluding all prior regrade IDs; no outcome filtering",
        "excluded_prior_case_count": len(old_ids),
        "input_bindings": {
            "task_parquet": {"path": str(parquet), "sha256": sha(parquet)},
            "all_predictions": {"path": str(predictions_path), "sha256": sha(predictions_path)},
            "task_row_sha256": hashlib.sha256(json.dumps(tasks[instance_id], sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "prediction_row_sha256": hashlib.sha256(json.dumps(prediction, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "patch": {"path": str(patch), "sha256": sha(patch)},
            "compressed_original_test_log": {"path": str(files["test_output.txt.gz"]), "sha256": sha(files["test_output.txt.gz"])},
            "archived_report": {"path": str(files["report.json"]), "sha256": sha(files["report.json"]), "outcome_read_during_selection": False},
            "grader_source": {"path": str(package), "sha256": sha(package), "revision": EXPECTED_REVISION},
            "source_identity_file": {"path": str(HISTORY / "UPSTREAM_SOURCE_IDENTITY.json"), "sha256": sha(HISTORY / "UPSTREAM_SOURCE_IDENTITY.json"), "verified_files": len(source_bindings)},
        },
        "source_binding_manifest": source_bindings,
    }
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"run_id": result["run_id"], "task_id": instance_id, "excluded_prior_case_count": len(old_ids), "selected_before_outcome_read": True}, sort_keys=True))


if __name__ == "__main__":
    main()
