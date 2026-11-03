from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from runtime.candidate.multibenchmark.software import (
    UNKNOWN,
    SoftwareSourceError,
    parse_swebench,
    parse_swebench_pro,
)

COMMIT = "a" * 40


def _swe_record(task_id: str) -> dict[str, str]:
    return {
        "instance_id": task_id,
        "repo": "owner/repo",
        "base_commit": COMMIT,
        "patch": "diff",
        "test_patch": "tests",
        "problem_statement": "Issue description",
    }


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _harbor_task(root: Path, task_id: str = "instance_repo__repo-abc-v1") -> Path:
    task_dir = root / task_id
    (task_dir / "tests").mkdir(parents=True)
    (task_dir / "solution").mkdir()
    (task_dir / "task.toml").write_text(
        f'''schema_version = "1.4"
[task]
name = "swebench-pro/{task_id}"
version = "1.0.0"
[metadata]
category = "debugging"
tags = ["debugging", "repo_task"]
[verifier]
network_mode = "public"
''',
        encoding="utf-8",
    )
    (task_dir / "instruction.md").write_text("Resolve the reported issue.", encoding="utf-8")
    (task_dir / "tests" / "test.sh").write_text("echo inert", encoding="utf-8")
    (task_dir / "solution" / "gold_patch.diff").write_text("diff --git a/a b/a\n", encoding="utf-8")
    return task_dir / "task.toml"


def test_swebench_parquet_preserves_row_metadata_and_unknowns(tmp_path):
    source = tmp_path / "tasks.parquet"
    table = pa.Table.from_pylist([
        {**_swe_record("repo__repo-1"), "problem_statement": "issue", "difficulty": "medium"},
        {**_swe_record("repo__repo-2"), "problem_statement": "issue 2", "difficulty": "hard"},
    ])
    pq.write_table(table, source)

    tasks = parse_swebench(source, expected_variant="full")

    assert [task["task_id"] for task in tasks] == ["repo__repo-1", "repo__repo-2"]
    assert tasks[0]["source_family_id"] == "swebench"
    assert tasks[0]["original_category"] == UNKNOWN
    assert tasks[0]["capabilities"] == UNKNOWN
    assert tasks[0]["reference_type"] == "reference_patch_with_test_patch"
    assert tasks[0]["evaluator_type"] == "test_patch"
    assert tasks[0]["source_path"] == str(source.absolute())
    assert tasks[0]["source_revision"] == UNKNOWN
    assert tasks[0]["source_pointer"] == UNKNOWN
    assert tasks[0]["metadata"]["problem_statement"] == "issue"
    assert "requested_variant" not in tasks[0]["metadata"]


def test_swebench_jsonl_records_exact_line_selector_and_rejects_duplicate_ids(tmp_path):
    source = tmp_path / "tasks.jsonl"
    source.write_text(
        "\n" + json.dumps(_swe_record("repo__repo-1")) + "\n" + json.dumps(_swe_record("repo__repo-2")) + "\n",
        encoding="utf-8",
    )
    tasks = parse_swebench(source)
    assert [task["source_pointer"] for task in tasks] == ["line:2", "line:3"]
    assert [task["metadata"]["source_line_number"] for task in tasks] == [2, 3]

    source.write_text(json.dumps(_swe_record("repo__repo-1")) + "\n" + json.dumps(_swe_record("repo__repo-1")) + "\n", encoding="utf-8")
    with pytest.raises(SoftwareSourceError, match="duplicate task identifier"):
        parse_swebench(source)


@pytest.mark.parametrize(
    "contents",
    [
        '[{"instance_id":"bad id"}]',
        '[{"instance_id":"repo__repo-1"},{"instance_id":"repo__repo-1"}]',
        '{"instance_id":"repo__repo-1","instance_id":"repo__repo-2"}',
        '[{"problem_statement":"missing id"}]',
    ],
)
def test_swebench_rejects_malformed_or_ambiguous_records(tmp_path, contents):
    source = tmp_path / "tasks.json"
    source.write_text(contents, encoding="utf-8")
    with pytest.raises(SoftwareSourceError):
        parse_swebench(source)


def test_swebench_rejects_mixed_benchmark_family(tmp_path):
    source = _write_json(tmp_path / "tasks.json", [_swe_record("repo__repo-1") | {"docker_image": "image"}])
    with pytest.raises(SoftwareSourceError, match="Pro shaped record"):
        parse_swebench(source)


def test_swebench_pro_parses_harbor_and_preserves_task_source_path(tmp_path):
    task_file = _harbor_task(tmp_path)

    task = parse_swebench_pro(task_file, expected_variant="v2")[0]

    assert task["task_id"] == "instance_repo__repo-abc-v1"
    assert task["source_family_id"] == "swebench_pro"
    assert task["original_category"] == "debugging"
    assert task["capabilities"] == ["debugging", "repo_task"]
    assert task["reference_type"] == "gold_patch.diff"
    assert task["evaluator_type"] == "Harbor tests/test.sh"
    assert task["source_path"] == str((task_file.parent / "instruction.md").absolute())
    assert task["source_revision"] == UNKNOWN
    assert task["source_pointer"] == UNKNOWN
    assert task["metadata"]["instruction_text"] == "Resolve the reported issue."
    assert task["metadata"]["artifact_references"]
    assert any(reference["path"].endswith("task.toml") for reference in task["metadata"]["artifact_references"])
    assert any(artifact["role"] == "EVALUATOR_SOURCE" for artifact in task["metadata"]["ancillary_artifacts"])
    assert any(artifact["role"] == "REFERENCE_SOLUTION" for artifact in task["metadata"]["ancillary_artifacts"])
    assert parse_swebench_pro(Path(task["source_path"]))[0] == task


def test_swebench_pro_parses_all_harbor_tasks_and_rejects_duplicate_ids(tmp_path):
    first = _harbor_task(tmp_path / "one", "instance_repo__repo-abc-v1")
    second = _harbor_task(tmp_path / "two", "instance_repo__repo-def-v1")
    tasks = parse_swebench_pro(tmp_path, expected_variant="v2")
    assert {task["task_id"] for task in tasks} == {"instance_repo__repo-abc-v1", "instance_repo__repo-def-v1"}

    duplicate = _harbor_task(tmp_path / "three", "instance_repo__repo-abc-v1")
    with pytest.raises(SoftwareSourceError, match="duplicate task identifier"):
        parse_swebench_pro(tmp_path)


def test_swebench_pro_rejects_invalid_variant_and_path_identity(tmp_path):
    with pytest.raises(SoftwareSourceError, match="only explicit SWE-bench Pro variant v2"):
        parse_swebench_pro(tmp_path, expected_variant="v1")

    wrong = _harbor_task(tmp_path, "instance_repo__repo-not-the-id-v1")
    wrong.write_text(
        wrong.read_text(encoding="utf-8").replace(
            "instance_repo__repo-not-the-id-v1", "instance_repo__repo-abc-v1"
        ),
        encoding="utf-8",
    )
    with pytest.raises(SoftwareSourceError, match="differs from its directory identity"):
        parse_swebench_pro(wrong)


def test_swebench_pro_rejects_duplicate_toml_keys(tmp_path):
    task_file = _harbor_task(tmp_path)
    task_file.write_text('[task]\nname="swebench-pro/instance_repo__repo-abc-v1"\nname="duplicate"\n', encoding="utf-8")
    with pytest.raises(SoftwareSourceError, match="TOML is malformed"):
        parse_swebench_pro(task_file)


def test_swebench_pro_rejects_unacquired_json_layout(tmp_path):
    source = _write_json(tmp_path / "tasks.json", [_swe_record("repo__repo-1")])
    with pytest.raises(SoftwareSourceError, match="acquired Harbor V2"):
        parse_swebench_pro(source)


def test_swebench_pro_uses_revision_only_when_primary_bytes_match_manifest(tmp_path):
    task_file = _harbor_task(tmp_path)
    instruction = task_file.parent / "instruction.md"
    raw = instruction.read_bytes()
    manifest = {
        "schema": "pgop1.multibenchmark.software-acquisition.v1",
        "corpus_root": str(tmp_path.resolve()),
        "source_revision": "a" * 40,
        "files": [{
            "path": instruction.relative_to(tmp_path).as_posix(),
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }],
    }
    (tmp_path / "SOURCE_MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")

    assert parse_swebench_pro(instruction)[0]["source_revision"] == "a" * 40
    instruction.write_text("changed source", encoding="utf-8")
    assert parse_swebench_pro(instruction)[0]["source_revision"] == UNKNOWN
