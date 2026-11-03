from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

MODULE_DIR = Path(__file__).resolve().parents[1] / "runtime" / "candidate" / "multibenchmark"
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import operations


def write_tb_task(root: Path, *, task_id: str = "unit-task", category: str = "debugging") -> Path:
    task_dir = root / task_id
    (task_dir / "tests").mkdir(parents=True)
    (task_dir / "environment").mkdir()
    (task_dir / "task.toml").write_text(
        f'''schema_version = "1.1"\n[task]\nname = "terminal-bench/{task_id}"\nkeywords = ["python", "debugging"]\n[metadata]\ncategory = "{category}"\n[environment]\ncpus = 1\n''',
        encoding="utf-8",
    )
    (task_dir / "instruction.md").write_text("Do the task.\n", encoding="utf-8")
    (task_dir / "tests" / "test.sh").write_text("exit 0\n", encoding="utf-8")
    (task_dir / "tests" / "test_outputs.py").write_text("# inert fixture source\n", encoding="utf-8")
    (task_dir / "environment" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    return task_dir


def write_mcp_task(root: Path, *, task_id: str = "unit_task", category: str = "file_property",
                   service: str = "filesystem", declared_mcp: str | None = None) -> Path:
    task_dir = root / "tasks" / service / "standard" / category / task_id
    task_dir.mkdir(parents=True)
    (task_dir / "meta.json").write_text(json.dumps({
        "task_id": task_id,
        "task_name": "Unit Task",
        "category_id": category,
        "category_name": "File Property",
        "difficulty": "L1",
        "tags": ["file organization"],
        "mcp": [declared_mcp or service],
    }), encoding="utf-8")
    (task_dir / "description.md").write_text("Organize the provided files.\n", encoding="utf-8")
    (task_dir / "verify.py").write_text("# inert verifier source\n", encoding="utf-8")
    return task_dir


def test_terminal_bench_parses_directory_and_task_files(tmp_path: Path) -> None:
    task_dir = write_tb_task(tmp_path)
    first = operations.parse_terminal_bench(task_dir)[0]
    second = operations.parse_terminal_bench(task_dir / "task.toml")[0]
    third = operations.parse_terminal_bench(task_dir / "instruction.md")[0]
    assert first == second == third
    assert first["task_id"] == "unit-task"
    assert first["source_family_id"] == "terminal-bench-2.0"
    assert first["original_category"] == "debugging"
    assert first["capabilities"] == ["python", "debugging"]
    assert first["reference_type"] == "public_task_verifier"
    assert first["evaluator_type"] == "shell_entrypoint_with_python_tests"
    assert first["source_path"] == str((task_dir / "task.toml").resolve())
    assert first["source_pointer"] == operations.UNKNOWN
    assert first["source_revision"] == operations.UNKNOWN
    assert {a["role"] for a in first["metadata"]["ancillary_artifacts"]} == {
        "task_config", "task_instruction", "verifier_entrypoint", "verifier_source", "environment_build_config"
    }
    assert all(len(a["sha256"]) == 64 and Path(a["path"]).is_absolute() for a in first["metadata"]["ancillary_artifacts"])


def test_terminal_bench_rejects_task_id_path_mismatch(tmp_path: Path) -> None:
    task_dir = write_tb_task(tmp_path, task_id="actual-task")
    toml_path = task_dir / "task.toml"
    toml_path.write_text(toml_path.read_text(encoding="utf-8").replace("actual-task", "other-task"), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        operations.parse_terminal_bench(task_dir)


def test_terminal_bench_rejects_missing_category_and_evaluator(tmp_path: Path) -> None:
    task_dir = write_tb_task(tmp_path)
    config = task_dir / "task.toml"
    config.write_text(config.read_text(encoding="utf-8").replace('category = "debugging"', 'category = ""'), encoding="utf-8")
    with pytest.raises(ValueError, match="metadata.category"):
        operations.parse_terminal_bench(task_dir)
    config.write_text(config.read_text(encoding="utf-8").replace('category = ""', 'category = "debugging"'), encoding="utf-8")
    (task_dir / "tests" / "test.sh").unlink()
    with pytest.raises(ValueError, match="test.sh"):
        operations.parse_terminal_bench(task_dir)


def test_terminal_bench_rejects_duplicate_capability_tags(tmp_path: Path) -> None:
    task_dir = write_tb_task(tmp_path)
    config = task_dir / "task.toml"
    config.write_text(config.read_text(encoding="utf-8").replace('["python", "debugging"]', '["python", "python"]'), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        operations.parse_terminal_bench(task_dir)


def test_mcpmark_parses_directory_and_metadata_file(tmp_path: Path) -> None:
    task_dir = write_mcp_task(tmp_path)
    first = operations.parse_mcpmark(task_dir)[0]
    second = operations.parse_mcpmark(task_dir / "meta.json")[0]
    third = operations.parse_mcpmark(task_dir / "verify.py")[0]
    assert first == second == third
    assert first["task_id"] == "filesystem/standard/file_property/unit_task"
    assert first["source_family_id"] == "mcpmark"
    assert first["original_category"] == "file_property"
    assert first["capabilities"] == ["file organization"]
    assert first["reference_type"] == "public_task_verifier"
    assert first["evaluator_type"] == "python_verify_script"
    assert first["source_path"] == str((task_dir / "meta.json").resolve())
    assert first["source_pointer"] == "/task_id"
    assert first["source_revision"] == operations.UNKNOWN
    assert {a["role"] for a in first["metadata"]["ancillary_artifacts"]} == {
        "task_metadata", "task_description", "verifier_source"
    }


def test_mcpmark_rejects_directory_metadata_mismatch_and_missing_verifier(tmp_path: Path) -> None:
    task_dir = write_mcp_task(tmp_path, task_id="directory-task")
    meta_file = task_dir / "meta.json"
    data = json.loads(meta_file.read_text(encoding="utf-8"))
    data["task_id"] = "different-task"
    meta_file.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match directory"):
        operations.parse_mcpmark(task_dir)
    data["task_id"] = "directory-task"
    meta_file.write_text(json.dumps(data), encoding="utf-8")
    (task_dir / "verify.py").unlink()
    with pytest.raises(ValueError, match="verify.py"):
        operations.parse_mcpmark(task_dir)


def test_mcpmark_accepts_web_arena_path_key_mapped_to_playwright(tmp_path: Path) -> None:
    task_dir = write_mcp_task(tmp_path, service="playwright_webarena", declared_mcp="playwright")
    result = operations.parse_mcpmark(task_dir)[0]
    assert result["task_id"] == "playwright_webarena/standard/file_property/unit_task"
    assert result["metadata"]["task_service"] == "playwright_webarena"
    assert result["metadata"]["explicit_fields"]["mcp"] == ["playwright"]


def test_mcpmark_rejects_category_or_service_mismatch(tmp_path: Path) -> None:
    task_dir = write_mcp_task(tmp_path)
    meta_file = task_dir / "meta.json"
    data = json.loads(meta_file.read_text(encoding="utf-8"))
    data["category_id"] = "not_file_property"
    meta_file.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match directory"):
        operations.parse_mcpmark(task_dir)
    data["category_id"] = "file_property"
    data["mcp"] = ["not_filesystem"]
    meta_file.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="absent from meta.json"):
        operations.parse_mcpmark(task_dir)


def test_mcpmark_rejects_duplicate_tags_and_bad_json(tmp_path: Path) -> None:
    task_dir = write_mcp_task(tmp_path)
    meta_file = task_dir / "meta.json"
    data = json.loads(meta_file.read_text(encoding="utf-8"))
    data["tags"] = ["x", "x"]
    meta_file.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        operations.parse_mcpmark(task_dir)
    meta_file.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid MCPMark meta.json"):
        operations.parse_mcpmark(task_dir)


def test_mcpmark_rejects_duplicate_json_keys_and_nonfinite_numbers(tmp_path: Path) -> None:
    task_dir = write_mcp_task(tmp_path)
    meta_file = task_dir / "meta.json"
    meta_file.write_text('{"task_id":"unit_task","task_id":"unit_task"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        operations.parse_mcpmark(task_dir)
    meta_file.write_text('{"task_id":NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON numeric constant"):
        operations.parse_mcpmark(task_dir)


def test_parsers_reject_symlink_input_ancestors(tmp_path: Path) -> None:
    task_dir = write_tb_task(tmp_path)
    link = tmp_path / "task-link"
    try:
        link.symlink_to(task_dir, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is unavailable in this environment")
    with pytest.raises(ValueError, match="reparse point or symlink"):
        operations.parse_terminal_bench(link)
