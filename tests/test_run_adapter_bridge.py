import hashlib
import json
import os
import subprocess
import sys

import pytest

from runtime.candidate.context_engine import Engine
from runtime.candidate.multibenchmark.core import EvidenceError
from runtime.candidate.run_adapter_bridge import (
    FAMILY_ADAPTERS, family_capabilities, family_operations, process_authored_unit,
)


def _bfcl_source(root):
    source = root / "BFCL_v4_simple_python.json"
    source.write_text(json.dumps([{
        "id": "simple_python_synthetic_001",
        "question": [[{"role": "user", "content": "Synthetic task: call the declared function."}]],
        "function": [{"name": "synthetic_fn", "description": "Authored fixture function.",
                      "parameters": {"type": "object", "properties": {}}}],
    }]), encoding="utf-8")
    return source


def test_registry_covers_existing_six_family_parser_dispatch():
    assert set(FAMILY_ADAPTERS) == {
        "swebench", "swebench_pro_v2", "terminal_bench_2",
        "mcpmark_verified", "bfcl_v4", "tau_bench",
    }
    assert set(family_capabilities()) == set(FAMILY_ADAPTERS)
    assert all(row.parser and row.capability_ids for row in FAMILY_ADAPTERS.values())
    for operations in family_operations().values():
        assert set(operations) == {"DISCOVER", "VALIDATE", "NORMALIZE", "AUDIT", "PERSIST", "RECOVER"}
        assert "SEMANTIC_AUDIT_UNSUPPORTED" in operations["AUDIT"]


def test_authored_descriptor_uses_existing_parser_and_engine_readback(tmp_path):
    source = _bfcl_source(tmp_path)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    commitments = {str(source.resolve()): digest}
    result = process_authored_unit(
        Engine(tmp_path / "context"), family="bfcl_v4", version="V4",
        revision="a" * 40, source_path=source,
        task_id="simple_python_synthetic_001", source_sha256=digest,
        allowed_roots=[tmp_path], source_commitments=commitments,
    )
    assert result["processing_status"] == "SOURCE_BOUND_TASK_DEFINITION_STORED_AND_READ_BACK"
    assert result["evaluator_status"] == "NOT_RUN"
    assert result["semantic_status"] == "UNKNOWN"
    assert result["task_capabilities"] == ["function_calling", "structured_function_arguments"]


def test_fresh_process_recovers_engine_receipt(tmp_path):
    source = _bfcl_source(tmp_path)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    result = process_authored_unit(
        Engine(tmp_path / "context"), family="bfcl_v4", version="V4",
        revision="b" * 40, source_path=source,
        task_id="simple_python_synthetic_001", source_sha256=digest,
        allowed_roots=[tmp_path], source_commitments={str(source.resolve()): digest},
    )
    code = (
        "import json,sys; from runtime.candidate.context_engine import Engine; "
        "from runtime.candidate.multibenchmark.core import recover; "
        "e=Engine(sys.argv[1]); x=recover(e,json.loads(sys.argv[2])); "
        "assert x['audit_verdict']=='NOT_EVALUATED' and x['evaluator_executed'] is False; "
        "print('FRESH_PROCESS_RECOVERY=PASS')"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", code, str(tmp_path / "context"),
         json.dumps(result["receipt"])],
        cwd=os.getcwd(), capture_output=True, text=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "FRESH_PROCESS_RECOVERY=PASS" in completed.stdout


def test_commitment_mismatch_fails_before_parser_or_engine_write(tmp_path):
    source = _bfcl_source(tmp_path)
    with pytest.raises(EvidenceError, match="hash differs"):
        process_authored_unit(
            Engine(tmp_path / "context"), family="bfcl_v4", version="V4",
            revision="c" * 40, source_path=source,
            task_id="simple_python_synthetic_001", source_sha256="0" * 64,
            allowed_roots=[tmp_path], source_commitments={str(source.resolve()): "0" * 64},
        )
    assert Engine(tmp_path / "context").latest() is None


def test_source_outside_allowlisted_root_is_rejected_before_engine_admission(tmp_path):
    source = _bfcl_source(tmp_path)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    engine = Engine(tmp_path / "context")
    with pytest.raises(EvidenceError, match="outside explicit roots"):
        process_authored_unit(
            engine, family="bfcl_v4", version="V4", revision="d" * 40,
            source_path=source, task_id="simple_python_synthetic_001",
            source_sha256=digest, allowed_roots=[allowed],
            source_commitments={str(source.resolve()): digest},
        )
    assert engine.latest() is None


def test_parent_traversal_source_is_rejected_before_engine_admission(tmp_path):
    source = _bfcl_source(tmp_path)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    traversed = allowed / ".." / source.name
    engine = Engine(tmp_path / "context")
    with pytest.raises(EvidenceError, match="outside explicit roots"):
        process_authored_unit(
            engine, family="bfcl_v4", version="V4", revision="f" * 40,
            source_path=traversed, task_id="simple_python_synthetic_001",
            source_sha256=digest, allowed_roots=[allowed],
            source_commitments={str(source.resolve()): digest},
        )
    assert engine.latest() is None


def test_symlink_source_is_rejected_before_engine_admission(tmp_path):
    source = _bfcl_source(tmp_path)
    link = tmp_path / "BFCL_v4_link.json"
    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable on this host: {exc}")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    engine = Engine(tmp_path / "context")
    with pytest.raises(EvidenceError, match="reparse source rejected"):
        process_authored_unit(
            engine, family="bfcl_v4", version="V4", revision="e" * 40,
            source_path=link, task_id="simple_python_synthetic_001",
            source_sha256=digest, allowed_roots=[tmp_path],
            source_commitments={str(link.resolve()): digest},
        )
    assert engine.latest() is None


def test_six_authored_family_fixtures_parse_and_persist_without_evaluation(tmp_path):
    from runtime.candidate.run_adapter_bridge import process_authored_unit

    revision = "a" * 40
    cases = []

    swe = tmp_path / "swe.json"
    swe.write_text(json.dumps([{"instance_id": "synthetic_swe_001", "repo": "org/repo",
                                "base_commit": revision, "patch": "synthetic patch bytes", "test_patch": "synthetic test patch bytes",
                                "problem_statement": "Authored synthetic task."}]), encoding="utf-8")
    cases.append(("swebench", "full", revision, swe, "synthetic_swe_001"))

    pro_dir = tmp_path / "pro" / "instance_synthetic_pro_001"
    pro_dir.mkdir(parents=True)
    pro = pro_dir / "task.toml"
    pro.write_text('schema_version = "1.0"\n[task]\nname = "swebench-pro/instance_synthetic_pro_001"\n', encoding="utf-8")
    pro_instruction = pro_dir / "instruction.md"
    pro_instruction.write_text("Authored synthetic task.\n", encoding="utf-8")
    cases.append(("swebench_pro_v2", "V2", revision, pro_instruction, "instance_synthetic_pro_001"))

    tb_dir = tmp_path / "terminal" / "synthetic-terminal"
    (tb_dir / "tests").mkdir(parents=True)
    (tb_dir / "task.toml").write_text('schema_version = "1.0"\n[task]\nname = "terminal-bench/synthetic-terminal"\nkeywords = ["synthetic"]\n[metadata]\ncategory = "synthetic"\n', encoding="utf-8")
    (tb_dir / "instruction.md").write_text("Authored synthetic task.\n", encoding="utf-8")
    (tb_dir / "tests" / "test.sh").write_text("# inert authored fixture\n", encoding="utf-8")
    (tb_dir / "tests" / "test_fixture.py").write_text("# inert authored fixture\n", encoding="utf-8")
    cases.append(("terminal_bench_2", "2.0", revision, tb_dir / "task.toml", "synthetic-terminal"))

    mcp_dir = tmp_path / "mcp" / "tasks" / "synthetic" / "standard" / "synthetic-category" / "synthetic-task"
    mcp_dir.mkdir(parents=True)
    (mcp_dir / "meta.json").write_text(json.dumps({"task_id": "synthetic-task", "category_id": "synthetic-category",
                                                      "mcp": ["synthetic"], "tags": ["authored"]}), encoding="utf-8")
    (mcp_dir / "description.md").write_text("Authored synthetic task.\n", encoding="utf-8")
    (mcp_dir / "verify.py").write_text("# inert authored fixture\n", encoding="utf-8")
    cases.append(("mcpmark_verified", "Verified@" + revision[:12], revision,
                  mcp_dir / "meta.json", "synthetic/standard/synthetic-category/synthetic-task"))

    bfcl = tmp_path / "BFCL_v4_simple_python.json"
    bfcl.write_text(json.dumps([{"id": "simple_python_synthetic_002", "question": [[{"role": "user", "content": "synthetic"}]],
                                "function": []}]), encoding="utf-8")
    cases.append(("bfcl_v4", "V4", revision, bfcl, "simple_python_synthetic_002"))

    tau = tmp_path / "tau" / "retail" / "tasks.json"
    tau.parent.mkdir(parents=True)
    tau.write_text(json.dumps([{"id": "synthetic_001", "user_scenario": {"instructions": {
        "domain": "retail", "reason_for_call": "Authored synthetic task."}}, "evaluation_criteria": {"actions": []}}]), encoding="utf-8")
    cases.append(("tau_bench", "2.0.0:text-v1", revision, tau, "tau2:retail:synthetic_001"))

    def commitments_for(root):
        return {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in root.rglob("*") if path.is_file()}

    for index, (family, version, source_revision, source, task_id) in enumerate(cases):
        commitments = commitments_for(tmp_path)
        digest = commitments[str(source.resolve())]
        result = process_authored_unit(
            Engine(tmp_path / f"context-{index}"), family=family, version=version,
            revision=source_revision, source_path=source, task_id=task_id,
            source_sha256=digest, allowed_roots=[tmp_path], source_commitments=commitments,
        )
        assert result["processing_status"] == "SOURCE_BOUND_TASK_DEFINITION_STORED_AND_READ_BACK"
        assert result["evaluator_status"] == "NOT_RUN"
        assert result["semantic_status"] == "UNKNOWN"
