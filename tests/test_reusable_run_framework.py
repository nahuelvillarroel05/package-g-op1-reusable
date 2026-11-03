import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from runtime.candidate.run_framework import FrameworkError, load_config


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_config(tmp_path, run_id="run-001", attempt_id="attempt-001"):
    code_root=tmp_path/"candidate"
    code_root.mkdir()
    subprocess.run(["git","init","-q",str(code_root)],check=True,capture_output=True)
    subprocess.run(["git","-c",f"safe.directory={code_root}","-C",str(code_root),"config","user.name","Framework Test"],check=True,capture_output=True)
    subprocess.run(["git","-c",f"safe.directory={code_root}","-C",str(code_root),"config","user.email","framework@example.invalid"],check=True,capture_output=True)
    files = {}
    for name, data in {
        "contract.json": b'{"contract":"v1"}', "dataset.json": b'{"units":["u1","u2"]}',
        "adapter.json": b'{"adapter":"test"}', "predicates.json": b'{"predicates":[]}',
        "selection.json": b'{"expected_units":["u1","u2"]}', "exclusions.json": b'{"excluded":[]}',
        "code.py": b"VALUE = 1\n", "input.json": b'{"input":1}',
    }.items():
        p = code_root / name if name=="code.py" else tmp_path / name
        p.write_bytes(data)
        files[name] = p
    subprocess.run(["git","-c",f"safe.directory={code_root}","-C",str(code_root),"add","code.py"],check=True,capture_output=True)
    subprocess.run(["git","-c",f"safe.directory={code_root}","-C",str(code_root),"commit","-qm","candidate fixture"],check=True,capture_output=True)
    commit = subprocess.run(["git","-c",f"safe.directory={code_root}","-C",str(code_root),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
    tree = subprocess.run(["git","-c",f"safe.directory={code_root}","-C",str(code_root),"rev-parse","HEAD^{tree}"],check=True,capture_output=True,text=True).stdout.strip()
    config = {
        "schema": "pgop1.experimental.run-execution.v1", "campaign_id": "campaign-001", "run_id": run_id,
        "campaign_attempt_id": attempt_id,
        "contract_version": "rev001", "run_purpose": "bounded framework regression", "candidate_commit": commit,
        "candidate_tree": tree, "code_root": str(code_root),
        "code_files": [{"path": str(files["code.py"]), "sha256": sha(files["code.py"])}],
        "contract_path": str(files["contract.json"]), "contract_sha256": sha(files["contract.json"]),
        "dataset_manifest_path": str(files["dataset.json"]), "input_manifest_sha256": sha(files["dataset.json"]),
        "input_bindings": [{"path": str(files["input.json"]), "sha256": sha(files["input.json"])}],
        "benchmark_families": ["synthetic"], "adapter_registry": {"path": str(files["adapter.json"]), "sha256": sha(files["adapter.json"])},
        "predicate_contracts": {"path": str(files["predicates.json"]), "sha256": sha(files["predicates.json"])},
        "execution_modes": ["offline"], "selection_manifest": {"path": str(files["selection.json"]), "sha256": sha(files["selection.json"])},
        "exclusion_ledger": {"path": str(files["exclusions.json"]), "sha256": sha(files["exclusions.json"])},
        "resource_budget": {"max_units_per_shard": 2}, "stop_criteria": {"on_error": "stop"},
        "checkpoint_policy": {"interval": 1}, "recovery_policy": {"mode": "READ_ONLY_NO_RESUME"}, "audit_policy": {"required": True},
        "allowlisted_roots": [str(tmp_path)], "expected_units": ["u1", "u2"],
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    return config_path, config


def campaign(tmp_path, output=None):
    path = tmp_path / "config.json"
    if not path.exists(): fixture_config(tmp_path)
    obj = load_config(path, [tmp_path], output or tmp_path / "run-001" / "attempts" / "attempt-001", [tmp_path], [tmp_path])
    obj.preflight()
    return obj


def test_start_terminal_receipts_checkpoint_and_new_object_read_recovery(tmp_path):
    c = campaign(tmp_path)
    c.begin_unit("u1", {"started": True})
    c.complete_unit("u1", "DISPOSITION_RECORDED", {"result_sha256": "a" * 64})
    c2 = campaign(tmp_path)
    state = c2.recover()
    assert state["completed"] == {"u1"}
    assert state["pending"] == {"u2"}
    assert c2.report()["status"] == "PARTIAL"
    assert c2.report()["execution_completeness"] == "NOT_CERTIFIED"


def test_subprocess_cli_recovers_immutable_attempt_state(tmp_path):
    c = campaign(tmp_path)
    c.begin_unit("u1", {"started": True})
    command = ["python", "-B", "-m", "runtime.candidate.run_framework", "recover",
               "--config", str(tmp_path / "config.json"), "--config-root", str(tmp_path),
               "--trusted-root", str(tmp_path),
               "--output-root", str(tmp_path), "--output", str(c.output)]
    result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], check=True, capture_output=True, text=True, timeout=30)
    recovered = json.loads(result.stdout)
    assert recovered["inflight"] == ["u1"]
    assert recovered["pending"] == ["u2"]


def test_precreated_competing_writer_and_fresh_attempt_namespace(tmp_path):
    first=campaign(tmp_path)
    second=campaign(tmp_path)
    first.begin_unit("u1",{"started":True})
    with pytest.raises(FrameworkError):
        second.complete_unit("u1","DONE",{})
    config_path=tmp_path/"config.json"
    config=json.loads(config_path.read_text(encoding="utf-8"))
    config["campaign_attempt_id"]="attempt-002"
    second_path=tmp_path/"config-attempt-002.json"
    second_path.write_text(json.dumps(config,sort_keys=True,separators=(",",":")),encoding="utf-8")
    second=load_config(second_path,[tmp_path],tmp_path/"run-001"/"attempts"/"attempt-002",[tmp_path],[tmp_path])
    second.preflight()
    second.begin_unit("u1",{"started":True})
    second.complete_unit("u1","DONE",{})
    config["campaign_attempt_id"]="attempt-003"
    config["campaign_id"]="other-campaign"
    third_path=tmp_path/"config-attempt-003.json"
    third_path.write_text(json.dumps(config,sort_keys=True,separators=(",",":")),encoding="utf-8")
    third=load_config(third_path,[tmp_path],tmp_path/"run-001"/"attempts"/"attempt-003",[tmp_path],[tmp_path])
    third.preflight()
    with pytest.raises(FrameworkError,match="RUN_ID is already bound"):
        third.begin_unit("u2",{"started":True})


def test_bound_code_change_after_preflight_quarantines_attempt(tmp_path):
    c=campaign(tmp_path)
    code=Path(c.config["code_files"][0]["path"])
    original=code.read_bytes()
    code.write_bytes(original+b"# changed\n")
    try:
        with pytest.raises(FrameworkError):
            c.begin_unit("u1",{"started":True})
        code.write_bytes(original)
        with pytest.raises(FrameworkError,match="read-only"):
            c.begin_unit("u1",{"started":True})
    finally:
        code.write_bytes(original)


def test_shard_plan_reconciles_full_population_and_policy(tmp_path):
    c=campaign(tmp_path)
    plan=c.shard_plan()
    assert plan["EXPECTED_UNITS"]==2
    assert len(plan["shards"])==1


def test_dotted_run_and_attempt_ids_have_collision_free_registry_names(tmp_path):
    left=tmp_path/"left"; right=tmp_path/"right"
    left.mkdir(); right.mkdir()
    left_config,_=fixture_config(left,run_id="a.b",attempt_id="c")
    right_config,_=fixture_config(right,run_id="a",attempt_id="b.c")
    a=load_config(left_config,[left],tmp_path/"a.b"/"attempts"/"c",[tmp_path],[tmp_path])
    b=load_config(right_config,[right],tmp_path/"a"/"attempts"/"b.c",[tmp_path],[tmp_path])
    a.preflight(); b.preflight()
    a.begin_unit("u1",{"started":True})
    b.begin_unit("u1",{"started":True})
    assert (tmp_path/".pgop1-attempt-registry"/(hashlib.sha256(json.dumps(["a.b","c"],separators=(",",":"),ensure_ascii=False).encode()).hexdigest()+".json")).is_file()
    assert (tmp_path/".pgop1-attempt-registry"/(hashlib.sha256(json.dumps(["a","b.c"],separators=(",",":"),ensure_ascii=False).encode()).hexdigest()+".json")).is_file()


def test_in_memory_config_policy_mutation_is_rejected(tmp_path):
    c=campaign(tmp_path)
    c.config["resource_budget"]["max_units_per_shard"]=999
    with pytest.raises(FrameworkError,match="in-memory external configuration changed"):
        c.shard_plan()


def test_duplicate_and_omitted_units_never_report_complete(tmp_path):
    c = campaign(tmp_path)
    c.begin_unit("u1", {"started": True})
    with pytest.raises(FrameworkError):
        c.begin_unit("u1", {"started": True})
    c.complete_unit("u1", "DONE", {})
    assert c.report()["status"] == "PARTIAL"
    assert c.report()["pending_units"] == ["u2"]


def test_fresh_process_recovery_is_read_only_no_resume(tmp_path):
    c = campaign(tmp_path)
    c.begin_unit("u1", {"started": True})
    recovered = campaign(tmp_path)
    assert recovered.recover()["inflight"] == {"u1"}
    with pytest.raises(FrameworkError, match="read-only"):
        recovered.complete_unit("u1", "DONE", {})


def test_byte_tampering_and_truncated_index_fail_closed(tmp_path):
    c = campaign(tmp_path)
    c.begin_unit("u1", {"started": True})
    receipt = next((c.output / "receipts").glob("*.json"))
    receipt.write_bytes(receipt.read_bytes() + b" ")
    with pytest.raises(FrameworkError):
        c.recover()


def test_orphan_publication_blocks_instead_of_resuming(tmp_path):
    c = campaign(tmp_path)
    c.output.mkdir(parents=True)
    (c.output / "receipts").mkdir()
    (c.output / "receipts" / "orphan.json").write_bytes(b"{}")
    with pytest.raises(FrameworkError):
        c.recover()


def test_strict_config_duplicate_keys_rejected(tmp_path):
    path, _ = fixture_config(tmp_path)
    path.write_bytes(b'{"schema":"x","schema":"y"}')
    with pytest.raises(FrameworkError):
        load_config(path, [tmp_path], tmp_path / "out", [tmp_path], [tmp_path])


