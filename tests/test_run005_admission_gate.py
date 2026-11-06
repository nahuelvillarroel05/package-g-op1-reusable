"""Operation-rights decisions fail closed before any output body read."""
from copy import deepcopy

import pytest

from runtime.candidate.run_framework.core import FrameworkError
from runtime.candidate.run_framework.run005 import admission_gate


def inputs():
    permission = {"path": "permission.json", "sha256": "a" * 64}
    output = {"path": "output.json", "sha256": "b" * 64}
    unit = {"unit_id": "output-1", "task_id": "task-1", "predicate_profile": "BFCL_STRUCTURAL_V2",
            "source_path": output["path"], "source_sha256": output["sha256"],
            "predicate_input": {**output, "task_id": "task-1"}, "evidence_references": [output],
            "authentic_output_references": [output]}
    row = {"OUTPUT_ID": "output-1", "TASK_ID": "task-1", "OUTPUT_SHA256": output["sha256"],
           "AUDIT_DISPOSITION": "ADMITTED_AUTHENTIC_OUTPUT", "processing_status": "PROCESSING_PERMITTED",
           "reserved": False, "permission_references": [permission]}
    return {"outputs": [row], "allowed_read_references": [permission, output]}, [unit], [permission, output]


def test_exact_permission_and_output_metadata_admit_without_reading_bodies(monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("gate must not open source bodies"))
    assert admission_gate(*inputs()) == {"admitted_outputs": 1, "rights_granted_by_runner": False}


@pytest.mark.parametrize("mutation", ["no-admitted", "rights-unknown", "reserved", "missing-grant",
                                     "rebound-output", "duplicate", "wrong-task", "unsupported-profile"])
def test_refuses_unadmitted_unpermitted_or_substituted_output(mutation):
    admission, units, bindings = deepcopy(inputs())
    row = admission["outputs"][0]
    if mutation == "no-admitted": row["AUDIT_DISPOSITION"] = "RIGHTS_UNRESOLVED"
    elif mutation == "rights-unknown": row["processing_status"] = "RIGHTS_UNRESOLVED"
    elif mutation == "reserved": row["reserved"] = True
    elif mutation == "missing-grant": bindings.pop(0)
    elif mutation == "rebound-output": row["OUTPUT_SHA256"] = "c" * 64
    elif mutation == "duplicate": admission["outputs"].append(deepcopy(row))
    elif mutation == "wrong-task": row["TASK_ID"] = "other-task"
    else: units[0]["predicate_profile"] = "DEFINITION_ONLY"
    with pytest.raises(FrameworkError):
        admission_gate(admission, units, bindings)


def test_engine_result_is_real_persisted_and_recoverable_with_safe_filename(tmp_path):
    from runtime.candidate.context_engine import Engine
    from runtime.candidate.run_framework.resources import ResourceGuard
    from runtime.candidate.run_framework.run005 import record_engine_result, ENGINE_BYTES
    from runtime.candidate.run_framework.core import canonical, digest
    root = tmp_path / "engine"
    engine = Engine(root)
    unit = {"unit_id": "synthetic/output:1", "task_id": "synthetic-task-1"}
    result = {"audit_result": {"synthetic": True, "verdict": "ABSTAIN"}}
    event = record_engine_result(engine, ResourceGuard(root, max_bytes=ENGINE_BYTES), unit, result, "SYNTHETIC-DEV")
    expected = root / (digest(canonical(unit["unit_id"])) + ".json")
    assert expected.read_bytes() == canonical(result)
    fresh = Engine(root)
    assert fresh.read_source(unit["unit_id"]) == canonical(result)
    assert event["manifest"]["version"] == 1
    assert fresh.verify() is not None
    assert fresh.query(task_id=unit["task_id"])[0]["id"] == unit["unit_id"]


def test_duplicate_selected_units_are_rejected():
    admission, units, bindings = inputs()
    with pytest.raises(FrameworkError, match="MEMBERSHIP"):
        admission_gate(admission, units + deepcopy(units), bindings)


def test_ungranted_extra_preflight_input_rejected_before_read(monkeypatch):
    from pathlib import Path
    admission, units, bindings = inputs()
    bindings.append({"path": "unpermitted-body.json", "sha256": "c" * 64})
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("must reject before opening bodies"))
    with pytest.raises(FrameworkError, match="INPUT_READ_PERMISSION"):
        admission_gate(admission, units, bindings)


def test_bfcl_rebound_predicate_input_rejected_without_read(monkeypatch):
    from pathlib import Path
    admission, units, bindings = inputs()
    units[0]["predicate_input"]["path"] = "unpermitted-body.json"
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("must reject before opening bodies"))
    with pytest.raises(FrameworkError, match="ADAPTER_INPUT_NOT_BOUND"):
        admission_gate(admission, units, bindings)


def test_swe_missing_auxiliary_grant_rejected_without_read(monkeypatch, tmp_path):
    from pathlib import Path
    from runtime.candidate.swebench_claim_audit.adapter import RUN_REPO
    admission, units, bindings = inputs()
    unit = units[0]
    unit.update(predicate_profile="SWE_ARCHIVED_COMPLETION_V1", predicate_input={"data_root": str(tmp_path), "task_id": "task-1"})
    relatives = ["logs/all_preds.jsonl", "logs/trajs/task-1.traj.json",
                 *["logs/logs/task-1/" + n for n in ("report.json", "patch.diff", "test_output.txt.gz")],
                 *[(RUN_REPO / n).as_posix() for n in ("per_instance_details.json", "results/results.json", "metadata.yaml", "README.md")]]
    refs = [{"path": str((tmp_path / r).resolve()), "sha256": "d" * 64} for r in relatives]
    unit["evidence_references"].extend(refs)
    bindings.extend(refs)
    admission["allowed_read_references"].extend(refs[:-1])
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("must reject before opening bodies"))
    with pytest.raises(FrameworkError, match="INPUT_READ_PERMISSION"):
        admission_gate(admission, units, bindings)


def test_adapter_rejects_unbound_bfcl_input_before_read(monkeypatch):
    from pathlib import Path
    from runtime.candidate.run_framework.run005 import adapter
    _, units, _ = inputs()
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("must reject before opening bodies"))
    with pytest.raises(FrameworkError, match="ADAPTER_READ_PERMISSION"):
        adapter(units[0], {"all": []})


def test_ungranted_transitive_source_rejected_before_sourcebindings(monkeypatch, tmp_path):
    from pathlib import Path
    from runtime.candidate.run_framework.run005 import source_manifest_read_gate
    from runtime.candidate.run_framework.core import canonical, digest
    denied = tmp_path / "ungranted-body.json"
    denied.write_bytes(b"synthetic body must not be read")
    source = {"path": str(denied), "sha256": digest(b"synthetic body must not be read")}
    manifest = tmp_path / "sources.json"
    dependencies = tmp_path / "dependencies.json"
    manifest.write_bytes(canonical({"sources": [source]}))
    dependencies.write_bytes(canonical({"units": []}))
    refs = [{"path": str(p), "sha256": digest(p.read_bytes())} for p in (manifest, dependencies)]
    allowed = {"allowed_read_references": refs}
    original = Path.open

    def guarded(path, *args, **kwargs):
        if path == denied:
            pytest.fail("transitive source must be rejected before body open")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    with pytest.raises(FrameworkError, match="TRANSITIVE_SOURCE_READ_PERMISSION"):
        source_manifest_read_gate(allowed, refs, {"source_manifest": refs[0], "dependency_manifest": refs[1]}, [tmp_path])


def test_source_manifest_metadata_requires_explicit_read_permission(monkeypatch):
    from pathlib import Path
    from runtime.candidate.run_framework.run005 import source_manifest_read_gate
    monkeypatch.setattr(Path, "open", lambda *a, **k: pytest.fail("metadata grant must precede open"))
    with pytest.raises(FrameworkError, match="SOURCE_METADATA_READ_PERMISSION"):
        source_manifest_read_gate({"allowed_read_references": []}, [],
                                  {"source_manifest": {"path": "metadata", "sha256": "a" * 64}}, [])
