"""Synthetic RUN006 rights gates and row adapter regressions."""
from copy import deepcopy
import pytest

from runtime.candidate.run_framework.core import FrameworkError, canonical, digest
from runtime.candidate.run_framework.run006 import (
    RUN006_ASSESSMENT_SCHEMA, RUN006_CONFIG_SCHEMA, RUN006_SELECTION_SCHEMA,
    assess_processing_rights, bfcl_row_adapter, dispatch, validate_dispatch_config,
)


def _dispatch_inputs(enabled, status="RIGHTS_UNRESOLVED"):
    selection, evidence = _rights_fixture()
    for grant in evidence["source_operations"]:
        grant["processing_status"] = status
    assessment = assess_processing_rights(selection, evidence)
    config = {"schema": RUN006_CONFIG_SCHEMA, "enabled": enabled,
              "selection_sha256": digest(canonical(selection)),
              "rights_assessment_sha256": digest(canonical(assessment))}
    return config, selection, assessment


def _rights_fixture():
    selection = {"schema": RUN006_SELECTION_SCHEMA, "selection_id": "synthetic-selection",
                 "items": [{"selection_id": "synthetic-row", "output_id": "synthetic-output",
                            "task_id": "synthetic-task", "sources": []}]}
    evidence_ref = {"path": "rights-evidence.json", "sha256": "a" * 64}
    snapshot_ref = {"path": "snapshot-receipt.json", "sha256": "b" * 64}
    sources, grants = [], []
    for role in ("task", "response"):
        source = {"role": role, "path": "snapshot/" + role + ".row",
                  "row_sha256": ("c" if role == "task" else "d") * 64,
                  "operation": "LOCAL_STRUCTURAL_PROCESSING", "purpose": "SYNTHETIC_AUDIT",
                  "repository": "example/repo", "commit": "e" * 40,
                  "repo_path": "results/" + role + ".jsonl", "source_blob_sha1": "f" * 40}
        sources.append(source)
        grant = {"selection_id": "synthetic-row", "output_id": "synthetic-output",
                 "task_id": "synthetic-task", **{key: source[key] for key in (
                     "role", "repository", "commit", "repo_path", "source_blob_sha1", "path",
                     "row_sha256", "operation", "purpose")},
                 "sha256": source["row_sha256"], "grant_id": "grant-" + role,
                 "processing_status": "PROCESSING_PERMITTED", "redistribution_status": "UNRESOLVED",
                 "evidence_references": [evidence_ref, snapshot_ref]}
        scope = {"selection_id": grant["selection_id"], "output_id": grant["output_id"],
                 "task_id": grant["task_id"], "role": grant["role"],
                 "repository": grant["repository"], "commit": grant["commit"],
                 "repo_path": grant["repo_path"], "source_blob_sha1": grant["source_blob_sha1"],
                 "path": grant["path"], "sha256": grant["sha256"], "operation": grant["operation"],
                 "purpose": grant["purpose"], "evidence_references": grant["evidence_references"]}
        grant["operation_scope_sha256"] = digest(canonical(scope))
        grants.append(grant)
    selection["items"][0]["sources"] = sources
    evidence = {"schema": "pgop1.run006.source-rights.v1", "source_operations": grants,
                "evidence_references": [evidence_ref, snapshot_ref], "excluded_output_ids": ["reserved-output"]}
    return selection, evidence


def test_rights_resolver_binds_repo_commit_path_operation_and_exclusions():
    selection, evidence = _rights_fixture()
    result = assess_processing_rights(selection, evidence)
    assert result["status"] == "PROCESSING_PERMITTED"
    assert result["rights_granted_by_runner"] is False
    assert len({row["operation_scope_sha256"] for row in result["sources"]}) == 2
    changed = deepcopy(selection)
    changed["items"][0]["sources"][0]["repo_path"] = "different/path.jsonl"
    with pytest.raises(FrameworkError, match="UNSELECTED_RIGHTS_GRANT"):
        assess_processing_rights(changed, evidence)


def test_rights_resolver_does_not_admit_excluded_output_by_family_name():
    selection, evidence = _rights_fixture()
    selection["items"][0]["output_id"] = "reserved-output"
    selection["items"][0]["sources"][0]["role"] = "task"
    with pytest.raises(FrameworkError, match="SELECTED_OUTPUT_EXCLUDED"):
        assess_processing_rights(selection, evidence)


def test_disabled_dispatch_fails_before_runner_or_any_body_read(tmp_path, monkeypatch):
    config, selection, assessment = _dispatch_inputs(False)
    called = []
    monkeypatch.setattr("pathlib.Path.read_bytes", lambda *_: pytest.fail("disabled gate read a body"))
    with pytest.raises(FrameworkError, match="EXECUTION_DISABLED"):
        dispatch(config, selection, assessment, object(), runner=lambda *args, **kwargs: called.append(True))
    assert called == []


def test_enabled_without_scoped_rights_fails_before_runner():
    config, selection, assessment = _dispatch_inputs(True)
    called = []
    with pytest.raises(FrameworkError, match="PROCESSING_RIGHTS_NOT_GRANTED"):
        dispatch(config, selection, assessment, object(), runner=lambda *args, **kwargs: called.append(True))
    assert called == []


def test_enabled_rights_metadata_still_requires_owner_launch_and_freeze():
    config, selection, assessment = _dispatch_inputs(True, "PROCESSING_PERMITTED")
    assessment["sources"][0]["processing_status"] = "PROCESSING_PERMITTED"
    config["rights_assessment_sha256"] = digest(canonical(assessment))
    with pytest.raises(FrameworkError, match="OWNER_LAUNCH_AUTHORIZATION_REQUIRED"):
        dispatch(config, selection, assessment, object(), runner=lambda *args, **kwargs: pytest.fail("runner called"))


def test_owner_authorized_frozen_config_passes_only_the_pre_dispatch_gate():
    selection, evidence = _rights_fixture()
    assessment = assess_processing_rights(selection, evidence)
    selection_sha = digest(canonical(selection))
    rights_sha = digest(canonical(assessment))
    authorization = {"schema": "pgop1.run006.launch-authorization.v1", "status": "OWNER_AUTHORIZED",
                     "selection_sha256": selection_sha, "rights_assessment_sha256": rights_sha,
                     "campaign_attempt_id": "RUN006-ATTEMPT-SYNTHETIC"}
    authorization_sha = digest(canonical(authorization))
    freeze = {"schema": "pgop1.run006.execution-freeze.v1", "status": "FROZEN",
              "campaign_attempt_id": authorization["campaign_attempt_id"],
              "selection_sha256": selection_sha, "rights_assessment_sha256": rights_sha,
              "launch_authorization_sha256": authorization_sha,
              "fresh_attempt": True, "reuse_prior_attempt": False}
    runner_config_sha = "d" * 64
    freeze["runner_config_sha256"] = runner_config_sha
    freeze["candidate_commit"] = "1" * 40
    freeze["candidate_tree"] = "2" * 40
    config = {"schema": RUN006_CONFIG_SCHEMA, "enabled": True,
              "selection_sha256": selection_sha, "rights_assessment_sha256": rights_sha,
              "launch_authorization_sha256": authorization_sha,
              "runner_config_sha256": runner_config_sha,
              "candidate_commit": "1" * 40, "candidate_tree": "2" * 40,
              "execution_freeze_sha256": digest(canonical(freeze))}
    gate = validate_dispatch_config(config, selection, assessment, authorization, freeze)
    assert gate["rights_granted_by_runner"] is False
    assert gate["selected_sources"] == 2


def test_row_adapter_checks_two_exact_snapshot_hashes_and_matching_ids(tmp_path):
    task = {"id": "simple_python_900001", "function": [{"name": "f", "parameters": {
        "type": "dict", "properties": {"x": {"type": "integer"}}, "required": ["x"]}}]}
    response = {"id": task["id"], "result": [{"f": {"x": 3}}]}
    task_path, response_path = tmp_path / "task.jsonlrow", tmp_path / "response.jsonlrow"
    task_bytes, response_bytes = canonical(task), canonical(response)
    task_path.write_bytes(task_bytes)
    response_path.write_bytes(response_bytes)
    task_ref = {"path": str(task_path), "sha256": digest(task_bytes)}
    response_ref = {"path": str(response_path), "sha256": digest(response_bytes)}
    unit = {"predicate_profile": "BFCL_ARCHIVED_ROW_PAIR_V1", "task_id": task["id"],
            "predicate_input": {"task": task_ref, "response": response_ref}}
    references = {"all": [task_ref, response_ref]}
    audited = bfcl_row_adapter(unit, references, roots=[tmp_path])
    assert audited["status"] == "STRUCTURAL_PASS"
    assert audited["task_id"] == task["id"]

    other_response = {**response, "id": "simple_python_synthetic_2"}
    response_path.write_bytes(canonical(other_response))
    with pytest.raises(FrameworkError, match="byte hash mismatch"):
        bfcl_row_adapter(unit, references, roots=[tmp_path])


def test_row_adapter_rejects_unbound_or_mismatched_source_before_audit(tmp_path, monkeypatch):
    task_ref = {"path": str(tmp_path / "task.jsonlrow"), "sha256": "a" * 64}
    response_ref = {"path": str(tmp_path / "response.jsonlrow"), "sha256": "b" * 64}
    unit = {"predicate_profile": "BFCL_ARCHIVED_ROW_PAIR_V1", "task_id": "simple_python_synthetic_1",
            "predicate_input": {"task": task_ref, "response": response_ref}}
    monkeypatch.setattr("pathlib.Path.read_bytes", lambda *_: pytest.fail("unbound row was read"))
    with pytest.raises(FrameworkError, match="ROW_PAIR_NOT_IN_SOURCE_BINDINGS"):
        bfcl_row_adapter(unit, {"all": [task_ref]}, roots=[tmp_path])


def test_direct_run005_entrypoint_cannot_dispatch_run006(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from runtime.candidate.run_framework import run005

    config = tmp_path / "run006-config.json"
    config.write_bytes(canonical({"run_id": "RUN006-BFCL-FIRST20",
                                  "campaign_attempt_id": "RUN006-ATTEMPT-1"}))
    monkeypatch.setattr(run005, "load_config", lambda *a, **k: pytest.fail("campaign instantiated"))
    args = SimpleNamespace(config=config)
    with pytest.raises(FrameworkError, match="REQUIRES_DISABLED_AND_OWNER_AUTHORIZED_DISPATCH"):
        run005.run(args)


def test_row_adapter_rejects_duplicate_json_keys(tmp_path):
    task_bytes = b'{"id":"simple_python_900001","id":"simple_python_900001","function":[]}'
    response_bytes = b'{"id":"simple_python_900001","result":[]}'
    task_path, response_path = tmp_path / "task.jsonlrow", tmp_path / "response.jsonlrow"
    task_path.write_bytes(task_bytes)
    response_path.write_bytes(response_bytes)
    task_ref = {"path": str(task_path), "sha256": digest(task_bytes)}
    response_ref = {"path": str(response_path), "sha256": digest(response_bytes)}
    unit = {"predicate_profile": "BFCL_ARCHIVED_ROW_PAIR_V1", "task_id": "simple_python_900001",
            "predicate_input": {"task": task_ref, "response": response_ref}}
    with pytest.raises(FrameworkError, match="ROW_JSON_INVALID:task"):
        bfcl_row_adapter(unit, {"all": [task_ref, response_ref]}, roots=[tmp_path])


def test_synthetic_row_pair_uses_caller_engine_checkpoint_and_recovery(tmp_path):
    import json
    from types import SimpleNamespace
    from pathlib import Path
    from runtime.candidate.run_framework.core import load_config
    from runtime.candidate.run_framework.run005 import run
    from test_reusable_run_framework import fixture_config

    config_path, config = fixture_config(tmp_path)
    config["run_id"] = "RUN006-SYNTHETIC-ROW"
    config["campaign_id"] = "RUN006-SYNTHETIC"
    config["campaign_attempt_id"] = "attempt-synthetic-row"
    config["checkpoint_policy"] = {"schema": "pgop1.reusable-run-checkpoint.v2", "interval": 1,
                                   "receipt_parent_chain": True}
    task = {"id": "simple_python_900001", "function": [{"name": "f", "parameters": {
        "type": "dict", "properties": {"x": {"type": "integer"}}, "required": ["x"]}}]}
    response = {"id": task["id"], "result": [{"f": {"x": 3}}]}
    task_path, response_path = tmp_path / "task.jsonlrow", tmp_path / "response.jsonlrow"
    task_path.write_bytes(canonical(task))
    response_path.write_bytes(canonical(response))
    task_ref = {"path": str(task_path), "sha256": digest(task_path.read_bytes())}
    response_ref = {"path": str(response_path), "sha256": digest(response_path.read_bytes())}
    unit_id = "synthetic-output-1"
    predicate_path = Path(config["predicate_contracts"]["path"])
    predicate = {"contract_id": "pgop1.modality-a.predicate-applicability.v1", "version": "1.0.0"}
    predicate_path.write_bytes(canonical(predicate))
    predicate_ref = {"path": str(predicate_path), "sha256": digest(predicate_path.read_bytes())}
    config["predicate_contracts"]["sha256"] = predicate_ref["sha256"]
    unit = {"unit_id": unit_id, "task_id": task["id"], "source_id": "task-source",
            "source_path": task_ref["path"], "source_sha256": task_ref["sha256"],
            "benchmark_id": "bfcl_v4", "benchmark_version": "V4", "unit_subtype": "simple_python",
            "adapter_id": "pgop1.bfcl.archived-row-pair", "adapter_version": "1.0.0",
            "predicate_contract": {"contract_id": predicate["contract_id"], "version": predicate["version"],
                                   "sha256": predicate_ref["sha256"]},
            "predicate_profile": "BFCL_ARCHIVED_ROW_PAIR_V1",
            "predicate_input": {"task": task_ref, "response": response_ref},
            "authentic_output_references": [response_ref],
            "evidence_references": [task_ref, response_ref]}
    dataset = Path(config["dataset_manifest_path"])
    dataset.write_bytes(canonical({"units": [unit]}))
    config["dataset_manifest_path"] = str(dataset)
    config["input_manifest_sha256"] = digest(dataset.read_bytes())
    config["expected_units"] = [unit_id]
    config["resource_budget"].update(max_units_per_shard=1, max_units=1, max_bytes=8 * 1024**2,
                                     max_errors=1, max_payload_bytes=65536)
    config["benchmark_families"] = ["bfcl_v4"]
    config["adapter_registry"] = {"path": str(Path(config["adapter_registry"]["path"])),
                                  "sha256": "0" * 64}
    registry = Path(config["adapter_registry"]["path"])
    registry.write_bytes(canonical({"families": {"bfcl_v4": {"adapter_id": unit["adapter_id"],
        "adapter_version": unit["adapter_version"], "versions": ["V4"]}}}))
    config["adapter_registry"]["sha256"] = digest(registry.read_bytes())
    contract_path = Path(config["contract_path"])
    contract_path.write_bytes(canonical({"producers": {"PGOP1-RUN006-E1": {"identity_status": "DECLARED"}}}))
    config["contract_sha256"] = digest(contract_path.read_bytes())
    exclusion_path = Path(config["exclusion_ledger"]["path"])
    exclusion_path.write_bytes(canonical({"excluded": []}))
    config["exclusion_ledger"]["sha256"] = digest(exclusion_path.read_bytes())
    source_path, dependency_path = tmp_path / "sources.json", tmp_path / "dependencies.json"
    source_manifest = {"schema": "pgop1.source-manifest.v1", "sources": [
        {"source_id": "task-source", **task_ref, "role": "PRIMARY"},
        {"source_id": "response-source", **response_ref, "role": "SUPPORTING"}]}
    source_path.write_bytes(canonical(source_manifest))
    dependency_manifest = {"schema": "pgop1.unit-source-dependencies.v1",
        "source_manifest_sha256": digest(source_path.read_bytes()),
        "expected_units_sha256": digest(canonical([unit_id])), "groups": {},
        "units": [{"unit_id": unit_id, "primary_source_id": "task-source",
            "dependency_group_ids": [], "supporting_source_ids": ["response-source"],
            "normative_companion_ids": []}]}
    dependency_path.write_bytes(canonical(dependency_manifest))
    config["audit_policy"] = {"generic_caller": {"schema": "pgop1.generic-caller-config.v1",
        "source_manifest": {"path": str(source_path), "sha256": digest(source_path.read_bytes())},
        "dependency_manifest": {"path": str(dependency_path), "sha256": digest(dependency_path.read_bytes())},
        "predicate_validation": "pgop1.predicate-evidence.v1"}}
    admission_path = tmp_path / "admission.json"
    evidence_path = tmp_path / "rights-decision.json"
    receipt_path = tmp_path / "snapshot-receipt.json"
    evidence_path.write_bytes(canonical({"synthetic": "rights metadata fixture"}))
    receipt_path.write_bytes(canonical({"synthetic": "snapshot metadata fixture"}))
    rights_selection, rights_evidence = _rights_fixture()
    rights_selection["items"][0].update(selection_id=unit_id, output_id=unit_id, task_id=task["id"])
    rights_selection["expected_units"] = [unit_id]
    rights_evidence["evidence_references"] = [
        {"path": str(evidence_path), "sha256": digest(evidence_path.read_bytes())},
        {"path": str(receipt_path), "sha256": digest(receipt_path.read_bytes())}]
    for source in rights_selection["items"][0]["sources"]:
        source_ref = task_ref if source["role"] == "task" else response_ref
        source.update(path=source_ref["path"], row_sha256=source_ref["sha256"])
    for grant in rights_evidence["source_operations"]:
        source_ref = task_ref if grant["role"] == "task" else response_ref
        grant.update(selection_id=unit_id, output_id=unit_id, task_id=task["id"],
                     path=source_ref["path"], sha256=source_ref["sha256"],
                     evidence_references=rights_evidence["evidence_references"])
        scope = {"selection_id": grant["selection_id"], "output_id": grant["output_id"],
                 "task_id": grant["task_id"], "role": grant["role"],
                 "repository": grant["repository"], "commit": grant["commit"],
                 "repo_path": grant["repo_path"], "source_blob_sha1": grant["source_blob_sha1"],
                 "path": grant["path"], "sha256": grant["sha256"], "operation": grant["operation"],
                 "purpose": grant["purpose"], "evidence_references": grant["evidence_references"]}
        grant["operation_scope_sha256"] = digest(canonical(scope))
    assessment = assess_processing_rights(rights_selection, rights_evidence)
    selection_path = Path(config["selection_manifest"]["path"])
    selection_path.write_bytes(canonical(rights_selection) + b"\n")
    config["selection_manifest"]["sha256"] = digest(selection_path.read_bytes())
    rights_doc_path = tmp_path / "source-rights-evidence.json"
    rights_doc_path.write_bytes(canonical(rights_evidence) + b"\n")
    assessment_path = tmp_path / "source-rights-assessment.json"
    assessment_path.write_bytes(canonical(assessment) + b"\n")
    metadata_files = [dataset, registry, contract_path, selection_path, exclusion_path,
                      predicate_path, source_path, dependency_path, evidence_path, receipt_path,
                      rights_doc_path, assessment_path]
    metadata_refs = [{"path": str(p), "sha256": digest(p.read_bytes())} for p in metadata_files]
    config["input_bindings"] = [{"path": task_ref["path"], "sha256": task_ref["sha256"]},
                                {"path": response_ref["path"], "sha256": response_ref["sha256"]},
                                *metadata_refs]
    admission = {"outputs": [{"OUTPUT_ID": unit_id, "TASK_ID": task["id"],
        "OUTPUT_SHA256": response_ref["sha256"], "AUDIT_DISPOSITION": "ADMITTED_AUTHENTIC_OUTPUT",
        "processing_status": "PROCESSING_PERMITTED", "reserved": False,
        "permission_references": rights_evidence["evidence_references"]}],
        "allowed_read_references": config["input_bindings"]}
    admission_path.write_bytes(canonical(admission))
    admission_ref = {"path": str(admission_path), "sha256": digest(admission_path.read_bytes())}
    config["input_bindings"].append(admission_ref)
    config_path.write_bytes(canonical(config))
    output = tmp_path / config["run_id"] / "attempts" / config["campaign_attempt_id"]
    runner_args = SimpleNamespace(config=config_path, config_root=[tmp_path], admission=admission_path,
        output=output, trusted_root=[tmp_path], output_root=[tmp_path], action="execute")
    with pytest.raises(FrameworkError, match="REQUIRES_DISABLED_AND_OWNER_AUTHORIZED_DISPATCH"):
        run(runner_args)
    legacy_config = dict(config)
    legacy_config["run_id"] = "legacy-unrelated-run"
    legacy_config_path = tmp_path / "legacy-runner-config.json"
    legacy_config_path.write_bytes(canonical(legacy_config))
    legacy_args = SimpleNamespace(**{**vars(runner_args), "config": legacy_config_path,
        "output": tmp_path / "legacy-unrelated-run" / "attempts" / legacy_config["campaign_attempt_id"]})
    original_read_bytes = Path.read_bytes
    def reject_selected_source_reads(path):
        if str(path) in {task_ref["path"], response_ref["path"]}:
            pytest.fail("legacy row-profile guard read a selected body")
        return original_read_bytes(path)
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(Path, "read_bytes", reject_selected_source_reads)
    try:
        with pytest.raises(FrameworkError, match="ROW_PROFILE_REQUIRES_DISABLED_AND_OWNER_AUTHORIZED_DISPATCH"):
            run(legacy_args)
    finally:
        monkeypatch.undo()

    selection_sha = digest(canonical(rights_selection))
    rights_sha = digest(canonical(assessment))
    authorization = {"schema": "pgop1.run006.launch-authorization.v1", "status": "OWNER_AUTHORIZED",
        "selection_sha256": selection_sha, "rights_assessment_sha256": rights_sha,
        "campaign_attempt_id": config["campaign_attempt_id"]}
    authorization_sha = digest(canonical(authorization))
    freeze = {"schema": "pgop1.run006.execution-freeze.v1", "status": "FROZEN",
        "campaign_attempt_id": config["campaign_attempt_id"], "candidate_commit": config["candidate_commit"],
        "candidate_tree": config["candidate_tree"], "selection_sha256": selection_sha,
        "rights_assessment_sha256": rights_sha, "launch_authorization_sha256": authorization_sha,
        "runner_config_sha256": digest(config_path.read_bytes()), "fresh_attempt": True,
        "reuse_prior_attempt": False}
    outer = {"schema": RUN006_CONFIG_SCHEMA, "enabled": True, "selection_sha256": selection_sha,
        "rights_assessment_sha256": rights_sha, "launch_authorization_sha256": authorization_sha,
        "runner_config_sha256": digest(config_path.read_bytes()), "execution_freeze_sha256": digest(canonical(freeze)),
        "runner_config": {"path": str(config_path), "sha256": digest(config_path.read_bytes())},
        "selection": {"path": str(selection_path), "sha256": digest(selection_path.read_bytes())},
        "rights_evidence": {"path": str(rights_doc_path), "sha256": digest(rights_doc_path.read_bytes())},
        "rights_assessment": {"path": str(assessment_path), "sha256": digest(assessment_path.read_bytes())},
        "admission": admission_ref,
        "metadata_bindings": [*metadata_refs, admission_ref],
        "candidate_commit": config["candidate_commit"], "candidate_tree": config["candidate_tree"]}
    result = dispatch(outer, rights_selection, assessment, runner_args,
                      launch_authorization=authorization, freeze=freeze)
    result = result["runner_result"]
    assert result["state"]["complete"] is True
    assert result["state"]["completed"] == [unit_id]
    assert result["engine_events"][0]["manifest"]["version"] == 1
    recovered = load_config(config_path, [tmp_path], output, [tmp_path], [tmp_path])
    recovered.preflight()
    assert recovered.recover()["completed"] == {unit_id}

