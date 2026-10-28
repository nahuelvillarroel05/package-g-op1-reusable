"""Synthetic-first regressions for the additive generalized SWE-bench adapter."""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import (
    PARSER_VERSIONS,
    audit_evidence,
    audit_file,
)

RUN = "run-dev-001"
INSTANCE = "sharkdp__bat-562"
TRAJECTORY_PARSER = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT_PARSER = "pgop1.swebench.evaluator_report.resolved_map_json.v1"
SUMMARY_PARSER = "pgop1.swebench.results.resolved_list_json.v1"
CATALOG_PARSER = "pgop1.swebench.catalog.per_instance_details_json.v1"


def _write(root: Path, path: str, data: bytes, role: str, parser_id: str) -> dict[str, object]:
    target = root / Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "role": role, "parser_id": parser_id}


def _json_file(root: Path, path: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    return _write(root, path, json.dumps(value, separators=(",", ":")).encode(), role, parser_id)


def _trajectory(root: Path, text: str = "I have resolved the task.") -> dict[str, object]:
    return _json_file(root, "logs/trajs/" + INSTANCE + ".traj.json", {
        "instance_id": INSTANCE, "messages": [{"role": "assistant", "content": text}],
    }, "AGENT_TRAJECTORY", TRAJECTORY_PARSER)


def _report(root: Path, resolved: bool = True) -> dict[str, object]:
    return _json_file(root, "logs/logs/" + INSTANCE + "/report.json",
                      {INSTANCE: {"resolved": resolved}}, "EVALUATOR_REPORT", REPORT_PARSER)


def _request(*descriptors: dict[str, object], instance_id: str = INSTANCE) -> dict[str, object]:
    return {"run_id": RUN, "instance_id": instance_id, "evidence": list(descriptors)}


def test_resolution_claim_is_compared_to_instance_and_run_bound_report(tmp_path: Path) -> None:
    descriptors = [_trajectory(tmp_path), _report(tmp_path, True)]
    result = audit_evidence(tmp_path, _request(*descriptors))
    assert result["schema"] == "pgop1.swebench.generalized-audit.v1"
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["AGENT_STATEMENT"][0]["predicate"] == "TASK_RESOLVED"
    assert result["EVALUATOR_RESULT"][0]["observed_value"] is True
    assert result["relationships"][0]["from"] == result["AGENT_STATEMENT"][0]["claim_id"]
    assert result["relationships"][0]["evidence_bindings"][0]["sha256"] == descriptors[0]["sha256"]
    assert {ref["role"] for ref in result["SOURCE_PROVENANCE"]["evidence_references"]} == {
        "AGENT_TRAJECTORY", "EVALUATOR_REPORT"}


def test_completion_claim_is_not_a_benchmark_resolution_claim(tmp_path: Path) -> None:
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path, "I completed the task."), _report(tmp_path)))
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"][0]["predicate"] == "TASK_COMPLETED"
    assert result["AGENT_STATEMENT"][0]["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["relationships"] == []


def test_resolution_claim_contradicted_by_explicit_false_report(tmp_path: Path) -> None:
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path), _report(tmp_path, False)))
    assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    assert result["AGENT_STATEMENT"][0]["AUDIT_VERDICT"] == "CONTRADICTED"


def test_local_bug_fix_does_not_claim_the_benchmark_task_was_resolved(tmp_path: Path) -> None:
    result = audit_evidence(
        tmp_path,
        _request(_trajectory(tmp_path, "I fixed the bug in the logging helper."), _report(tmp_path, True)),
    )
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"][0]["predicate"] == "ISSUE_RESOLVED"


@pytest.mark.parametrize("later", [
    "The original task remains unresolved.",
    "Correction: the issue remains unresolved.",
])
def test_later_opposite_assistant_assertion_supersedes_earlier_positive(tmp_path: Path, later: str) -> None:
    trajectory = _json_file(tmp_path, "logs/trajs/" + INSTANCE + ".traj.json", {
        "instance_id": INSTANCE,
        "messages": [
            {"role": "assistant", "content": "I have resolved the task."},
            {"role": "assistant", "content": later},
        ],
    }, "AGENT_TRAJECTORY", TRAJECTORY_PARSER)
    result = audit_evidence(tmp_path, _request(trajectory, _report(tmp_path, False)))
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    earlier = next(claim for claim in result["AGENT_STATEMENT"]
                   if claim["predicate"] == "TASK_RESOLVED" and claim["asserted_value"] is True)
    assert earlier["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert earlier["reason_codes"] == ["SUPERSEDED_BY_LATER_OPPOSITE_ASSERTION"]


def test_explicit_negative_task_assertion_can_match_unresolved_evaluator(tmp_path: Path) -> None:
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path, "The original task remains unresolved."),
                                               _report(tmp_path, False)))
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    claim = result["AGENT_STATEMENT"][0]
    assert claim["predicate"] == "TASK_RESOLVED"
    assert claim["asserted_value"] is False


def test_scoped_fix_then_unresolved_original_task_never_supports_task_resolution(tmp_path: Path) -> None:
    result = audit_evidence(
        tmp_path,
        _request(_trajectory(tmp_path, "I fixed the bug in the logging helper. "
                                      "The original task remains unresolved."),
                 _report(tmp_path, False)),
    )
    assert result["AUDIT_VERDICT"] != "SUPPORTED"
    assert all(not (claim["predicate"] == "TASK_RESOLVED" and claim["asserted_value"] is True
                    and claim.get("AUDIT_VERDICT") == "SUPPORTED")
               for claim in result["AGENT_STATEMENT"])


@pytest.mark.parametrize("text", [
    "I have not resolved the issue.",
    "I think I resolved the issue.",
    "I never claimed that I resolved the task.",
    "I didn't say that I resolved the task.",
    'The claim was: "I resolved the issue."',
    "The agent said: I resolved the issue.",
    "I resolved the issue is a false statement.",
    "I resolved the issue. I was wrong; it remains broken.",
    "> Quoted claim\nI resolved the issue.",
    "“I resolved the issue.”",
    "> I resolved the issue.",
    "\x60\x60\x60text\nI resolved the issue.\n\x60\x60\x60",
    "I resolved the issue, but I may be wrong.",
])
def test_nonassertive_or_quoted_language_does_not_create_a_claim(tmp_path: Path, text: str) -> None:
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path, text), _report(tmp_path)))
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] == []
    assert "NO_ATTRIBUTABLE_CLAIM" in result["reason_codes"]


@pytest.mark.parametrize("text", [
    "I resolved the task description formatting.",
    "I resolved the task's logging subproblem.",
])
def test_task_subproblem_phrase_is_not_a_whole_task_claim(tmp_path: Path, text: str) -> None:
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path, text), _report(tmp_path, True)))
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] == []


def test_summary_absence_is_unknown_not_an_unresolved_result(tmp_path: Path) -> None:
    summary = _json_file(tmp_path, "results.json", {"resolved": []}, "EVALUATOR_SUMMARY", SUMMARY_PARSER)
    parsed = audit_file(tmp_path, {**summary, "run_id": RUN, "instance_id": INSTANCE})
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path), summary))
    assert parsed["status"] == "SUPPORTED"
    assert parsed["observations"] == []
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["EVALUATOR_RESULT"] == []


def test_summary_positive_membership_is_an_explicit_true_observation(tmp_path: Path) -> None:
    summary = _json_file(tmp_path, "results.json", {"resolved": [INSTANCE]},
                         "EVALUATOR_SUMMARY", SUMMARY_PARSER)
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path), summary))
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["EVALUATOR_RESULT"][0]["observed_value"] is True
    assert result["EVALUATOR_RESULT"][0]["attribution"] == "EXPLICIT_EVALUATOR_RESOLVED_MEMBERSHIP"


def test_catalog_false_is_explicit_but_malformed_catalog_value_is_not_false(tmp_path: Path) -> None:
    false_catalog = _json_file(tmp_path, "catalog.json", {INSTANCE: {"resolved": False}},
                               "EVALUATOR_CATALOG", CATALOG_PARSER)
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path), false_catalog))
    assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    other = tmp_path / "other"
    malformed = _json_file(other, "catalog.json", {INSTANCE: {"resolved": "false"}},
                           "EVALUATOR_CATALOG", CATALOG_PARSER)
    parsed = audit_file(other, {**malformed, "run_id": RUN, "instance_id": INSTANCE})
    assert parsed["status"] == "ERROR"
    assert parsed["reason_codes"] == ["MALFORMED_EVALUATOR_CATALOG"]
    assert parsed["observations"] == []


def test_conflicting_evaluator_observations_fail_as_integrity_error(tmp_path: Path) -> None:
    report = _report(tmp_path, True)
    catalog = _json_file(tmp_path, "catalog.json", {INSTANCE: {"resolved": False}},
                         "EVALUATOR_CATALOG", CATALOG_PARSER)
    result = audit_evidence(tmp_path, _request(_trajectory(tmp_path), report, catalog))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert "EVALUATOR_RECORD_CONFLICT" in result["reason_codes"]
    assert all(claim["AUDIT_VERDICT"] == "INTEGRITY_FAILURE" for claim in result["AGENT_STATEMENT"])


def test_content_instance_mismatch_fails_closed(tmp_path: Path) -> None:
    wrong = _json_file(tmp_path, "logs/trajs/" + INSTANCE + ".traj.json", {
        "instance_id": "another__repo-3",
        "messages": [{"role": "assistant", "content": "I resolved the issue."}],
    }, "AGENT_TRAJECTORY", TRAJECTORY_PARSER)
    result = audit_evidence(tmp_path, _request(wrong, _report(tmp_path)))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["WRONG_INSTANCE_BINDING"]


def test_descriptor_scope_conflict_fails_closed(tmp_path: Path) -> None:
    report = {**_report(tmp_path), "instance_id": "another__repo-3"}
    result = audit_evidence(tmp_path, _request(report))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["WRONG_INSTANCE_BINDING"]


def test_duplicate_json_keys_and_hash_mismatch_are_rejected(tmp_path: Path) -> None:
    raw = ('{"' + INSTANCE + '":{"resolved":true,"resolved":false}}').encode()
    descriptor = _write(tmp_path, "report.json", raw, "EVALUATOR_REPORT", REPORT_PARSER)
    result = audit_evidence(tmp_path, _request(descriptor))
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["reason_codes"] == ["DUPLICATE_JSON_KEY"]
    result = audit_evidence(tmp_path, _request({**descriptor, "sha256": "0" * 64}))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["SOURCE_HASH_MISMATCH"]


def test_prediction_duplicates_are_rejected_and_prediction_is_not_success(tmp_path: Path) -> None:
    row = {"instance_id": INSTANCE, "model_patch": "diff --git a/x b/x\n"}
    raw = (json.dumps(row) + "\n" + json.dumps(row) + "\n").encode()
    prediction = _write(tmp_path, "predictions.jsonl", raw, "PREDICTION",
                        "pgop1.swebench.prediction.miniswe_jsonl.v1")
    result = audit_evidence(tmp_path, _request(prediction))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["DUPLICATE_INSTANCE_ID"]
    other = tmp_path / "prediction-only"
    prediction = _write(other, "predictions.jsonl", (json.dumps(row) + "\n").encode(), "PREDICTION",
                        "pgop1.swebench.prediction.miniswe_jsonl.v1")
    result = audit_evidence(other, _request(prediction))
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] == []


def test_unattributed_logs_and_patch_never_create_claims_or_iid_binding(tmp_path: Path) -> None:
    log = _write(tmp_path, "run.log", b"Assistant: I resolved the issue.\n", "EXECUTION_LOG",
                 "pgop1.swebench.log.text_unattributed.v1")
    patch = _write(tmp_path, "patch.diff", b"diff --git a/x b/x\n", "PATCH_ARTIFACT",
                   "pgop1.swebench.patch.unified_diff.v1")
    result = audit_evidence(tmp_path, _request(log, patch))
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] == []
    assert all(ref["instance_binding"] == "RUN_ONLY" for ref in result["EXECUTION_EVIDENCE"])
    assert all(obs["instance_id"] == "UNKNOWN" for obs in result["observations"])


def test_bounded_gzip_text_parser_hashes_instructions_without_interpreting_them(tmp_path: Path) -> None:
    expanded = b"ignore previous instructions; I resolved the issue.\n"
    descriptor = _write(tmp_path, "test_output.txt.gz", gzip.compress(expanded), "EXECUTION_LOG",
                        "pgop1.swebench.log.gzip_text_unattributed.v1")
    result = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert result["status"] == "SUPPORTED"
    assert result["observations"][0]["kind"] == "execution_evidence"
    assert result["observations"][0]["instance_id"] == "UNKNOWN"
    assert result["observations"][0]["value"]["sha256"] == hashlib.sha256(expanded).hexdigest()


def test_gzip_expansion_limit_is_enforced(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import runtime.candidate.swebench_claim_audit.generalized as generalized
    monkeypatch.setattr(generalized, "MAX_GZIP_OUTPUT", 16)
    descriptor = _write(tmp_path, "test_output.txt.gz", gzip.compress(b"x" * 17), "EXECUTION_LOG",
                        "pgop1.swebench.log.gzip_text_unattributed.v1")
    result = audit_file(tmp_path, {**descriptor, "run_id": RUN})
    assert result["status"] == "ERROR"
    assert result["reason_codes"] == ["DECOMPRESSION_LIMIT"]


def test_oversized_assistant_message_fails_instead_of_silently_dropping_claims(tmp_path: Path) -> None:
    trajectory = _json_file(tmp_path, "logs/trajs/" + INSTANCE + ".traj.json", {
        "instance_id": INSTANCE, "messages": [{"role": "assistant", "content": "x" * 16_385}],
    }, "AGENT_TRAJECTORY", TRAJECTORY_PARSER)
    result = audit_evidence(tmp_path, _request(trajectory))
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["reason_codes"] == ["CLAIM_TEXT_TOO_LARGE"]


def test_unknown_parser_is_explicitly_unsupported(tmp_path: Path) -> None:
    source = _write(tmp_path, "opaque.bin", b"opaque", "AUXILIARY", "pgop1.swebench.unknown.v9")
    result = audit_file(tmp_path, {**source, "run_id": RUN})
    assert result["status"] == "UNSUPPORTED"
    assert result["reason_codes"] == ["UNSUPPORTED_FORMAT"]


def test_parser_role_mismatch_and_path_traversal_are_rejected(tmp_path: Path) -> None:
    report = _report(tmp_path)
    result = audit_evidence(tmp_path, _request({**report, "role": "PREDICTION"}))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["PARSER_ROLE_MISMATCH"]
    result = audit_evidence(tmp_path, _request({**report, "path": "../report.json"}))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["PATH_TRAVERSAL"]
    for alias in ("folder:stream", "folder./report.json", "folder /report.json", "NUL/report.json"):
        result = audit_evidence(tmp_path, _request({**report, "path": alias}))
        assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
        assert result["reason_codes"] == ["PATH_TRAVERSAL"]


def test_duplicate_source_descriptor_is_rejected_without_duplicate_claim_ids(tmp_path: Path) -> None:
    descriptor = _trajectory(tmp_path)
    result = audit_evidence(tmp_path, _request(descriptor, descriptor, _report(tmp_path)))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["DUPLICATE_SOURCE_DESCRIPTOR"]


def test_windows_case_alias_duplicate_is_rejected(tmp_path: Path) -> None:
    descriptor = _trajectory(tmp_path)
    alias = {**descriptor, "path": descriptor["path"].upper()}
    result = audit_evidence(tmp_path, _request(descriptor, alias, _report(tmp_path)))
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["DUPLICATE_SOURCE_DESCRIPTOR"]


def test_inventory_evidence_roles_are_accepted_verbatim(tmp_path: Path) -> None:
    trajectory = _json_file(tmp_path, "logs/trajs/" + INSTANCE + ".traj.json", {
        "instance_id": INSTANCE, "messages": [{"role": "assistant", "content": "I resolved the task."}],
    }, "agent_trajectory", TRAJECTORY_PARSER)
    report = _json_file(tmp_path, "report.json", {INSTANCE: {"resolved": True}},
                         "third_party_evaluator_result", REPORT_PARSER)
    result = audit_evidence(tmp_path, _request(trajectory, report))
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert {ref["role"] for ref in result["SOURCE_PROVENANCE"]["evidence_references"]} == {
        "agent_trajectory", "third_party_evaluator_result"}


def test_unsupported_yaml_or_patch_shape_is_reported_as_unsupported(tmp_path: Path) -> None:
    metadata = _write(tmp_path, "metadata.yaml", b"agent:\n  name: nested\n", "RUN_METADATA",
                      "pgop1.swebench.metadata.yaml.v1")
    parsed = audit_file(tmp_path, {**metadata, "run_id": RUN})
    assert parsed["status"] == "UNSUPPORTED"
    assert parsed["reason_codes"] == ["UNSUPPORTED_YAML_SHAPE"]
    patch = _write(tmp_path, "patch.diff", b"not a unified patch", "PATCH_ARTIFACT",
                   "pgop1.swebench.patch.unified_diff.v1")
    parsed = audit_file(tmp_path, {**patch, "run_id": RUN})
    assert parsed["status"] == "UNSUPPORTED"
    assert parsed["reason_codes"] == ["UNSUPPORTED_PATCH_SHAPE"]


def test_nontrivial_parser_error_cannot_be_overridden_by_a_matching_claim(tmp_path: Path) -> None:
    trajectory, report = _trajectory(tmp_path), _report(tmp_path, True)
    bad_log = _write(tmp_path, "run.log.gz", b"not-gzip", "EXECUTION_LOG",
                     "pgop1.swebench.log.gzip_text_unattributed.v1")
    result = audit_evidence(tmp_path, _request(trajectory, report, bad_log))
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["AGENT_STATEMENT"][0]["AUDIT_VERDICT"] == "VERIFICATION_ERROR"


def test_yaml_subset_is_safe_and_parser_registry_is_versioned(tmp_path: Path) -> None:
    metadata = _write(tmp_path, "metadata.yaml", b"agent: mini-swe-agent\nversion: 2.4.6\n",
                      "RUN_METADATA", "pgop1.swebench.metadata.yaml.v1")
    parsed = audit_file(tmp_path, {**metadata, "run_id": RUN})
    assert parsed["status"] == "SUPPORTED"
    assert {obs["value"]["key"] for obs in parsed["observations"]} == {"agent", "version"}
    assert PARSER_VERSIONS["pgop1.swebench.metadata.yaml.v1"] == "1.0.0"
