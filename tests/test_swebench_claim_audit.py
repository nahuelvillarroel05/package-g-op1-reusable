"""Adversarial tests for the prospective SWE-bench claim adapter."""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import struct
import zipfile

import pytest

from runtime.candidate.swebench_claim_audit.adapter import (
    AuditError,
    RUN_REPO,
    _gzip_bytes,
    audit_instance,
    validate_zip_archive,
)
from runtime.candidate.swebench_claim_audit.engine_bridge import bind_to_context_engine


INSTANCE = "apache__druid-13704"
PATCH = "diff --git a/example.txt b/example.txt\n--- a/example.txt\n+++ b/example.txt\n@@ -1 +1 @@\n-old\n+new\n"
CLAIM = "I have successfully completed the task and submitted the final output patch."


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _fixture(tmp_path: Path, *, resolved: bool = True, with_claim: bool = True) -> Path:
    root = tmp_path / "data"
    prediction = {"instance_id": INSTANCE, "model_name_or_path": "gemini-3-5-flash-fair",
                  "model_patch": PATCH}
    _write(root / "logs" / "all_preds.jsonl", (json.dumps(prediction) + "\n").encode())
    _write(root / "logs" / "logs" / INSTANCE / "patch.diff", PATCH.encode())
    report = {INSTANCE: {"patch_exists": True, "patch_successfully_applied": True,
                         "resolved": resolved, "infra_failure": False}}
    _write(root / "logs" / "logs" / INSTANCE / "report.json", json.dumps(report).encode())
    _write(root / "logs" / "logs" / INSTANCE / "test_output.txt.gz",
           gzip.compress(b"bounded synthetic fixture test output\n"))
    response_text = CLAIM if with_claim else "Patch prepared for the next step."
    trajectory = {
        "trajectory_format": "mini-swe-agent-1.1",
        "instance_id": INSTANCE,
        "messages": [{"role": "user", "content": "Submit the patch.", "extra": {
            "response": {"id": "response-local-fixture", "model": "gemini-3-5-flash-fair",
                         "choices": [{"message": {"role": "assistant", "content": response_text},
                                      "finish_reason": "stop"}]}}}],
    }
    _write(root / "logs" / "trajs" / (INSTANCE + ".traj.json"), json.dumps(trajectory).encode())
    run = root / RUN_REPO
    detail = {"resolved": resolved, "api_calls": 2, "cost": 0.1}
    _write(run / "per_instance_details.json", json.dumps({INSTANCE: detail}).encode())
    summary = {"resolved": [INSTANCE] if resolved else [], "no_generation": [], "no_logs": []}
    _write(run / "results" / "results.json", json.dumps(summary).encode())
    _write(run / "metadata.yaml", b"mini-swe-agent_version: 2.4.6\nagent: mini-SWE-agent\n")
    _write(run / "README.md", b"SWE-bench Multilingual local fixture\n")
    return root


def test_explicit_success_claim_is_compared_with_consistent_result_records(tmp_path: Path) -> None:
    result = audit_instance(_fixture(tmp_path), INSTANCE)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["AGENT_STATEMENT"]["predicate"] == "TASK_RESOLVED"
    assert result["AGENT_STATEMENT"]["source_pointer"].endswith("/message/content")
    assert result["EVALUATOR_RESULT"]["report_resolved"] is True
    assert result["SOURCE_PROVENANCE"]["provider_identity"] == "NOT_CRYPTOGRAPHICALLY_ATTESTED"
    assert result["authority"]["OP1_authority_claimed"] is False


@pytest.mark.parametrize("claim", [
    "I have completed the task and submitted the final patch.",
    "I have completed the task and verified the changes.",
    "I completed the task.",
])
def test_plain_first_person_completion_claim_is_recognized(tmp_path: Path, claim: str) -> None:
    root = _fixture(tmp_path)
    trajectory_path = root / "logs" / "trajs" / (INSTANCE + ".traj.json")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    trajectory["messages"][0]["extra"]["response"]["choices"][0]["message"]["content"] = claim
    _write(trajectory_path, json.dumps(trajectory).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["AGENT_STATEMENT"]["source_pointer"] == "/messages/0/extra/response/choices/0/message/content"
    assert claim.startswith(result["AGENT_STATEMENT"]["matched_text"])
    assert result["AGENT_STATEMENT"]["match_span"][0] == 0


@pytest.mark.parametrize("claim", [
    "I have successfully resolved the serialization issue and submitted the patch.",
    "I have successfully fixed the exponential backoff calculation and submitted the patch.",
])
def test_selected_descriptive_resolution_forms_are_recognized(tmp_path: Path, claim: str) -> None:
    root = _fixture(tmp_path)
    trajectory_path = root / "logs" / "trajs" / (INSTANCE + ".traj.json")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    trajectory["messages"][0]["extra"]["response"]["choices"][0]["message"]["content"] = claim
    _write(trajectory_path, json.dumps(trajectory).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["AGENT_STATEMENT"]["matched_text"] == claim.split(" and submitted")[0]


def test_explanatory_where_clause_does_not_erase_direct_completion_claim(tmp_path: Path) -> None:
    claim = (
        "I have resolved the issue where two values were considered equal if their lower bits matched. "
        "The fix compares the large values directly."
    )
    root = _fixture(tmp_path)
    trajectory_path = root / "logs" / "trajs" / (INSTANCE + ".traj.json")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    trajectory["messages"][0]["extra"]["response"]["choices"][0]["message"]["content"] = claim
    _write(trajectory_path, json.dumps(trajectory).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert result["AGENT_STATEMENT"]["matched_text"] == "I have resolved the issue"


@pytest.mark.parametrize("claim", [
    "I have not completed the task.",
    'The quoted claim was: "I have completed the task."',
    "I think I have completed the task.",
    "The agent stated: I have completed the task.",
    "Have I completed the task?",
])
def test_negated_quoted_hedged_or_question_text_is_not_a_claim(tmp_path: Path, claim: str) -> None:
    root = _fixture(tmp_path)
    trajectory_path = root / "logs" / "trajs" / (INSTANCE + ".traj.json")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    trajectory["messages"][0]["extra"]["response"]["choices"][0]["message"]["content"] = claim
    _write(trajectory_path, json.dumps(trajectory).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] is None


@pytest.mark.parametrize("claim", [
    "If I have completed the task, then I can submit it.",
    "I have completed the task, but I may be wrong.",
    "I have completed the task, but actually I have not.",
    "I have completed the task. Actually, I have not; it remains broken.",
    "I have completed the task is a false statement.",
    "I have completed the task. It remains broken.",
    "I have completed the task, if the patch is accepted.",
    "> I have completed the task.",
    "```text\nI have completed the task.\n```",
])
def test_conditional_qualified_retracted_or_markdown_claim_is_not_accepted(
    tmp_path: Path, claim: str
) -> None:
    root = _fixture(tmp_path)
    trajectory_path = root / "logs" / "trajs" / (INSTANCE + ".traj.json")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    trajectory["messages"][0]["extra"]["response"]["choices"][0]["message"]["content"] = claim
    _write(trajectory_path, json.dumps(trajectory).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] is None


def test_repeated_identical_success_claim_keeps_each_source_pointer(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    trajectory_path = root / "logs" / "trajs" / (INSTANCE + ".traj.json")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    repeated = json.loads(json.dumps(trajectory["messages"][0]))
    trajectory["messages"].append(repeated)
    _write(trajectory_path, json.dumps(trajectory).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    assert len(result["AGENT_STATEMENT"]["source_pointers"]) == 2


def test_explicit_success_claim_is_contradicted_by_consistent_unresolved_records(tmp_path: Path) -> None:
    result = audit_instance(_fixture(tmp_path, resolved=False), INSTANCE)
    assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    assert result["EVALUATOR_RESULT"]["report_resolved"] is False


def test_resolved_result_never_creates_an_agent_claim(tmp_path: Path) -> None:
    result = audit_instance(_fixture(tmp_path, with_claim=False), INSTANCE)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["AGENT_STATEMENT"] is None
    assert result["reason_codes"] == ["NO_EXPLICIT_COMPLETION_CLAIM"]


def test_wrong_instance_join_is_an_integrity_failure(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    _write(root / "logs" / "logs" / INSTANCE / "report.json",
           json.dumps({"another__repo-1": {"resolved": True}}).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["WRONG_INSTANCE_BINDING"]


def test_prediction_patch_mismatch_is_an_integrity_failure(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    row = {"instance_id": INSTANCE, "model_patch": PATCH + "# changed\n"}
    _write(root / "logs" / "all_preds.jsonl", (json.dumps(row) + "\n").encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["PATCH_BINDING_MISMATCH"]


def test_duplicate_instance_rows_are_rejected(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    row = {"instance_id": INSTANCE, "model_patch": PATCH}
    _write(root / "logs" / "all_preds.jsonl", ((json.dumps(row) + "\n") * 2).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["DUPLICATE_INSTANCE"]


def test_corrupt_gzip_is_reported_without_execution(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    _write(root / "logs" / "logs" / INSTANCE / "test_output.txt.gz", b"not-gzip")
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["reason_codes"] == ["CORRUPT_GZIP"]


def test_gzip_decompression_limit_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import runtime.candidate.swebench_claim_audit.adapter as adapter

    monkeypatch.setattr(adapter, "MAX_TEST_OUTPUT_BYTES", 32)
    with pytest.raises(AuditError, match="decompressed byte limit") as caught:
        _gzip_bytes(gzip.compress(b"x" * 33))
    assert caught.value.code == "DECOMPRESSION_LIMIT"


def test_inconsistent_evaluator_sources_are_not_a_claim_verdict(tmp_path: Path) -> None:
    root = _fixture(tmp_path, resolved=False)
    run = root / RUN_REPO
    _write(run / "per_instance_details.json", json.dumps({INSTANCE: {"resolved": True}}).encode())
    _write(run / "results" / "results.json", json.dumps({"resolved": [INSTANCE]}).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["EVALUATOR_RECORD_CONFLICT"]


def test_ambiguous_multiple_success_claims_do_not_get_a_verdict(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    trajectory_path = root / "logs" / "trajs" / (INSTANCE + ".traj.json")
    trajectory = json.loads(trajectory_path.read_text(encoding="utf-8"))
    trajectory["messages"].append({"role": "assistant", "content": "I have successfully resolved the issue."})
    _write(trajectory_path, json.dumps(trajectory).encode())
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["reason_codes"] == ["AMBIGUOUS_AGENT_CLAIM"]


def test_path_traversal_instance_id_is_rejected(tmp_path: Path) -> None:
    result = audit_instance(_fixture(tmp_path), "../escape")
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE"
    assert result["reason_codes"] == ["PATH_TRAVERSAL"]


def test_missing_execution_log_remains_insufficient_evidence(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    (root / "logs" / "logs" / INSTANCE / "test_output.txt.gz").unlink()
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"
    assert result["reason_codes"] == ["EVIDENCE_MISSING"]


def test_duplicate_json_fields_are_not_silently_collapsed(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    raw = (f'{{"{INSTANCE}":{{"resolved":true,"resolved":false}}}}').encode()
    _write(root / "logs" / "logs" / INSTANCE / "report.json", raw)
    result = audit_instance(root, INSTANCE)
    assert result["AUDIT_VERDICT"] == "VERIFICATION_ERROR"
    assert result["reason_codes"] == ["DUPLICATE_JSON_KEY"]


def test_zip_validator_does_not_extract_and_rejects_path_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "traversal.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape.txt", b"data")
    with pytest.raises(ValueError, match="unsafe member path"):
        validate_zip_archive(archive_path)


@pytest.mark.parametrize("alias", ["./payload.txt", "folder//payload.txt", "folder/./payload.txt"])
def test_zip_validator_rejects_noncanonical_member_aliases(
    tmp_path: Path, alias: str
) -> None:
    archive_path = tmp_path / "member-alias.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("payload.txt", b"first")
        archive.writestr(alias, b"second")
    with pytest.raises(ValueError, match="unsafe member path"):
        validate_zip_archive(archive_path)


def test_zip_validator_rejects_separator_alias_duplicates(tmp_path: Path) -> None:
    archive_path = tmp_path / "separator-alias.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        alias = zipfile.ZipInfo("folder/payload.txt")
        alias.filename = "folder\\payload.txt"
        archive.writestr(alias, b"first")
        archive.writestr("folder/payload.txt", b"second")
    with pytest.raises(ValueError, match="duplicate member name"):
        validate_zip_archive(archive_path)


def test_zip_validator_accepts_safe_directory_and_nested_member(tmp_path: Path) -> None:
    archive_path = tmp_path / "safe-nested.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("folder/", b"")
        archive.writestr("folder/payload.txt", b"data")
    result = validate_zip_archive(archive_path)
    assert result["status"] == "PASS"
    assert result["member_count"] == 2


def test_zip_validator_detects_corrupt_member_crc(tmp_path: Path) -> None:
    archive_path = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("logs/report.json", b"payload" * 100)
    raw = bytearray(archive_path.read_bytes())
    central = raw.rindex(b"PK\x01\x02")
    raw[central + 16] ^= 0x01
    archive_path.write_bytes(raw)
    with pytest.raises(ValueError, match="CRC validation"):
        validate_zip_archive(archive_path)


def test_zip_validator_enforces_expansion_bound(tmp_path: Path) -> None:
    archive_path = tmp_path / "ratio.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.txt", b"0" * 100_000)
    with pytest.raises(ValueError, match="expansion-ratio"):
        validate_zip_archive(archive_path, max_ratio=5)


def test_context_engine_persists_bindings_and_reads_them_in_fresh_process(tmp_path: Path) -> None:
    data_root = _fixture(tmp_path)
    audit = audit_instance(data_root, INSTANCE)
    result = bind_to_context_engine(audit, data_root, tmp_path / "context-store")
    engine = result["context_engine"]
    assert engine["status"] == "PASS"
    assert engine["fresh_process_readback"]["status"] == "PASS"
    assert engine["fresh_process_readback"]["read_only_api_operations"] is True
    assert engine["fresh_process_readback"]["filesystem_mutation_status"] == "NOT_PROVEN"
    assert engine["fresh_process_readback"]["index_reconstruction"] == "POSSIBLE"
    assert result["fixed_i7_provider_dispatch"] == "NOT_PERFORMED"
    assert result["provider_recovery"] == "NOT_APPLICABLE_NO_PROVIDER_OPERATION_CREATED"
    assert result["redispatch"] == "NOT_APPLICABLE_NO_PROVIDER_OPERATION_CREATED"
    assert engine["semantic_claim_verification_by_context_engine"] == "NOT_PERFORMED"
    provenance_path = next((tmp_path / "context-store" / "versions").rglob("provenance.json"))
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    assert provenance["schema"] == "I5-NEXT-v0.1"
    assert all(row["provider_identity"] == "UNKNOWN" for row in provenance["records"])
    assert all(row["process_identity"] == "UNKNOWN" for row in provenance["records"])
    assert all(row["independent_custody"] == "NOT_PROVEN" for row in provenance["records"])


def test_context_engine_rejects_changed_source_commitment(tmp_path: Path) -> None:
    data_root = _fixture(tmp_path)
    audit = audit_instance(data_root, INSTANCE)
    audit["SOURCE_PROVENANCE"]["evidence_references"][0]["sha256"] = "0" * 64
    with pytest.raises(AuditError) as caught:
        bind_to_context_engine(audit, data_root, tmp_path / "context-store")
    assert caught.value.code == "BRIDGE_SOURCE_COMMITMENT_MISMATCH"
