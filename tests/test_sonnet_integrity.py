from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit import generalized_bridge
from runtime.candidate.swebench_claim_audit.generalized import audit_evidence
from runtime.candidate.swebench_claim_audit.generalized_bridge import (
    bind_generalized_audit,
    recover_generalized_audit,
)
from runtime.candidate.swebench_claim_audit import source_fragments as fragments


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _fragmented_source(tmp_path: Path, raw: bytes, *, fragment_bytes: int = 4) -> Path:
    data = tmp_path / "data"
    data.mkdir()
    (data / "source.bin").write_bytes(raw)
    output = tmp_path / "origin"
    fragments.fragment_source(data, "source.bin", _sha(raw), len(raw), output,
                              fragment_bytes=fragment_bytes)
    return output


def _fragment_observation(identifier: str, digest: str, size: int, start: int, end: int,
                          value: object, *, exact_text: str | None = None) -> dict:
    row = {
        "observation_id": identifier,
        "kind": "source_observation",
        "run_id": "integrity-run",
        "instance_id": "UNKNOWN",
        "value": value,
        "source_ref": {"path": "source.bin", "sha256": digest, "bytes": size, "pointer": "/value"},
        "source_byte_span": {"unit": "BYTE_SPAN", "start": start, "end": end},
    }
    if exact_text is not None:
        row["source_text_assertion"] = {
            "schema": fragments.CONTENT_ASSERTION_SCHEMA,
            "association": "EXACT_BYTE_SPAN",
            "encoding": "utf-8",
            "text": exact_text,
        }
    return row


@pytest.mark.parametrize("device", [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM9", "LPT1", "LPT9",
    *("COM" + chr(codepoint) for codepoint in (0xB9, 0xB2, 0xB3)),
    *("LPT" + chr(codepoint) for codepoint in (0xB9, 0xB2, 0xB3)),
])
def test_bridge_rejects_windows_device_aliases(device: str) -> None:
    with pytest.raises(AuditError, match="device name"):
        generalized_bridge._safe_relative(device)


def _put_evidence(root: Path, path: str, payload: object, role: str, parser_id: str) -> dict:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return {"path": path, "sha256": _sha(raw), "bytes": len(raw), "role": role, "parser_id": parser_id}


def _derived_audit(root: Path, *, claim: str, resolved: bool) -> dict:
    instance = "sample__repo-1"
    trajectory = _put_evidence(root, "trajectory.json",
                               {"instance_id": instance, "messages": [{"role": "assistant", "content": claim}]},
                               "AGENT_TRAJECTORY", "pgop1.swebench.trajectory.miniswe_json.v1")
    report = _put_evidence(root, "report.json", {instance: {"resolved": resolved}},
                           "EVALUATOR_REPORT", "pgop1.swebench.evaluator_report.resolved_map_json.v1")
    return audit_evidence(root, {"run_id": "integrity-run", "instance_id": instance,
                                 "evidence": [trajectory, report]})


@pytest.mark.parametrize("tamper", ["aggregate", "claim"])
def test_bridge_rederives_claim_and_aggregate_verdict_from_engine_bytes(tmp_path: Path, tamper: str) -> None:
    result = _derived_audit(tmp_path, claim="I have resolved the task.", resolved=False)
    assert result["semantic_derivation_schema"] == "pgop1.swebench.audit-derivation.v1"
    assert result["AUDIT_VERDICT"] == "CONTRADICTED"
    if tamper == "aggregate":
        result["AUDIT_VERDICT"] = "SUPPORTED"
    else:
        result["AGENT_STATEMENT"][0]["AUDIT_VERDICT"] = "SUPPORTED"

    with pytest.raises(AuditError) as error:
        bind_generalized_audit(result, tmp_path, tmp_path / "context")
    assert error.value.code == "BRIDGE_SEMANTIC_DERIVATION_MISMATCH"


def test_bridge_recovery_rederives_versioned_result_and_labels_unverified_semantics(tmp_path: Path) -> None:
    result = _derived_audit(tmp_path, claim="The original task remains unresolved.", resolved=False)
    assert result["AUDIT_VERDICT"] == "SUPPORTED"
    bound = bind_generalized_audit(result, tmp_path, tmp_path / "context")

    assert bound["context_engine"]["status"] == "PASS"
    assert bound["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert bound["context_engine"]["byte_integrity_status"] == "BYTE_INTEGRITY_VERIFIED"
    assert bound["context_engine"]["semantic_claim_validation"] == "SEMANTIC_VALIDATION_NOT_PROVEN"
    recovered = recover_generalized_audit(tmp_path / "context")
    assert recovered["status"] == "PASS"
    assert recovered["derivation"]["status"] == "DERIVATION_VERIFIED"
    assert recovered["adapter_rerun"] == "PERFORMED_FROM_ENGINE_BYTES"
    assert recovered["semantic_claim_validation"] == "SEMANTIC_VALIDATION_NOT_PROVEN"


def test_unmarked_legacy_result_keeps_integrity_scope_without_derivation_claim(tmp_path: Path) -> None:
    result = _derived_audit(tmp_path, claim="The original task remains unresolved.", resolved=False)
    result.pop("semantic_derivation_schema")
    bound = bind_generalized_audit(result, tmp_path, tmp_path / "context")
    recovered = recover_generalized_audit(tmp_path / "context")

    assert bound["context_engine"]["status"] == "PASS"
    assert bound["derivation"]["status"] == "DERIVATION_NOT_VERIFIED"
    assert recovered["byte_integrity_status"] == "BYTE_INTEGRITY_VERIFIED"
    assert recovered["derivation"]["status"] == "DERIVATION_NOT_VERIFIED"
    assert recovered["semantic_claim_validation"] == "SEMANTIC_VALIDATION_NOT_PROVEN"


def test_strict_receipt_cannot_be_downgraded_to_legacy_during_recovery(tmp_path: Path) -> None:
    result = _derived_audit(tmp_path, claim="The original task remains unresolved.", resolved=False)
    context = tmp_path / "context"
    bind_generalized_audit(result, tmp_path, context)
    receipt_path = context / "generalized-bridge-receipt.json"
    receipt = json.loads(receipt_path.read_bytes())
    receipt["derivation"] = {
        "schema": "pgop1.swebench.audit-derivation.v1",
        "status": "DERIVATION_NOT_VERIFIED",
        "scope": "LEGACY_UNMARKED_INPUT",
        "source_objects_read": 0,
    }
    receipt_path.write_bytes(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())

    with pytest.raises(AuditError) as error:
        recover_generalized_audit(context)
    assert error.value.code == "BRIDGE_RECOVERY_DERIVATION_MISMATCH"


def test_fragment_mapping_requires_explicit_exact_text_and_rechecks_engine_bytes(tmp_path: Path) -> None:
    raw = b"PASS plus extra"
    digest = _sha(raw)
    output = _fragmented_source(tmp_path, raw)
    result = fragments.spool_fragment_observations(
        output,
        [
            _fragment_observation("exact", digest, len(raw), 0, 4, {"meaning": "not inferred"}, exact_text="PASS"),
            _fragment_observation("unverified", digest, len(raw), 5, 9, "arbitrary semantic value"),
            _fragment_observation("mismatch", digest, len(raw), 0, 4, "FAIL", exact_text="FAIL"),
        ],
        expected_run_id="integrity-run",
    )

    assert result["status"] == "PARTIAL"
    assert result["mapped_observation_count"] == 2
    assert result["rejected_record_count"] == 1
    rejection = json.loads((output / "mapping-rejections.json").read_bytes())
    assert rejection["rejections"][0]["record_id"] == "mismatch"
    assert rejection["rejections"][0]["reason_code"] == "BYTE_SPAN_CONTENT_MISMATCH"

    spool = sqlite3.connect(output / "observation-spool.sqlite")
    try:
        mapped = {row[0]: json.loads(row[1]) for row in spool.execute(
            "SELECT record_id,mapped_json FROM records WHERE status='MAPPED'")}
    finally:
        spool.close()
    assert mapped["exact"]["origin_content_verification"] == "CONTENT_VERIFIED"
    assert mapped["unverified"]["origin_content_verification"] == "CONTENT_NOT_VERIFIED"

    fragments.bind_fragment_observations(output)
    recovery = fragments.recover_fragmented_source(output)
    assert recovery["status"] == "PASS"
    assert recovery["content_verified_observations"] == 1
    assert recovery["content_not_verified_observations"] == 1


@pytest.mark.parametrize(
    "assertion",
    [
        {"association": "EXACT_BYTE_SPAN", "encoding": "utf-8", "text": "PASS"},
        {"schema": fragments.CONTENT_ASSERTION_SCHEMA, "association": "TEXT_SEARCH", "encoding": "utf-8", "text": "PASS"},
        {"schema": fragments.CONTENT_ASSERTION_SCHEMA, "association": "EXACT_BYTE_SPAN", "encoding": "ascii", "text": "PASS"},
    ],
)
def test_fragment_mapping_rejects_unversioned_or_ambiguous_text_assertions(
    tmp_path: Path, assertion: dict,
) -> None:
    raw = b"PASS"
    digest = _sha(raw)
    output = _fragmented_source(tmp_path, raw)
    row = _fragment_observation("bad-assertion", digest, len(raw), 0, 4, "PASS")
    row["source_text_assertion"] = assertion

    result = fragments.spool_fragment_observations(output, [row], expected_run_id="integrity-run")

    assert result["mapped_observation_count"] == 0
    rejection = json.loads((output / "mapping-rejections.json").read_bytes())
    assert rejection["rejections"][0]["reason_code"] == "BYTE_SPAN_CONTENT_MISMATCH"


def test_recovery_detects_engine_span_text_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = b"PASS"
    digest = _sha(raw)
    output = _fragmented_source(tmp_path, raw)
    fragments.spool_fragment_observations(
        output,
        [_fragment_observation("exact", digest, len(raw), 0, 4, "PASS", exact_text="PASS")],
        expected_run_id="integrity-run",
    )
    fragments.bind_fragment_observations(output)

    original = fragments._text_assertion_bytes
    monkeypatch.setattr(fragments, "_text_assertion_bytes", lambda row: b"FAIL" if row.get("observation_id") == "exact" else original(row))
    with pytest.raises(AuditError, match="Engine-admitted parent bytes differ") as error:
        fragments.recover_fragmented_source(output)
    assert error.value.code == "BYTE_SPAN_CONTENT_MISMATCH"


def test_exact_utf8_text_may_cross_fragment_boundary_and_recovers(tmp_path: Path) -> None:
    raw = "café!".encode("utf-8")
    digest = _sha(raw)
    output = _fragmented_source(tmp_path, raw, fragment_bytes=4)
    row = _fragment_observation("utf8-crossing", digest, len(raw), 0, len("café".encode("utf-8")),
                                "semantic text", exact_text="café")

    mapped = fragments.spool_fragment_observations(output, [row], expected_run_id="integrity-run")
    assert mapped["mapped_observation_count"] == 1
    fragments.bind_fragment_observations(output)
    recovered = fragments.recover_fragmented_source(output)
    assert recovered["content_verified_observations"] == 1
    assert recovered["content_not_verified_observations"] == 0
