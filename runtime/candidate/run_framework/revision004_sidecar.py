"""Read-only, fail-closed verification for prospective rev004 sidecar snapshots.

This does not write receipts, resume work, or authenticate a producer. The V2
crosswalk is read from the same CampaignV2 object that performs fresh recovery.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from .revision004_wire import (
    Rev004WireError,
    decode_payload,
    validate_unit_payload,
    validated_checkpoint_context,
)


class SidecarVerificationError(ValueError):
    """A sidecar snapshot is incomplete, unsafe, or disagrees with V2 recovery."""


INDEX_V1 = "pgop1.run004.receipt-index.rev004"
INDEX_V2 = "pgop1.run004.receipt-index.rev004.v2"
INDEX_V3 = "pgop1.run004.receipt-index.rev004.v3"
V3_RECEIPT_INDEX = "VERIFIED_CAMPAIGN_V2_JOURNAL"
_RECEIPT_PATH = re.compile(r"receipts/([0-9]{8})-([0-9a-f]{64})\.json\Z")
_CHECKPOINT_PATH = re.compile(r"checkpoints/([0-9]{8})-([0-9a-f]{64})\.json\Z")
_RECEIPT_FILENAME = re.compile(r"([0-9]{8})-([0-9a-f]{64})\.json\Z")
_CHECKPOINT_FILENAME = re.compile(r"([0-9]{8})-([0-9a-f]{64})\.json\Z")
_REPARSE_POINT = 0x400
_TYPED_RESULT_SCHEMA = "pgop1.modality-a-payload.v1"
_PREDICATE_RESULT_SCHEMA = "pgop1.predicate-evidence.v1"
_PROCESSING_DISPOSITIONS = {"TASK_DEFINITION_PROCESSED", "AGENT_OUTPUT_AUDITED"}
_AUDIT_DISPOSITIONS = {"NOT_AUDITED_MISSING_AGENT_OUTPUT", "AUDITED", "ABSTAIN", "VERIFICATION_ERROR"}


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SidecarVerificationError(f"PATH_UNAVAILABLE:{path.name}") from exc
    if stat.S_ISLNK(info.st_mode) or getattr(path, "is_junction", lambda: False)():
        return True
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _check_components(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        if _is_reparse(component):
            raise SidecarVerificationError(f"SIDECAR_REPARSE_TRAVERSAL:{component.name}")
    return absolute


def _read_regular(path: Path) -> bytes:
    _check_components(path)
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise SidecarVerificationError(f"SIDECAR_ENTRY_NOT_REGULAR:{path.name}")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise SidecarVerificationError(f"SIDECAR_ENTRY_NOT_REGULAR:{path.name}")
            raw = stream.read()
        after = path.lstat()
    except SidecarVerificationError:
        raise
    except OSError as exc:
        raise SidecarVerificationError(f"SIDECAR_READ_FAILED:{path.name}") from exc
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
    if identity(before) != identity(opened) or identity(before) != identity(after):
        raise SidecarVerificationError(f"SIDECAR_ENTRY_CHANGED_DURING_READ:{path.name}")
    return raw


def _directory_names(path: Path) -> set[str]:
    _check_components(path)
    try:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise SidecarVerificationError(f"SIDECAR_DIRECTORY_TYPE_INVALID:{path.name}")
        entries = list(path.iterdir())
    except SidecarVerificationError:
        raise
    except OSError as exc:
        raise SidecarVerificationError(f"SIDECAR_DIRECTORY_READ_FAILED:{path.name}") from exc
    names = set()
    for entry in entries:
        if _is_reparse(entry):
            raise SidecarVerificationError(f"SIDECAR_REPARSE_TRAVERSAL:{entry.name}")
        names.add(entry.name)
    return names


def _exact_names(actual: set[str], expected: set[str], kind: str) -> None:
    if actual - expected:
        raise SidecarVerificationError(f"ORPHAN_SIDECAR_{kind}:{','.join(sorted(actual - expected))}")
    if expected - actual:
        raise SidecarVerificationError(f"MISSING_SIDECAR_{kind}:{','.join(sorted(expected - actual))}")


def _decode(raw: bytes, description: str) -> tuple[dict[str, Any], str]:
    sha = hashlib.sha256(raw).hexdigest()
    try:
        return decode_payload(raw, sha), sha
    except Rev004WireError as exc:
        raise SidecarVerificationError(f"SIDECAR_NONCANONICAL_OR_TRUNCATED:{description}") from exc


def _index_rows(index: dict[str, Any]) -> tuple[list[dict[str, Any]] | None,
                                                 list[dict[str, Any]] | None, str]:
    schema = index.get("schema")
    if schema == INDEX_V1:
        if set(index) != {"schema", "receipts", "checkpoint"}:
            raise SidecarVerificationError("LEGACY_INDEX_LAYOUT_AMBIGUOUS")
        checkpoint = index["checkpoint"]
        if not isinstance(checkpoint, dict) or set(checkpoint) != {"sequence", "path", "sha256"}:
            raise SidecarVerificationError("LEGACY_INDEX_CHECKPOINT_LAYOUT_UNSUPPORTED")
        checkpoints = [checkpoint]
        profile = INDEX_V1
    elif schema == INDEX_V2:
        if set(index) != {"schema", "receipts", "checkpoints"}:
            raise SidecarVerificationError("INDEX_V2_LAYOUT_INVALID")
        checkpoints = index["checkpoints"]
        profile = INDEX_V2
    elif schema == INDEX_V3:
        required = {"schema", "receipt_index", "run_id", "campaign_id", "campaign_attempt_id",
                    "config_sha256", "contract_sha256", "expected_units_sha256"}
        if set(index) != required:
            raise SidecarVerificationError("INDEX_V3_CONTROL_HEADER_LAYOUT_INVALID")
        return None, None, INDEX_V3
    else:
        raise SidecarVerificationError("SIDECAR_INDEX_SCHEMA_UNSUPPORTED")
    receipts = index["receipts"]
    if not isinstance(receipts, list) or not isinstance(checkpoints, list) or not checkpoints:
        raise SidecarVerificationError("SIDECAR_INDEX_ROWS_INVALID")
    return receipts, checkpoints, profile


def _v3_receipt_rows(directory: Path, v2_crosswalk: list[dict[str, Any]]) -> list[dict[str, Any]]:
    names = _directory_names(directory)
    found: dict[int, tuple[str, str]] = {}
    for name in names:
        match = _RECEIPT_FILENAME.fullmatch(name)
        if match is None:
            raise SidecarVerificationError(f"SIDECAR_RECEIPT_FILENAME_INVALID:{name}")
        sequence = int(match.group(1))
        if sequence in found:
            raise SidecarVerificationError(f"DUPLICATE_SIDECAR_RECEIPT_SEQUENCE:{sequence}")
        found[sequence] = (name, match.group(2))
    expected = set(range(1, len(v2_crosswalk) + 1))
    if set(found) - expected:
        raise SidecarVerificationError("ORPHAN_SIDECAR_RECEIPT")
    if expected - set(found):
        raise SidecarVerificationError("MISSING_SIDECAR_RECEIPT")
    return [{"sequence": sequence, "path": f"receipts/{found[sequence][0]}",
             "sha256": found[sequence][1], "unit_id": v2_crosswalk[sequence - 1]["unit_id"],
             "phase": v2_crosswalk[sequence - 1]["phase"]}
            for sequence in range(1, len(v2_crosswalk) + 1)]


def _v3_checkpoint_rows(directory: Path, maximum_count: int) -> list[dict[str, Any]]:
    names = _directory_names(directory)
    found: dict[int, tuple[str, str]] = {}
    for name in names:
        match = _CHECKPOINT_FILENAME.fullmatch(name)
        if match is None:
            raise SidecarVerificationError(f"SIDECAR_CHECKPOINT_FILENAME_INVALID:{name}")
        sequence = int(match.group(1))
        if sequence in found:
            raise SidecarVerificationError(f"DUPLICATE_SIDECAR_CHECKPOINT_SEQUENCE:{sequence}")
        found[sequence] = (name, match.group(2))
    if any(sequence > maximum_count for sequence in found):
        raise SidecarVerificationError("ORPHAN_SIDECAR_CHECKPOINT")
    expected = set(range(1, len(found) + 1))
    if not found or set(found) != expected:
        raise SidecarVerificationError("SIDECAR_CHECKPOINT_SEQUENCE_GAP_OR_EMPTY")
    return [{"sequence": sequence, "path": f"checkpoints/{found[sequence][0]}",
             "sha256": found[sequence][1]}
            for sequence in range(1, len(found) + 1)]


def _validate_index_path(row: Any, sequence: int, pattern: re.Pattern[str], kind: str) -> str:
    required = {"sequence", "path", "sha256"}
    if kind == "RECEIPT":
        required |= {"unit_id", "phase"}
    if not isinstance(row, dict) or set(row) != required:
        raise SidecarVerificationError(f"SIDECAR_{kind}_INDEX_ROW_INVALID")
    if type(row["sequence"]) is not int or row["sequence"] != sequence:
        raise SidecarVerificationError(f"SIDECAR_{kind}_INDEX_SEQUENCE_INVALID")
    path = row["path"]
    if type(path) is not str or (match := pattern.fullmatch(path)) is None:
        raise SidecarVerificationError(f"SIDECAR_{kind}_PATH_UNSAFE")
    if row["sha256"] != match.group(2):
        raise SidecarVerificationError(f"SIDECAR_{kind}_INDEX_HASH_PATH_MISMATCH")
    return path


def _project_v2_receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    """Project the supported typed V2 receipt fields into rev004 sidecar claims.

    Only the existing typed modality-A caller envelope is mapped. Unknown V2
    result shapes fail closed; predicate-level evidence never becomes a global
    verdict. The V2 payload digest binds every unprojected predicate detail.
    """
    from .core import canonical, digest

    if not isinstance(receipt, dict) or receipt.get("phase") not in {"start", "terminal"}:
        raise SidecarVerificationError("V2_RECEIPT_PROJECTION_PROFILE_UNSUPPORTED")
    v2_payload = receipt.get("payload")
    if not isinstance(v2_payload, dict):
        raise SidecarVerificationError("V2_RECEIPT_PROJECTION_PROFILE_UNSUPPORTED")
    v2_payload_sha = digest(canonical(v2_payload))
    if receipt["phase"] == "start":
        if receipt.get("disposition") != "STARTED":
            raise SidecarVerificationError("V2_START_DISPOSITION_UNSUPPORTED")
        return {"processing_result": "STARTED", "audit_status": "NOT_PERFORMED",
                "audit_reason": "START_EVENT_HAS_NO_AUDIT_RESULT", "verdict": "UNKNOWN",
                "abstention_reason": None, "verdict_scope_reason": "START_EVENT_HAS_NO_AUDIT_RESULT",
                "audit_result_sha256": None, "v2_receipt_payload_sha256": v2_payload_sha}
    required_envelope = {"result_type", "result_payload", "result_payload_sha256"}
    if (not required_envelope.issubset(v2_payload)
            or v2_payload["result_type"] != _TYPED_RESULT_SCHEMA
            or not isinstance(v2_payload["result_payload"], dict)):
        raise SidecarVerificationError("V2_TERMINAL_RESULT_PROFILE_UNSUPPORTED")
    result = v2_payload["result_payload"]
    result_fields = {"schema", "benchmark_id", "benchmark_version", "adapter_id", "adapter_version",
                     "predicate_contract", "supporting_source_references", "normative_companion_references",
                     "producer_provenance_status", "processing_disposition", "audit_disposition",
                     "audit_result", "result_sha256"}
    if set(result) != result_fields or result["schema"] != _TYPED_RESULT_SCHEMA:
        raise SidecarVerificationError("V2_TERMINAL_RESULT_PROFILE_UNSUPPORTED")
    audit_result = result["audit_result"]
    if (not isinstance(audit_result, dict)
            or result["result_sha256"] != digest(canonical(audit_result))
            or v2_payload["result_payload_sha256"] != digest(canonical(result))):
        raise SidecarVerificationError("V2_TERMINAL_RESULT_HASH_INVALID")
    processing = result["processing_disposition"]
    audit_disposition = result["audit_disposition"]
    if (processing not in _PROCESSING_DISPOSITIONS or audit_disposition not in _AUDIT_DISPOSITIONS
            or receipt.get("disposition") != processing):
        raise SidecarVerificationError("V2_TERMINAL_DISPOSITION_MISMATCH")
    if ((processing == "TASK_DEFINITION_PROCESSED") != (audit_disposition == "NOT_AUDITED_MISSING_AGENT_OUTPUT")):
        raise SidecarVerificationError("V2_PROCESSING_AUDIT_DISPOSITION_MISMATCH")

    audit_sha = digest(canonical(audit_result))
    if processing == "TASK_DEFINITION_PROCESSED":
        return {"processing_result": processing, "audit_status": "NOT_PERFORMED",
                "audit_reason": audit_disposition, "verdict": "UNKNOWN", "abstention_reason": None,
                "verdict_scope_reason": "AUDIT_NOT_PERFORMED", "audit_result_sha256": audit_sha,
                "v2_receipt_payload_sha256": v2_payload_sha}

    # Definition-only processing may carry arbitrary caller metadata. The
    # typed envelope and both digests are still validated and bound, while no
    # audit semantics are inferred from that metadata.
    scalar_result = "decision" in audit_result or "reason" in audit_result
    predicate_result = (audit_result.get("schema") == _PREDICATE_RESULT_SCHEMA
                        and isinstance(audit_result.get("predicate_results"), list)
                        and bool(audit_result["predicate_results"])
                        and all(isinstance(row, dict) and type(row.get("predicate_id")) is str
                                and type(row.get("decision")) is str
                                for row in audit_result["predicate_results"]))
    if predicate_result and scalar_result:
        raise SidecarVerificationError("V2_AUDIT_RESULT_PROFILE_AMBIGUOUS")
    if scalar_result:
        if (("decision" in audit_result and audit_result["decision"] is not None
             and type(audit_result["decision"]) is not str)
                or ("reason" in audit_result and audit_result["reason"] is not None
                    and type(audit_result["reason"]) is not str)):
            raise SidecarVerificationError("V2_SCALAR_AUDIT_RESULT_INVALID")
    elif not predicate_result:
        raise SidecarVerificationError("V2_AUDIT_RESULT_PROFILE_UNSUPPORTED")

    if scalar_result:
        decision, reason = audit_result.get("decision"), audit_result.get("reason")
        if ((decision is not None and type(decision) is not str)
                or (reason is not None and type(reason) is not str)):
            raise SidecarVerificationError("V2_SCALAR_AUDIT_RESULT_INVALID")
        allowed = {"SUPPORTED", "CONTRADICTED", "ABSTAIN", "VERIFICATION_ERROR", "UNKNOWN"}
        if decision is not None and decision not in allowed:
            raise SidecarVerificationError("V2_SCALAR_DECISION_UNSUPPORTED")
        if ((decision in {"SUPPORTED", "CONTRADICTED"} and audit_disposition != "AUDITED")
                or (decision == "ABSTAIN" and audit_disposition != "ABSTAIN")
                or (decision == "VERIFICATION_ERROR" and audit_disposition != "VERIFICATION_ERROR")):
            raise SidecarVerificationError("V2_SCALAR_DECISION_DISPOSITION_MISMATCH")
        return {"processing_result": processing, "audit_status": "PERFORMED",
                "audit_reason": reason, "verdict": decision or "UNKNOWN",
                "abstention_reason": reason if audit_disposition == "ABSTAIN" else None,
                "verdict_scope_reason": None if decision is not None else "SCALAR_RESULT_HAS_NO_DECISION",
                "audit_result_sha256": audit_sha, "v2_receipt_payload_sha256": v2_payload_sha}

    if predicate_result:
        return {"processing_result": processing, "audit_status": "PERFORMED",
                "audit_reason": None, "verdict": "UNKNOWN", "abstention_reason": None,
                "verdict_scope_reason": "PREDICATE_RESULTS_HAVE_NO_SINGLE_GLOBAL_VERDICT",
                "audit_result_sha256": audit_sha, "v2_receipt_payload_sha256": v2_payload_sha}
    raise SidecarVerificationError("V2_AUDIT_RESULT_PROFILE_UNSUPPORTED")


def project_v2_receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    """Copy the verified typed projection and declared error/blocker annotations.

    Annotation values are producer declarations, not independent error truth.
    Structured annotations are preserved as canonical JSON text, never inferred.
    """
    from .core import canonical
    projected = _project_v2_receipt_payload(receipt)
    projected.update(error=None, blocker=None,
                     recovery_status="INFLIGHT" if receipt["phase"] == "start" else "TERMINAL_RECORDED")
    if receipt["phase"] == "terminal":
        typed = receipt["payload"]["result_payload"]
        audit_result = typed["audit_result"]
        for field in ("error", "blocker"):
            value = audit_result.get(field)
            if value is not None:
                projected[field] = value if type(value) is str else canonical(value).decode("utf-8")
        if typed["audit_disposition"] == "VERIFICATION_ERROR" and projected["error"] is None:
            reason = audit_result.get("reason")
            projected["error"] = reason if type(reason) is str and reason else "VERIFICATION_ERROR_WITHOUT_DECLARED_ERROR_TEXT"
    return projected


def _v2_crosswalk(campaign, state: dict[str, Any]) -> list[dict[str, Any]]:
    from .core import _loads, canonical, digest
    from .incremental import CampaignV2, _safe_artifact

    if not isinstance(campaign, CampaignV2):
        raise SidecarVerificationError("SAME_OBJECT_CAMPAIGN_V2_CONTEXT_REQUIRED")
    expected_campaign = campaign.config["campaign_id"]
    expected_run = campaign.run_id
    crosswalk = []
    for sequence, summary in enumerate(state["receipts"], 1):
        if summary.get("sequence") != sequence:
            raise SidecarVerificationError("V2_CROSSWALK_SEQUENCE_INVALID")
        path = _safe_artifact(campaign.output, summary["path"], "receipts")
        raw = _read_regular(path)
        receipt = _loads(raw)
        if canonical(receipt) != raw or digest(raw) != summary["sha256"]:
            raise SidecarVerificationError("V2_CROSSWALK_RECEIPT_BYTES_INVALID")
        if (receipt.get("campaign_id") != expected_campaign or receipt.get("run_id") != expected_run
                or receipt.get("sequence") != sequence or receipt.get("unit_id") != summary.get("unit_id")
                or receipt.get("phase") != summary.get("phase")):
            raise SidecarVerificationError("V2_CROSSWALK_RECEIPT_IDENTITY_MISMATCH")
        crosswalk.append({"unit_id": receipt["unit_id"], "phase": receipt["phase"].upper(),
                          "attempt_id": receipt["attempt_id"],
                          **project_v2_receipt_payload(receipt)})
    return crosswalk


def verify_revision004_sidecar(sidecar_root: str | os.PathLike[str], campaign_v2) -> dict[str, Any]:
    """Verify the exact sidecar snapshot against a fresh same-object V2 recovery.

    This function only reads. ``campaign_v2.recover()`` is invoked on the object
    supplied by the caller; the V2 receipt crosswalk is derived from that same
    object's recovered receipt paths and bytes. The function does not authenticate
    the object or establish its external custody.
    """
    from .incremental import CampaignV2
    if not isinstance(campaign_v2, CampaignV2):
        raise SidecarVerificationError("SAME_OBJECT_CAMPAIGN_V2_CONTEXT_REQUIRED")
    try:
        v2_state = campaign_v2.recover()
    except Exception as exc:
        raise SidecarVerificationError("V2_READ_RECOVERY_BLOCKED") from exc
    if v2_state.get("recovery_status") == "INCOMPLETE_READ_ONLY":
        raise SidecarVerificationError("V2_READ_RECOVERY_INCOMPLETE")

    root = _check_components(Path(sidecar_root))
    if not root.is_dir():
        raise SidecarVerificationError("SIDECAR_ROOT_INVALID")
    top_names = _directory_names(root)
    _exact_names(top_names, {"INDEX.json", "receipts", "checkpoints"}, "ROOT_ENTRY")
    receipt_dir, checkpoint_dir = root / "receipts", root / "checkpoints"
    index_raw = _read_regular(root / "INDEX.json")
    index, _index_sha = _decode(index_raw, "INDEX.json")
    receipts_rows, checkpoint_rows, profile = _index_rows(index)

    expected_campaign = campaign_v2.config["campaign_id"]
    expected_attempt = campaign_v2.config["campaign_attempt_id"]
    expected_config = campaign_v2.config_sha256
    expected_contract = campaign_v2.config["contract_sha256"]
    selected = tuple(sorted(campaign_v2.config["expected_units"]))
    if tuple(sorted(v2_state["completed"] | v2_state["pending"] | v2_state["inflight"])) != selected:
        raise SidecarVerificationError("V2_SELECTED_UNIT_STATE_INVALID")
    try:
        v2_crosswalk = _v2_crosswalk(campaign_v2, v2_state)
    except SidecarVerificationError:
        raise
    except Exception as exc:
        raise SidecarVerificationError("V2_READ_CROSSWALK_BLOCKED") from exc

    if profile == INDEX_V3:
        from .core import canonical, digest
        expected_header = {
            "schema": INDEX_V3,
            "receipt_index": V3_RECEIPT_INDEX,
            "run_id": campaign_v2.run_id,
            "campaign_id": expected_campaign,
            "campaign_attempt_id": expected_attempt,
            "config_sha256": expected_config,
            "contract_sha256": expected_contract,
            "expected_units_sha256": digest(canonical(list(selected))),
        }
        if index != expected_header:
            raise SidecarVerificationError("INDEX_V3_CONTROL_HEADER_BINDING_MISMATCH")
        receipts_rows = _v3_receipt_rows(receipt_dir, v2_crosswalk)
        checkpoint_rows = _v3_checkpoint_rows(checkpoint_dir, max(1, len(v2_crosswalk)))

    receipt_paths = []
    for sequence, row in enumerate(receipts_rows, 1):
        receipt_paths.append(_validate_index_path(row, sequence, _RECEIPT_PATH, "RECEIPT"))
    if len({row["path"] for row in receipts_rows}) != len(receipts_rows):
        raise SidecarVerificationError("DUPLICATE_SIDECAR_RECEIPT_PATH")
    if len(receipts_rows) != len(v2_crosswalk):
        raise SidecarVerificationError("V2_SIDECAR_RECEIPT_COUNT_MISMATCH")
    _exact_names(_directory_names(receipt_dir), {Path(path).name for path in receipt_paths}, "RECEIPT")

    receipt_payloads = []
    receipt_hashes = []
    authoritative_units = {}
    parent = None
    identity = (expected_campaign, expected_attempt, expected_config, expected_contract)
    for sequence, (row, relative) in enumerate(zip(receipts_rows, receipt_paths), 1):
        raw = _read_regular(receipt_dir / Path(relative).name)
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise SidecarVerificationError("SIDECAR_RECEIPT_HASH_MISMATCH")
        payload, sha = _decode(raw, relative)
        try:
            validate_unit_payload(payload)
        except Rev004WireError as exc:
            raise SidecarVerificationError("SIDECAR_RECEIPT_INVALID") from exc
        if (payload["sequence"] != sequence or payload["parent_receipt_sha256"] != parent
                or payload["campaign_id"] != expected_campaign
                or payload["campaign_attempt_id"] != expected_attempt
                or payload["bindings"]["config_sha256"] != expected_config
                or payload["bindings"]["contract_sha256"] != expected_contract
                or (payload["unit_id"], payload["phase"]) != (row.get("unit_id"), row.get("phase"))):
            raise SidecarVerificationError("SIDECAR_RECEIPT_IDENTITY_OR_CHAIN_MISMATCH")
        crosswalk = v2_crosswalk[sequence - 1]
        if profile == INDEX_V3:
            from .revision004_profile import project_unit_metadata
            try:
                if payload["unit_id"] not in authoritative_units:
                    authoritative_units[payload["unit_id"]] = project_unit_metadata(campaign_v2, payload["unit_id"])
                expected_unit = authoritative_units[payload["unit_id"]]
            except Exception as exc:
                raise SidecarVerificationError("SIDECAR_AUTHORITATIVE_UNIT_BINDING_UNAVAILABLE") from exc
            if any(payload.get(field) != value for field, value in expected_unit.items()):
                raise SidecarVerificationError("SIDECAR_AUTHORITATIVE_UNIT_METADATA_MISMATCH")
        expected_recovery = "INFLIGHT" if payload["phase"] == "START" else "TERMINAL_RECORDED"
        if payload["recovery_status"] != expected_recovery:
            raise SidecarVerificationError("SIDECAR_PHASE_RECOVERY_STATUS_MISMATCH")
        projection_fields = ("processing_result", "audit_status", "audit_reason", "verdict",
                             "abstention_reason", "verdict_scope_reason", "audit_result_sha256",
                             "v2_receipt_payload_sha256", "error", "blocker", "recovery_status")
        if (payload["verdict"] != crosswalk["verdict"]
                or payload["abstention_reason"] != crosswalk["abstention_reason"]
                or payload["audit_status"] != crosswalk["audit_status"]):
            raise SidecarVerificationError("SIDECAR_SEMANTIC_CLAIM_MISMATCH")
        if (payload["unit_id"] != crosswalk["unit_id"] or payload["phase"] != crosswalk["phase"]
                or payload["attempt_id"] != crosswalk["attempt_id"]
                or any(payload.get(field) != crosswalk[field] for field in projection_fields)):
            raise SidecarVerificationError("V2_SIDECAR_RECEIPT_CROSSWALK_MISMATCH")
        if (payload["campaign_id"], payload["campaign_attempt_id"],
                payload["bindings"]["config_sha256"], payload["bindings"]["contract_sha256"]) != identity:
            raise SidecarVerificationError("SIDECAR_RECEIPT_BINDING_MISMATCH")
        parent = sha
        receipt_hashes.append(sha)
        receipt_payloads.append(payload)

    checkpoint_paths = []
    for sequence, row in enumerate(checkpoint_rows, 1):
        checkpoint_paths.append(_validate_index_path(row, sequence, _CHECKPOINT_PATH, "CHECKPOINT"))
    if len({row["path"] for row in checkpoint_rows}) != len(checkpoint_rows):
        raise SidecarVerificationError("DUPLICATE_SIDECAR_CHECKPOINT_PATH")
    _exact_names(_directory_names(checkpoint_dir), {Path(path).name for path in checkpoint_paths}, "CHECKPOINT")
    if profile == INDEX_V1 and len(checkpoint_rows) != 1:
        raise SidecarVerificationError("LEGACY_INDEX_CHECKPOINT_CHAIN_UNSUPPORTED")

    checkpoint_context = None
    final_checkpoint = None
    for row, relative in zip(checkpoint_rows, checkpoint_paths):
        raw = _read_regular(checkpoint_dir / Path(relative).name)
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise SidecarVerificationError("SIDECAR_CHECKPOINT_HASH_MISMATCH")
        checkpoint, _sha = _decode(raw, relative)
        if (checkpoint["campaign_id"] != expected_campaign
                or checkpoint["campaign_attempt_id"] != expected_attempt
                or checkpoint["bindings"].get("config_sha256") != expected_config
                or checkpoint["bindings"].get("contract_sha256") != expected_contract):
            raise SidecarVerificationError("SIDECAR_CHECKPOINT_IDENTITY_MISMATCH")
        current_hashes = checkpoint.get("ordered_receipt_payload_sha256")
        if (not isinstance(current_hashes, list) or len(current_hashes) > len(receipt_hashes)
                or current_hashes != receipt_hashes[:len(current_hashes)]):
            raise SidecarVerificationError("SIDECAR_CHECKPOINT_RECEIPT_PREFIX_MISMATCH")
        if profile == INDEX_V1 and checkpoint.get("parent_checkpoint_sha256") is not None:
            raise SidecarVerificationError("LEGACY_INDEX_CHAIN_CONTEXT_UNSUPPORTED")
        try:
            checkpoint_context = validated_checkpoint_context(
                checkpoint, selected, receipt_payloads[:len(current_hashes)], checkpoint_context)
        except Rev004WireError as exc:
            raise SidecarVerificationError("SIDECAR_CHECKPOINT_CHAIN_INVALID") from exc
        final_checkpoint = checkpoint
    if final_checkpoint["ordered_receipt_payload_sha256"] != receipt_hashes:
        raise SidecarVerificationError("SIDECAR_RECEIPTS_NOT_COVERED_BY_FINAL_CHECKPOINT")
    if (set(final_checkpoint["completed_units"]) != set(v2_state["completed"])
            or set(final_checkpoint["pending_units"]) != set(v2_state["pending"])
            or set(final_checkpoint["inflight_units"]) != set(v2_state["inflight"])):
        raise SidecarVerificationError("V2_SIDECAR_COMPLETION_STATE_MISMATCH")
    return {"status": "READ_ONLY_SIDECAR_MATCHES_SAME_OBJECT_V2_RECOVERY",
            "index_profile": profile, "receipt_count": len(receipt_payloads),
            "checkpoint_count": len(checkpoint_rows), "selected_units": list(selected),
            "completed_units": sorted(v2_state["completed"]),
            "pending_units": sorted(v2_state["pending"]),
            "inflight_units": sorted(v2_state["inflight"]),
            "campaign_id": expected_campaign, "campaign_attempt_id": expected_attempt,
            "config_sha256": expected_config,
            "verified_scope": ["same-object CampaignV2 recovery and ordered receipt identity",
                               "sidecar campaign/config/contract bindings",
                               "unit/phase/attempt crosswalk and typed result projection",
                               "literal receipt/checkpoint content hashes, membership and predecessor chain"],
            "unit_metadata_verification": "FROZEN_TYPED_UNIT_AND_EVIDENCE_BYTES" if profile == INDEX_V3 else "LEGACY_DESCRIPTIVE_FIELDS_NOT_VERIFIED",
            "unverified_crosswalk_fields": ([] if profile == INDEX_V3 else ["source_uri", "source_sha256", "logical_id", "benchmark",
                                            "version", "revision", "split", "locale", "modality",
                                            "contract_id", "predicate_version", "available_evidence",
                                            "missing_evidence", "producer_provenance", "integrity_status",
                                            "authentic_agent_output_status"]) + ["processing_started_at_unix_ns",
                                            "processing_ended_at_unix_ns", "processing_duration_ns"],
            "external_custody_established": False,
            "independent_antirollback_established": False}
