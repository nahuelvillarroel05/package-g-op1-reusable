"""Validation of terminal v2 result envelopes against frozen campaign inputs.

This module admits structural provenance only. It does not authenticate a
producer or certify that an execution actually occurred.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .core import FrameworkError, _loads, _path, _within, canonical, digest

RESULT_SCHEMA = "pgop1.run-result-envelope.v2"
_ENVELOPE_FIELDS = {
    "schema", "run_id", "campaign_attempt_id", "campaign_id", "unit_id",
    "source_id", "source_sha256", "contract_sha256", "candidate_commit",
    "candidate_tree", "producer_id", "producer_identity_status", "result_id",
    "result_type", "evidence_references", "result_payload_sha256", "result_payload",
}


def _read_bound_file(path_value: str, expected_hash: str, roots: list[Path], label: str) -> tuple[Path, bytes]:
    try:
        path = _path(path_value, True)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise FrameworkError(f"{label} path is unavailable or unsafe") from exc
    if not path.is_file() or not _within(path, roots):
        raise FrameworkError(f"{label} is outside trusted roots or is not a regular file")
    raw = path.read_bytes()
    if digest(raw) != expected_hash:
        raise FrameworkError(f"{label} byte hash mismatch")
    return path, raw


def _producer_ids(contract: Any) -> set[str]:
    if not isinstance(contract, dict):
        raise FrameworkError("contract producer declarations are invalid")
    producers = contract.get("producers")
    found: set[str] = set()
    if isinstance(producers, dict):
        rows = [(key, value) for key, value in producers.items()]
    elif isinstance(producers, list):
        rows = []
        for value in producers:
            if not isinstance(value, dict) or not isinstance(value.get("producer_id"), str):
                raise FrameworkError("contract producer declarations are invalid")
            rows.append((value["producer_id"], value))
    else:
        raise FrameworkError("contract producer declarations are missing")
    for producer_id, declaration in rows:
        if not isinstance(producer_id, str) or not producer_id or producer_id in found:
            raise FrameworkError("contract producer declarations are invalid")
        if not isinstance(declaration, dict):
            raise FrameworkError("contract producer declaration must be an object")
        # A declaration is not authentication. Reject claims stronger than that.
        declared_status = declaration.get("identity_status", declaration.get("status", "DECLARED"))
        if declared_status != "DECLARED":
            raise FrameworkError("contract producer status must be DECLARED")
        found.add(producer_id)
    return found


def _manifest_index(campaign: Any) -> dict[str, Any]:
    """Verify pinned bytes once, then cache the parsed authoritative records."""
    cached = getattr(campaign, "_v2_provenance_index", None)
    key = (getattr(campaign, "config_sha256", id(campaign.config)),
           campaign.config.get("input_manifest_sha256"), campaign.config.get("contract_sha256"))
    if isinstance(cached, tuple) and len(cached) == 2 and cached[0] == key:
        return cached[1]

    cfg = campaign.config
    roots = [_path(root, True) for root in cfg.get("allowlisted_roots", [])]
    if not roots:
        raise FrameworkError("independent trusted source roots are required")
    _, manifest_bytes = _read_bound_file(cfg.get("dataset_manifest_path", ""),
                                         cfg.get("input_manifest_sha256", ""), roots, "dataset manifest")
    _, contract_bytes = _read_bound_file(cfg.get("contract_path", ""),
                                         cfg.get("contract_sha256", ""), roots, "contract")
    manifest = _loads(manifest_bytes)
    contract = _loads(contract_bytes)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("units"), list):
        raise FrameworkError("dataset manifest units must be a list of objects")
    bindings: dict[str, list[tuple[str, str]]] = {}
    for item in cfg.get("input_bindings", []):
        if not isinstance(item, dict) or set(item) != {"path", "sha256"}:
            raise FrameworkError("input binding is invalid")
        try:
            bound_path = _path(item["path"], True)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise FrameworkError("source input path is unavailable or unsafe") from exc
        if not bound_path.is_file() or not _within(bound_path, roots):
            raise FrameworkError("source input is outside trusted roots or is not a regular file")
        bindings.setdefault(item["sha256"], []).append((str(bound_path), item["sha256"]))

    units: dict[str, dict] = {}
    for row in manifest["units"]:
        if not isinstance(row, dict) or not all(isinstance(row.get(k), str) and row[k] for k in ("unit_id", "source_id", "source_sha256")):
            raise FrameworkError("dataset manifest unit identity is invalid")
        if row["unit_id"] in units:
            raise FrameworkError("dataset manifest unit identity is duplicated")
        candidates = bindings.get(row["source_sha256"], [])
        if "source_path" in row:
            if not isinstance(row["source_path"], str) or not any(path == row["source_path"] for path, _ in candidates):
                raise FrameworkError("dataset source has no matching bound source bytes")
        elif len(candidates) != 1:
            raise FrameworkError("dataset source has no uniquely bound source bytes")
        if not candidates:
            raise FrameworkError("dataset source has no uniquely bound source bytes")
        units[row["unit_id"]] = row

    if set(units) != set(campaign.config.get("expected_units", [])):
        raise FrameworkError("dataset manifest unit set differs from frozen expected units")
    # Evidence is authorized per unit. A reference belonging to another unit
    # cannot be borrowed, and empty references require an explicit future mode.
    evidence: dict[str, set[tuple[str, str]]] = {}
    for row in units.values():
        refs = row.get("evidence_references")
        if not isinstance(refs, list) or not refs:
            raise FrameworkError("dataset manifest unit evidence_references must be a nonempty list")
        unit_refs: set[tuple[str, str]] = set()
        for ref in refs:
            if not isinstance(ref, dict) or not isinstance(ref.get("path"), str) or not isinstance(ref.get("sha256"), str):
                raise FrameworkError("dataset manifest unit evidence reference is invalid")
            pair = (ref["path"], ref["sha256"])
            if pair in unit_refs:
                raise FrameworkError("dataset manifest unit evidence reference is duplicated")
            unit_refs.add(pair)
        evidence[row["unit_id"]] = unit_refs
    result = {"units": units, "bindings": bindings, "evidence": evidence,
              "producers": _producer_ids(contract), "roots": roots}
    try:
        campaign._v2_provenance_index = (key, result)
    except Exception:
        pass
    return result


def validate_result(campaign: Any, unit_id: str, payload: Any) -> dict[str, Any]:
    """Validate a v2 terminal envelope or raise ``FrameworkError``.

    V1 callers do not call this function; the function itself deliberately has
    no side effects so the framework can preserve rejected payload bytes.
    """
    if not isinstance(unit_id, str) or not isinstance(payload, dict) or not _ENVELOPE_FIELDS.issubset(payload):
        raise FrameworkError("RESULT_WITHOUT_PROVENANCE")
    if set(payload) != _ENVELOPE_FIELDS:
        raise FrameworkError("RESULT_PROVENANCE_FIELDS_INVALID")
    if payload.get("schema") != RESULT_SCHEMA:
        raise FrameworkError("RESULT_WITHOUT_PROVENANCE")
    cfg = campaign.config
    for field, expected in (("run_id", cfg.get("run_id")),
                            ("campaign_attempt_id", cfg.get("campaign_attempt_id")),
                            ("campaign_id", cfg.get("campaign_id"))):
        if payload.get(field) != expected:
            raise FrameworkError("RESULT_FROM_ANOTHER_CAMPAIGN")
    if payload.get("unit_id") != unit_id:
        raise FrameworkError("RESULT_UNIT_MISMATCH")
    index = _manifest_index(campaign)
    unit = index["units"].get(unit_id)
    if unit is None or unit_id not in cfg.get("expected_units", []):
        raise FrameworkError("RESULT_UNIT_NOT_IN_FROZEN_MANIFEST")
    source_candidates = index["bindings"][unit["source_sha256"]]
    if "source_path" in unit:
        source_match = [binding for binding in source_candidates if binding[0] == unit["source_path"]]
        if not source_match:
            raise FrameworkError("RESULT_PROVENANCE_MISMATCH:source_path")
        source_path, source_hash = source_match[0]
    else:
        source_path, source_hash = source_candidates[0]
    _read_bound_file(source_path, source_hash, index["roots"], "dataset source")
    expected_identity = {
        "source_id": unit["source_id"], "source_sha256": unit["source_sha256"],
        "contract_sha256": cfg.get("contract_sha256"),
        "candidate_commit": cfg.get("candidate_commit"), "candidate_tree": cfg.get("candidate_tree"),
    }
    for field, expected in expected_identity.items():
        if payload.get(field) != expected:
            raise FrameworkError("RESULT_PROVENANCE_MISMATCH:" + field)
    producer_id = payload.get("producer_id")
    if not isinstance(producer_id, str) or producer_id not in index["producers"]:
        raise FrameworkError("RESULT_PRODUCER_UNKNOWN")
    if payload.get("producer_identity_status") != "DECLARED":
        raise FrameworkError("RESULT_PRODUCER_NOT_AUTHENTICATED")
    for field in ("result_id", "result_type"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise FrameworkError("RESULT_PROVENANCE_MISMATCH:" + field)
    try:
        result_hash = digest(canonical(payload["result_payload"]))
    except FrameworkError as exc:
        raise FrameworkError("RESULT_PAYLOAD_INVALID") from exc
    if payload.get("result_payload_sha256") != result_hash:
        raise FrameworkError("RESULT_PAYLOAD_HASH_MISMATCH")
    refs = payload.get("evidence_references")
    if not isinstance(refs, list) or not refs:
        raise FrameworkError("RESULT_EVIDENCE_MISSING")
    seen = set()
    for ref in refs:
        if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
                or not isinstance(ref["path"], str) or not isinstance(ref["sha256"], str)):
            raise FrameworkError("RESULT_EVIDENCE_REFERENCE_INVALID")
        pair = (ref["path"], ref["sha256"])
        if pair in seen:
            raise FrameworkError("RESULT_EVIDENCE_REFERENCE_INVALID")
        seen.add(pair)
    if seen != index["evidence"][unit_id]:
        raise FrameworkError("RESULT_EVIDENCE_NOT_IN_MANIFEST")
    for pair in seen:
        _read_bound_file(pair[0], pair[1], index["roots"], "result evidence")
    return {
        "admission_status": "STRUCTURALLY_ADMITTED",
        "execution_certification": "NOT_EXECUTION_CERTIFIED",
        "producer_identity_status": "DECLARED",
        "run_id": cfg["run_id"], "campaign_attempt_id": cfg["campaign_attempt_id"],
        "campaign_id": cfg["campaign_id"], "unit_id": unit_id,
        "result_id": payload["result_id"], "result_payload_sha256": result_hash,
    }
