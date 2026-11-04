"""Strict rev004 detached receipt/checkpoint payload primitives.

These helpers define the byte-level rules in the frozen RUN004 rev004 contract.
They do not retrofit CampaignV2's compact event checkpoint or authorize a run.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Iterable, Mapping
import weakref


class Rev004WireError(ValueError):
    """A rev004 payload violates canonical bytes or linkage requirements."""


UNIT_PAYLOAD_SCHEMA = "pgop1.run004.unit-receipt-payload.rev004"
CHECKPOINT_PAYLOAD_SCHEMA = "pgop1.run004.checkpoint-payload.rev004"
_CHECKPOINT_CONTEXT_SEAL = object()
_ISSUED_CHECKPOINT_CONTEXTS: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


@dataclass(frozen=True)
class ValidatedCheckpointContext:
    """In-process context returned only after validating a checkpoint and its chain."""
    payload_bytes: bytes
    payload_sha256: str
    selected_units: tuple[str, ...]
    ordered_receipt_payload_sha256: tuple[str, ...]
    completed_units: tuple[str, ...]
    pending_units: tuple[str, ...]
    inflight_units: tuple[str, ...]
    _seal: object


def _checkpoint_context_fingerprint(context: ValidatedCheckpointContext) -> tuple[Any, ...]:
    return (context.payload_bytes, context.payload_sha256, context.selected_units,
            context.ordered_receipt_payload_sha256, context.completed_units,
            context.pending_units, context.inflight_units, context._seal)


def _selected_unit_tuple(selected_units: Iterable[str]) -> tuple[str, ...]:
    if isinstance(selected_units, (str, bytes)):
        raise Rev004WireError("selected units must be an iterable of unique nonempty strings")
    try:
        values = tuple(selected_units)
    except TypeError as exc:
        raise Rev004WireError("selected units must be an iterable of unique nonempty strings") from exc
    if (any(type(unit) is not str or not unit for unit in values)
            or len(values) != len(set(values))):
        raise Rev004WireError("selected units must be unique nonempty strings")
    return tuple(sorted(values))


def _validate_json(value: Any) -> None:
    if value is None or type(value) in (str, bool, int):
        return
    if isinstance(value, float):
        raise Rev004WireError("rev004 payloads forbid floating point values")
    if isinstance(value, list):
        for item in value:
            _validate_json(item)
        return
    if isinstance(value, dict):
        if any(type(key) is not str for key in value):
            raise Rev004WireError("rev004 JSON object keys must be strings")
        for item in value.values():
            _validate_json(item)
        return
    raise Rev004WireError("unsupported rev004 JSON value")


def canonical_payload(payload: Mapping[str, Any]) -> bytes:
    """Return the contract's exact UTF-8 JSON payload bytes (no framing newline)."""
    if not isinstance(payload, Mapping):
        raise Rev004WireError("payload must be a JSON object")
    value = dict(payload)
    _validate_json(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def decode_payload(raw: bytes, expected_sha256: str) -> dict[str, Any]:
    """Check detached SHA-256, strict UTF-8 JSON, duplicate keys and canonical bytes."""
    if not isinstance(raw, bytes) or not isinstance(expected_sha256, str):
        raise Rev004WireError("payload bytes and detached digest are required")
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected_sha256:
        raise Rev004WireError("detached payload digest mismatch")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Rev004WireError("duplicate JSON key")
            result[key] = value
        return result
    def reject_constant(_value):
        raise Rev004WireError("nonfinite JSON value")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Rev004WireError("invalid UTF-8 JSON payload") from exc
    if not isinstance(value, dict):
        raise Rev004WireError("payload root must be an object")
    _validate_json(value)
    if canonical_payload(value) != raw:
        raise Rev004WireError("payload bytes are not canonical or contain framing bytes")
    return value


def validate_unit_payload(payload: Mapping[str, Any]) -> bytes:
    """Validate the literal per-unit fields required by RUN004 rev004."""
    required = {
        "schema", "campaign_id", "campaign_attempt_id", "unit_id", "logical_id",
        "benchmark", "version", "revision", "split", "locale", "modality",
        "source_uri", "source_sha256", "integrity_status",
        "available_evidence", "missing_evidence", "authentic_agent_output_status",
        "producer_provenance", "contract_id", "contract_sha256", "predicate_version",
        "processing_started_at_unix_ns", "processing_ended_at_unix_ns",
        "processing_duration_ns", "processing_result", "audit_status",
        "audit_reason", "verdict", "abstention_reason", "error", "blocker",
        "recovery_status", "phase", "parent_receipt_sha256", "attempt_id", "sequence", "bindings",
    }
    if not required.issubset(payload):
        raise Rev004WireError("receipt lacks literal rev004 identity, evidence, timing or disposition fields")
    if any(type(payload[key]) is not str or not payload[key] for key in
           ("campaign_id", "campaign_attempt_id", "unit_id", "logical_id", "benchmark", "version",
            "revision", "split", "locale", "source_uri", "integrity_status", "contract_id",
            "authentic_agent_output_status", "producer_provenance", "predicate_version",
            "processing_result", "audit_status", "recovery_status", "attempt_id")):
        raise Rev004WireError("receipt literal identity/status fields must be nonempty strings")
    if payload["schema"] != UNIT_PAYLOAD_SCHEMA:
        raise Rev004WireError("receipt schema identifier is not the frozen rev004 profile")
    if payload["modality"] not in {"A", "B"}:
        raise Rev004WireError("receipt modality must be explicit A or B")
    for key in ("contract_sha256", "source_sha256"):
        if not _is_sha(payload[key]):
            raise Rev004WireError("receipt source/contract digest is invalid")
    if payload["parent_receipt_sha256"] is not None and not _is_sha(payload["parent_receipt_sha256"]):
        raise Rev004WireError("receipt parent digest must be null or lowercase SHA-256")
    if type(payload["sequence"]) is not int or payload["sequence"] < 1:
        raise Rev004WireError("receipt sequence must be a positive integer")
    if payload["phase"] not in {"START", "TERMINAL"}:
        raise Rev004WireError("receipt phase must be START or TERMINAL")
    if (payload["sequence"] == 1) != (payload["parent_receipt_sha256"] is None):
        raise Rev004WireError("receipt parent linkage must be null only at sequence one")
    for key in ("processing_started_at_unix_ns", "processing_ended_at_unix_ns", "processing_duration_ns"):
        if type(payload[key]) is not int or payload[key] < 0:
            raise Rev004WireError("receipt timing values must be nonnegative integer nanoseconds")
    if (payload["processing_started_at_unix_ns"] <= 0
            or payload["processing_ended_at_unix_ns"] < payload["processing_started_at_unix_ns"]):
        raise Rev004WireError("receipt processing start/end ordering is invalid")
    if "callback_timings_ns" in payload:
        callback_timings = payload["callback_timings_ns"]
        if (not isinstance(callback_timings, dict) or not callback_timings
                or any(type(value) is not int or value < 0 for value in callback_timings.values())):
            raise Rev004WireError("callback timing observations must be named nonnegative integer nanoseconds")
    if payload["audit_status"] not in {"PERFORMED", "NOT_PERFORMED"}:
        raise Rev004WireError("receipt audit status must state performed or not performed")
    if payload["audit_status"] == "NOT_PERFORMED" and not payload["audit_reason"]:
        raise Rev004WireError("receipt NOT_PERFORMED audit requires a reason")
    for key in ("verdict", "abstention_reason", "audit_reason", "error", "blocker"):
        if payload[key] is not None and type(payload[key]) is not str:
            raise Rev004WireError("receipt decision/error fields must be strings or null")
    for key in ("available_evidence", "missing_evidence"):
        if not isinstance(payload[key], list):
            raise Rev004WireError("receipt evidence references must be lists")
        for ref in payload[key]:
            if (not isinstance(ref, dict) or type(ref.get("source_uri")) is not str
                    or not ref["source_uri"] or (ref.get("sha256") is not None and not _is_sha(ref["sha256"]))):
                raise Rev004WireError("receipt evidence reference/hash is malformed")
    bindings = payload["bindings"]
    if not isinstance(bindings, dict) or not {"source_sha256", "contract_sha256", "config_sha256"}.issubset(bindings):
        raise Rev004WireError("receipt source/contract/config bindings are required")
    if any(not _is_sha(bindings[key]) for key in ("source_sha256", "contract_sha256", "config_sha256")):
        raise Rev004WireError("receipt binding digest is invalid")
    if payload["source_sha256"] != bindings["source_sha256"] or payload["contract_sha256"] != bindings["contract_sha256"]:
        raise Rev004WireError("receipt top-level source/contract digests differ from binding digests")
    return canonical_payload(payload)


def _is_sha(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _validate_checkpoint_payload(payload: Mapping[str, Any], selected_units: Iterable[str],
                                 receipt_payloads: Iterable[Mapping[str, Any]] | None,
                                 predecessor_context: ValidatedCheckpointContext | None) -> bytes:
    """Validate full sets and reconcile every ordered start/terminal receipt."""
    required = {"schema", "campaign_id", "campaign_attempt_id", "parent_checkpoint_sha256",
                "ordered_receipt_payload_sha256", "completed_units", "pending_units",
                "inflight_units", "bindings"}
    if not required.issubset(payload):
        raise Rev004WireError("checkpoint lacks rev004 chain, receipt, set or binding fields")
    if payload["parent_checkpoint_sha256"] is not None and not _is_sha(payload["parent_checkpoint_sha256"]):
        raise Rev004WireError("checkpoint parent digest must be null or lowercase SHA-256")
    if (payload["schema"] != CHECKPOINT_PAYLOAD_SCHEMA
            or type(payload["campaign_id"]) is not str or not payload["campaign_id"]
            or type(payload["campaign_attempt_id"]) is not str or not payload["campaign_attempt_id"]):
        raise Rev004WireError("checkpoint schema or campaign identity is invalid")
    receipts = payload["ordered_receipt_payload_sha256"]
    if not isinstance(receipts, list) or any(not _is_sha(item) for item in receipts):
        raise Rev004WireError("checkpoint ordered receipt payload hashes are invalid")
    if len(set(receipts)) != len(receipts):
        raise Rev004WireError("checkpoint receipt hashes contain duplicates")
    selected = set(_selected_unit_tuple(selected_units))
    groups = []
    for key in ("completed_units", "pending_units", "inflight_units"):
        values = payload[key]
        if (not isinstance(values, list) or any(type(item) is not str for item in values)
                or values != sorted(values) or len(values) != len(set(values))):
            raise Rev004WireError(f"checkpoint {key} must be a sorted unique string list")
        groups.append(set(values))
    if any(groups[i] & groups[j] for i in range(3) for j in range(i + 1, 3)):
        raise Rev004WireError("checkpoint unit sets must be disjoint")
    if set.union(*groups) != selected:
        raise Rev004WireError("checkpoint sets do not exactly reconcile selected units")
    if receipt_payloads is None:
        raise Rev004WireError("checkpoint receipt-to-unit membership context is required")
    rows = list(receipt_payloads)
    if len(rows) != len(receipts):
        raise Rev004WireError("checkpoint receipt payload count differs from ordered hash count")
    started, terminal, attempts = set(), set(), {}
    identity = None
    previous_hash = None
    for sequence, (expected_hash, receipt) in enumerate(zip(receipts, rows), 1):
        raw = validate_unit_payload(receipt)
        actual_hash = hashlib.sha256(raw).hexdigest()
        if actual_hash != expected_hash:
            raise Rev004WireError("checkpoint receipt payload hash/order mismatch")
        if receipt["sequence"] != sequence or receipt["parent_receipt_sha256"] != previous_hash:
            raise Rev004WireError("checkpoint receipt sequence/parent chain mismatch")
        unit, phase, attempt = receipt["unit_id"], receipt["phase"], receipt["attempt_id"]
        row_identity = (receipt["campaign_id"], receipt["campaign_attempt_id"],
                        receipt["bindings"]["config_sha256"], receipt["bindings"]["contract_sha256"])
        if identity is None:
            identity = row_identity
        elif row_identity != identity:
            raise Rev004WireError("receipt campaign/config/contract bindings change across checkpoint chain")
        if unit not in selected:
            raise Rev004WireError("checkpoint receipt references unselected unit")
        if phase == "START":
            if unit in started or unit in terminal:
                raise Rev004WireError("checkpoint duplicates or reopens a unit start")
            started.add(unit)
            attempts[unit] = attempt
        else:
            if unit not in started or unit in terminal or attempts.get(unit) != attempt:
                raise Rev004WireError("checkpoint terminal receipt lacks its unique matching start")
            terminal.add(unit)
        previous_hash = actual_hash
    if terminal != groups[0] or started - terminal != groups[2] or selected - started != groups[1]:
        raise Rev004WireError("checkpoint receipt phases do not reconcile completed/pending/inflight sets")
    if (not isinstance(payload["bindings"], dict)
            or not {"config_sha256", "contract_sha256"}.issubset(payload["bindings"])):
        raise Rev004WireError("checkpoint binding hashes are required")
    for value in payload["bindings"].values():
        if not _is_sha(value):
            raise Rev004WireError("checkpoint binding digest is invalid")
    checkpoint_identity = (payload["campaign_id"], payload["campaign_attempt_id"],
                           payload["bindings"]["config_sha256"], payload["bindings"]["contract_sha256"])
    if identity is not None and identity != checkpoint_identity:
        raise Rev004WireError("checkpoint campaign/config/contract identity differs from receipts")
    raw = canonical_payload(payload)
    parent_sha = payload["parent_checkpoint_sha256"]
    if parent_sha is None:
        if predecessor_context is not None:
            raise Rev004WireError("genesis checkpoint cannot have a predecessor context")
        return raw
    if predecessor_context is None:
        raise Rev004WireError("non-genesis checkpoint requires validated predecessor context")
    if (type(predecessor_context) is not ValidatedCheckpointContext
            or predecessor_context._seal is not _CHECKPOINT_CONTEXT_SEAL):
        raise Rev004WireError("checkpoint predecessor context was not produced by validation")
    try:
        issued_fingerprint = _ISSUED_CHECKPOINT_CONTEXTS.get(predecessor_context)
    except TypeError:
        issued_fingerprint = None
    if (issued_fingerprint is None
            or issued_fingerprint != _checkpoint_context_fingerprint(predecessor_context)):
        raise Rev004WireError("checkpoint predecessor context is unissued or has been modified")
    previous_raw = predecessor_context.payload_bytes
    previous_sha = hashlib.sha256(previous_raw).hexdigest()
    if previous_sha != predecessor_context.payload_sha256:
        raise Rev004WireError("validated predecessor context digest is inconsistent")
    previous_payload = decode_payload(previous_raw, previous_sha)
    previous_completed = tuple(previous_payload["completed_units"])
    previous_pending = tuple(previous_payload["pending_units"])
    previous_inflight = tuple(previous_payload["inflight_units"])
    previous_selected = tuple(sorted(set(previous_completed + previous_pending + previous_inflight)))
    if (predecessor_context.selected_units != previous_selected
            or predecessor_context.ordered_receipt_payload_sha256 != tuple(previous_payload["ordered_receipt_payload_sha256"])
            or predecessor_context.completed_units != previous_completed
            or predecessor_context.pending_units != previous_pending
            or predecessor_context.inflight_units != previous_inflight):
        raise Rev004WireError("validated predecessor context metadata is inconsistent")
    if parent_sha != previous_sha:
        raise Rev004WireError("checkpoint parent digest does not match validated predecessor")
    if (payload["campaign_id"] != previous_payload["campaign_id"]
            or payload["campaign_attempt_id"] != previous_payload["campaign_attempt_id"]
            or payload["bindings"] != previous_payload["bindings"]):
        raise Rev004WireError("checkpoint predecessor belongs to a different campaign or binding context")
    if tuple(sorted(selected)) != predecessor_context.selected_units:
        raise Rev004WireError("checkpoint predecessor selected-unit context differs")
    previous_receipts = tuple(previous_payload["ordered_receipt_payload_sha256"])
    if (len(receipts) <= len(previous_receipts)
            or tuple(receipts[:len(previous_receipts)]) != previous_receipts):
        raise Rev004WireError("checkpoint receipt history rollback or non-advancing predecessor")
    previous_completed = set(previous_completed)
    previous_pending = set(previous_pending)
    previous_inflight = set(previous_inflight)
    current_completed, current_pending, current_inflight = groups
    if (not previous_completed.issubset(current_completed)
            or not previous_inflight.issubset(current_inflight | current_completed)
            or not previous_pending.issubset(current_pending | current_inflight | current_completed)):
        raise Rev004WireError("checkpoint unit state rollback from validated predecessor")
    return raw


def validate_checkpoint_payload(payload: Mapping[str, Any], selected_units: Iterable[str],
                                receipt_payloads: Iterable[Mapping[str, Any]] | None = None,
                                predecessor_context: ValidatedCheckpointContext | None = None) -> bytes:
    """Validate checkpoint bytes and require explicit context for non-genesis links.

    A parent digest alone is not accepted as trust evidence. The predecessor
    context must come from :func:`validated_checkpoint_context`.
    """
    return _validate_checkpoint_payload(payload, selected_units, receipt_payloads,
                                        predecessor_context)


def validated_checkpoint_context(payload: Mapping[str, Any], selected_units: Iterable[str],
                                 receipt_payloads: Iterable[Mapping[str, Any]] | None = None,
                                 predecessor_context: ValidatedCheckpointContext | None = None
                                 ) -> ValidatedCheckpointContext:
    """Validate a checkpoint and return reusable explicit context for its child."""
    selected = _selected_unit_tuple(selected_units)
    raw = _validate_checkpoint_payload(payload, selected, receipt_payloads, predecessor_context)
    context = ValidatedCheckpointContext(
        payload_bytes=raw,
        payload_sha256=hashlib.sha256(raw).hexdigest(),
        selected_units=selected,
        ordered_receipt_payload_sha256=tuple(payload["ordered_receipt_payload_sha256"]),
        completed_units=tuple(payload["completed_units"]),
        pending_units=tuple(payload["pending_units"]),
        inflight_units=tuple(payload["inflight_units"]),
        _seal=_CHECKPOINT_CONTEXT_SEAL,
    )
    _ISSUED_CHECKPOINT_CONTEXTS[context] = _checkpoint_context_fingerprint(context)
    return context


@dataclass(frozen=True)
class CallbackTiming:
    """Observed local timing; it does not terminate or isolate a callback."""
    started_unix_ns: int
    ended_unix_ns: int
    duration_ns: int


def observe_callback(callback, *args, clock_ns=None, wall_ns=None, **kwargs):
    """Run a callback and return its local duration observation with its result.

    The callback runs synchronously. A stuck callback cannot be interrupted by
    this helper, and no process RSS is measured or isolated.
    """
    import time
    monotonic = clock_ns or time.monotonic_ns
    wall = wall_ns or time.time_ns
    start_wall = wall()
    start = monotonic()
    try:
        result = callback(*args, **kwargs)
    except BaseException:
        end = monotonic()
        raise
    else:
        end = monotonic()
        return result, CallbackTiming(start_wall, wall(), max(0, end - start))

CHECKPOINT_V2_REQUIRED_FIELDS = frozenset({
    "parent_checkpoint_sha256", "ordered_receipt_payload_sha256",
    "completed_units", "pending_units", "inflight_units", "bindings",
})


def assess_compact_checkpoint_v2(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Report whether an existing compact V2 checkpoint carries rev004 fields.

    This is intentionally an assessment, not a migration or a renamed schema.
    """
    missing = sorted(CHECKPOINT_V2_REQUIRED_FIELDS - set(payload))
    return {"status": "INCOMPATIBLE" if missing else "FIELDS_PRESENT_NOT_VALIDATED",
            "compatibility": "NOT_ESTABLISHED",
            "missing_rev004_fields": missing,
            "mapping_performed": False,
            "normative_amendment_required": True}
