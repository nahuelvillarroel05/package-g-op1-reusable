"""Deterministic scoring for explicitly identity-bound predicate references.

This module scores caller-supplied reference rows. It acquires or adjudicates no
labels, and an UNKNOWN reference is retained in counts but excluded from metrics.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from itertools import islice
import re
from typing import Any, Iterable

IDENTITY_FIELDS = ("run_id", "instance_id", "scope", "timestamp", "source_sha256",
                   "source_bytes", "message_id", "span_start", "span_end", "predicate")
VERDICTS = {"SUPPORTED", "CONTRADICTED", "INSUFFICIENT_EVIDENCE",
            "INTEGRITY_FAILURE", "VERIFICATION_ERROR"}
MAX_REFERENCE_ROWS = 20_000
_RUN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReferenceError(ValueError):
    """Reference or prediction violates the explicit scoring contract."""


def _identity(row: dict[str, Any]) -> tuple[Any, ...]:
    missing = [field for field in IDENTITY_FIELDS if field not in row]
    if missing:
        raise ReferenceError("IDENTITY_FIELDS_MISSING:" + ",".join(missing))
    values = tuple(row[field] for field in IDENTITY_FIELDS)
    run_id, instance_id, scope, timestamp, digest, source_bytes, message_id, start, end, predicate = values
    if not isinstance(run_id, str) or not _RUN.fullmatch(run_id):
        raise ReferenceError("RUN_ID_INVALID")
    if not isinstance(instance_id, str) or not _IDENTIFIER.fullmatch(instance_id):
        raise ReferenceError("INSTANCE_ID_INVALID")
    if not isinstance(scope, str) or not scope.strip() or len(scope) > 256:
        raise ReferenceError("SCOPE_INVALID")
    if not isinstance(timestamp, str) or len(timestamp) > 64:
        raise ReferenceError("TIMESTAMP_INVALID")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReferenceError("TIMESTAMP_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReferenceError("TIMESTAMP_TIMEZONE_REQUIRED")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise ReferenceError("SOURCE_SHA256_INVALID")
    if type(source_bytes) is not int or source_bytes < 1:
        raise ReferenceError("SOURCE_BYTES_INVALID")
    if not isinstance(message_id, str) or not message_id or len(message_id) > 256:
        raise ReferenceError("MESSAGE_ID_INVALID")
    if type(start) is not int or type(end) is not int or start < 0 or end <= start or end > source_bytes:
        raise ReferenceError("MESSAGE_SPAN_INVALID")
    if not isinstance(predicate, str) or not _IDENTIFIER.fullmatch(predicate):
        raise ReferenceError("PREDICATE_INVALID")
    return values


def evaluate_reference_cases(predictions: Iterable[dict[str, Any]],
                             references: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Score exact identity matches; absent predictions are missed extractions.

    References require `reference_id`, `polarity` (true, false, or null),
    `adjudication` (DECIDED or UNKNOWN), `evidence_commitment`, and `rationale`.
    Predictions require the same identity fields plus `verdict`. An unmatched
    prediction is rejected, as are duplicate case IDs or duplicate identities.
    """
    refs = list(islice(references, MAX_REFERENCE_ROWS + 1))
    preds = list(islice(predictions, MAX_REFERENCE_ROWS + 1))
    if len(refs) > MAX_REFERENCE_ROWS or len(preds) > MAX_REFERENCE_ROWS:
        raise ReferenceError("REFERENCE_ROW_LIMIT")
    by_id: dict[str, dict[str, Any]] = {}
    ref_identity: set[tuple[Any, ...]] = set()
    for ref in refs:
        if not isinstance(ref, dict):
            raise ReferenceError("REFERENCE_ROW_INVALID")
        reference_id = ref.get("reference_id")
        if not isinstance(reference_id, str) or not reference_id or len(reference_id) > 256:
            raise ReferenceError("REFERENCE_ID_INVALID")
        if reference_id in by_id:
            raise ReferenceError("DUPLICATE_REFERENCE_ID")
        identity = _identity(ref)
        if identity in ref_identity:
            raise ReferenceError("DUPLICATE_REFERENCE_IDENTITY")
        adjudication, polarity = ref.get("adjudication"), ref.get("polarity")
        if adjudication == "DECIDED":
            if type(polarity) is not bool:
                raise ReferenceError("DECIDED_REFERENCE_POLARITY_INVALID")
        elif adjudication == "UNKNOWN":
            if polarity is not None:
                raise ReferenceError("UNKNOWN_REFERENCE_HAS_POLARITY")
        else:
            raise ReferenceError("REFERENCE_ADJUDICATION_INVALID")
        if not isinstance(ref.get("evidence_commitment"), str) or not _SHA256.fullmatch(ref["evidence_commitment"]):
            raise ReferenceError("REFERENCE_EVIDENCE_COMMITMENT_MISSING")
        if not isinstance(ref.get("rationale"), str) or not ref["rationale"].strip():
            raise ReferenceError("REFERENCE_RATIONALE_MISSING")
        by_id[reference_id] = ref
        ref_identity.add(identity)

    pred_by_id: dict[str, dict[str, Any]] = {}
    for pred in preds:
        if not isinstance(pred, dict):
            raise ReferenceError("PREDICTION_ROW_INVALID")
        reference_id = pred.get("reference_id")
        if not isinstance(reference_id, str) or reference_id not in by_id:
            raise ReferenceError("PREDICTION_WITHOUT_REFERENCE")
        if reference_id in pred_by_id:
            raise ReferenceError("DUPLICATE_PREDICTION")
        if _identity(pred) != _identity(by_id[reference_id]):
            raise ReferenceError("PREDICTION_REFERENCE_IDENTITY_MISMATCH")
        if not isinstance(pred.get("verdict"), str) or pred.get("verdict") not in VERDICTS:
            raise ReferenceError("PREDICTION_VERDICT_INVALID")
        pred_by_id[reference_id] = pred

    counts: Counter[str] = Counter()
    excluded_rows: list[str] = []
    for reference_id, ref in by_id.items():
        if ref["adjudication"] == "UNKNOWN":
            counts["unknown_reference_rows"] += 1
            excluded_rows.append(reference_id)
            continue
        polarity = ref["polarity"]
        pred = pred_by_id.get(reference_id)
        if pred is None:
            counts["missed_extractions"] += 1
            counts["missed_positive_reference_claims" if polarity else "missed_negative_reference_claims"] += 1
            continue
        verdict = pred["verdict"]
        if verdict == "INSUFFICIENT_EVIDENCE":
            counts["positive_abstentions" if polarity else "negative_abstentions"] += 1
        elif verdict in {"INTEGRITY_FAILURE", "VERIFICATION_ERROR"}:
            counts[verdict] += 1
            counts["positive_error_outcomes" if polarity else "negative_error_outcomes"] += 1
        elif polarity and verdict == "SUPPORTED":
            counts["TP"] += 1
        elif polarity and verdict == "CONTRADICTED":
            counts["FN"] += 1
        elif not polarity and verdict == "SUPPORTED":
            counts["FP"] += 1
        elif not polarity and verdict == "CONTRADICTED":
            counts["TN"] += 1

    tp, fp, tn, fn = (counts[key] for key in ("TP", "FP", "TN", "FN"))
    positive_abstentions = counts["positive_abstentions"]
    positive_errors = counts["positive_error_outcomes"]
    missed_positive = counts["missed_positive_reference_claims"]
    precision_denominator = tp + fp
    recall_denominator = tp + fn + positive_abstentions + missed_positive + positive_errors
    accuracy_denominator = tp + tn + fp + fn
    decided_rows = accuracy_denominator
    decided_count = sum(ref["adjudication"] == "DECIDED" for ref in by_id.values())
    return {
        "schema": "pgop1.swebench.predicate-evaluation.v1",
        "status": "NOT_COMPUTABLE" if not decided_count else "COMPUTED",
        "reference_rows": len(by_id), "decided_reference_rows": decided_count,
        "counts": {key: counts[key] for key in (
            "TP", "FP", "TN", "FN", "positive_abstentions", "negative_abstentions",
            "missed_extractions", "missed_positive_reference_claims",
            "missed_negative_reference_claims", "unknown_reference_rows",
            "INTEGRITY_FAILURE", "VERIFICATION_ERROR", "positive_error_outcomes",
            "negative_error_outcomes")},
        "metrics": {
            "precision": tp / precision_denominator if precision_denominator else None,
            "recall": tp / recall_denominator if recall_denominator else None,
            "decided_accuracy": (tp + tn) / accuracy_denominator if accuracy_denominator else None,
            "coverage": decided_rows / decided_count if decided_count else None,
        },
        "excluded_unknown_reference_ids": excluded_rows,
        "limitations": ["REFERENCE_SCORING_ONLY", "NO_INDEPENDENT_LABEL_AUTHENTICATION"],
    }


def verify_predicate_claim(claim: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """Compare one claim with one exact-identity, committed predicate record.

    The sole v1 contract is TASK_RESOLVED against the explicit
    `pgop1.swebench.task-resolved-boolean.v1` record. This function validates
    record structure and identity; the caller remains responsible for obtaining
    evidence from a trusted source and verifying its byte commitment.
    """
    if not isinstance(claim, dict) or not isinstance(evidence, dict):
        raise ReferenceError("CLAIM_OR_EVIDENCE_INVALID")
    claim_identity = _identity(claim)
    evidence_identity = _identity(evidence)
    predicate = claim["predicate"]
    if predicate != "TASK_RESOLVED":
        return {"verdict": "INSUFFICIENT_EVIDENCE", "reason_code": "PREDICATE_CONTRACT_UNAVAILABLE"}
    if evidence.get("contract") != "pgop1.swebench.task-resolved-boolean.v1":
        return {"verdict": "INSUFFICIENT_EVIDENCE", "reason_code": "EVIDENCE_CONTRACT_UNAVAILABLE"}
    if claim_identity != evidence_identity:
        return {"verdict": "INSUFFICIENT_EVIDENCE", "reason_code": "EVIDENCE_IDENTITY_MISMATCH"}
    asserted = claim.get("asserted_value")
    observed = evidence.get("observed_value")
    if type(asserted) is not bool or type(observed) is not bool:
        raise ReferenceError("PREDICATE_VALUE_INVALID")
    verdict = "SUPPORTED" if asserted is observed else "CONTRADICTED"
    return {"verdict": verdict, "reason_code": "EXACT_PREDICATE_EVIDENCE_MATCH"
            if verdict == "SUPPORTED" else "EXACT_PREDICATE_EVIDENCE_CONTRADICTION"}


__all__ = ["ReferenceError", "evaluate_reference_cases", "verify_predicate_claim"]
