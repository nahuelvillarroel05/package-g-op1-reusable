"""Strict summary contract for the prospective RUN-010 E1 claim evaluation."""
from __future__ import annotations

SCHEMA = "pgop1.run010.semantic-summary.v1"
_TOP = {"schema", "run_id", "counts", "by_provenance_level", "by_reference_type"}
_COUNTS = {
    "selected", "attempted", "processed", "structural", "semantic",
    "abstained", "verification_error", "not_evaluable",
}


class SummaryValidationError(ValueError):
    """A RUN-010 summary violates its explicit accounting contract."""


def _counts(value, name):
    if not isinstance(value, dict):
        raise SummaryValidationError(f"{name} must be an object")
    result = {}
    for key, count in value.items():
        if not isinstance(key, str) or not key:
            raise SummaryValidationError(f"{name} keys must be nonempty strings")
        if type(count) is not int or count < 0:
            raise SummaryValidationError(f"{name} values must be nonnegative integers")
        result[key] = count
    return result


def validate_summary(value: dict) -> dict:
    """Validate counters and return the original mapping unchanged.

    `structural` is an overlapping quality counter. The four terminal outcome
    counters partition processed claims; `semantic` counts definitive
    SUPPORTED/CONTRADICTED decisions only.
    """
    if not isinstance(value, dict) or set(value) != _TOP:
        raise SummaryValidationError("summary fields do not match RUN-010 schema")
    if value["schema"] != SCHEMA:
        raise SummaryValidationError("unsupported RUN-010 summary schema")
    run_id = value["run_id"]
    if not isinstance(run_id, str) or (run_id != "RUN010" and not run_id.startswith("RUN010-")):
        raise SummaryValidationError("run_id must identify RUN-010")
    counts = value["counts"]
    if not isinstance(counts, dict) or set(counts) != _COUNTS:
        raise SummaryValidationError("count fields do not match RUN-010 contract")
    if any(type(v) is not int or v < 0 for v in counts.values()):
        raise SummaryValidationError("counts must be nonnegative integers")
    if counts["attempted"] > counts["selected"]:
        raise SummaryValidationError("attempted exceeds selected")
    if counts["processed"] > counts["attempted"]:
        raise SummaryValidationError("processed exceeds attempted")
    if counts["structural"] > counts["processed"]:
        raise SummaryValidationError("structural exceeds processed")
    terminal = sum(counts[key] for key in
                   ("semantic", "abstained", "verification_error", "not_evaluable"))
    if terminal != counts["processed"]:
        raise SummaryValidationError("terminal outcomes do not partition processed claims")
    for field in ("by_provenance_level", "by_reference_type"):
        dimension = _counts(value[field], field)
        if sum(dimension.values()) != counts["processed"]:
            raise SummaryValidationError(f"{field} does not account for processed claims")
    return value
