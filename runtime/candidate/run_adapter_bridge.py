"""Capability-indexed bridge to existing task parsers and Context Engine.

This module only records task definitions. It never executes benchmark tasks,
agents, verifiers, evaluators, network calls, or model code.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from runtime.candidate.context_engine import Engine
from runtime.candidate.multibenchmark.core import (
    EvidenceError, FAMILIES, UNKNOWN, checked_source, ingest, normalize, parse_committed, recover,
)


@dataclass(frozen=True)
class FamilyAdapter:
    family: str
    versions: tuple[str, ...]
    parser: str
    capability_ids: tuple[str, ...]


CAPABILITY_OPERATIONS = {
    "DISCOVER": "SUPPORTED_BY_EXISTING_FAMILY_PARSER",
    "VALIDATE": "SUPPORTED_BY_EXISTING_FAMILY_PARSER_AND_ENVELOPE_VALIDATOR",
    "NORMALIZE": "SUPPORTED_BY_EXISTING_TASK_ONLY_NORMALIZER",
    "AUDIT": "TASK_DEFINITION_BOUNDARY_CHECK_ONLY_SEMANTIC_AUDIT_UNSUPPORTED",
    "PERSIST": "SUPPORTED_BY_EXISTING_CONTEXT_ENGINE_INGEST",
    "RECOVER": "SUPPORTED_BY_EXISTING_CONTEXT_ENGINE_READBACK",
}


# These are explicit family-level affordances, not claims that a task or agent
# demonstrated the capability. Per-task parser labels are retained separately.
FAMILY_ADAPTERS = {
    "swebench": FamilyAdapter("swebench", ("full", "lite", "verified", "multilingual"), "software.parse_swebench", ("software_issue_resolution",)),
    "swebench_pro_v2": FamilyAdapter("swebench_pro_v2", ("V2",), "software.parse_swebench_pro", ("software_issue_resolution",)),
    "terminal_bench_2": FamilyAdapter("terminal_bench_2", ("2.0",), "operations.parse_terminal_bench", ("terminal_environment_task",)),
    "mcpmark_verified": FamilyAdapter("mcpmark_verified", (), "operations.parse_mcpmark", ("mcp_tool_environment_task",)),
    "bfcl_v4": FamilyAdapter("bfcl_v4", ("V4",), "calling.parse_bfcl", ("function_calling_task",)),
    "tau_bench": FamilyAdapter("tau_bench", ("2.0.0:text-v1",), "calling.parse_tau", ("stateful_tool_environment_task",)),
}


def family_capabilities() -> dict[str, tuple[str, ...]]:
    """Return a stable copy of the explicit family capability registry."""
    return {family: adapter.capability_ids for family, adapter in FAMILY_ADAPTERS.items()}


def family_operations() -> dict[str, dict[str, str]]:
    """Return explicit operation availability, including unsupported semantic audit."""
    return {family: dict(CAPABILITY_OPERATIONS) for family in FAMILY_ADAPTERS}


def _validate_family_version(family: str, version: str, revision: str) -> None:
    if family not in FAMILIES or family not in FAMILY_ADAPTERS:
        raise EvidenceError("unsupported benchmark family")
    adapter = FAMILY_ADAPTERS[family]
    if adapter.versions and version not in adapter.versions:
        raise EvidenceError("unsupported benchmark version")
    if family == "mcpmark_verified" and (not revision or revision == UNKNOWN or version != "Verified@" + revision[:12]):
        raise EvidenceError("MCPMark Verified requires matching pinned revision")


def process_authored_unit(
    engine: Engine, *, family: str, version: str, revision: str,
    source_path: str | Path, task_id: str, source_sha256: str,
    allowed_roots, source_commitments, source_session=None,
) -> dict:
    """Parse, bind, ingest, and reread one already-authored synthetic unit.

    Caller owns synthetic source creation and explicit root/hash commitments.
    The returned receipt establishes source-bound task persistence only.
    """
    _validate_family_version(family, version, revision)
    if not isinstance(source_commitments, dict):
        raise EvidenceError("synthetic source commitments required")
    original = Path(source_path).absolute()
    # Validate containment/reparse ancestry and the byte commitment before any
    # parser touches the caller-provided source.
    from runtime.candidate.multibenchmark.core import checked_path
    path = checked_path(original, allowed_roots)
    if source_commitments.get(str(path)) != source_sha256:
        raise EvidenceError("synthetic source commitment missing")
    path, _ = checked_source(path, allowed_roots, source_sha256)
    parsed = [row for row in parse_committed(family,path,allowed_roots,source_commitments) if row.get("task_id") == task_id]
    if len(parsed) != 1:
        raise EvidenceError(f"expected exactly one parsed task identity for {family}:{task_id}")
    task = parsed[0]
    envelope = normalize(
        task, benchmark_id=family, version=version, revision=revision,
        source_sha256=source_sha256, allowed_roots=allowed_roots,
        source_commitments=source_commitments, source_session=source_session,
    )
    if (envelope["audit_verdict"] != "NOT_EVALUATED" or envelope["evaluator_executed"] is not False
            or envelope["gate11_eligible"] is not False or envelope["agent_statement"] != UNKNOWN
            or envelope["trajectory_id"] != UNKNOWN or envelope["evaluator_result"] != UNKNOWN):
        raise EvidenceError("task-only evidence boundary violated")
    expected = {key: envelope[key] for key in (
        "benchmark_id", "benchmark_version", "task_id", "source_revision", "source_sha256")}
    receipt = ingest(engine, envelope, allowed_roots=allowed_roots,
                     source_commitments=source_commitments, expected_identity=expected,
                     source_session=source_session)
    recovered = recover(engine, receipt)
    if recovered != envelope:
        raise EvidenceError("Context Engine same-process readback differs")
    capabilities = task.get("capabilities", UNKNOWN)
    declared_capabilities = isinstance(capabilities, list)
    return {
        "family": family,
        "task_id": task_id,
        "source_sha256": source_sha256,
        "capability_ids": list(FAMILY_ADAPTERS[family].capability_ids),
        "task_capabilities": list(capabilities) if declared_capabilities else UNKNOWN,
        "task_capabilities_status": "DECLARED_METADATA" if declared_capabilities else UNKNOWN,
        "operation_capabilities": dict(CAPABILITY_OPERATIONS),
        "receipt": receipt,
        "processing_status": "SOURCE_BOUND_TASK_DEFINITION_STORED_AND_READ_BACK",
        "evaluator_status": "NOT_RUN",
        "semantic_status": "UNKNOWN",
    }
