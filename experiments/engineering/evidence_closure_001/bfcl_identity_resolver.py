"""Experimental BFCL prompt identity resolver. It performs no evaluator work."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Sequence

FORMAT_ID = re.compile(r"^format_sensitivity_([0-9]+):([^:]+):([A-Za-z0-9_-]+)$")


@dataclass(frozen=True)
class TaskRef:
    category: str
    task_id: str
    source_path: str
    source_sha256: str
    source_row_index: int
    source_row_sha256: str
    has_function: bool


def resolve_identity(
    task_id: str,
    category: str,
    task_index: Mapping[str, Sequence[TaskRef]],
    format_allowlist: Mapping[str, set[str]],
    reserved_ids: set[str],
    valid_format_configs: set[str] | None = None,
) -> dict:
    """Resolve exact prompt-row identity without asserting evaluator compatibility.

    Direct IDs require one exact source row in the same category. Format variants
    remain unresolved: a config name and base allowlist cannot establish the
    exact official (variant index, config, base) tuple or transformed prompt.
    Reserved simple_python IDs are rejected before any source-map lookup.
    """
    if task_id in reserved_ids:
        return {"identity_status": "RESERVE_BLOCKED", "identity_kind": "DIRECT_RESERVED_ID"}

    if category == "format_sensitivity":
        match = FORMAT_ID.fullmatch(task_id)
        if not match:
            return {"identity_status": "UNRESOLVED_FORMAT_ID_SHAPE", "identity_kind": "FORMAT_VARIANT"}
        variant_index, config, base_id = match.groups()
        if base_id in reserved_ids:
            return {"identity_status": "RESERVE_BLOCKED", "identity_kind": "FORMAT_VARIANT_RESERVED_BASE"}
        # Config/base lists alone cannot prove this exact transformed task.
        # Keep arguments for the existing caller; they grant no new identity.
        return {"identity_status": "FORMAT_CONFIG_NOT_PINNED", "identity_kind": "FORMAT_VARIANT", "base_task_id": base_id}

    candidates = list(task_index.get(task_id, ()))
    if len(candidates) > 1:
        return {"identity_status": "AMBIGUOUS_SOURCE_ID", "identity_kind": "DIRECT_ID", "candidate_count": len(candidates)}
    if not candidates:
        return {"identity_status": "NO_EXACT_TASK_ID_SOURCE", "identity_kind": "DIRECT_ID"}
    if candidates[0].category != category:
        return {
            "identity_status": "WRONG_CATEGORY_SOURCE",
            "identity_kind": "DIRECT_ID",
            "source_category": candidates[0].category,
        }
    return {
        "identity_status": "EXACT_PROMPT_IDENTITY",
        "identity_kind": "DIRECT_ID",
        "task_ref": candidates[0],
        "structural_schema_status": "FUNCTION_SCHEMA_PRESENT" if candidates[0].has_function else "FUNCTION_SCHEMA_MISSING",
    }
