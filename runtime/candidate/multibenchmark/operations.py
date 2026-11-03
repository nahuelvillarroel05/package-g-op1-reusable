"""Read-only structural adapters for pinned Terminal-Bench 2 and MCPMark tasks.

These functions parse public metadata and point to published evaluators. They do
not import or execute task instructions, verifier scripts, Dockerfiles, or code.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import tomllib
from typing import Any

UNKNOWN = "UNKNOWN"
_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
_TB_NAME = re.compile(r"^terminal-bench/([a-z0-9]+(?:-[a-z0-9]+)*)$")
_MCP_SERVICE_ALIASES = {"playwright_webarena": "playwright"}


def _reject_reparse_ancestors(path: Path) -> None:
    """Reject symlinks and Windows junction/reparse ancestors before reading."""
    candidate = path.expanduser().absolute()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for item in list(reversed(candidate.parents)) + [candidate]:
        try:
            details = item.lstat()
        except FileNotFoundError:
            continue
        attributes = getattr(details, "st_file_attributes", 0)
        if item.is_symlink() or attributes & reparse_flag:
            raise ValueError(f"reparse point or symlink is not permitted in source path: {item}")


def _resolved(path: str | Path) -> Path:
    raw = Path(path).expanduser().absolute()
    _reject_reparse_ancestors(raw)
    candidate = raw.resolve(strict=True)
    if candidate.is_file():
        return candidate
    if not candidate.is_dir():
        raise ValueError(f"source path is not a file or task directory: {path}")
    return candidate


def _plain_file_exists(path: Path) -> bool:
    _reject_reparse_ancestors(path)
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except FileNotFoundError:
        return False


def _plain_directory_exists(path: Path) -> bool:
    _reject_reparse_ancestors(path)
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except FileNotFoundError:
        return False


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a nonempty string")
    return value.strip()


def _identifier(value: Any, field: str) -> str:
    result = _required_text(value, field)
    if not _ID.fullmatch(result):
        raise ValueError(f"{field} is not a valid benchmark identifier: {result!r}")
    return result


def _string_list(value: Any, field: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ValueError(f"{field} must be {'a nonempty ' if not allow_empty else 'a '}list of strings")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{field} contains a non-string or empty value")
    if len(set(value)) != len(value):
        raise ValueError(f"{field} contains duplicate values")
    return list(value)


def _artifact(path: Path, role: str) -> dict[str, Any]:
    _reject_reparse_ancestors(path)
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"expected file for {role}: {resolved}")
    content = resolved.read_bytes()
    return {
        "role": role,
        "path": str(resolved),
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON numeric constant: {value}")


def _source_revision(path: Path, repo: str, marker: str) -> str:
    """Return a revision only when a pinned manifest SHA-256 matches these bytes."""
    _reject_reparse_ancestors(path)
    indexes = [i for i, component in enumerate(path.parts) if component == marker]
    if not indexes:
        return UNKNOWN
    source_root = Path(*path.parts[: indexes[-1] + 1])
    relative = path.relative_to(source_root).as_posix()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    workspace_root = Path(__file__).resolve().parents[6]
    manifest_path = workspace_root / "Engineering" / "PGOP1_MULTIBENCHMARK_001" / "operations" / "acquisition_004" / "manifest.json"
    try:
        _reject_reparse_ancestors(manifest_path)
        data = json.loads(manifest_path.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object, parse_constant=_reject_json_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return UNKNOWN
    if not isinstance(data, dict) or data.get("status") != "ACQUIRED_PUBLIC_BYTES_ONLY":
        return UNKNOWN
    entries = data.get("files", [])
    if not isinstance(entries, list):
        return UNKNOWN
    matches = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        if (item.get("repository", "").rstrip("/") == f"https://github.com/{repo}"
                and item.get("path") == relative and item.get("sha256") == digest):
            matches.append(item.get("revision"))
    if len(matches) == 1 and isinstance(matches[0], str) and matches[0]:
        return matches[0]
    return UNKNOWN


def _single(record: dict[str, Any]) -> list[dict[str, Any]]:
    return [record]


def parse_terminal_bench(path: str | Path) -> list[dict[str, Any]]:
    """Parse one Harbor-format Terminal-Bench task directory or task file.

    `path` may be a task directory, `task.toml`, `instruction.md`, or a file in
    `tests/`. The source task configuration is required; no category or
    capability is inferred from free-text descriptions.
    """
    source = _resolved(path)
    task_dir = source if source.is_dir() else (source.parent.parent if source.parent.name == "tests" else source.parent)
    task_file_candidate = task_dir / "task.toml"
    if not _plain_file_exists(task_file_candidate):
        raise ValueError(f"missing Terminal-Bench task.toml: {task_file_candidate}")
    task_file = task_file_candidate.resolve(strict=True)
    try:
        document = tomllib.loads(task_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError(f"invalid Terminal-Bench task.toml: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("task"), dict) or not isinstance(document.get("metadata"), dict):
        raise ValueError("Terminal-Bench task.toml must contain [task] and [metadata] tables")
    _required_text(document.get("schema_version"), "schema_version")
    task, metadata = document["task"], document["metadata"]
    match = _TB_NAME.fullmatch(_required_text(task.get("name"), "task.name"))
    if not match:
        raise ValueError("task.name must use the terminal-bench/<kebab-case-id> format")
    task_id = match.group(1)
    if task_dir.name != task_id:
        raise ValueError(f"task directory name {task_dir.name!r} does not match task.name {task_id!r}")
    category = _identifier(metadata.get("category"), "metadata.category")
    capabilities = _string_list(task.get("keywords", []), "task.keywords")
    test_dir = task_dir / "tests"
    shell_test = test_dir / "test.sh"
    python_tests = sorted(p for p in test_dir.glob("*.py") if _plain_file_exists(p)) if _plain_directory_exists(test_dir) else []
    if not _plain_file_exists(shell_test) or not python_tests:
        raise ValueError("Terminal-Bench task must have tests/test.sh and at least one tests/*.py evaluator")
    artifacts = [
        _artifact(task_file, "task_config"),
        _artifact(task_dir / "instruction.md", "task_instruction"),
        _artifact(shell_test, "verifier_entrypoint"),
    ]
    artifacts.extend(_artifact(p, "verifier_source") for p in python_tests)
    dockerfile = task_dir / "environment" / "Dockerfile"
    if _plain_file_exists(dockerfile):
        artifacts.append(_artifact(dockerfile, "environment_build_config"))
    explicit = {
        "schema_version": document.get("schema_version"),
        "task_name": task["name"],
        "task_keywords": capabilities,
        "difficulty": metadata.get("difficulty"),
        "category": metadata["category"],
        "tags": metadata.get("tags"),
        "verifier_timeout_sec": (document.get("verifier") or {}).get("timeout_sec") if isinstance(document.get("verifier"), dict) else None,
        "environment": document.get("environment"),
    }
    record = {
        "task_id": task_id,
        "source_family_id": "terminal-bench-2.0",
        "original_category": category,
        "metadata": {"explicit_fields": explicit, "ancillary_artifacts": artifacts},
        "capabilities": capabilities,
        "reference_type": "public_task_verifier",
        "evaluator_type": "shell_entrypoint_with_python_tests",
        "source_path": str(task_file),
        "source_revision": _source_revision(task_file, "harbor-framework/terminal-bench-2", "terminal-bench-2"),
        "source_pointer": UNKNOWN,
    }
    return _single(record)


def parse_mcpmark(path: str | Path) -> list[dict[str, Any]]:
    """Parse one MCPMark task directory or one of its task files."""
    source = _resolved(path)
    task_dir = source if source.is_dir() else source.parent
    if source.is_file() and source.name in {"meta.json", "description.md", "verify.py"}:
        task_dir = source.parent
    meta_candidate = task_dir / "meta.json"
    if not _plain_file_exists(meta_candidate):
        raise ValueError(f"missing MCPMark meta.json: {meta_candidate}")
    meta_file = meta_candidate.resolve(strict=True)
    try:
        metadata = json.loads(meta_file.read_text(encoding="utf-8"), object_pairs_hook=_strict_json_object, parse_constant=_reject_json_constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid MCPMark meta.json: {exc}") from exc
    if not isinstance(metadata, dict):
        raise ValueError("MCPMark meta.json must contain a JSON object")
    parts = task_dir.parts
    if len(parts) < 5 or parts[-5] != "tasks":
        raise ValueError("MCPMark task directory must be tasks/<service>/<suite>/<category>/<task>")
    service, suite, category_segment, task_segment = parts[-4:]
    _identifier(service, "service")
    if suite not in {"standard", "easy"}:
        raise ValueError(f"unsupported MCPMark suite identifier: {suite!r}")
    task_id = _identifier(metadata.get("task_id"), "task_id")
    if task_id != task_segment:
        raise ValueError(f"meta.json task_id {task_id!r} does not match directory {task_segment!r}")
    category = _identifier(metadata.get("category_id"), "category_id")
    if category != category_segment:
        raise ValueError(f"meta.json category_id {category!r} does not match directory {category_segment!r}")
    declared_mcps = _string_list(metadata.get("mcp"), "mcp", allow_empty=False)
    declared_service = _MCP_SERVICE_ALIASES.get(service, service)
    if declared_service not in declared_mcps:
        raise ValueError(f"task path service {service!r} is absent from meta.json mcp list")
    capabilities = _string_list(metadata.get("tags", []), "tags")
    description = task_dir / "description.md"
    verifier = task_dir / "verify.py"
    if not _plain_file_exists(description) or not _plain_file_exists(verifier):
        raise ValueError("MCPMark task must have description.md and verify.py")
    artifacts = [
        _artifact(meta_file, "task_metadata"),
        _artifact(description, "task_description"),
        _artifact(verifier, "verifier_source"),
    ]
    explicit = {
        "declared_task_id": task_id,
        "task_name": metadata.get("task_name"),
        "category_id": category,
        "category_name": metadata.get("category_name"),
        "difficulty": metadata.get("difficulty"),
        "mcp": declared_mcps,
        "tags": capabilities,
        "created_at": metadata.get("created_at"),
    }
    qualified_id = "/".join((service, suite, category, task_id))
    record = {
        "task_id": qualified_id,
        "source_family_id": "mcpmark",
        "original_category": category,
        "metadata": {"explicit_fields": explicit, "ancillary_artifacts": artifacts,
                     "task_service": service, "task_suite": suite},
        "capabilities": capabilities,
        "reference_type": "public_task_verifier",
        "evaluator_type": "python_verify_script",
        "source_path": str(meta_file),
        "source_revision": _source_revision(meta_file, "eval-sys/mcpmark", "mcpmark"),
        "source_pointer": "/task_id",
    }
    return _single(record)
