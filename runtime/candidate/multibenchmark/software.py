"""Read-only parsers for SWE-bench and SWE-bench Pro task sources.

The adapter normalizes public task records only. It never applies a patch,
executes a verifier, loads an image, or treats task text as an agent claim.
"""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any, Iterator


UNKNOWN = "UNKNOWN"
MAX_SOURCE_FILE_BYTES = 200 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SUPPORTED_PRO_VARIANTS = {"v2"}
_SOURCE_MANIFEST_CACHE: dict[str, dict[str, Any] | None] = {}


class SoftwareSourceError(ValueError):
    """Stable malformed, ambiguous, or unsupported software-source error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise SoftwareSourceError("SOURCE_UNAVAILABLE", "source path cannot be inspected") from exc
    attributes = getattr(info, "st_file_attributes", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _regular_file(path: Path) -> Path:
    candidate = path.absolute()
    cursor = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        cursor /= part
        if _is_reparse(cursor):
            raise SoftwareSourceError("UNSAFE_SOURCE_PATH", "source path contains a link or reparse point")
    try:
        resolved = candidate.resolve(strict=True)
        info = candidate.stat()
    except OSError as exc:
        raise SoftwareSourceError("SOURCE_UNAVAILABLE", "source file is unavailable") from exc
    if resolved != candidate or not stat.S_ISREG(info.st_mode):
        raise SoftwareSourceError("UNSAFE_SOURCE_PATH", "source must be a regular file")
    if info.st_size < 1 or info.st_size > MAX_SOURCE_FILE_BYTES:
        raise SoftwareSourceError("SOURCE_SIZE_LIMIT", "source file is empty or exceeds the per-file limit")
    return candidate


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise SoftwareSourceError("DUPLICATE_JSON_KEY", f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _reject_constant(value: str) -> Any:
    raise SoftwareSourceError("MALFORMED_JSON", f"non-finite JSON number is not allowed: {value}")


def _json_bytes(path: Path) -> Any:
    try:
        raw = _regular_file(path).read_bytes()
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except SoftwareSourceError:
        raise
    except (UnicodeError, json.JSONDecodeError, OSError) as exc:
        raise SoftwareSourceError("MALFORMED_JSON", "JSON source is not valid strict UTF-8 JSON") from exc


def _records_from_json(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        source = _regular_file(path)
        try:
            text = source.read_text(encoding="utf-8", errors="strict")
        except (UnicodeError, OSError) as exc:
            raise SoftwareSourceError("MALFORMED_JSONL", "JSONL source is not valid strict UTF-8") from exc
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line, object_pairs_hook=_strict_object, parse_constant=_reject_constant)
            except (json.JSONDecodeError, SoftwareSourceError) as exc:
                raise SoftwareSourceError("MALFORMED_JSONL", f"invalid JSONL record at line {line_number}") from exc
            if not isinstance(value, dict):
                raise SoftwareSourceError("MALFORMED_RECORD", f"JSONL record at line {line_number} must be an object")
            yield value, f"line:{line_number}"
        return

    value = _json_bytes(path)
    if isinstance(value, list):
        for index, record in enumerate(value):
            if not isinstance(record, dict):
                raise SoftwareSourceError("MALFORMED_RECORD", f"JSON array item {index} must be an object")
            yield record, f"/{index}"
        return
    if isinstance(value, dict) and isinstance(value.get("data"), list):
        for index, record in enumerate(value["data"]):
            if not isinstance(record, dict):
                raise SoftwareSourceError("MALFORMED_RECORD", f"data item {index} must be an object")
            yield record, f"/data/{index}"
        return
    if isinstance(value, dict):
        yield value, ""
        return
    raise SoftwareSourceError("MALFORMED_RECORD", "JSON source must contain an object or an array of objects")


def _records_from_parquet(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    source = _regular_file(path)
    try:
        import pyarrow.parquet as parquet
    except ImportError as exc:
        raise SoftwareSourceError("PARQUET_READER_UNAVAILABLE", "pyarrow is required to parse parquet sources") from exc
    try:
        reader = parquet.ParquetFile(source)
        names = reader.schema_arrow.names
        if len(names) != len(set(names)):
            raise SoftwareSourceError("DUPLICATE_PARQUET_COLUMN", "parquet schema contains duplicate top-level fields")
        row_index = 0
        for batch in reader.iter_batches(batch_size=64):
            for record in batch.to_pylist():
                yield record, UNKNOWN
                row_index += 1
    except SoftwareSourceError:
        raise
    except Exception as exc:
        raise SoftwareSourceError("MALFORMED_PARQUET", "parquet source could not be read") from exc


def _records(path: Path) -> Iterator[tuple[dict[str, Any], str]]:
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl"}:
        yield from _records_from_json(path)
    elif suffix == ".parquet":
        yield from _records_from_parquet(path)
    else:
        raise SoftwareSourceError("UNSUPPORTED_SOURCE_FORMAT", "expected JSON, JSONL, parquet, TOML, or a task directory")


def _first_present(record: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return UNKNOWN


def _task_id(record: dict[str, Any]) -> str:
    value = _first_present(record, "instance_id", "task_id", "id")
    if not isinstance(value, str) or value == UNKNOWN or not TASK_ID_RE.fullmatch(value):
        raise SoftwareSourceError("INVALID_TASK_ID", "task record has a missing or invalid task identifier")
    return value


def _validate_swebench_record(record: dict[str, Any]) -> None:
    required_text = ("instance_id", "repo", "base_commit", "patch", "test_patch", "problem_statement")
    for key in required_text:
        value = record.get(key)
        if not isinstance(value, str) or (key != "patch" and not value.strip()):
            raise SoftwareSourceError("INVALID_SWEBENCH_RECORD", f"SWE-bench record requires a valid {key}")
    if not COMMIT_RE.fullmatch(record["base_commit"]):
        raise SoftwareSourceError("INVALID_SWEBENCH_RECORD", "SWE-bench base_commit must be a 40-character lowercase commit hash")
    pro_markers = {"docker_image", "dockerhub_tag", "hard", "issue_categories"}
    if pro_markers.intersection(record) or record.get("version") == "2.0.0":
        raise SoftwareSourceError("MIXED_BENCHMARK_FAMILY", "SWE-bench parser received a SWE-bench Pro shaped record")


def _category(record: dict[str, Any]) -> Any:
    return _first_present(record, "original_category", "category", "issue_categories")


def _capabilities(record: dict[str, Any]) -> Any:
    return _first_present(record, "capabilities", "skills", "tags")


def _source_revision_for(path: Path) -> str:
    """Return a revision only when a neighboring manifest commits exact bytes."""
    try:
        resolved = path.resolve(strict=True)
        raw = resolved.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
    except OSError:
        return UNKNOWN
    for directory in resolved.parents:
        manifest_path = directory / "SOURCE_MANIFEST.json"
        if not manifest_path.is_file():
            continue
        cache_key = str(manifest_path.absolute())
        if cache_key not in _SOURCE_MANIFEST_CACHE:
            try:
                value = _json_bytes(manifest_path)
                _SOURCE_MANIFEST_CACHE[cache_key] = value if isinstance(value, dict) else None
            except SoftwareSourceError:
                _SOURCE_MANIFEST_CACHE[cache_key] = None
        manifest = _SOURCE_MANIFEST_CACHE[cache_key]
        if not isinstance(manifest, dict) or manifest.get("schema") != "pgop1.multibenchmark.software-acquisition.v1":
            return UNKNOWN
        root_value = manifest.get("corpus_root")
        if not isinstance(root_value, str):
            return UNKNOWN
        try:
            corpus_root = Path(root_value).resolve(strict=True)
            relative_path = resolved.relative_to(corpus_root).as_posix()
        except (OSError, ValueError):
            return UNKNOWN
        for entry in manifest.get("files", []):
            if (
                isinstance(entry, dict)
                and entry.get("path") == relative_path
                and entry.get("bytes") == len(raw)
                and entry.get("sha256") == digest
            ):
                revision = manifest.get("source_revision")
                return revision if isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision) else UNKNOWN
        return UNKNOWN
    return UNKNOWN


def _row_task(
    record: dict[str, Any],
    path: Path,
    pointer: str,
    *,
    family: str,
    explicit_variant: str | None = None,
) -> dict[str, Any]:
    task_id = _task_id(record)
    category = _category(record)
    capabilities = _capabilities(record)
    if "patch" in record and "test_patch" in record:
        reference_type = "reference_patch_with_test_patch"
    elif "patch" in record or "gold_patch" in record:
        reference_type = "reference_patch"
    else:
        reference_type = UNKNOWN
    evaluator_type = _first_present(record, "eval_type", "evaluator_type")
    if evaluator_type == UNKNOWN and "test_patch" in record:
        evaluator_type = "test_patch"
    metadata = dict(record)
    if pointer.startswith("line:"):
        metadata["source_line_number"] = int(pointer.split(":", 1)[1])
    return {
        "task_id": task_id,
        "source_family_id": family,
        "original_category": category,
        "metadata": metadata,
        "capabilities": capabilities,
        "reference_type": reference_type,
        "evaluator_type": evaluator_type,
        "source_path": str(path.absolute()),
        "source_revision": UNKNOWN,
        "source_pointer": pointer,
    }


def _parse_records(
    path: Path,
    *,
    family: str,
    expected_variant: str | None = None,
) -> list[dict[str, Any]]:
    output = []
    seen: set[str] = set()
    for record, pointer in _records(path):
        if family == "swebench":
            _validate_swebench_record(record)
        task = _row_task(record, path, pointer, family=family, explicit_variant=expected_variant)
        if task["task_id"] in seen:
            raise SoftwareSourceError("DUPLICATE_TASK_ID", f"duplicate task identifier: {task['task_id']}")
        seen.add(task["task_id"])
        output.append(task)
    if not output:
        raise SoftwareSourceError("EMPTY_SOURCE", "source contains no task records")
    return output


def parse_swebench(path: str | os.PathLike[str], *, expected_variant: str | None = None) -> list[dict[str, Any]]:
    """Parse SWE-bench JSON/JSONL/parquet into task records.

    The optional variant is an explicit caller binding (for example ``full`` or
    ``verified``); it is never inferred from the source path.
    """
    source = Path(path)
    if expected_variant is not None and (not isinstance(expected_variant, str) or not expected_variant.strip()):
        raise SoftwareSourceError("INVALID_VARIANT", "expected_variant must be a non-empty string when supplied")
    return _parse_records(source, family="swebench", expected_variant=expected_variant)


def _toml_task_id(config: dict[str, Any]) -> str:
    task_section = config.get("task")
    if not isinstance(task_section, dict):
        raise SoftwareSourceError("MALFORMED_TASK_CONFIG", "Harbor task TOML must contain a task table")
    name = task_section.get("name")
    if not isinstance(name, str) or not name:
        raise SoftwareSourceError("INVALID_TASK_ID", "Harbor task config has no task.name")
    if not name.startswith('swebench-pro/instance_') or name.count('/') != 1:
        raise SoftwareSourceError('MIXED_BENCHMARK_FAMILY', 'Harbor task is outside the supported swebench-pro/instance_ namespace')
    candidate = name.rsplit("/", 1)[-1]
    if candidate == UNKNOWN or not TASK_ID_RE.fullmatch(candidate):
        raise SoftwareSourceError("INVALID_TASK_ID", "Harbor task config has an invalid task.name identifier")
    return candidate


def _parse_harbor_task(config_path: Path, expected_variant: str | None) -> dict[str, Any]:
    config_path = _regular_file(config_path)
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8", errors="strict"))
    except SoftwareSourceError:
        raise
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SoftwareSourceError("MALFORMED_TASK_CONFIG", "Harbor task TOML is malformed or invalid UTF-8") from exc
    task_id = _toml_task_id(config)
    metadata = config.get("metadata", {})
    if not isinstance(metadata, dict):
        raise SoftwareSourceError("MALFORMED_TASK_CONFIG", "Harbor metadata must be a TOML table")
    verifier = config.get("verifier", {})
    if not isinstance(verifier, dict):
        raise SoftwareSourceError("MALFORMED_TASK_CONFIG", "Harbor verifier must be a TOML table")
    task_dir = config_path.parent
    parent_id = task_dir.name
    if parent_id.startswith("instance_") and parent_id != task_id:
        raise SoftwareSourceError("TASK_ID_PATH_MISMATCH", "Harbor task identifier differs from its directory identity")
    instruction_path = task_dir / "instruction.md"
    if instruction_path.exists():
        source_path = _regular_file(instruction_path)
    else:
        source_path = config_path
    verifier_test = task_dir / "tests" / "test.sh"
    solution_patch = task_dir / "solution" / "gold_patch.diff"
    tags = metadata.get("tags", UNKNOWN)
    category = _first_present(metadata, "original_category", "category")
    artifact_references = []
    ancillary_artifacts = []
    artifact_paths = sorted(item for item in task_dir.rglob("*") if item.is_file())
    if len(artifact_paths) > MAX_SOURCE_FILES:
        raise SoftwareSourceError("SOURCE_FILE_COUNT_LIMIT", "Harbor task exceeds the related-artifact limit")
    for artifact in artifact_paths:
        artifact_file = _regular_file(artifact)
        artifact_bytes = artifact_file.read_bytes()
        relative_parts = artifact.relative_to(task_dir).parts
        if artifact.name == "task.toml":
            role = "TASK_CONFIGURATION"
        elif artifact.name == "instruction.md":
            role = "TASK_INSTRUCTION"
        elif relative_parts and relative_parts[0] == "tests":
            role = "EVALUATOR_SOURCE"
        elif relative_parts and relative_parts[0] == "solution":
            role = "REFERENCE_SOLUTION"
        elif relative_parts and relative_parts[0] == "environment":
            role = "ENVIRONMENT_CONFIGURATION"
        else:
            role = "RELATED_TASK_ARTIFACT"
        artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        artifact_references.append({
            "path": str(artifact_file.absolute()),
            "bytes": len(artifact_bytes),
            "sha256": artifact_sha256,
        })
        ancillary_artifacts.append({
            "path": str(artifact_file.absolute()),
            "role": role,
            "sha256": artifact_sha256,
        })
    source_metadata: dict[str, Any] = {
        "task_config": config,
        "verifier_network_mode": verifier.get("network_mode", UNKNOWN),
        "verifier_config_path": str(config_path.absolute()),
        "instruction_path": str(instruction_path.absolute()) if instruction_path.exists() else UNKNOWN,
        "instruction_text": source_path.read_text(encoding="utf-8", errors="strict") if source_path == instruction_path else UNKNOWN,
        "declared_version": config.get("schema_version", UNKNOWN),
        "artifact_references": artifact_references,
        "ancillary_artifacts": ancillary_artifacts,
        "evaluator_path": str(verifier_test.absolute()) if verifier_test.is_file() else UNKNOWN,
        "reference_path": str(solution_patch.absolute()) if solution_patch.is_file() else UNKNOWN,
    }
    return {
        "task_id": task_id,
        "source_family_id": "swebench_pro",
        "original_category": category,
        "metadata": source_metadata,
        "capabilities": tags,
        "reference_type": "gold_patch.diff" if solution_patch.is_file() else UNKNOWN,
        "evaluator_type": "Harbor tests/test.sh" if verifier_test.is_file() else UNKNOWN,
        "source_path": str(source_path.absolute()),
        "source_revision": _source_revision_for(source_path),
        "source_pointer": UNKNOWN,
    }


def parse_swebench_pro(
    path: str | os.PathLike[str],
    *,
    expected_variant: str | None = None,
) -> list[dict[str, Any]]:
    """Parse SWE-bench Pro JSON/JSONL/parquet or Harbor V2 task sources.

    ``expected_variant="v2"`` is an explicit caller binding for Harbor task
    directories. It is recorded as a requested filter and is not inferred from
    directory names or from Harbor schema versions.
    """
    if expected_variant is not None and (
        not isinstance(expected_variant, str) or expected_variant not in SUPPORTED_PRO_VARIANTS
    ):
        raise SoftwareSourceError("UNSUPPORTED_VARIANT", "only explicit SWE-bench Pro variant v2 is supported")
    source = Path(path)
    for component in (source.absolute(), *source.absolute().parents):
        if _is_reparse(component):
            raise SoftwareSourceError('UNSAFE_SOURCE_PATH', 'source path contains a link or reparse point')
    if source.is_file():
        if source.suffix.lower() == ".toml" and source.name == "task.toml":
            return [_parse_harbor_task(source, expected_variant)]
        if source.name == "instruction.md":
            task_config = source.parent / "task.toml"
            if not task_config.is_file():
                raise SoftwareSourceError("MISSING_TASK_CONFIG", "Harbor instruction has no sibling task.toml")
            return [_parse_harbor_task(task_config, expected_variant)]
        raise SoftwareSourceError("UNSUPPORTED_SOURCE_FORMAT", "SWE-bench Pro parser accepts acquired Harbor V2 task.toml or instruction.md sources only")
    try:
        root = source.resolve(strict=True)
    except OSError as exc:
        raise SoftwareSourceError("SOURCE_UNAVAILABLE", "SWE-bench Pro directory is unavailable") from exc
    if not root.is_dir():
        raise SoftwareSourceError("UNSAFE_SOURCE_PATH", "SWE-bench Pro source must be a file or directory")
    if (root / "task.toml").is_file():
        configs = [root / "task.toml"]
    else:
        configs = []
        for current, directories, names in os.walk(root, followlinks=False):
            for directory in directories:
                if _is_reparse(Path(current) / directory):
                    raise SoftwareSourceError('UNSAFE_SOURCE_PATH', 'source directory contains a link or reparse point')
            if 'task.toml' in names:
                configs.append(Path(current) / 'task.toml')
        configs.sort()
    if len(configs) > MAX_SOURCE_FILES:
        raise SoftwareSourceError("SOURCE_FILE_COUNT_LIMIT", "Harbor task directory exceeds file-count limit")
    if not configs:
        raise SoftwareSourceError("EMPTY_SOURCE", "directory contains no Harbor task.toml files")
    output = []
    seen: set[str] = set()
    for config_path in configs:
        task = _parse_harbor_task(config_path, expected_variant)
        if task["task_id"] in seen:
            raise SoftwareSourceError("DUPLICATE_TASK_ID", f"duplicate task identifier: {task['task_id']}")
        seen.add(task["task_id"])
        output.append(task)
    return output
