# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Bounded Engineering composition over the preserved Fiveflow totals path."""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import io
import os
import re
import stat
import sys
import subprocess
import shutil
import threading
import uuid
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

WORKSPACE = Path(__file__).resolve().parent
ENGINE_ROOT = WORKSPACE / "engine"
RUNS_ROOT = WORKSPACE / "runs"
INPUTS_ROOT = WORKSPACE / "inputs"
PROVIDER_ID = "safe.synthetic.totals.v1"
CASE_ID = "CASE-LOCAL-TOTALS"
INPUT_SCHEMA = "pg_i7.input.v1"
RUN_SCHEMA = "pg_i7.run.v1"
MAX_INPUT_BYTES = 16384
MAX_VALUES = 64
MIN_VALUE = -(2**31)
MAX_VALUE = 2**31 - 1
EXPECTED_OPERATIONS = frozenset({"inspect", "demo", "run", "graph", "verify", "query", "recover"})
ENGINEERING_ROOT = Path(r"PRIVATE_ENGINEERING_NOT_DISTRIBUTED")
R5_PRIMARY_READER_SHA256 = "f8a2d357cd79a3bff0c197564cbfffedf192600ec851608fda5dfe03e6dd1b21"
R5_OWNER_CHECKPOINT_SEAL_SHA256 = "755c8e53d1b5f8dff99cfc1fbe16e20d1fe42f1b9d4061c3e6e5f9ae59bf8f90"
VALIDATION_ROOT = Path(r"PRIVATE_VALIDATION_NOT_DISTRIBUTED")
FOCUSED_PROFILE_SHA256 = "3709ed8f3409f2252925bfca1fad6f9d0f653a170081893a5dac0c76138cc457"


def _discover_focused_root() -> tuple[Path, tuple[str, str] | None]:
    start = Path(os.path.abspath(os.fspath(Path(__file__).parent)))
    for candidate in list(start.parents)[:5]:
        profile = candidate / "FOCUSED_WORKSPACE_PROFILE.json"
        if not os.path.lexists(profile):
            continue
        cursor = Path(profile.anchor)
        try:
            for component in profile.parts[1:]:
                cursor = cursor / component
                if os.path.lexists(cursor):
                    attrs = getattr(cursor.lstat(), "st_file_attributes", 0)
                    if cursor.is_symlink() or attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                        return candidate, ("FOCUSED_PROFILE_REPARSE", "focused workspace profile path contains a reparse point")
            if hashlib.sha256(profile.read_bytes()).hexdigest() != FOCUSED_PROFILE_SHA256:
                return candidate, ("FOCUSED_PROFILE_PIN_MISMATCH", "focused workspace profile pin mismatch")
        except OSError:
            return candidate, ("FOCUSED_PROFILE_UNREADABLE", "focused workspace profile is not readable")
        return candidate, None
    return start, ("FOCUSED_PROFILE_NOT_FOUND", "focused workspace profile was not found in bounded CLI ancestry")


FOCUSED_ROOT, FOCUSED_PROFILE_ERROR = _discover_focused_root()
SOURCE_BASELINE = FOCUSED_ROOT / "run_inputs"
CAMPAIGN_ROOT = FOCUSED_ROOT / "campaigns"
SOURCE_COPY_MANIFEST = FOCUSED_ROOT / "SOURCE_COPY_MANIFEST.json"
SOURCE_COPY_MANIFEST_SHA256 = "0d56b655d576832c85da034775794b6cddae9b6d935ee72944858ba1e30f7954"
PROSPECTIVE_SOURCE_COPY_MANIFEST_SHA256 = "aa25512d1762f8264b1b5f4a9df0180ef1f85cb2ee16bb929d03acec7cc6cf23"
REAL_DOCUMENT_SELECTION = FOCUSED_ROOT / "REAL_DOCUMENT_SELECTION.json"
REAL_DOCUMENT_SELECTION_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
WORKSPACE_BINDING_NAME = "FOCUSED_WORKSPACE_BINDING.json"
WORKSPACE_PRODUCER_INTENT_NAME = "WORKSPACE_PRODUCER_INTENT.json"
WORKSPACE_CLOSED_NAME = "WORKSPACE_CLOSED.json"
ACTIVE_OUTPUT_DIR: Path | None = None
_EXECUTION_LOCK = threading.Lock()


class I7Error(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class StructuredArgumentParser(argparse.ArgumentParser):
    json_help = False

    def error(self, message: str) -> None:
        raise I7Error("CLI_ARGUMENT_ERROR", message)

    def print_help(self, file: Any = None) -> None:
        if self.json_help:
            print(json.dumps({"schema": "pg_i7.help.v1", "status": "HELP", "help": self.format_help()},
                             ensure_ascii=True, sort_keys=True, separators=(",", ":")), file=file or sys.stdout)
            return
        super().print_help(file)


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number: " + value)


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate JSON object key: " + key)
        obj[key] = value
    return obj


def _parse_json(body: bytes, label: str) -> Any:
    try:
        return json.loads(body.decode("utf-8"), object_pairs_hook=_object_no_duplicates, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise I7Error("INVALID_JSON", f"{label}: {exc}") from exc


def _is_reparse(path: Path) -> bool:
    try:
        attrs = path.lstat().st_file_attributes
    except AttributeError:
        return path.is_symlink()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _lexical_path(value: str | os.PathLike[str], *, must_exist: bool, base: Path | None = None) -> Path:
    return _checked_absolute(value, base=base or WORKSPACE, must_exist=must_exist)


def _within(path: Path, parent: Path, *, allow_equal: bool = False) -> bool:
    try:
        rel = path.relative_to(parent)
    except ValueError:
        return False
    return allow_equal or bool(rel.parts)


def _workspace_output_dir(value: str | None) -> Path:
    runs = _lexical_path("runs", must_exist=False, base=WORKSPACE)
    path = runs if value is None else _checked_absolute(value, base=WORKSPACE, must_exist=False)
    if value is None:
        return path
    if not _beneath(path, runs) or not _same_path(path.parent, runs):
        raise I7Error("OUTPUT_NOT_FRESH_RUN_CHILD", "mutable outputs must use a fresh direct child beneath runs/")
    if path.exists() and not path.is_dir():
        raise I7Error("OUTPUT_NOT_DIRECTORY", "output directory is not a directory")
    return path


def _normpath(path: Path) -> str:
    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))


def _same_path(left: Path, right: Path) -> bool:
    return _normpath(left) == _normpath(right)


def _beneath(path: Path, parent: Path, *, equal: bool = False) -> bool:
    child_norm, parent_norm = _normpath(path), _normpath(parent)
    if child_norm == parent_norm:
        return equal
    return child_norm.startswith(parent_norm.rstrip("\\/") + os.sep)


def _object_id(path: Path) -> tuple[int, int]:
    info = path.stat(follow_symlinks=False)
    return int(info.st_dev), int(info.st_ino)


def _checked_absolute(value: str | os.PathLike[str], *, base: Path, must_exist: bool) -> Path:
    raw_text = os.fspath(value)
    if not isinstance(raw_text, str) or raw_text.startswith(("\\\\", "//", "\\??\\")):
        raise I7Error("PATH_NAMESPACE_REJECTED", "device, extended-length, and UNC path namespaces are not accepted")
    raw = Path(raw_text)
    if raw.drive and not raw.is_absolute():
        raise I7Error("DRIVE_RELATIVE_PATH_REJECTED", "drive-relative paths are not accepted")
    if ".." in raw.parts:
        raise I7Error("PATH_TRAVERSAL", "parent traversal is not allowed in paths")
    for part in raw.parts:
        if part in {raw.anchor, "\\", "/"}:
            continue
        if (part.endswith((".", " ")) or any(ch in part for ch in '<>:"|?*')
                or part.upper().split(".", 1)[0] in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", part.upper().split(".", 1)[0])):
            raise I7Error("WINDOWS_PATH_COMPONENT_REJECTED", "path contains a reserved or ambiguous Windows component")
    lexical = Path(os.path.abspath(os.fspath(raw if raw.is_absolute() else base / raw)))
    cursor = Path(lexical.anchor)
    observed: list[tuple[Path, tuple[int, int]]] = []
    for component in lexical.parts[1:]:
        cursor = cursor / component
        if os.path.lexists(cursor):
            info = cursor.lstat()
            if _is_reparse(cursor):
                raise I7Error("REPARSE_PATH", f"reparse point in path: {cursor}")
            if stat.S_ISREG(info.st_mode) and int(getattr(info, "st_nlink", 1)) != 1:
                raise I7Error("HARDLINK_PATH_REJECTED", f"multiply-linked regular file is not accepted: {cursor}")
            resolved = Path(os.path.abspath(os.path.realpath(os.fspath(cursor))))
            if not _same_path(cursor, resolved) or not os.path.samefile(cursor, resolved):
                raise I7Error("PATH_OBJECT_CHANGED", f"canonical path/object mismatch: {cursor}")
            observed.append((cursor, (int(info.st_dev), int(info.st_ino))))
    if must_exist and not lexical.exists():
        raise I7Error("PATH_NOT_FOUND", f"path does not exist: {lexical}")
    if not lexical.exists():
        nearest = lexical.parent
        while not os.path.lexists(nearest) and nearest != nearest.parent:
            nearest = nearest.parent
        if not nearest.exists() or not nearest.is_dir():
            raise I7Error("PATH_PARENT_NOT_FOUND", f"no existing directory ancestor for path: {lexical}")
    for observed_path, original_id in observed:
        try:
            current = observed_path.lstat()
        except OSError as exc:
            raise I7Error("PATH_ANCESTOR_CHANGED", "path ancestor disappeared during validation") from exc
        if _is_reparse(observed_path) or (int(current.st_dev), int(current.st_ino)) != original_id:
            raise I7Error("PATH_ANCESTOR_CHANGED", "path ancestor object changed during validation")
    return lexical


def _write_probe(directory: Path) -> None:
    directory = _checked_absolute(directory, base=FOCUSED_ROOT, must_exist=True)
    if not directory.is_dir():
        raise I7Error("WRITE_PROBE_NOT_DIRECTORY", "effective write probe target is not a directory")
    before_id = _object_id(directory)
    probe = directory / (".pg-i7-write-probe-" + uuid.uuid4().hex)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(probe, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"pg-i7-effective-write-probe-v1\n")
            stream.flush()
            os.fsync(stream.fileno())
        if probe.read_bytes() != b"pg-i7-effective-write-probe-v1\n":
            raise I7Error("WRITE_PROBE_READBACK_FAILED", "effective write probe bytes did not read back")
        if _object_id(directory) != before_id:
            raise I7Error("WRITE_PROBE_PARENT_CHANGED", "write-probe parent object changed during probe")
        probe.unlink()
        if probe.exists():
            raise I7Error("WRITE_PROBE_DELETE_FAILED", "effective write probe file could not be removed")
    except I7Error:
        raise
    except OSError as exc:
        raise I7Error("EFFECTIVE_WRITE_DENIED", f"effective create/write/read/delete probe failed: {exc}") from exc


def _source_copy_rows() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = _checked_absolute(SOURCE_COPY_MANIFEST, base=FOCUSED_ROOT, must_exist=True)
    raw = manifest_path.read_bytes()
    if _sha(raw) != SOURCE_COPY_MANIFEST_SHA256:
        raise I7Error("SOURCE_COPY_MANIFEST_PIN_MISMATCH", "published source-copy manifest changed")
    manifest = _parse_json(raw, "source-copy manifest")
    rows = manifest.get("members") if type(manifest) is dict else None
    if (manifest.get("schema") != "i7.focused.source-copy-manifest.v1" or type(rows) is not list
            or manifest.get("member_count") != len(rows)):
        raise I7Error("SOURCE_COPY_MANIFEST_INVALID", "published source-copy manifest is malformed")
    return manifest, rows


def _prospective_copy_manifest() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = FOCUSED_ROOT / "PROSPECTIVE_SOURCE_COPY_MANIFEST.json"
    raw = _checked_absolute(path, base=FOCUSED_ROOT, must_exist=True).read_bytes()
    expected = globals().get("PROSPECTIVE_SOURCE_COPY_MANIFEST_SHA256")
    if not isinstance(expected, str) or _sha(raw) != expected:
        raise I7Error("PROSPECTIVE_SOURCE_MANIFEST_PIN_MISMATCH", "prospective source-copy manifest is not pinned")
    manifest = _parse_json(raw, "prospective source-copy manifest")
    rows = manifest.get("members") if type(manifest) is dict else None
    if (manifest.get("schema") != "i7.focused.prospective-source-copy-manifest.v1"
            or type(rows) is not list or manifest.get("member_count") != len(rows)):
        raise I7Error("PROSPECTIVE_SOURCE_MANIFEST_INVALID", "prospective source-copy manifest is malformed")
    return manifest, rows


def _check_source_tree(root: Path, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checked: list[dict[str, Any]] = []
    root_id = _object_id(root)
    for row in rows:
        rel, size, digest = row.get("path"), row.get("bytes"), row.get("sha256")
        if (not isinstance(rel, str) or not rel or Path(rel).is_absolute() or Path(rel).drive
                or ".." in Path(rel).parts or type(size) is not int
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise I7Error("SOURCE_COPY_MEMBER_INVALID", "source-copy member row is malformed")
        path = _checked_absolute(root / rel, base=root, must_exist=True)
        if not _beneath(path, root) or not path.is_file():
            raise I7Error("SOURCE_COPY_PATH_INVALID", "source-copy member escaped the candidate root")
        body = path.read_bytes()
        if len(body) != size or _sha(body) != digest:
            raise I7Error("SOURCE_COPY_PIN_MISMATCH", f"source-copy member pin mismatch: {rel}")
        checked.append({"path": rel, "bytes": size, "sha256": digest})
    if _object_id(root) != root_id:
        raise I7Error("SOURCE_COPY_ROOT_CHANGED", "source-copy root object changed during validation")
    return checked


def _composition_cli_pin(root: Path) -> str:
    path = _checked_absolute(root / "I7_LOCAL_COMPOSITION_MANIFEST.json", base=root, must_exist=True)
    manifest = _parse_json(path.read_bytes(), "composition manifest")
    matches = [row for row in manifest.get("components", [])
               if type(row) is dict and row.get("workspace_path") == "pg_i7.py" and row.get("runtime_pin") is True]
    if len(matches) != 1 or not isinstance(matches[0].get("sha256"), str):
        raise I7Error("COMPOSITION_CLI_PIN_MISSING", "composition manifest must pin exactly one active CLI source")
    return matches[0]["sha256"]


def _validate_workspace_root(value: str | os.PathLike[str]) -> Path:
    path = _checked_absolute(value, base=CAMPAIGN_ROOT, must_exist=False)
    if not _beneath(path, CAMPAIGN_ROOT):
        raise I7Error("WORKSPACE_OUTSIDE_ALLOWLIST", "workspace must be a child of the focused campaigns root")
    if path.exists() and (not path.is_dir() or _same_path(path, CAMPAIGN_ROOT)):
        raise I7Error("WORKSPACE_NOT_DIRECTORY", "workspace path must be a dedicated directory")
    return path


def _copy_candidate_workspace(target: Path) -> None:
    source_manifest, published_rows = _source_copy_rows()
    prospective, rows = _prospective_copy_manifest()
    source_root = _checked_absolute(FOCUSED_ROOT / "candidate", base=FOCUSED_ROOT, must_exist=True)
    if not source_root.is_dir():
        raise I7Error("SOURCE_CANDIDATE_MISSING", "pinned candidate source directory is unavailable")
    source_checked = _check_source_tree(source_root, rows)
    published_paths = {row.get("path") for row in published_rows if type(row) is dict}
    excluded = {"pg_i7.py", "I7_LOCAL_COMPOSITION_MANIFEST.json"}
    additions = prospective.get("explicit_additions")
    addition_paths = [row.get("path") for row in additions] if type(additions) is list else []
    if (addition_paths != ["context_engine.py", "i7_api.py", "prospective_adapter.py", "readonly_recovery.py", "documents_policy.py", "deps/i4_i5/I4_I5_DEPENDENCY_MANIFEST.json", "documents_policy_manifest.json", "schemas/pg_i7.documents.selection.v2.json"]
            or len(published_paths) != source_manifest.get("member_count")
            or set(row["path"] for row in source_checked)
            != (published_paths - excluded) | set(addition_paths)):
        raise I7Error("SOURCE_COPY_MEMBER_COUNT_MISMATCH", "prospective copy set must equal the frozen subset plus the five explicit API/policy/NEXT modules")
    cli_sha = _composition_cli_pin(source_root)
    composition_manifest = source_root / "I7_LOCAL_COMPOSITION_MANIFEST.json"
    composition_manifest_sha = _sha(composition_manifest.read_bytes())
    cli_path = source_root / "pg_i7.py"
    cli_body = cli_path.read_bytes()
    if _sha(cli_body) != cli_sha:
        raise I7Error("SOURCE_COPY_CLI_PIN_MISMATCH", "prospective CLI differs from its composition manifest pin")
    target.mkdir(mode=0o700, parents=False, exist_ok=False)
    target_id = _object_id(target)
    _write_probe(target)
    for row in source_checked:
        source = source_root / row["path"]
        destination = target / row["path"]
        parent = destination.parent
        if not parent.exists():
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = _checked_absolute(parent, base=target, must_exist=True)
        if not _beneath(parent, target, equal=True):
            raise I7Error("WORKSPACE_COPY_PATH_REDIRECT", "candidate copy destination is redirected")
        parent_id = _object_id(parent)
        if destination.exists():
            raise I7Error("WORKSPACE_COPY_COLLISION", "candidate copy destination already exists")
        body = source.read_bytes()
        if len(body) != row["bytes"] or _sha(body) != row["sha256"]:
            raise I7Error("SOURCE_COPY_PIN_MISMATCH", f"candidate changed during copy: {row['path']}")
        with destination.open("xb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        if _object_id(parent) != parent_id:
            raise I7Error("WORKSPACE_COPY_PARENT_CHANGED", "candidate destination parent changed during copy")
    cli_destination = target / "pg_i7.py"
    with cli_destination.open("xb") as stream:
        stream.write(cli_body)
        stream.flush()
        os.fsync(stream.fileno())
    with (target / "I7_LOCAL_COMPOSITION_MANIFEST.json").open("xb") as stream:
        body = composition_manifest.read_bytes()
        if _sha(body) != composition_manifest_sha:
            raise I7Error("COMPOSITION_MANIFEST_CHANGED", "composition manifest changed during candidate copy")
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
    if _object_id(target) != target_id:
        raise I7Error("WORKSPACE_OBJECT_CHANGED", "workspace directory object changed during source copy")
    binding = {"schema": "i7.focused.workspace-binding.v1", "workspace": str(target),
               "workspace_object_id": list(target_id), "published_source_manifest_sha256": SOURCE_COPY_MANIFEST_SHA256,
               "prospective_source_manifest_sha256": _sha((FOCUSED_ROOT / "PROSPECTIVE_SOURCE_COPY_MANIFEST.json").read_bytes()),
               "cli_sha256": cli_sha,
               "composition_manifest_sha256": composition_manifest_sha,
               "source_bundle_sha256": source_manifest.get("source_bundle_sha256"),
               "member_count": len(source_checked), "members": source_checked,
               "mutable_state_root": "engine", "mutable_output_root": "runs"}
    binding_path = target / WORKSPACE_BINDING_NAME
    with binding_path.open("xb") as stream:
        stream.write(_json_bytes(binding))
        stream.flush()
        os.fsync(stream.fileno())


def _validate_workspace_binding(root: Path) -> None:
    root = _checked_absolute(root, base=CAMPAIGN_ROOT, must_exist=True)
    if not _beneath(root, CAMPAIGN_ROOT) or not root.is_dir():
        raise I7Error("WORKSPACE_OUTSIDE_ALLOWLIST", "active workspace is outside the focused campaigns root")
    binding_path = _checked_absolute(root / WORKSPACE_BINDING_NAME, base=root, must_exist=True)
    binding = _parse_json(binding_path.read_bytes(), "workspace binding")
    if (binding.get("schema") != "i7.focused.workspace-binding.v1"
            or not _same_path(Path(binding.get("workspace", "")), root)
            or binding.get("workspace_object_id") != list(_object_id(root))
            or binding.get("published_source_manifest_sha256") != SOURCE_COPY_MANIFEST_SHA256):
        raise I7Error("WORKSPACE_BINDING_INVALID", "workspace lacks an exact focused bootstrap binding")
    _, rows = _prospective_copy_manifest()
    if binding.get("members") != rows or binding.get("member_count") != len(rows):
        raise I7Error("WORKSPACE_SOURCE_BINDING_MISMATCH", "workspace source members differ from the selected code pins")
    _check_source_tree(root, rows)
    cli_path = _checked_absolute(root / "pg_i7.py", base=root, must_exist=True)
    cli_sha = _composition_cli_pin(root)
    if binding.get("cli_sha256") != cli_sha or _sha(cli_path.read_bytes()) != cli_sha:
        raise I7Error("WORKSPACE_CLI_PIN_MISMATCH", "workspace CLI differs from its prospective composition pin")
    composition_manifest = _checked_absolute(root / "I7_LOCAL_COMPOSITION_MANIFEST.json", base=root, must_exist=True)
    candidate_manifest = _checked_absolute(FOCUSED_ROOT / "candidate" / "I7_LOCAL_COMPOSITION_MANIFEST.json",
                                           base=FOCUSED_ROOT, must_exist=True)
    if (_sha(composition_manifest.read_bytes()) != binding.get("composition_manifest_sha256")
            or _sha(composition_manifest.read_bytes()) != _sha(candidate_manifest.read_bytes())):
        raise I7Error("WORKSPACE_MANIFEST_PIN_MISMATCH", "workspace composition manifest differs from its pinned candidate")


def _require_bound_workspace() -> None:
    if FOCUSED_PROFILE_ERROR is not None:
        raise I7Error(FOCUSED_PROFILE_ERROR[0], FOCUSED_PROFILE_ERROR[1])
    if not _beneath(WORKSPACE, CAMPAIGN_ROOT):
        raise I7Error("WORKSPACE_REQUIRED", "direct API calls require a bound focused campaign workspace")
    _validate_workspace_binding(WORKSPACE)
    if str(WORKSPACE) not in sys.path:
        sys.path.insert(0, str(WORKSPACE))


def _require_workspace_open(root: Path | None = None) -> None:
    root = WORKSPACE if root is None else root
    marker = _checked_absolute(root / WORKSPACE_CLOSED_NAME, base=root, must_exist=False)
    if marker.exists():
        raise I7Error("WORKSPACE_CLOSED", "workspace is sealed for read-only verification and recovery")


def _consume_producer_intent(kind: str) -> str:
    """Reserve the workspace for its sole source-reading or engine producer operation."""
    _require_bound_workspace()
    _require_workspace_open()
    marker = _checked_absolute(WORKSPACE / WORKSPACE_PRODUCER_INTENT_NAME,
                               base=WORKSPACE, must_exist=False)
    body = _json_bytes({"schema": "pg_i7.workspace-producer-intent.v1",
                        "kind": kind, "status": "CONSUMED_NO_RETRY",
                        "operation_id": "INTENT-" + uuid.uuid4().hex})
    try:
        with marker.open("xb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise I7Error("WORKSPACE_PRODUCER_ALREADY_USED",
                      "this workspace already consumed its one producer intent; start a fresh workspace") from exc
    _checked_absolute(marker, base=WORKSPACE, must_exist=True)
    return json.loads(body.decode("utf-8"))["operation_id"]


def _assert_pipeline_intent(operation_id: str | None = None) -> None:
    marker = _checked_absolute(WORKSPACE / WORKSPACE_PRODUCER_INTENT_NAME,
                               base=WORKSPACE, must_exist=True)
    intent = _parse_json(marker.read_bytes(), "workspace producer intent")
    if (type(intent) is not dict or intent.get("kind") != "pipeline-documents-to-totals"
            or intent.get("status") != "CONSUMED_NO_RETRY"
            or not isinstance(intent.get("operation_id"), str)
            or not intent["operation_id"].startswith("INTENT-")
            or (operation_id is not None and intent["operation_id"] != operation_id)):
        raise I7Error("PIPELINE_INTENT_INVALID", "pipeline continuation requires its exact consumed producer intent")


def _enable_local_i4_i5_dependency_path() -> None:
    """Expose the preinstalled JSON Schema dependency under -I without network or installation."""
    import site
    user_site = site.getusersitepackages()
    if not isinstance(user_site, str) or not user_site:
        raise I7Error("FROZEN_DEPENDENCY_UNAVAILABLE", "Python user-site package root is unavailable")
    path = _checked_absolute(user_site, base=FOCUSED_ROOT, must_exist=True)
    if not path.is_dir():
        raise I7Error("FROZEN_DEPENDENCY_UNAVAILABLE", "Python user-site package root is not a directory")
    if str(path) not in sys.path:
        sys.path.append(str(path))


def _ensure_workspace(value: str, command: str) -> Path:
    target = _validate_workspace_root(value)
    mutating = command in {"demo", "run", "pipeline", "documents-inspect", "documents-prepare",
                          "documents-validate", "engineering-documents", "engineering-adapt-documents"}
    if mutating and not CAMPAIGN_ROOT.exists():
        campaign_root = _checked_absolute(CAMPAIGN_ROOT, base=FOCUSED_ROOT, must_exist=False)
        if not _same_path(campaign_root.parent, FOCUSED_ROOT):
            raise I7Error("WORKSPACE_CAMPAIGNS_ROOT_INVALID", "campaign workspace root must be a direct child of the focused campaign")
        parent_id = _object_id(FOCUSED_ROOT)
        _write_probe(FOCUSED_ROOT)
        try:
            campaign_root.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise I7Error("WORKSPACE_CAMPAIGNS_ROOT_COLLISION", "campaign workspaces root appeared during exclusive creation") from exc
        if _object_id(FOCUSED_ROOT) != parent_id or _is_reparse(campaign_root):
            raise I7Error("WORKSPACE_CAMPAIGNS_ROOT_CHANGED", "campaign workspaces root changed during creation")
    if not target.exists():
        if not mutating:
            raise I7Error("WORKSPACE_NOT_INITIALIZED", "read-only command requires an existing bound workspace")
        _write_probe(target.parent)
        _copy_candidate_workspace(target)
    _validate_workspace_binding(target)
    if mutating:
        _require_workspace_open(target)
    return target


def _route_workspace(args: argparse.Namespace, original_args: list[str]) -> int | None:
    if not isinstance(args.workspace_dir, str) or not args.workspace_dir:
        raise I7Error("WORKSPACE_REQUIRED", "every CLI command requires --workspace-dir")
    forwarded = list(original_args)
    for index, token in enumerate(forwarded):
        if args.command == "run" and token == "--input" and index + 1 < len(forwarded):
            raw_input = Path(forwarded[index + 1])
            if raw_input.drive and not raw_input.is_absolute():
                raise I7Error("DRIVE_RELATIVE_PATH_REJECTED", "drive-relative input paths are not accepted")
            if ".." in raw_input.parts:
                raise I7Error("PATH_TRAVERSAL", "parent traversal is not allowed in input paths")
            forwarded[index + 1] = os.path.abspath(os.fspath(raw_input))
        elif args.command == "run" and token.startswith("--input="):
            raw_input = Path(token.split("=", 1)[1])
            if raw_input.drive and not raw_input.is_absolute():
                raise I7Error("DRIVE_RELATIVE_PATH_REJECTED", "drive-relative input paths are not accepted")
            if ".." in raw_input.parts:
                raise I7Error("PATH_TRAVERSAL", "parent traversal is not allowed in input paths")
            forwarded[index] = "--input=" + os.path.abspath(os.fspath(raw_input))
    workspace_operation = ("documents-" + args.documents_action if args.command == "documents"
                           else args.command)
    target = _ensure_workspace(args.workspace_dir, workspace_operation)
    if _same_path(WORKSPACE, target):
        return None
    child = target / "pg_i7.py"
    if not child.is_file():
        raise I7Error("WORKSPACE_CLI_MISSING", "bound workspace does not contain the selected CLI")
    for index, token in enumerate(forwarded):
        if token == "--workspace-dir" and index + 1 < len(forwarded):
            forwarded[index + 1] = str(target)
        elif token.startswith("--workspace-dir="):
            forwarded[index] = "--workspace-dir=" + str(target)
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["TEMP"] = r"PRIVATE_PROJECT_NOT_DISTRIBUTED\Temp"
    env["TMP"] = r"PRIVATE_PROJECT_NOT_DISTRIBUTED\Temp"
    try:
        completed = subprocess.run([sys.executable, "-I", "-B", str(child), *forwarded],
                                   cwd=str(target), env=env, shell=False, check=False)
    except OSError as exc:
        raise I7Error("WORKSPACE_COMMAND_START_FAILED", f"focused workspace command could not start: {exc}") from exc
    return int(completed.returncode)


def _strict_input(value: str | None, *, demo: bool) -> tuple[dict[str, Any], str, bytes]:
    if demo:
        body = _json_bytes({"schema": INPUT_SCHEMA, "values": [3, 5, 8, 13, 21]})
        source = "<built-in-demo>"
    else:
        if not value:
            raise I7Error("INPUT_REQUIRED", "run requires --input FILE")
        candidate = _checked_absolute(value, base=WORKSPACE, must_exist=True)
        if _beneath(candidate, WORKSPACE) and candidate.is_file():
            path = candidate
        else:
            source_root = _checked_absolute(SOURCE_BASELINE, base=FOCUSED_ROOT, must_exist=True)
            if not _beneath(candidate, source_root):
                raise I7Error("INPUT_SOURCE_SCOPE", "external run input must be an explicit file beneath run_inputs/")
            path = _checked_absolute(candidate, base=source_root, must_exist=True)
            if not path.is_file():
                raise I7Error("INPUT_NOT_FILE", "input must be a workspace file or an explicit file below run_inputs/")
        before = path.stat()
        before_id = (int(before.st_dev), int(before.st_ino), int(before.st_size), int(before.st_mtime_ns))
        if before.st_size > MAX_INPUT_BYTES:
            raise I7Error("INPUT_TOO_LARGE", f"input exceeds {MAX_INPUT_BYTES} bytes")
        with path.open("rb") as stream:
            body = stream.read(MAX_INPUT_BYTES + 1)
        after = path.stat()
        after_id = (int(after.st_dev), int(after.st_ino), int(after.st_size), int(after.st_mtime_ns))
        _checked_absolute(path, base=WORKSPACE if _beneath(path, WORKSPACE) else SOURCE_BASELINE, must_exist=True)
        if before_id != after_id or not path.is_file():
            raise I7Error("INPUT_SOURCE_CHANGED", "explicit input identity or size changed during the bounded read")
        if len(body) > MAX_INPUT_BYTES:
            raise I7Error("INPUT_TOO_LARGE", f"input exceeds {MAX_INPUT_BYTES} bytes")
        if not _beneath(path, WORKSPACE):
            source = str(path)
            if not INPUTS_ROOT.exists():
                _checked_absolute(INPUTS_ROOT, base=WORKSPACE, must_exist=False)
                _write_probe(WORKSPACE)
                try:
                    INPUTS_ROOT.mkdir(mode=0o700, exist_ok=False)
                except FileExistsError as exc:
                    raise I7Error("INPUT_STAGE_COLLISION", "workspace input stage appeared during exclusive creation") from exc
            stage_path = _checked_absolute(INPUTS_ROOT / (_sha(body) + ".json"), base=WORKSPACE, must_exist=False)
            if not _beneath(stage_path, INPUTS_ROOT):
                raise I7Error("INPUT_STAGE_SCOPE", "staged input path escaped the workspace input directory")
            try:
                with stage_path.open("xb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError as exc:
                raise I7Error("INPUT_STAGE_COLLISION", "staged input already exists in this fresh workspace") from exc
            if _sha(stage_path.read_bytes()) != _sha(body):
                raise I7Error("INPUT_STAGE_PIN_MISMATCH", "staged input bytes differ from the explicit source")
            source = str(stage_path)
        else:
            source = str(path)
    doc = _parse_json(body, "input")
    if type(doc) is not dict or set(doc) != {"schema", "values"}:
        raise I7Error("INPUT_SCHEMA", "input must contain exactly schema and values")
    if doc["schema"] != INPUT_SCHEMA:
        raise I7Error("INPUT_SCHEMA", f"expected schema {INPUT_SCHEMA}")
    values = doc["values"]
    if type(values) is not list or not 1 <= len(values) <= MAX_VALUES:
        raise I7Error("INPUT_VALUES", f"values must be a list of 1..{MAX_VALUES} integers")
    if any(type(item) is not int or not MIN_VALUE <= item <= MAX_VALUE for item in values):
        raise I7Error("INPUT_VALUES", "values must be bounded 32-bit JSON integers; booleans are excluded")
    return {"schema": INPUT_SCHEMA, "values": list(values)}, source, body


def _source_commitments() -> dict[str, str]:
    manifest_path = _lexical_path("I7_LOCAL_COMPOSITION_MANIFEST.json", must_exist=True, base=WORKSPACE)
    if not _within(manifest_path, WORKSPACE):
        raise I7Error("COMPOSITION_MANIFEST_OUTSIDE_WORKSPACE", "composition manifest is outside the workspace")
    manifest = _parse_json(manifest_path.read_bytes(), "composition manifest")
    if type(manifest) is not dict or type(manifest.get("components")) is not list:
        raise I7Error("COMPOSITION_MANIFEST_INVALID", "composition manifest has an invalid component list")
    commitments: dict[str, str] = {}
    seen: set[str] = set()
    for entry in manifest["components"]:
        if type(entry) is not dict:
            raise I7Error("COMPOSITION_MANIFEST_INVALID", "composition manifest components must be objects")
        path = entry.get("workspace_path")
        digest = entry.get("sha256")
        role = entry.get("role")
        runtime_pin = entry.get("runtime_pin", True)
        source_path = entry.get("source_path")
        source_digest = entry.get("source_sha256")
        if (not isinstance(path, str) or not path.strip()
                or not isinstance(role, str) or not role.strip()
                or not isinstance(digest, str) or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)
                or type(runtime_pin) is not bool
                or (source_path is not None and (not isinstance(source_path, str) or not source_path.strip()))
                or (source_digest is not None and (not isinstance(source_digest, str) or len(source_digest) != 64
                    or any(ch not in "0123456789abcdef" for ch in source_digest)))
                or path in seen):
            raise I7Error("COMPOSITION_MANIFEST_INVALID", "composition manifest component has invalid or duplicate pins")
        seen.add(path)
        if runtime_pin:
            commitments[path] = digest
    return commitments


def _expected_engine_source_pins() -> dict[str, str]:
    engine_root = _lexical_path("engine", must_exist=True, base=WORKSPACE)
    if not _within(engine_root, WORKSPACE) or not engine_root.is_dir():
        raise I7Error("ENGINE_OUTSIDE_WORKSPACE", "engine root is outside the composition workspace")
    config_path = _lexical_path("CONFIG.json", must_exist=True, base=engine_root)
    config = _parse_json(config_path.read_bytes(), "engine config")
    for key in ("integration_root", "prospective_root"):
        configured = config.get(key)
        if not isinstance(configured, str) or not configured or Path(configured).is_absolute() or Path(configured).drive:
            raise I7Error("LEGACY_CONFIG_PATH_REJECTED", f"engine config {key} must be an unambiguous relative path")
        resolved_config_path = Path(os.path.abspath(os.fspath(engine_root / configured)))
        if not _within(resolved_config_path, WORKSPACE):
            raise I7Error("LEGACY_CONFIG_PATH_REJECTED", f"engine config {key} escapes the bound workspace")
        _checked_absolute(resolved_config_path, base=WORKSPACE, must_exist=True)
    pins: dict[str, str] = {}
    for candidate in sorted(engine_root.glob("*.py")):
        path = _lexical_path(candidate.name, must_exist=True, base=engine_root)
        if not _within(path, WORKSPACE) or not path.is_file():
            raise I7Error("ENGINE_OUTSIDE_WORKSPACE", "engine source is outside the composition workspace")
        pins[str(path)] = _sha(path.read_bytes())
    pins[str(config_path)] = _sha(config_path.read_bytes())
    baseline_pins = config.get("baseline_pins")
    if type(baseline_pins) is not dict or not baseline_pins:
        raise I7Error("ENGINE_CONFIG_INVALID", "engine config baseline_pins must be a nonempty object")
    for relative_path, digest in baseline_pins.items():
        if type(relative_path) is not str or Path(relative_path).is_absolute() or Path(relative_path).drive:
            raise I7Error("DEPENDENCY_PATH_INVALID", "engine dependency pin must be a relative path")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise I7Error("DEPENDENCY_PIN_INVALID", "engine dependency digest must be lowercase SHA-256")
        # The frozen CONFIG intentionally uses ../deps paths. Normalize that
        # trusted, pinned input before applying the same lexical/reparse checks.
        normalized = Path(os.path.abspath(os.fspath(engine_root / relative_path)))
        path = _checked_absolute(normalized, base=WORKSPACE, must_exist=True)
        if not _within(path, WORKSPACE):
            raise I7Error("DEPENDENCY_OUTSIDE_WORKSPACE", "engine dependency escaped workspace")
        pins[relative_path] = digest
    return pins


def _validate_composition_bindings(record: dict[str, Any]) -> None:
    expected = _source_commitments()
    if record.get("source_commitments") != expected:
        raise I7Error("COMPOSITION_PIN_MISMATCH", "run record composition pins do not match the local manifest")
    for relative_path, digest in expected.items():
        path = _lexical_path(relative_path, must_exist=True, base=WORKSPACE)
        if not _within(path, WORKSPACE) or _sha(path.read_bytes()) != digest:
            raise I7Error("COMPOSITION_PIN_MISMATCH", f"composition source pin mismatch: {relative_path}")


def _load_engine():
    _require_bound_workspace()
    # Imports are fixed to the copied composition and the composition pin is checked
    # before the historical guard or provider can execute.
    engine_root = _lexical_path("engine", must_exist=True, base=WORKSPACE)
    if not _within(engine_root, WORKSPACE) or not engine_root.is_dir():
        raise I7Error("ENGINE_OUTSIDE_WORKSPACE", "engine root is outside the composition workspace")
    for name, expected in _source_commitments().items():
        path = _lexical_path(name, must_exist=True, base=WORKSPACE)
        if not _within(path, WORKSPACE) or not path.is_file() or _sha(path.read_bytes()) != expected:
            raise I7Error("COMPOSITION_PIN_MISMATCH", f"composition source pin mismatch: {name}")
    expected_modules = {
        "engine": engine_root / "engine.py",
        "runtime": engine_root / "runtime.py",
        "bounded_adapter": engine_root / "bounded_adapter.py",
        "loader": WORKSPACE / "deps" / "Engineering" / "I7-Integration-20261014T1430Z" / "loader.py",
        "durable_registry": WORKSPACE / "deps" / "Engineering" / "I7-Integration-20261014T1430Z" / "durable_registry.py",
        "integration": WORKSPACE / "deps" / "Engineering" / "I7-Integration-20261014T1430Z" / "integration.py",
    }
    for module_name, expected_path in expected_modules.items():
        loaded = sys.modules.get(module_name)
        if loaded is not None:
            loaded_file = getattr(loaded, "__file__", None)
            if not isinstance(loaded_file, str) or Path(os.path.abspath(loaded_file)) != expected_path:
                raise I7Error("IMPORT_COLLISION", f"preloaded module {module_name} is not from the fixed composition path")
    if str(engine_root) not in sys.path:
        sys.path.insert(0, str(engine_root))
    import engine  # type: ignore[import-not-found]
    import bounded_adapter  # type: ignore[import-not-found]
    import runtime  # type: ignore[import-not-found]
    for module_name, module in (("engine", engine), ("bounded_adapter", bounded_adapter), ("runtime", runtime)):
        expected_path = expected_modules[module_name]
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str) or Path(os.path.abspath(module_file)) != expected_path:
            raise I7Error("IMPORT_COLLISION", f"loaded module {module_name} is not from the fixed composition path")
    if Path(runtime.ROOT) != engine_root:
        raise I7Error("ENGINE_ROOT_MISMATCH", "runtime root differs from the fixed composition engine root")
    return engine, bounded_adapter, runtime


def inspect(*, data_digest: bool = False, causal_data: bool = False, provenance: bool = False) -> dict[str, Any]:
    manifest = _parse_json((WORKSPACE / "I7_LOCAL_COMPOSITION_MANIFEST.json").read_bytes(), "composition manifest")
    pins = _source_commitments()
    for relative, expected in pins.items():
        path = _lexical_path(relative, must_exist=True, base=WORKSPACE)
        if not _within(path, WORKSPACE) or _sha(path.read_bytes()) != expected:
            raise I7Error("COMPOSITION_PIN_MISMATCH", f"composition source pin mismatch: {relative}")
    return {
        "schema": "pg_i7.inspect.v1",
        "status": "AVAILABLE",
        "composition_id": manifest.get("composition_id"),
        "composition_status": manifest.get("status"),
        "components": [{"path": row["workspace_path"], "sha256": row["sha256"], "role": row["role"], "source_path": row.get("source_path"), "source_sha256": row.get("source_sha256")} for row in manifest.get("components", []) if row.get("runtime_pin", True)],
        "provider_registry": {
            PROVIDER_ID: {"output_schema": "engineering.totals.v1", "source": "existing Fiveflow structured totals provider and consumer"},
            "safe.documents.metadata.v1": {"output_schema": "i7.engineering.document-scan@1",
                                             "selection": "exact pinned eight-document manifest",
                                             "source": "preserved exact v1 guarded Engineering document scanner"},
            "safe.documents.metadata.v2": {"output_schema": "i7.engineering.document-scan.v2",
                                             "selection": "fixed-root policy-bound pg_i7.documents.selection.v2",
                                             "source": "same bounded metadata scan path with streaming v2 selection"}},
        "operations": sorted((*EXPECTED_OPERATIONS, "pipeline", "documents", "run_provider", "get_provenance")),
        "artifact_flags": {"data_digest": data_digest, "causal_data": causal_data, "provenance": provenance},
        "authority_scope": "LOCAL_SYNTHETIC_ENGINEERING_ONLY",
        "protected_operations": "NOT_AVAILABLE",
        "python_runtime": {"version": sys.version.split()[0], "stdlib_only_core": True},
    }


def _new_output_dir(path: Path, operation_id: str, *, explicit: bool) -> Path:
    runs = _lexical_path("runs", must_exist=False, base=WORKSPACE)
    if explicit and (not _same_path(path.parent, runs) or not _beneath(path, runs)):
        raise I7Error("OUTPUT_NOT_FRESH_RUN_CHILD", "explicit output must be a fresh direct child beneath runs/")
    if not runs.exists():
        _write_probe(WORKSPACE)
        try:
            runs.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise I7Error("OUTPUT_PARENT_COLLISION", "runs directory appeared during exclusive creation") from exc
    if _is_reparse(runs) or not _beneath(runs, WORKSPACE):
        raise I7Error("OUTPUT_OUTSIDE_WORKSPACE", "runs directory is redirected or outside the workspace")
    parent_id = _object_id(runs)
    _write_probe(runs)
    out = path if explicit else runs / operation_id
    try:
        out.mkdir(mode=0o700, exist_ok=False)
    except FileExistsError as exc:
        raise I7Error("REPLAY_REJECTED", "output directory already exists; each operation requires a fresh directory") from exc
    if _object_id(runs) != parent_id or not _beneath(out, runs):
        raise I7Error("OUTPUT_PARENT_CHANGED", "output parent object changed during exclusive creation")
    _checked_absolute(out, base=WORKSPACE, must_exist=True)
    _write_probe(out)
    return out


def _prepare_registry(runtime: Any) -> None:
    _write_probe(ENGINE_ROOT)
    journal = ENGINE_ROOT / "journal.jsonl"
    _checked_absolute(journal, base=WORKSPACE, must_exist=False)
    case_root = ENGINE_ROOT / "cases" / CASE_ID / "attempts"
    for directory in (ENGINE_ROOT / "cases", ENGINE_ROOT / "cases" / CASE_ID, case_root):
        directory = _checked_absolute(directory, base=WORKSPACE, must_exist=False)
        if directory.exists():
            if not directory.is_dir():
                raise I7Error("ENGINE_STATE_PATH_INVALID", "synthetic attempt root component is not a directory")
        else:
            parent_id = _object_id(directory.parent)
            _write_probe(directory.parent)
            try:
                directory.mkdir(mode=0o700, exist_ok=False)
            except FileExistsError as exc:
                raise I7Error("ENGINE_STATE_PATH_COLLISION", "synthetic attempt directory appeared during exclusive creation") from exc
            if _object_id(directory.parent) != parent_id:
                raise I7Error("ENGINE_STATE_PARENT_CHANGED", "synthetic attempt parent changed during directory creation")
        _write_probe(directory)
    registry = _checked_absolute(ENGINE_ROOT / "ATTEMPT_REGISTRY.jsonl", base=WORKSPACE, must_exist=False)
    if not journal.exists():
        runtime.DurableRegistry.create(journal)


def _execute_impl(*, operation: str, input_value: str | None, output_dir: str | None, provider_id: str, negative: bool, flags: dict[str, bool], input_sha256: str | None = None, provenance_mode: str = "formal", strict_formal: bool = False, pipeline_transfer: dict[str, Any] | None = None) -> dict[str, Any]:
    global ACTIVE_OUTPUT_DIR
    if provider_id != PROVIDER_ID:
        raise I7Error("PROVIDER_NOT_ALLOWLISTED", f"provider is not in the reviewed registry: {provider_id}")
    data, input_path, input_body = _strict_input(input_value, demo=(operation == "demo"))
    actual_input_hash = _sha(input_body)
    if input_sha256 and input_sha256 != actual_input_hash:
        raise I7Error("INPUT_PIN_MISMATCH", "input SHA-256 does not match --input-sha256")
    _expected_engine_source_pins()
    engine, guard, runtime = _load_engine()
    operation_id = "OP-" + uuid.uuid4().hex
    out = _new_output_dir(_workspace_output_dir(output_dir), operation_id, explicit=output_dir is not None)
    ACTIVE_OUTPUT_DIR = out
    if negative:
        # Existing Fiveflow structured flow has a reviewed OUTPUT_TAMPER negative.
        variant = "NEGATIVE"
    else:
        variant = "CLEAN_A"
    _prepare_registry(runtime)
    rel = guard.register_relationship(
        CASE_ID,
        str(ENGINE_ROOT / "provider_structured.py"),
        str(ENGINE_ROOT / "consumer_structured.py"),
        "engineering.totals.v1",
        "OUTPUT_TAMPER",
    )
    original_build_request = engine.build_request
    values = data["values"]

    def build_request_with_input(relationship: dict[str, Any], attempt: str, parent: str | None, requested_variant: str) -> dict[str, Any]:
        request = original_build_request(relationship, attempt, parent, requested_variant)
        request["values"] = list(values)
        request["expected_sum"] = sum(values)
        return request

    engine.build_request = build_request_with_input
    captured_engine_output = io.StringIO()
    try:
        with contextlib.redirect_stdout(captured_engine_output):
            result = guard.execute(rel, variant)
    finally:
        engine.build_request = original_build_request
    if result.get("BOUNDED_ADAPTER_VERDICT") not in {"PASS_CLEAN", "PASS_EXPECTED_FAILURE"}:
        raise I7Error("ENGINE_RESULT_NOT_VERIFIED", "existing engine did not verify the bounded result")
    if negative and result.get("BOUNDED_ADAPTER_EXPECTED_FAILURE") != "PASS":
        raise I7Error("NEGATIVE_CAUSE_NOT_PROVEN", "the observed negative result did not match the expected controlled cause")
    if not negative and result.get("FINAL_STATUS") != "CLEAN_EXECUTION_PASS":
        raise I7Error("ENGINE_RESULT_NOT_VERIFIED", "clean provider/consumer result did not pass recomputation")

    attempt_dir = _lexical_path(result["directory"], must_exist=True)
    attempts_root = (ENGINE_ROOT / "cases" / CASE_ID / "attempts").resolve()
    if not _within(attempt_dir.resolve(), attempts_root):
        raise I7Error("ARTIFACT_OUTSIDE_WORKSPACE", "engine returned an attempt outside its fixed case root")
    attempt_result_path = attempt_dir / "result.json"
    attempt_result_body = attempt_result_path.read_bytes()
    attempt_result = _parse_json(attempt_result_body, "engine attempt result")
    attempt_request_path = attempt_dir / "request.json"
    attempt_request_body = attempt_request_path.read_bytes()
    parsed_request = _parse_json(attempt_request_body, "engine request")
    if parsed_request.get("values") != values or parsed_request.get("expected_sum") != sum(values):
        raise I7Error("INPUT_BINDING_MISMATCH", "engine request did not consume the exact supplied values")
    operation_status = "EXPECTED_FAILURE" if negative else "PASS"
    verification_result = "PASS_EXPECTED_FAILURE" if negative else "PASS"
    sidecar_flags = dict(flags)
    if provenance_mode == "prospective":
        sidecar_flags["causal_data"] = True
        sidecar_flags["provenance"] = False
    elif strict_formal:
        sidecar_flags["causal_data"] = True
        sidecar_flags["provenance"] = True
    run_record: dict[str, Any] = {
        "schema": RUN_SCHEMA,
        "operation_id": operation_id,
        "operation": operation,
        "status": operation_status,
        "code": "CONTROLLED_NEGATIVE_DETECTED" if negative else None,
        "verification_result": verification_result,
        "provider_id": PROVIDER_ID,
        "provider_schema": "engineering.totals.v1",
        "input": {"path": input_path, "sha256": actual_input_hash, "bytes": len(input_body), "schema": INPUT_SCHEMA, "values": values, "bytes_base64": base64.b64encode(input_body).decode("ascii")},
        "source_commitments": _source_commitments(),
        "request_sha256": _sha((attempt_dir / "request.json").read_bytes()),
        "engine_result_sha256": _sha((attempt_dir / "result.json").read_bytes()),
        "engine_artifact_commitments": _parse_json((attempt_dir / "result.json").read_bytes(), "engine result").get("artifact_commitments", {}),
        "engine_source_commitments": _parse_json((attempt_dir / "request.json").read_bytes(), "engine request").get("SOURCE_SHA256", {}),
        "engine_result": result,
        "attempt_directory": str(attempt_dir),
        "flags": sidecar_flags,
        "requested_flags": dict(flags),
        "provenance_mode": provenance_mode,
        "limitations": ["LOCAL_SYNTHETIC_ENGINEERING_ONLY", "NOT_I7_QUALIFICATION", "NO_OPERATIONAL_AUTHORITY"],
    }
    result_record = {
        "schema": "pg_i7.result_record.v1",
        "operation_id": operation_id,
        "operation": operation,
        "status": operation_status,
        "code": "CONTROLLED_NEGATIVE_DETECTED" if negative else None,
        "verification_result": verification_result,
        "provider_id": PROVIDER_ID,
        "input_sha256": actual_input_hash,
        "result": {**attempt_result, "directory": str(attempt_dir), "request_sha256": _sha(attempt_request_body), "result_sha256": _sha(attempt_result_body)},
        "attempt_result": attempt_result,
        "final_result": result,
        "consumer_result": attempt_result.get("CONSUMER_RESULT"),
        "provider_stdout_sha256": attempt_result.get("OUTPUT_HASHES", {}).get("stdout"),
        "request_sha256": _sha(attempt_request_body),
        "attempt_result_sha256": _sha(attempt_result_body),
        "attempt_directory": str(attempt_dir),
        "evidence_paths": {"request": str(attempt_request_path), "result": str(attempt_result_path), "provider_stdout": str(attempt_dir / "provider.stdout"), "consumer_stdout": str(attempt_dir / "consumer.stdout")},
        "attempt_directory": str(attempt_dir),
    }
    result_path = out / "result.json"
    _write_new(result_path, result_record)
    result_hash = _sha(result_path.read_bytes())
    input_record = {
        "schema": "pg_i7.input_record.v1",
        "operation": operation,
        "input_path": input_path,
        "input_sha256": actual_input_hash,
        "input_byte_length": len(input_body),
        "input_bytes_base64": base64.b64encode(input_body).decode("ascii"),
        "input_schema": INPUT_SCHEMA,
        "values": values,
        "attempt_directory": str(attempt_dir),
        "provider_id": PROVIDER_ID,
        "source_commitments": run_record["source_commitments"],
        "causal_data_requested": flags["causal_data"],
        "data_digest_requested": flags["data_digest"],
        "provenance_requested": flags["provenance"],
    }
    if pipeline_transfer is not None:
        input_record["pipeline_transfer"] = pipeline_transfer
    result_record["result_path"] = str(result_path)
    result_record["result_sha256"] = result_hash
    if any(sidecar_flags.values()):
        _enable_local_i4_i5_dependency_path()
        try:
            import evidence_sidecar  # type: ignore[import-not-found]
        except ImportError as exc:
            raise I7Error("SIDECAR_UNAVAILABLE", "requested evidence sidecar is unavailable") from exc
        input_record["causal_data_requested"] = sidecar_flags["causal_data"]
        input_record["provenance_requested"] = sidecar_flags["provenance"]
        artifacts = evidence_sidecar.build_artifacts(operation_id, "local-engineering", PROVIDER_ID, input_record, result_record, str(out), sidecar_flags)
        run_record["evidence_artifacts"] = artifacts
    run_record_path = out / "run.json"
    _write_new(run_record_path, run_record)
    run_hash = _sha(run_record_path.read_bytes())
    run_record["run_record_path"] = str(run_record_path)
    run_record["run_record_sha256"] = run_hash
    _write_new(out / "run.index.json", run_record)
    response = {"schema": "pg_i7.response.v1", "status": operation_status, "operation": operation,
                "operation_id": operation_id, "run_dir": str(out), "run": run_record}
    if provenance_mode == "prospective":
        adapter = _prospective_adapter()
        try:
            response["prospective_provenance"] = adapter.build_for_run(WORKSPACE, out)
        except Exception as exc:
            raise I7Error("PROSPECTIVE_PROVENANCE_FAILED", f"Context Engine NEXT adapter rejected run evidence: {type(exc).__name__}: {exc}") from exc
    elif strict_formal:
        integration = _parse_json((out / "PROVENANCE.json").read_bytes(), "formal provenance") if (out / "PROVENANCE.json").is_file() else {}
        current = integration.get("current_i4_i5_integration", {})
        if current and current.get("status") not in {"PASS", "FINGERPRINT_MATCH_REQUIRES_FROZEN_API_VALIDATION"}:
            response.update(status="REJECTED_REQUIRED_I5", code="I5_FROZEN_CONTRACT_REJECTED",
                            required_i5_status="NOT_SATISFIED", formal_i5_status=current.get("status"))
    if negative:
        response["code"] = "CONTROLLED_NEGATIVE_DETECTED"
        response["message"] = "the selected OUTPUT_TAMPER negative was detected for its exact expected cause"
        response["verification_result"] = verification_result
    return response


def _execute(*, operation: str, input_value: str | None, output_dir: str | None, provider_id: str, negative: bool, flags: dict[str, bool], input_sha256: str | None = None, provenance_mode: str = "formal", strict_formal: bool = False, pipeline_transfer: dict[str, Any] | None = None, _pipeline_intent_id: str | None = None) -> dict[str, Any]:
    global ACTIVE_OUTPUT_DIR
    _require_bound_workspace()
    if _pipeline_intent_id is not None:
        _assert_pipeline_intent(_pipeline_intent_id)
    else:
        _consume_producer_intent("synthetic-" + operation)
    if not _EXECUTION_LOCK.acquire(blocking=False):
        raise I7Error("CONCURRENT_OPERATION", "the local engine adapter allows one in-process operation at a time")
    ACTIVE_OUTPUT_DIR = None
    try:
        response = _execute_impl(operation=operation, input_value=input_value, output_dir=output_dir,
                                 provider_id=provider_id, negative=negative, flags=flags,
                                 input_sha256=input_sha256, provenance_mode=provenance_mode,
                                 strict_formal=strict_formal, pipeline_transfer=pipeline_transfer)
        ACTIVE_OUTPUT_DIR = None
        return response
    finally:
        _EXECUTION_LOCK.release()


def _write_new(path: Path, value: Any) -> None:
    body = _json_bytes(value)
    with path.open("xb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def _write_bytes_new(path: Path, body: bytes) -> None:
    if not isinstance(body, bytes):
        raise TypeError("exact source copy requires bytes")
    with path.open("xb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def demo(*, output_dir: str | None = None, provider_id: str = PROVIDER_ID, negative: bool = False, data_digest: bool = False, causal_data: bool = False, provenance: bool = False, provenance_mode: str = "formal", strict_formal: bool = False) -> dict[str, Any]:
    return _execute(operation="demo", input_value=None, output_dir=output_dir, provider_id=provider_id, negative=negative, flags={"data_digest": data_digest, "causal_data": causal_data, "provenance": provenance}, provenance_mode=provenance_mode, strict_formal=strict_formal)


def run(*, input: str, output_dir: str | None = None, provider_id: str = PROVIDER_ID, negative: bool = False, data_digest: bool = False, causal_data: bool = False, provenance: bool = False, input_sha256: str | None = None, provenance_mode: str = "formal", strict_formal: bool = False) -> dict[str, Any]:
    return _execute(operation="run", input_value=input, output_dir=output_dir, provider_id=provider_id, negative=negative, flags={"data_digest": data_digest, "causal_data": causal_data, "provenance": provenance}, input_sha256=input_sha256, provenance_mode=provenance_mode, strict_formal=strict_formal)


def _load_run(from_run: str, expected_operation_id: str | None = None) -> tuple[Path, dict[str, Any]]:
    _require_bound_workspace()
    run_dir = _lexical_path(from_run, must_exist=True)
    if not _within(run_dir, WORKSPACE) or not run_dir.is_dir():
        raise I7Error("RUN_OUTSIDE_WORKSPACE", "run directory must be beneath the composition workspace")
    path = _checked_absolute(run_dir / "run.index.json", base=run_dir, must_exist=True)
    body = path.read_bytes()
    record = _parse_json(body, "run record")
    if type(record) is not dict or record.get("schema") != RUN_SCHEMA:
        raise I7Error("RUN_SCHEMA", "unsupported or missing run record schema")
    base_record_path = _lexical_path(str(record.get("run_record_path", "")), must_exist=True)
    if not _within(base_record_path, run_dir) or _sha(base_record_path.read_bytes()) != record.get("run_record_sha256"):
        raise I7Error("RUN_RECORD_PIN_MISMATCH", "run record does not match its stored anchor")
    base_record = _parse_json(base_record_path.read_bytes(), "anchored run record")
    index_core = {key: value for key, value in record.items() if key not in {"run_record_path", "run_record_sha256"}}
    if base_record != index_core:
        raise I7Error("RUN_INDEX_MISMATCH", "run index fields differ from the anchored run record")
    if expected_operation_id and record.get("operation_id") != expected_operation_id:
        raise I7Error("OPERATION_ID_MISMATCH", "run operation identity does not match --expected-operation-id")
    if record.get("provider_id") != PROVIDER_ID:
        raise I7Error("PROVIDER_NOT_ALLOWLISTED", "run record provider is not allowlisted")
    if record.get("attempt_directory") is None:
        raise I7Error("RUN_SCHEMA", "run record lacks its attempt anchor")
    attempt = _lexical_path(record["attempt_directory"], must_exist=True)
    if not _within(attempt.resolve(), (ENGINE_ROOT / "cases" / CASE_ID / "attempts").resolve()):
        raise I7Error("ARTIFACT_OUTSIDE_WORKSPACE", "attempt path escapes fixed workspace case")
    _validate_composition_bindings(record)
    request_path = _lexical_path("request.json", must_exist=True, base=attempt)
    engine_result_path = _lexical_path("result.json", must_exist=True, base=attempt)
    request_body, result_body = request_path.read_bytes(), engine_result_path.read_bytes()
    request = _parse_json(request_body, "engine request")
    engine_result = _parse_json(result_body, "engine result")
    if _sha(request_body) != record.get("request_sha256") or _sha(result_body) != record.get("engine_result_sha256"):
        raise I7Error("ENGINE_EVIDENCE_PIN_MISMATCH", "request or engine result differs from stored anchors")
    if request.get("SOURCE_SHA256") != record.get("engine_source_commitments") or request.get("SOURCE_SHA256") != _expected_engine_source_pins():
        raise I7Error("SOURCE_BINDING_MISMATCH", "engine request source pins do not match the fixed composition closure")
    relation = request.get("relationship")
    provider_path = str(ENGINE_ROOT / "provider_structured.py")
    consumer_path = str(ENGINE_ROOT / "consumer_structured.py")
    expected_provider = _source_commitments().get("engine/provider_structured.py")
    expected_consumer = _source_commitments().get("engine/consumer_structured.py")
    if type(relation) is not dict or relation.get("PROVIDER_SOURCE") != provider_path or relation.get("CONSUMER_SOURCE") != consumer_path or relation.get("PROVIDER_SHA256") != expected_provider or relation.get("CONSUMER_SHA256") != expected_consumer:
        raise I7Error("RELATIONSHIP_NOT_ALLOWLISTED", "run request relationship is outside the fixed structured totals provider")
    if relation.get("OUTPUT_SCHEMA") != "engineering.totals.v1" or request.get("journal") != str(ENGINE_ROOT / "journal.jsonl"):
        raise I7Error("ENGINE_REQUEST_BINDING_MISMATCH", "engine request schema or journal path differs from the fixed composition")
    encoded_input = record.get("input", {}).get("bytes_base64", "")
    if request.get("values") != record.get("input", {}).get("values") or _sha(base64.b64decode(encoded_input, validate=True)) != record.get("input", {}).get("sha256"):
        raise I7Error("INPUT_BINDING_MISMATCH", "engine request values or input bytes differ from run input")
    if engine_result.get("artifact_commitments") != record.get("engine_artifact_commitments"):
        raise I7Error("ENGINE_EVIDENCE_PIN_MISMATCH", "engine artifact commitment set changed")
    for name, digest in engine_result.get("artifact_commitments", {}).items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise I7Error("ARTIFACT_PATH_INVALID", "engine artifact path is not a contained relative path")
        artifact = _lexical_path(name, must_exist=True, base=attempt)
        if not _within(artifact.resolve(), attempt.resolve()) or _sha(artifact.read_bytes()) != digest:
            raise I7Error("ENGINE_ARTIFACT_PIN_MISMATCH", f"engine artifact commitment mismatch: {name}")
    consumer_dir = _lexical_path(engine_result.get("consumer_directory", ""), must_exist=True)
    if consumer_dir != attempt and (consumer_dir.parent != attempt or consumer_dir.name != "controlled-tamper"):
        raise I7Error("CONSUMER_PATH_INVALID", "consumer directory is outside the fixed clean/tamper attempt paths")
    for label in ("provider", "consumer"):
        proc_path = _lexical_path(label + ".process.json", must_exist=True, base=attempt)
        proc = _parse_json(proc_path.read_bytes(), label + " process record")
        expected_dir = str(attempt if label == "provider" else consumer_dir)
        expected_command = [sys.executable, "-I", "-B", str(ENGINE_ROOT / "worker.py"), label, expected_dir]
        if proc.get("command") != expected_command or proc.get("timed_out") is not False or proc.get("terminal_observed") is not True:
            raise I7Error("PROCESS_BINDING_MISMATCH", f"{label} process record does not match the fixed worker command")
        for suffix in ("stdout", "stderr"):
            out_path = _lexical_path(label + "." + suffix, must_exist=True, base=attempt)
            if out_path.stat().st_size > 65536:
                raise I7Error("PROCESS_OUTPUT_TOO_LARGE", f"{label}.{suffix} exceeds the reviewed output bound")
    artifact_refs = record.get("evidence_artifacts", {})
    if type(artifact_refs) is not dict:
        raise I7Error("EVIDENCE_ARTIFACTS_SCHEMA", "evidence artifact references must be an object")
    refs = artifact_refs.get("artifacts", {})
    if type(refs) is not dict:
        raise I7Error("EVIDENCE_ARTIFACTS_SCHEMA", "evidence artifact references lack an artifacts object")
    flags = record.get("flags", {})
    if type(flags) is not dict:
        raise I7Error("EVIDENCE_ARTIFACTS_SCHEMA", "evidence artifact flags are invalid")
    required_artifacts = {"evidence_binding"} if any(flags.get(flag) for flag in ("data_digest", "causal_data", "provenance")) else set()
    if flags.get("data_digest"):
        required_artifacts.add("data_digest")
    if flags.get("causal_data"):
        required_artifacts.update(("causal_graph", "causal_graph_dot"))
    if flags.get("provenance"):
        required_artifacts.add("provenance")
    if not required_artifacts.issubset(refs):
        raise I7Error("EVIDENCE_ARTIFACTS_MISSING", "run flags require evidence artifacts that are not committed")
    for key, ref in refs.items():
        if type(ref) is not dict or not isinstance(ref.get("path"), str):
            raise I7Error("EVIDENCE_ARTIFACTS_SCHEMA", f"evidence artifact reference is invalid: {key}")
        artifact_path = _lexical_path(ref["path"], must_exist=True)
        digest, byte_length = ref.get("sha256"), ref.get("byte_length")
        artifact_body = artifact_path.read_bytes()
        if (not _within(artifact_path, run_dir) or not isinstance(digest, str)
                or type(byte_length) is not int or len(artifact_body) != byte_length
                or _sha(artifact_body) != digest):
            raise I7Error("EVIDENCE_ARTIFACT_PIN_MISMATCH", f"evidence artifact commitment mismatch: {key}")
    return run_dir, record


def _prospective_adapter() -> Any:
    expected = _lexical_path("prospective_adapter.py", must_exist=True, base=WORKSPACE)
    pinned = _source_commitments().get("prospective_adapter.py")
    if not pinned or _sha(expected.read_bytes()) != pinned:
        raise I7Error("PROSPECTIVE_ADAPTER_PIN_MISMATCH", "prospective adapter differs from its composition pin")
    import importlib.util
    name = "_pg_i7_prospective_adapter"
    loaded = sys.modules.get(name)
    if loaded is not None:
        if Path(getattr(loaded, "__file__", "")).resolve() != expected.resolve():
            raise I7Error("IMPORT_COLLISION", "prospective adapter was loaded from another path")
        return loaded
    spec = importlib.util.spec_from_file_location(name, expected)
    if spec is None or spec.loader is None:
        raise I7Error("PROSPECTIVE_ADAPTER_UNAVAILABLE", "prospective adapter import specification is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _verify_prospective_run(run_dir: Path, operation_id: str) -> dict[str, Any]:
    try:
        return _prospective_adapter().verify(WORKSPACE, run_dir, expected_run_id=operation_id)
    except Exception as exc:
        raise I7Error("PROSPECTIVE_PROVENANCE_VERIFICATION_FAILED",
                      f"Context Engine NEXT graph did not verify: {type(exc).__name__}: {exc}") from exc


def _read_only_engine_recover(engine: Any, attempt: Path, request_hash: str,
                              result_hash: str) -> dict[str, Any]:
    import importlib.util
    helper_path = _lexical_path("readonly_recovery.py", must_exist=True, base=WORKSPACE)
    if not _within(helper_path, WORKSPACE):
        raise I7Error("RECOVERY_ADAPTER_SCOPE", "read-only recovery adapter escaped workspace")
    name = "_pg_i7_readonly_recovery_" + _sha(helper_path.read_bytes())[:12]
    helper = sys.modules.get(name)
    if helper is None:
        spec = importlib.util.spec_from_file_location(name, helper_path)
        if spec is None or spec.loader is None:
            raise I7Error("RECOVERY_ADAPTER_UNAVAILABLE", "read-only recovery adapter could not be loaded")
        helper = importlib.util.module_from_spec(spec)
        sys.modules[name] = helper
        spec.loader.exec_module(helper)
    return helper.recover(engine, str(attempt), request_hash, result_hash)


def _verify_impl(*, from_run: str, input_sha256: str | None = None, expected_operation_id: str | None = None) -> dict[str, Any]:
    run_dir, record = _load_run(from_run, expected_operation_id)
    if input_sha256 and record["input"].get("sha256") != input_sha256:
        raise I7Error("INPUT_PIN_MISMATCH", "run input SHA-256 differs from requested pin")
    engine, guard, runtime = _load_engine()
    attempt = Path(record["attempt_directory"])
    request_path, result_path = attempt / "request.json", attempt / "result.json"
    if not request_path.is_file() or not result_path.is_file():
        raise I7Error("RUN_EVIDENCE_MISSING", "request or result evidence is missing")
    request = _parse_json(request_path.read_bytes(), "request")
    if request.get("values") != record["input"].get("values"):
        raise I7Error("INPUT_BINDING_MISMATCH", "engine request values do not match run input")
    trusted_request_hash = record["request_sha256"]
    trusted_result_hash = record["engine_result_sha256"]
    if _sha(request_path.read_bytes()) != trusted_request_hash or _sha(result_path.read_bytes()) != trusted_result_hash:
        raise I7Error("ENGINE_EVIDENCE_PIN_MISMATCH", "recovery evidence differs from the stored request/result anchors")
    recovered = _read_only_engine_recover(engine, attempt, trusted_request_hash, trusted_result_hash)
    if recovered.get("status") != "PASS" or not recovered.get("replay_rejected"):
        raise I7Error("RECOVERY_NOT_VERIFIED", "existing engine recovery did not verify source/output/replay bindings")
    evidence_verification = None
    flags = record.get("flags", {})
    if any(flags.get(flag) for flag in ("data_digest", "causal_data", "provenance")):
        _enable_local_i4_i5_dependency_path()
        expected_sidecar = _lexical_path("evidence_sidecar.py", must_exist=True, base=WORKSPACE)
        loaded_sidecar = sys.modules.get("evidence_sidecar")
        if loaded_sidecar is not None:
            sidecar_file = getattr(loaded_sidecar, "__file__", None)
            if not isinstance(sidecar_file, str) or Path(os.path.abspath(sidecar_file)) != expected_sidecar:
                raise I7Error("IMPORT_COLLISION", "preloaded evidence_sidecar is not from the fixed composition path")
        try:
            import evidence_sidecar  # type: ignore[import-not-found]
        except ImportError as exc:
            raise I7Error("SIDECAR_UNAVAILABLE", "pinned evidence sidecar could not be loaded") from exc
        if Path(os.path.abspath(evidence_sidecar.__file__)) != expected_sidecar:
            raise I7Error("IMPORT_COLLISION", "loaded evidence_sidecar is not from the fixed composition path")
        try:
            evidence_verification = evidence_sidecar.verify_evidence(str(run_dir))
        except Exception as exc:
            raise I7Error("EVIDENCE_VERIFICATION_FAILED",
                          f"pinned evidence sidecar rejected its recorded artifacts: {type(exc).__name__}: {exc}") from exc
        if evidence_verification.get("status") != "PASS":
            raise I7Error("EVIDENCE_VERIFICATION_FAILED", "pinned evidence sidecar did not verify its recorded artifacts")
    negative = record.get("status") == "EXPECTED_FAILURE"
    result = {"schema": "pg_i7.verify.v1", "status": "PASS", "operation_id": record["operation_id"], "run_dir": str(run_dir), "recovery": recovered,
              "verification_result": "PASS_EXPECTED_FAILURE" if negative else "PASS",
              "evidence_verification": evidence_verification}
    if record.get("provenance_mode") == "prospective":
        result["prospective_provenance"] = _verify_prospective_run(run_dir, record["operation_id"])
    if negative:
        result["code"] = "CONTROLLED_NEGATIVE_DETECTED"
    return result


def verify(*, from_run: str, input_sha256: str | None = None, expected_operation_id: str | None = None) -> dict[str, Any]:
    if not _EXECUTION_LOCK.acquire(blocking=False):
        raise I7Error("CONCURRENT_OPERATION", "the local engine adapter allows one in-process operation at a time")
    try:
        return _verify_impl(from_run=from_run, input_sha256=input_sha256,
                            expected_operation_id=expected_operation_id)
    finally:
        _EXECUTION_LOCK.release()


def recover(*, from_run: str, input_sha256: str | None = None, expected_operation_id: str | None = None) -> dict[str, Any]:
    return verify(from_run=from_run, input_sha256=input_sha256, expected_operation_id=expected_operation_id)


def query(*, from_run: str, expected_operation_id: str | None = None) -> dict[str, Any]:
    run_dir, record = _load_run(from_run, expected_operation_id)
    verification = verify(from_run=from_run, expected_operation_id=expected_operation_id)
    result = record.get("engine_result", {})
    response = {"schema": "pg_i7.query.v1", "status": "PASS", "operation_id": record["operation_id"], "provider_id": record["provider_id"], "input": record["input"], "final_status": result.get("FINAL_STATUS"), "verification_result": verification["recovery"].get("status"), "run_dir": str(run_dir)}
    if record.get("provenance_mode") == "prospective":
        response["prospective_provenance"] = _verify_prospective_run(run_dir, record["operation_id"])
    return response


def graph(*, from_run: str, graph_format: str = "json", expected_operation_id: str | None = None) -> dict[str, Any]:
    run_dir, record = _load_run(from_run, expected_operation_id)
    verify(from_run=from_run, expected_operation_id=expected_operation_id)
    next_provenance = (_verify_prospective_run(run_dir, record["operation_id"])
                       if record.get("provenance_mode") == "prospective" else None)
    if graph_format not in {"json", "dot"}:
        raise I7Error("GRAPH_FORMAT", "graph format must be json or dot")
    evidence = record.get("evidence_artifacts", {})
    artifacts = evidence.get("artifacts", {}) if type(evidence) is dict else {}
    graph_ref = artifacts.get("causal_graph") or artifacts.get("CAUSAL_GRAPH.json")
    if graph_ref:
        path_value = graph_ref.get("path") if type(graph_ref) is dict else graph_ref
        graph_path = _lexical_path(path_value, must_exist=True)
        if not _within(graph_path.resolve(), run_dir.resolve()):
            raise I7Error("ARTIFACT_OUTSIDE_WORKSPACE", "causal graph path escapes run directory")
        if graph_format == "dot":
            dot_ref = artifacts.get("causal_graph_dot")
            dot_path = _lexical_path(dot_ref["path"], must_exist=True) if type(dot_ref) is dict else graph_path.with_suffix(".dot")
            if dot_path.is_file() and _within(dot_path.resolve(), run_dir.resolve()):
                response = {"schema": "pg_i7.graph.v1", "status": "PASS", "operation_id": record["operation_id"], "format": "dot", "graph": dot_path.read_text(encoding="utf-8")}
                if next_provenance is not None: response["prospective_provenance"] = next_provenance
                return response
        response = {"schema": "pg_i7.graph.v1", "status": "PASS", "operation_id": record["operation_id"], "format": "json", "graph": _parse_json(graph_path.read_bytes(), "causal graph")}
        if next_provenance is not None: response["prospective_provenance"] = next_provenance
        return response
    if graph_format == "dot":
        raise I7Error("GRAPH_NOT_AVAILABLE", "run has no causal graph DOT artifact")
    response = {"schema": "pg_i7.graph.v1", "status": "NOT_REQUESTED", "operation_id": record["operation_id"], "format": "json", "graph": {"nodes": [], "edges": [], "reason": "causal data was not requested"}}
    if next_provenance is not None: response["prospective_provenance"] = next_provenance
    return response


def _engineering_verification_api():
    expected = _lexical_path("engineering_verification.py", must_exist=True, base=WORKSPACE)
    loaded = sys.modules.get("engineering_verification")
    if loaded is not None and Path(os.path.abspath(getattr(loaded, "__file__", ""))) != expected:
        raise I7Error("IMPORT_COLLISION", "verification adapter was loaded from another path")
    import engineering_verification  # type: ignore[import-not-found]
    if Path(os.path.abspath(engineering_verification.__file__)) != expected:
        raise I7Error("IMPORT_COLLISION", "verification adapter is outside the composition")
    return engineering_verification


def _engineering_api():
    _require_bound_workspace()
    expected = _lexical_path("engineering_corpus.py", must_exist=True, base=WORKSPACE)
    loaded = sys.modules.get("engineering_corpus")
    if loaded is not None and Path(os.path.abspath(getattr(loaded, "__file__", ""))) != expected:
        raise I7Error("IMPORT_COLLISION", "engineering scanner was loaded from another path")
    import engineering_corpus  # type: ignore[import-not-found]
    if Path(os.path.abspath(engineering_corpus.__file__)) != expected:
        raise I7Error("IMPORT_COLLISION", "engineering scanner is outside the composition")
    return engineering_corpus


def _engineering_output(value: str) -> Path:
    path = _checked_absolute(value, must_exist=False, base=WORKSPACE)
    runs = WORKSPACE / "runs"
    if not _beneath(path, runs) or not _same_path(path.parent, runs):
        raise I7Error("OUTPUT_SCOPE", "engineering output must be a fresh direct child of workspace runs/")
    return path


def _engineering_read_output(value: str) -> Path:
    path = _checked_absolute(value, must_exist=True, base=WORKSPACE)
    if not _beneath(path, WORKSPACE / "runs"):
        raise I7Error("OUTPUT_SCOPE", "focused evidence reads must remain inside this workspace runs/")
    return path


def _engineering_last_manifest(output: Path, scanner) -> dict[str, Any]:
    """Read the final bounded manifest row from one verified held handle."""
    path = output / "corpus-manifest.jsonl"
    try:
        stream, before, opened, held_path = scanner._open_verified(path)
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:
        raise I7Error("CORPUS_MANIFEST_UNSAFE", "corpus manifest failed held-path validation") from exc
    max_row_bytes = 1024 * 1024
    stable_error = None
    try:
        stream.seek(0, os.SEEK_END)
        end = stream.tell()
        if end <= 0:
            raise I7Error("CORPUS_MANIFEST_EMPTY", "corpus manifest has no rows")
        tail_bytes = min(end, max_row_bytes + 1)
        stream.seek(end - tail_bytes, os.SEEK_SET)
        tail = stream.read(tail_bytes)
        if len(tail) != tail_bytes:
            raise I7Error("CORPUS_MANIFEST_CHANGED", "corpus manifest tail changed while reading")
        if end > tail_bytes:
            boundary = tail.find(b"\n")
            if boundary < 0:
                raise I7Error("CORPUS_MANIFEST_ROW_OVERSIZE", "last manifest row exceeds the byte limit")
            tail = tail[boundary + 1:]
        if not tail.endswith(b"\n"):
            raise I7Error("CORPUS_MANIFEST_TORN", "last manifest row is not newline terminated")
        lines = tail.splitlines(keepends=True)
        if not lines or lines[-1] == b"\n" or len(lines[-1]) > max_row_bytes:
            raise I7Error("CORPUS_MANIFEST_ROW_INVALID", "last manifest row is blank or oversized")
        try:
            manifest = json.loads(lines[-1])
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as exc:
            raise I7Error("CORPUS_MANIFEST_ROW_INVALID", "last manifest row is not valid JSON") from exc
        if (not isinstance(manifest, dict)
                or manifest.get("schema") != "i7-engineering-corpus-scan@1"
                or not isinstance(manifest.get("snapshot_id"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", manifest["snapshot_id"])):
            raise I7Error("CORPUS_MANIFEST_ROW_INVALID", "last manifest row has an invalid schema or snapshot ID")
    finally:
        try:
            after_fd = os.fstat(stream.fileno())
            after_path = path.lstat()
            final_path = scanner._final_path_from_handle(stream.fileno())
            expected_path = os.path.abspath(os.fspath(path))
            if (scanner._stat_tuple(opened) != scanner._stat_tuple(after_fd)
                    or scanner._stat_tuple(before) != scanner._stat_tuple(after_path)
                    or scanner._cross_api_stat_tuple(before) != scanner._cross_api_stat_tuple(opened)
                    or scanner._path_has_reparse_ancestor(path)
                    or scanner._is_reparse(path, after_path)
                    or final_path != held_path
                    or os.path.normcase(os.path.normpath(final_path or ""))
                    != os.path.normcase(os.path.normpath(expected_path))):
                stable_error = I7Error("CORPUS_MANIFEST_CHANGED", "corpus manifest changed during held read")
        except (OSError, ValueError) as exc:
            stable_error = I7Error("CORPUS_MANIFEST_CHANGED", "corpus manifest final-path check failed")
            stable_error.__cause__ = exc
        finally:
            stream.close()
    if stable_error is not None:
        raise stable_error
    return manifest


def _engineering_scan(*, output_dir: str, max_files: int | None, resume: bool,
                      flags: dict[str, bool], owner_checkpoint_seal: str | None = None) -> dict[str, Any]:
    if owner_checkpoint_seal is not None and owner_checkpoint_seal != R5_OWNER_CHECKPOINT_SEAL_SHA256:
        raise I7Error("OWNER_CHECKPOINT_SEAL_INVALID", "owner checkpoint seal must match the fixed reviewed seal")
    if owner_checkpoint_seal is not None and not resume:
        raise I7Error("OWNER_CHECKPOINT_SEAL_REQUIRES_RESUME", "owner checkpoint seal is valid only for explicit resume")
    scanner = _engineering_api()
    result = scanner.scan_corpus(ENGINEERING_ROOT, _engineering_output(output_dir),
                                 resume=resume, max_files=max_files,
                                 expected_owner_anchor_sha256=owner_checkpoint_seal)
    return {"schema": "pg_i7.engineering-scan.v1", **result,
            "requested_evidence_flags": flags,
            "evidence_integration": "DEFERRED_POSTPROCESS_REQUIRED",
            "next_commands": ["engineering-summarize", "engineering-verify", "engineering-integrate"]}


def _selected_document_input(scanner: Any, row: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    relative = row.get("relative_path")
    expected_path = row.get("path")
    expected_digest = row.get("sha256")
    expected_bytes = row.get("bytes")
    if (not isinstance(relative, str) or not relative or Path(relative).is_absolute()
            or Path(relative).drive or ".." in Path(relative).parts
            or not isinstance(expected_path, str)
            or not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
            or type(expected_bytes) is not int or expected_bytes < 0):
        raise I7Error("DOCUMENT_SELECTION_ROW_INVALID", "selected document identity is malformed")
    path = _checked_absolute(ENGINEERING_ROOT / relative, base=ENGINEERING_ROOT, must_exist=True)
    if not _same_path(path, Path(expected_path)) or not _beneath(path, ENGINEERING_ROOT) or not path.is_file():
        raise I7Error("DOCUMENT_SELECTION_PATH_MISMATCH", "selected document path differs from its fixed source root")
    before = path.lstat()
    if _is_reparse(path) or scanner._path_has_reparse_ancestor(path):
        raise I7Error("DOCUMENT_SELECTION_REPARSE", "selected document or an ancestor is a reparse point")
    document = scanner.inspect_document(path, relative_path=relative, expected_sha256=expected_digest,
                                        include_private_reference_paths=True)
    after = path.lstat()
    if (document.get("status") not in {"PARSED", "PARSED_AS_TEXT"}
            or document.get("byte_count") != expected_bytes
            or document.get("path_id") != row.get("path_id")
            or scanner._stat_tuple(before) != scanner._stat_tuple(after)
            or scanner._path_has_reparse_ancestor(path)):
        raise I7Error("DOCUMENT_SELECTION_CHANGED", "selected document failed exact identity, size, digest, or stable-read checks")
    return path, document


def _engineering_documents(*, output_dir: str, selection_manifest: str,
                           flags: dict[str, bool], _pipeline_intent_id: str | None = None) -> dict[str, Any]:
    if _pipeline_intent_id is not None:
        _assert_pipeline_intent(_pipeline_intent_id)
    else:
        _consume_producer_intent("engineering-documents")
    selection_path = _checked_absolute(selection_manifest, base=FOCUSED_ROOT, must_exist=True)
    if not _same_path(selection_path, REAL_DOCUMENT_SELECTION):
        raise I7Error("DOCUMENT_SELECTION_NOT_ALLOWLISTED", "only the root-selected focused document manifest is accepted")
    selection_raw = selection_path.read_bytes()
    if _sha(selection_raw) != REAL_DOCUMENT_SELECTION_SHA256:
        raise I7Error("DOCUMENT_SELECTION_PIN_MISMATCH", "root-selected document manifest changed")
    selection = _parse_json(selection_raw, "real document selection")
    rows = selection.get("documents") if type(selection) is dict else None
    if (selection.get("schema") != "i7.focused.real-document-selection.v1"
            or not isinstance(rows, list) or len(rows) != 8
            or not _same_path(Path(selection.get("source_root", "")), ENGINEERING_ROOT)):
        raise I7Error("DOCUMENT_SELECTION_INVALID", "document selection does not match the bounded eight-document contract")
    scanner = _engineering_api()
    selected: dict[str, dict[str, Any]] = {}
    path_rows: list[dict[str, str]] = []
    for row in rows:
        if type(row) is not dict:
            raise I7Error("DOCUMENT_SELECTION_ROW_INVALID", "document selection contains a non-object row")
        relative = Path(row.get("relative_path", "")).as_posix()
        if relative in selected:
            raise I7Error("DOCUMENT_SELECTION_DUPLICATE", "document selection repeats a path")
        _, document = _selected_document_input(scanner, row)
        selected[relative] = {"selection": row, "document": document}
        path_rows.append({"path_id": row["path_id"], "relative_path": relative})
    actual_document_bytes = sum(item["selection"]["bytes"] for item in selected.values())
    if actual_document_bytes != 140856:
        raise I7Error("DOCUMENT_SELECTION_BYTE_TOTAL_MISMATCH", "selected document byte total differs from the reviewed eight-document set")

    ledger_rows: list[dict[str, Any]] = []
    reference_count = resolved_count = unknown_count = reference_accounting_bytes = 0
    for relative, item in selected.items():
        row, document = item["selection"], item["document"]
        refs = []
        private_paths = document.pop("private_reference_paths", [])
        explicit_refs = document.get("explicit_references", [])
        if len(private_paths) != len(explicit_refs):
            raise I7Error("DOCUMENT_REFERENCE_PAIRING_INVALID", "document parser returned unpaired literal reference paths")
        for ref, target_relative in zip(explicit_refs, private_paths):
            target_relative = Path(target_relative).as_posix()
            target = selected.get(target_relative)
            target_id = ref.get("target_id")
            if not isinstance(target_id, str) or not re.fullmatch(r"[0-9a-f]{64}", target_id):
                raise I7Error("DOCUMENT_REFERENCE_ID_INVALID", "document parser returned an invalid target identity")
            path_rows.append({"path_id": target_id, "relative_path": target_relative})
            if target is None:
                refs.append({"target_id": target_id, "status": "MISSING_OR_UNRESOLVED", "sha256": None, "size": None})
                unknown_count += 1
            else:
                target_row = target["selection"]
                refs.append({"target_id": target_id, "status": "RESOLVED_EXACT_PATH",
                             "sha256": target_row["sha256"], "size": target_row["bytes"]})
                resolved_count += 1
                reference_accounting_bytes += target_row["bytes"]
            reference_count += 1
        ledger_rows.append({"path_id": row["path_id"], "status": "HASHED", "size": row["bytes"],
                            "sha256": row["sha256"], "bytes_read_hash": row["bytes"],
                            "document": document, "references": refs, "detail": None})
    h = hashlib.sha256()
    h.update(str(ENGINEERING_ROOT).casefold().encode("utf-8") + b"\0"
             + scanner.PROTECTION_POLICY_SHA256.encode("ascii") + b"\0")
    encoded_rows = [(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
                    for row in ledger_rows]
    for encoded in encoded_rows:
        h.update(encoded)
    snapshot_id = h.hexdigest()
    logical_document_bytes = actual_document_bytes + reference_accounting_bytes
    manifest = {"schema": "i7-engineering-document-scan@1", "snapshot_id": snapshot_id,
                "protection_policy_sha256": scanner.PROTECTION_POLICY_SHA256,
                "scope": "EXPLICIT_DOCUMENTS_AND_LITERAL_REFERENTS", "document_count": len(ledger_rows),
                "document_bytes_read": logical_document_bytes,
                "unique_document_bytes_hashed": actual_document_bytes,
                "reference_accounting_bytes": reference_accounting_bytes,
                "document_bytes_read_semantics": "UNIQUE_SOURCE_BYTES_PLUS_SELECTED_REFERENCE_ACCOUNTING; REFERENCE_TARGETS_REUSED_FROM_SELECTED_INPUT_SET",
                "read_failure_count": 0, "read_coverage_status": "COMPLETE", "structure_failure_count": 0,
                "structure_status": "EXTRACTED", "explicit_reference_count": reference_count,
                "reference_resolved_count": resolved_count, "reference_unknown_count": unknown_count,
                "reference_status": "ALL_EXPLICIT_RESOLVED" if unknown_count == 0 else "UNKNOWN_REFERENTS_RETAINED",
                "coverage_status": "COMPLETE", "ledger": "document-scan-ledger.jsonl",
                "private_path_mapping_local_only": "document-private-path-map.jsonl", "causal_edges": []}
    output_path = _engineering_output(output_dir)
    output = _new_output_dir(output_path, "DOC-" + uuid.uuid4().hex, explicit=True)
    ledger_path = output / "document-scan-ledger.jsonl"
    with ledger_path.open("xb") as stream:
        for encoded in encoded_rows:
            stream.write(encoded)
        stream.flush(); os.fsync(stream.fileno())
    with (output / "document-scan-manifest.jsonl").open("xb") as stream:
        stream.write((json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8"))
        stream.flush(); os.fsync(stream.fileno())
    unique_map: dict[str, str] = {}
    for row in path_rows:
        previous = unique_map.get(row["path_id"])
        if previous is not None and previous != row["relative_path"]:
            raise I7Error("DOCUMENT_PATH_ID_COLLISION", "selected source and reference path IDs collide")
        unique_map[row["path_id"]] = row["relative_path"]
    with (output / "document-private-path-map.jsonl").open("xb") as stream:
        for path_id, relative in sorted(unique_map.items()):
            line = json.dumps({"path_id": path_id, "relative_path": relative}, sort_keys=True, separators=(",", ":"))
            stream.write((line + "\n").encode("utf-8"))
        stream.flush(); os.fsync(stream.fileno())
    return {"schema": "pg_i7.engineering-documents.v1", **manifest,
            "output_dir": str(output), "requested_evidence_flags": flags,
            "actual_unique_document_bytes_read": actual_document_bytes,
            "reference_target_bytes_read": 0, "reference_target_resolution": "IN_MEMORY_SELECTED_SET_ONLY",
            "documentary_references_are_causal": False,
            "i4_graph_status": "AWAITING_INDEPENDENT_BYTE_RECEIPT",
            "i5_status": "NOT_RUN_FROZEN_I5_REQUIRES_I4_SEMANTIC_INPUT",
            "attribution": "UNKNOWN"}


def _engineering_documents_v2(*, output_dir: str, selection_manifest: str,
                               _pipeline_intent_id: str | None = None) -> dict[str, Any]:
    """Stream and hash only the documents in one independently policy-bound v2 selection."""
    if _pipeline_intent_id is not None:
        _assert_pipeline_intent(_pipeline_intent_id)
    else:
        _consume_producer_intent("engineering-documents-v2")
    documents_policy = _documents_policy_module()
    cli = sys.modules[__name__]
    scanner = _engineering_api()
    selection, rows, source_root, selection_raw = documents_policy._manifest(cli, scanner, selection_manifest)
    selected: dict[str, dict[str, Any]] = {}
    ledger_rows: list[dict[str, Any]] = []
    total_bytes = 0
    for row in rows:
        relative = row["relative_path"]
        current = documents_policy._inspect(cli, scanner, source_root, relative,
                                            row["sha256"], row["bytes"], row["file_identity"])
        if (current["path_id"] != row["path_id"] or current["path"] != row["path"]
                or current["file_identity"] != row["file_identity"]
                or current["document"] != row["document"]):
            raise I7Error("DOCUMENT_SELECTION_COMMITMENT_MISMATCH", "source changed after selection preparation")
        total_bytes += row["bytes"]
        selected[relative.casefold()] = {"row": row, "document": current["document"]}
        ledger_rows.append({"path_id": row["path_id"], "status": "HASHED", "size": row["bytes"],
                            "sha256": row["sha256"], "bytes_read_hash": row["bytes"],
                            "document": current["document"], "references": [], "detail": None})
    if len(selected) != len(rows):
        raise I7Error("DOCUMENT_SELECTION_DUPLICATE", "selection paths are not case-insensitively unique")
    digest = hashlib.sha256()
    digest.update(str(source_root).casefold().encode("utf-8") + b"\0")
    digest.update(selection["policy_id"].encode("ascii") + b"\0")
    digest.update(selection["selection_commitment_sha256"].encode("ascii") + b"\0")
    encoded_rows = [(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")
                    for row in ledger_rows]
    for encoded in encoded_rows:
        digest.update(encoded)
    snapshot_id = digest.hexdigest()
    manifest = {"schema": "i7-engineering-document-scan.v2", "snapshot_id": snapshot_id,
                "selection_id": selection["selection_id"], "selection_policy_id": selection["policy_id"],
                "selection_policy_version": selection["policy_version"],
                "selection_commitment_sha256": selection["selection_commitment_sha256"],
                "selection_manifest_sha256": _sha(selection_raw),
                "source_root": str(source_root), "document_count": len(rows),
                "snapshot_consistency": "PER_FILE_STABLE_READS_ONLY",
                "cross_document_snapshot_claim": "NOT_ASSERTED",
                "content_parsed": False, "content_disclosed": False,
                "document_bytes_read": total_bytes, "unique_document_bytes_hashed": total_bytes,
                "read_failure_count": 0, "read_coverage_status": "COMPLETE",
                "coverage_status": "COMPLETE", "ledger": "document-scan-ledger.jsonl",
                "private_path_mapping_local_only": "document-private-path-map.jsonl",
                "causal_edges": [], "documentary_references_are_causal": False}
    output_path = _engineering_output(output_dir)
    output = _new_output_dir(output_path, "DOC2-" + uuid.uuid4().hex, explicit=True)
    with (output / "document-scan-ledger.jsonl").open("xb") as stream:
        for encoded in encoded_rows:
            stream.write(encoded)
        stream.flush(); os.fsync(stream.fileno())
    with (output / "document-scan-manifest.jsonl").open("xb") as stream:
        stream.write((json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8"))
        stream.flush(); os.fsync(stream.fileno())
    with (output / "document-private-path-map.jsonl").open("xb") as stream:
        for row in rows:
            stream.write((json.dumps({"path_id": row["path_id"], "relative_path": row["relative_path"]},
                                     sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
        stream.flush(); os.fsync(stream.fileno())
    return {"schema": "pg_i7.engineering-documents.v2", **manifest,
            "output_dir": str(output), "actual_unique_document_bytes_read": total_bytes,
            "requested_evidence_flags": {"data_digest": False, "causal_data": False, "provenance": False},
            "read_only_source": True, "authority_effect": "NONE"}


def _engineering_adapt_documents(*, scan_dir: str, independent_receipt: str,
                                  output_dir: str, require_i5: bool = False,
                                  provenance_mode: str = "formal", strict_formal: bool = False) -> dict[str, Any]:
    _require_bound_workspace()
    _require_workspace_open()
    scan = _engineering_read_output(scan_dir)
    receipt = _checked_absolute(independent_receipt, base=FOCUSED_ROOT, must_exist=True)
    if not _beneath(receipt, FOCUSED_ROOT) or _beneath(receipt, ENGINEERING_ROOT):
        raise I7Error("INDEPENDENT_RECEIPT_SCOPE", "independent byte receipt must be a new focused-workspace artifact")
    output_path = _engineering_output(output_dir)
    output = _new_output_dir(output_path, "DOCGRAPH-" + uuid.uuid4().hex, explicit=True)
    sidecar_path = _lexical_path("evidence_sidecar.py", must_exist=True, base=WORKSPACE)
    _enable_local_i4_i5_dependency_path()
    loaded = sys.modules.get("evidence_sidecar")
    if loaded is not None and Path(os.path.abspath(getattr(loaded, "__file__", ""))) != sidecar_path:
        raise I7Error("IMPORT_COLLISION", "document graph adapter was loaded from outside the bound workspace")
    import evidence_sidecar  # type: ignore[import-not-found]
    if Path(os.path.abspath(evidence_sidecar.__file__)) != sidecar_path:
        raise I7Error("IMPORT_COLLISION", "document graph adapter is outside the bound workspace")
    try:
        result = evidence_sidecar.build_document_graph(scan, receipt, output)
    except Exception as exc:
        raise I7Error("DOCUMENT_GRAPH_ADAPTER_REJECTED", f"pinned I4/I5 document adapter rejected its bound inputs: {exc}") from exc
    frozen_i5_status = result.get("i5_status", result.get("status"))
    response = {"schema": "pg_i7.engineering-adapt-documents.v1", **result,
            "scan_dir": str(scan), "independent_receipt": str(receipt), "output_dir": str(output),
            "documentary_references_are_causal": False, "attribution": "UNKNOWN",
            "authority_effect": "NONE", "i5_append_attempted": False,
            "frozen_i5_status": frozen_i5_status}
    if provenance_mode == "prospective":
        receipt_copy = output / "independent-receipt-input.json"
        _write_bytes_new(receipt_copy, receipt.read_bytes())
        scan_manifest = _checked_absolute(scan / "document-scan-manifest.jsonl", base=WORKSPACE, must_exist=True)
        if not _beneath(scan_manifest, scan) or not scan_manifest.is_file():
            raise I7Error("DOCUMENT_SCAN_MANIFEST_SCOPE", "selected scan manifest escaped its exact workspace scan")
        scan_raw = scan_manifest.read_bytes()
        _write_new(output / "document-scan-manifest-input.json", {
            "schema": "i7.prospective.document-scan-manifest-envelope.v1",
            "original_path": str(scan_manifest), "sha256": _sha(scan_raw),
            "byte_length": len(scan_raw), "raw_base64": base64.b64encode(scan_raw).decode("ascii")})
        try:
            response["prospective_provenance"] = _prospective_adapter().build_for_documents(
                WORKSPACE, output, scan, receipt_copy)
        except Exception as exc:
            raise I7Error("PROSPECTIVE_PROVENANCE_FAILED",
                          f"Context Engine NEXT adapter rejected document evidence: {type(exc).__name__}: {exc}") from exc
        response["status"] = "PASS_PROSPECTIVE_ENGINEERING_ONLY"
        response["formal_i5_status"] = frozen_i5_status
    elif strict_formal and frozen_i5_status != "PASS":
        response.update(status="REJECTED_REQUIRED_I5", code="I5_FROZEN_CONTRACT_REJECTED",
                        required_i5_status="NOT_SATISFIED")
    if provenance_mode == "prospective" and require_i5 and frozen_i5_status != "PASS":
        response.update(status="REJECTED_REQUIRED_I5", code="I5_FROZEN_CONTRACT_REJECTED",
                        required_i5_status="NOT_SATISFIED")
    elif provenance_mode != "prospective" and require_i5 and frozen_i5_status != "PASS":
        response.update(status="REJECTED_REQUIRED_I5", code="I5_FROZEN_CONTRACT_REJECTED",
                        required_i5_status="NOT_SATISFIED")
    elif provenance_mode != "prospective" and not require_i5 and not strict_formal and frozen_i5_status != "PASS":
        response["status"] = "PARTIAL_I5_FROZEN_CONTRACT_LIMITATION"
    return response


def _engineering_verify_documents(*, graph_dir: str, expected_snapshot_id: str,
                                  recovery: bool = False, include_graph: bool = False,
                                  provenance_mode: str = "formal") -> dict[str, Any]:
    _require_bound_workspace()
    graph_path = _checked_absolute(graph_dir, base=WORKSPACE, must_exist=True)
    if not _beneath(graph_path, WORKSPACE / "runs") or not graph_path.is_dir():
        raise I7Error("DOCUMENT_GRAPH_SCOPE", "document graph must be inside this workspace runs/")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_snapshot_id):
        raise I7Error("SNAPSHOT_ID_INVALID", "expected snapshot ID must be lowercase SHA-256")
    sidecar_path = _lexical_path("evidence_sidecar.py", must_exist=True, base=WORKSPACE)
    _enable_local_i4_i5_dependency_path()
    loaded = sys.modules.get("evidence_sidecar")
    if loaded is not None and Path(os.path.abspath(getattr(loaded, "__file__", ""))) != sidecar_path:
        raise I7Error("IMPORT_COLLISION", "document graph verifier was loaded from outside the bound workspace")
    import evidence_sidecar  # type: ignore[import-not-found]
    if Path(os.path.abspath(evidence_sidecar.__file__)) != sidecar_path:
        raise I7Error("IMPORT_COLLISION", "document graph verifier is outside the bound workspace")
    try:
        result = evidence_sidecar.verify_document_graph(graph_path, expected_snapshot_id=expected_snapshot_id)
    except Exception as exc:
        raise I7Error("DOCUMENT_GRAPH_VERIFICATION_FAILED", f"pinned I4/I5 document reconstruction rejected artifacts: {exc}") from exc
    response = {"schema": "pg_i7.engineering-document-recovery.v1" if recovery
                else "pg_i7.engineering-document-verify.v1", **result,
                "graph_dir": str(graph_path), "expected_snapshot_id": expected_snapshot_id,
                "dispatch": "NOT_PERFORMED", "source_document_reads": 0,
                "i5_append_attempted": False, "read_only": True}
    if provenance_mode == "prospective":
        try:
            response["prospective_provenance"] = _prospective_adapter().verify(
                WORKSPACE, graph_path, expected_run_id=graph_path.name,
                documents=True,
                include_observations=include_graph)
        except Exception as exc:
            raise I7Error("PROSPECTIVE_PROVENANCE_VERIFICATION_FAILED",
                          f"Context Engine document NEXT graph did not verify: {type(exc).__name__}: {exc}") from exc
    if include_graph:
        graph_file = _checked_absolute(graph_path / "REAL_DOCUMENT_I4_GRAPH.json", base=graph_path, must_exist=True)
        response["graph"] = _parse_json(graph_file.read_bytes(), "verified document graph")
    return response


def _engineering_verify(*, output_dir: str, expected_snapshot_id: str,
                        receipt_path: str | None) -> dict[str, Any]:
    receipt = None
    if receipt_path is not None:
        receipt = _lexical_path(receipt_path, must_exist=False, base=VALIDATION_ROOT)
        if not _within(receipt, VALIDATION_ROOT) or _within(receipt, ENGINEERING_ROOT):
            raise I7Error("OUTPUT_SCOPE", "verification receipt must remain inside Validation")
        if not receipt.parent.exists():
            raise I7Error("RECEIPT_PARENT_NOT_FOUND", "verification receipt parent directory must already exist")
        if not receipt.parent.is_dir():
            raise I7Error("RECEIPT_PARENT_NOT_DIRECTORY", "verification receipt parent must be a directory")
        if receipt.exists():
            raise I7Error("RECEIPT_ALREADY_EXISTS", "verification receipt path must be fresh")
    scanner = _engineering_api()
    output = _engineering_read_output(output_dir)
    verification_adapter = _engineering_verification_api()
    try:
        result = verification_adapter.verify_snapshot(ENGINEERING_ROOT, output, snapshot_id=expected_snapshot_id)
    except verification_adapter.VerificationInputError as exc:
        raise I7Error(exc.code, str(exc)) from exc
    response = {"schema": "pg_i7.engineering-verify.v1", **result,
                "expected_snapshot_id": expected_snapshot_id}
    if receipt is not None:
        response["receipt_path"] = str(receipt)
        _write_new(receipt, response)
    return response


def _engineering_recover(*, output_dir: str, expected_snapshot_id: str,
                         owner_checkpoint_seal: str | None = None) -> dict[str, Any]:
    if owner_checkpoint_seal is not None and owner_checkpoint_seal != R5_OWNER_CHECKPOINT_SEAL_SHA256:
        raise I7Error("OWNER_CHECKPOINT_SEAL_INVALID", "owner checkpoint seal must match the fixed reviewed seal")
    scanner = _engineering_api()
    output = _engineering_read_output(output_dir)
    try:
        manifest = _engineering_last_manifest(output, scanner)
    except FileNotFoundError:
        # An interrupted scan may have durable state and ledger rows before its
        # first final manifest is published. Validate that checkpoint in place;
        # never invent a manifest to make the completed-scan reader succeed.
        state_path = output / "scan-state.json"
        try:
            state = scanner._read_small_json(state_path)
        except FileNotFoundError as exc:
            raise I7Error("INCOMPLETE_SCAN_STATE_MISSING",
                           "recovery requires a durable scan-state.json checkpoint") from exc
        except (OSError, ValueError, TypeError) as exc:
            raise I7Error("INCOMPLETE_SCAN_STATE_INVALID",
                           "scan-state.json failed bounded held-path validation") from exc
        checkpoint_snapshot = state.get("snapshot_id")
        completed_count = state.get("completed_count")
        if (not isinstance(checkpoint_snapshot, str)
                or not re.fullmatch(r"[0-9a-f]{64}", checkpoint_snapshot)
                or type(completed_count) is not int or completed_count < 0):
            raise I7Error("INCOMPLETE_SCAN_STATE_INVALID",
                           "scan-state.json lacks a valid snapshot ID or durable row count")
        if checkpoint_snapshot != expected_snapshot_id:
            raise I7Error("SNAPSHOT_ID_MISMATCH",
                           "expected snapshot ID differs from the durable incomplete scan state")
        try:
            marker = scanner._read_small_json(output / "OWNER_TRUSTED_PREFIX.json")
        except FileNotFoundError:
            marker = None
        except (OSError, ValueError, TypeError) as exc:
            raise I7Error("INCOMPLETE_OWNER_MARKER_INVALID",
                           "owner checkpoint marker failed bounded held-path validation") from exc
        if marker is not None:
            if (marker.get("schema") != "i7-engineering-owner-trusted-prefix@1"
                    or marker.get("status") != "TRUSTED_PREFIX_COMMITTED_AFTER_METADATA_PREFLIGHT"
                    or marker.get("snapshot_id") != checkpoint_snapshot):
                raise I7Error("INCOMPLETE_OWNER_MARKER_BINDING_INVALID",
                               "owner marker does not bind the expected checkpoint and fixed seal")
            if owner_checkpoint_seal is None:
                raise I7Error("OWNER_CHECKPOINT_SEAL_REQUIRED",
                               "R5 incomplete recovery requires the reviewed owner checkpoint seal")
            if marker.get("owner_checkpoint_seal_sha256") != owner_checkpoint_seal:
                raise I7Error("INCOMPLETE_OWNER_MARKER_BINDING_INVALID",
                               "owner marker does not bind the expected checkpoint and fixed seal")
        elif owner_checkpoint_seal is not None:
            raise I7Error("INCOMPLETE_OWNER_MARKER_MISSING",
                           "R5 incomplete recovery requires OWNER_TRUSTED_PREFIX.json")
        else:
            try:
                continuation = scanner._read_small_json(output / "CONTINUATION_IMPORT.json")
            except FileNotFoundError:
                continuation = None
            except (OSError, ValueError, TypeError) as exc:
                raise I7Error("INCOMPLETE_CONTINUATION_INVALID",
                               "continuation context failed bounded held-path validation") from exc
            if (continuation is not None
                    and continuation.get("new_reader_sha256") == R5_PRIMARY_READER_SHA256):
                raise I7Error("OWNER_CHECKPOINT_SEAL_REQUIRED",
                               "R5 incomplete recovery requires the reviewed owner checkpoint seal")
        ledger_path = output / "scan-ledger.jsonl"
        try:
            ledger_stream, _, _, _ = scanner._open_verified(ledger_path)
        except (OSError, ValueError) as exc:
            raise I7Error("INCOMPLETE_SCAN_LEDGER_MISSING_OR_UNSAFE",
                           "recovery requires a verified durable scan ledger") from exc
        else:
            ledger_stream.close()
        manifest_snapshot = checkpoint_snapshot
    else:
        manifest_snapshot = manifest.get("snapshot_id")
    if manifest_snapshot != expected_snapshot_id:
        raise I7Error("SNAPSHOT_ID_MISMATCH", "expected snapshot ID differs from latest manifest or checkpoint")
    stale_lock_review = None
    if (output / ".scan.lock").exists():
        try:
            import engineering_recovery  # type: ignore[import-not-found]
        except ImportError as exc:
            raise I7Error("RECOVERY_ADAPTER_UNAVAILABLE", "stale-lock review adapter is unavailable") from exc
        expected_adapter = _lexical_path("engineering_recovery.py", must_exist=True, base=WORKSPACE)
        if Path(os.path.abspath(engineering_recovery.__file__)) != expected_adapter:
            raise I7Error("IMPORT_COLLISION", "recovery adapter is outside the fixed composition")
        stale_lock_review = engineering_recovery.recover_after_crash(
            ENGINEERING_ROOT, output, expected_owner_anchor_sha256=owner_checkpoint_seal)
        result = stale_lock_review.get("recovery_result", {})
    else:
        result = scanner.recover_scan(ENGINEERING_ROOT, output,
                                      expected_owner_anchor_sha256=owner_checkpoint_seal)
    if result.get("snapshot_id") not in {None, expected_snapshot_id}:
        raise I7Error("SNAPSHOT_ID_MISMATCH", "recovery produced a different snapshot ID")
    return {"schema": "pg_i7.engineering-recover.v1", **result,
            "expected_snapshot_id": expected_snapshot_id,
            "stale_lock_review": stale_lock_review,
            "dispatch": "NOT_PERFORMED"}


def _engineering_inspect(*, output_dir: str, expected_snapshot_id: str) -> dict[str, Any]:
    scanner = _engineering_api()
    output = _engineering_read_output(output_dir)
    manifest = _engineering_last_manifest(output, scanner)
    if manifest.get("snapshot_id") != expected_snapshot_id:
        raise I7Error("SNAPSHOT_ID_MISMATCH", "expected snapshot ID differs from latest manifest")
    return {"schema": "pg_i7.engineering-inspect.v1", **manifest,
            "expected_snapshot_id": expected_snapshot_id, "read_only": True}


def _read_independent_verification(path: Path, expected_snapshot_id: str) -> dict[str, Any]:
    raw = path.read_bytes()
    try:
        independent = _parse_json(raw, "independent verification receipt")
    except I7Error as exc:
        raise I7Error("INDEPENDENT_VERIFICATION_INVALID", "independent receipt is not strict JSON") from exc
    independent["receipt_sha256"] = _sha(raw)
    independent["receipt_byte_length"] = len(raw)
    if independent.get("schema") == "pg_i7.independent-corpus-audit.v1":
        if (independent.get("status") != "ENUMERATED_AND_REHASHED_WITH_EXPLICIT_EXCEPTIONS"
                or independent.get("expected_producer_snapshot_id") != expected_snapshot_id):
            raise I7Error("INDEPENDENT_VERIFICATION_SNAPSHOT_MISMATCH",
                          "independent corpus audit does not bind the expected producer snapshot")
        posterior = independent.get("posterior_comparison")
        if (not isinstance(posterior, dict)
                or posterior.get("producer_inventory_recomputed_snapshot_id") != expected_snapshot_id
                or posterior.get("producer_inventory_snapshot_matches_expected") is not True
                or posterior.get("producer_cross_snapshot_rows") != 0):
            raise I7Error("INDEPENDENT_VERIFICATION_JOIN_INVALID",
                          "independent audit posterior does not join the exact expected producer snapshot")
    elif independent.get("schema") == "pg_i7.root-independent-document-verification.v1":
        if independent.get("status") != "PASS" or independent.get("snapshot_id") != expected_snapshot_id:
            raise I7Error("INDEPENDENT_VERIFICATION_SNAPSHOT_MISMATCH",
                          "document verification receipt is not a PASS for the expected snapshot")
    else:
        raise I7Error("INDEPENDENT_VERIFICATION_SCHEMA_UNSUPPORTED",
                      "independent receipt schema is not an approved audit contract")
    return independent


def _engineering_integrate(*, scan_dir: str, summary_dir: str, output_dir: str,
                           expected_snapshot_id: str, verification_receipt: str,
                           independent_verification: str | None,
                           repair_dir: str | None) -> dict[str, Any]:
    scanner = _engineering_api()
    scan = _engineering_read_output(scan_dir)
    summary = _engineering_read_output(summary_dir)
    repair = _engineering_read_output(repair_dir) if repair_dir is not None else None
    output = _engineering_output(output_dir)
    manifest = _engineering_last_manifest(scan, scanner)
    if manifest.get("snapshot_id") != expected_snapshot_id:
        raise I7Error("SNAPSHOT_ID_MISMATCH", "expected snapshot ID differs from latest scan manifest")
    receipt_path = _engineering_read_output(verification_receipt)
    verification = json.loads(receipt_path.read_bytes())
    counts = [verification.get(name) for name in ("checked_count", "missing_count", "extra_count", "mismatch_count")]
    if (verification.get("schema") != "pg_i7.engineering-verify.v1"
            or verification.get("expected_snapshot_id") != expected_snapshot_id
            or not all(isinstance(value, int) and value >= 0 for value in counts)
            or verification.get("inventory_matches") is not (verification.get("snapshot_id") == expected_snapshot_id)):
        raise I7Error("SCAN_RECEIPT_INVALID", "I4 integration requires a coherent exact-snapshot CLI verification receipt")
    if verification.get("status") == "VERIFIED":
        if (verification.get("inventory_matches") is not True
                or any(verification.get(name) != 0 for name in ("missing_count", "extra_count", "mismatch_count"))):
            raise I7Error("SCAN_RECEIPT_INVALID", "VERIFIED status conflicts with recorded source counts")
    elif verification.get("status") != "INCOMPLETE_OR_MISMATCH" or not (
            verification.get("inventory_matches") is False
            or any(verification.get(name, 0) > 0 for name in ("missing_count", "extra_count", "mismatch_count"))):
        raise I7Error("SCAN_RECEIPT_INVALID", "partial verifier status lacks explicit mismatch evidence")
    independent = None
    if independent_verification is not None:
        receipt_path = _engineering_read_output(independent_verification)
        independent = _read_independent_verification(receipt_path, expected_snapshot_id)
    try:
        import evidence_sidecar  # type: ignore[import-not-found]
    except ImportError as exc:
        raise I7Error("SIDECAR_UNAVAILABLE", "evidence sidecar is unavailable") from exc
    expected_sidecar = _lexical_path("evidence_sidecar.py", must_exist=True, base=WORKSPACE)
    if Path(os.path.abspath(evidence_sidecar.__file__)) != expected_sidecar:
        raise I7Error("IMPORT_COLLISION", "evidence sidecar is not from the fixed composition")
    output.mkdir(parents=True, exist_ok=False)
    result = evidence_sidecar.build_corpus_graph(summary, output, snapshot_id=expected_snapshot_id,
                                                  scan_verification=verification,
                                                  independent_verification=independent,
                                                  scan_dir=scan,
                                                  supplemental_repair_dir=repair)
    return {"schema": "pg_i7.engineering-integrate.v1", **result,
            "scan_dir": str(scan), "summary_dir": str(summary), "output_dir": str(output),
            "requested_evidence_flags": {"data_digest": True, "causal_data": True, "provenance": True}}


def _engineering_summarize(*, scan_dir: str, output_dir: str, expected_snapshot_id: str,
                           repair_dir: str | None) -> dict[str, Any]:
    scan = _engineering_read_output(scan_dir)
    output = _engineering_output(output_dir)
    repair = _engineering_read_output(repair_dir) if repair_dir is not None else None
    scanner = _engineering_api()
    manifest = _engineering_last_manifest(scan, scanner)
    if manifest.get("snapshot_id") != expected_snapshot_id:
        raise I7Error("SNAPSHOT_ID_MISMATCH", "expected snapshot ID differs from latest scan manifest")
    try:
        import summarize_corpus  # type: ignore[import-not-found]
    except ImportError as exc:
        raise I7Error("SUMMARIZER_UNAVAILABLE", "bounded corpus summarizer is unavailable") from exc
    expected_module = _lexical_path("summarize_corpus.py", must_exist=True, base=WORKSPACE)
    if Path(os.path.abspath(summarize_corpus.__file__)) != expected_module:
        raise I7Error("IMPORT_COLLISION", "summarizer is not from the fixed composition")
    output.mkdir(parents=True, exist_ok=False)
    result = summarize_corpus.summarize_scan(scan, output, repair_dir=repair)
    if result.get("snapshot_id") != expected_snapshot_id:
        raise I7Error("SNAPSHOT_ID_MISMATCH", "summary output differs from expected snapshot ID")
    return {"schema": "pg_i7.engineering-summarize.v1", **result,
            "scan_dir": str(scan), "output_dir": str(output), "read_only_source": True}


def _common(parser: argparse.ArgumentParser, *, input_arg: bool = False, from_run: bool = False) -> None:
    parser.add_argument("--workspace-dir", required=True,
                        help="dedicated focused workspace beneath the task campaigns root")
    parser.add_argument("--json", action="store_true", help="emit one structured JSON response")
    parser.add_argument("--output-dir", help="workspace-contained output directory; default: runs")
    parser.add_argument("--provider", default=PROVIDER_ID,
                        choices=[PROVIDER_ID, "safe.documents.metadata.v1", "safe.documents.metadata.v2"])
    parser.add_argument("--data-digest", action="store_true")
    parser.add_argument("--causal-data", action="store_true")
    parser.add_argument("--provenance", action="store_true")
    parser.add_argument("--provenance-mode", choices=("formal", "prospective"), default=None,
                        help="use formal compatibility behavior (default) or the separate Engineering-only NEXT store")
    if input_arg:
        parser.add_argument("--input", help="JSON input file following pg_i7.input.v1")
        parser.add_argument("--input-sha256")
        parser.add_argument("--negative", action="store_true", help="exercise the existing controlled OUTPUT_TAMPER path")
    if from_run:
        parser.add_argument("--from-run", required=True)
        parser.add_argument("--expected-operation-id")
        parser.add_argument("--input-sha256")


def _parser() -> argparse.ArgumentParser:
    parser = StructuredArgumentParser(
        prog="pg_i7",
        description="Compose the existing Fiveflow structured totals path for bounded local synthetic Engineering.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  py -3 pg_i7.py inspect --json
  py -3 pg_i7.py demo --json
  py -3 pg_i7.py run --input sample.json --data-digest --causal-data --provenance --json
  py -3 pg_i7.py verify --from-run runs/OP-id --expected-operation-id OP-id --json
  py -3 pg_i7.py pipeline documents-to-totals --selection-manifest REAL_DOCUMENT_SELECTION.json --workspace-dir campaigns/run-001 --data-digest --causal-data --provenance-mode prospective --json

Providers safe.synthetic.totals.v1, exact-legacy safe.documents.metadata.v1, and policy-bound safe.documents.metadata.v2 are registered. Inputs contain bounded 32-bit
integers. All output, recovery and graph paths must stay inside this workspace.
No protected I3/native dispatch, grants, claims, network, training, or installs.
""",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands._parser_class = StructuredArgumentParser
    for command in ("inspect", "demo", "run", "graph", "verify", "query", "recover", "pipeline", "documents",
                    "engineering-scan", "engineering-documents", "engineering-inspect", "engineering-summarize", "engineering-verify", "engineering-recover", "engineering-integrate", "engineering-adapt-documents", "engineering-verify-documents", "engineering-recover-documents", "engineering-query-documents"):
        summary = {
            "inspect": "Show the fixed local API and provider registry.",
            "demo": "Run the existing structured totals provider on built-in synthetic values.",
            "run": "Run the existing structured totals provider on a bounded JSON input file.",
            "graph": "Read the causal graph artifact for an existing run.",
            "verify": "Recompute existing consumer and replay evidence for a run.",
            "query": "Read a compact result view for an existing run.",
            "recover": "Reconstruct evidence for an existing run without re-execution.",
            "pipeline": "Run the selection-bound eight-document metadata to synthetic totals pipeline.",
            "documents": "Inspect, prepare, or validate a root-policy-bound document selection.",
            "engineering-scan": "Stream a path-redacted inventory of the fixed Engineering source root.",
            "engineering-documents": "Inspect 4 to 10 explicit Engineering documents as inert text.",
            "engineering-inspect": "Read a compact Engineering scan manifest with an expected snapshot ID.",
            "engineering-summarize": "Stream corpus coverage and documentary references from a completed snapshot.",
            "engineering-integrate": "Build a derived I4 graph from a complete or explicitly partial verification receipt and compact summary.",
            "engineering-verify": "Independently rehash a completed Engineering snapshot.",
            "engineering-recover": "Resume a paused Engineering inventory and bind the expected snapshot ID.",
            "engineering-adapt-documents": "Build a derived I4/I5 result from a committed selected-document scan and independent byte receipt.",
            "engineering-verify-documents": "Rebuild and verify a committed eight-document I4/I5 projection without source rereads.",
            "engineering-recover-documents": "Verify committed document evidence without redispatch, source rereads, or restart.",
            "engineering-query-documents": "Query the verified bounded I4 graph projection.",
        }[command]
        sub = commands.add_parser(command, help=summary, description=summary, formatter_class=argparse.RawDescriptionHelpFormatter)
        if command == "pipeline":
            sub.add_argument("pipeline_action", nargs="?", choices=("documents-to-totals",))
            sub.add_argument("--pipeline", dest="pipeline_flag", choices=("documents-to-totals",))
            sub.add_argument("--workspace-dir", required=True,
                             help="dedicated focused workspace beneath the task campaigns root")
            sub.add_argument("--selection-manifest", required=True)
            sub.add_argument("--data-digest", action="store_true", default=True)
            sub.add_argument("--causal-data", action="store_true", default=True)
            sub.add_argument("--provenance", action="store_true")
            sub.add_argument("--provenance-mode", choices=("prospective",), default="prospective")
            sub.add_argument("--json", action="store_true")
        elif command == "documents":
            document_commands = sub.add_subparsers(dest="documents_action", required=True)
            document_commands._parser_class = StructuredArgumentParser
            for action in ("inspect", "prepare", "validate"):
                doc_sub = document_commands.add_parser(action, help=f"{action.capitalize()} an allow-root document selection")
                doc_sub.add_argument("--workspace-dir", required=True)
                doc_sub.add_argument("--json", action="store_true")
                if action in {"inspect", "prepare"}:
                    doc_sub.add_argument("--policy-id", required=True, choices=("engineering", "package-fixtures"))
                if action == "prepare":
                    doc_sub.add_argument("--selection-id", required=True)
                    doc_sub.add_argument("--relative-path", required=True, action="append")
                    doc_sub.add_argument("--output", required=True)
                elif action == "validate":
                    doc_sub.add_argument("--selection-manifest", required=True)
        elif command in {"demo", "run"}:
            _common(sub, input_arg=(command == "run"))
        elif command in {"graph", "verify", "query", "recover"}:
            _common(sub, from_run=True)
        elif command == "engineering-scan":
            sub.add_argument("--output-dir", required=True)
            sub.add_argument("--max-files", type=int)
            sub.add_argument("--resume", action="store_true")
            sub.add_argument("--owner-checkpoint-seal", help="fixed reviewed R5 owner seal SHA-256; resume only")
        elif command == "engineering-documents":
            sub.add_argument("--workspace-dir", required=True,
                             help="dedicated focused workspace beneath the task campaigns root")
            sub.add_argument("--output-dir", required=True)
            sub.add_argument("--selection-manifest", required=True)
        elif command == "engineering-adapt-documents":
            sub.add_argument("--workspace-dir", required=True,
                             help="existing focused workspace containing the selected scan")
            sub.add_argument("--scan-dir", required=True)
            sub.add_argument("--independent-receipt", required=True)
            sub.add_argument("--output-dir", required=True)
            sub.add_argument("--require-i5", action="store_true",
                             help="return structured nonzero when frozen I5 cannot accept the current I4 semantic bytes")
        elif command in {"engineering-verify-documents", "engineering-recover-documents", "engineering-query-documents"}:
            sub.add_argument("--workspace-dir", required=True,
                             help="existing focused workspace containing committed document graph artifacts")
            sub.add_argument("--graph-dir", required=True)
            sub.add_argument("--expected-snapshot-id", required=True)
        elif command in {"engineering-inspect", "engineering-recover"}:
            sub.add_argument("--output-dir", required=True)
            sub.add_argument("--expected-snapshot-id", required=True)
            if command == "engineering-recover":
                sub.add_argument("--owner-checkpoint-seal", help="fixed reviewed R5 owner seal SHA-256")
        elif command == "engineering-summarize":
            sub.add_argument("--scan-dir", required=True)
            sub.add_argument("--output-dir", required=True)
            sub.add_argument("--expected-snapshot-id", required=True)
            sub.add_argument("--repair-dir", help="Validation-contained supplemental repair evidence directory")
        elif command == "engineering-verify":
            sub.add_argument("--output-dir", required=True)
            sub.add_argument("--expected-snapshot-id", required=True)
            sub.add_argument("--receipt")
        elif command == "engineering-integrate":
            sub.add_argument("--scan-dir", required=True)
            sub.add_argument("--summary-dir", required=True)
            sub.add_argument("--output-dir", required=True)
            sub.add_argument("--expected-snapshot-id", required=True)
            sub.add_argument("--verification-receipt", required=True)
            sub.add_argument("--independent-verification")
            sub.add_argument("--repair-dir", help="Validation-contained supplemental repair evidence directory")
        if command.startswith("engineering-"):
            sub.add_argument("--data-digest", action="store_true")
            sub.add_argument("--causal-data", action="store_true")
            sub.add_argument("--provenance", action="store_true")
            sub.add_argument("--provenance-mode", choices=("formal", "prospective"), default=None)
            sub.add_argument("--json", action="store_true")
        else:
            if command not in {"demo", "run", "graph", "verify", "query", "recover", "pipeline", "documents"}:
                _common(sub)
        if command == "graph":
            sub.add_argument("--graph-format", choices=("json", "dot"), default="json")
    return parser


def _api_module() -> Any:
    _require_bound_workspace()
    expected = _lexical_path("i7_api.py", must_exist=True, base=WORKSPACE)
    pinned = _source_commitments().get("i7_api.py")
    if not pinned or _sha(expected.read_bytes()) != pinned:
        raise I7Error("API_FACADE_PIN_MISMATCH", "workspace API facade differs from its composition pin")
    import importlib.util
    name = "_pg_i7_api_child"
    loaded = sys.modules.get(name)
    if loaded is not None:
        if Path(getattr(loaded, "__file__", "")).resolve() != expected.resolve():
            raise I7Error("IMPORT_COLLISION", "API facade is already loaded from another workspace")
        return loaded
    spec = importlib.util.spec_from_file_location(name, expected)
    if spec is None or spec.loader is None:
        raise I7Error("API_FACADE_UNAVAILABLE", "workspace API facade import specification is unavailable")
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    existing = sys.modules.get("i7_api")
    if existing is not None and Path(getattr(existing, "__file__", "")).resolve() != expected.resolve():
        raise I7Error("IMPORT_COLLISION", "i7_api module name is bound to another composition path")
    sys.modules.setdefault("i7_api", loaded)
    return loaded


def _documents_policy_module() -> Any:
    _require_bound_workspace()
    expected = _lexical_path("documents_policy.py", must_exist=True, base=WORKSPACE)
    pinned = _source_commitments().get("documents_policy.py")
    if not pinned or _sha(expected.read_bytes()) != pinned:
        raise I7Error("DOCUMENT_POLICY_PIN_MISMATCH", "document policy module differs from its composition pin")
    name = "documents_policy"
    loaded = sys.modules.get(name)
    if loaded is not None:
        if Path(getattr(loaded, "__file__", "")).resolve() != expected.resolve():
            raise I7Error("IMPORT_COLLISION", "documents_policy is already loaded from another composition")
        return loaded
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, expected)
    if spec is None or spec.loader is None:
        raise I7Error("DOCUMENT_POLICY_UNAVAILABLE", "fixed document policy import specification is unavailable")
    loaded = importlib.util.module_from_spec(spec)
    sys.modules[name] = loaded
    spec.loader.exec_module(loaded)
    return loaded


def _dispatch(args: argparse.Namespace) -> dict[str, Any]:
    i7_api = _api_module()
    if args.command.startswith("engineering-") and args.command not in {
            "engineering-documents", "engineering-adapt-documents", "engineering-verify-documents",
            "engineering-recover-documents", "engineering-query-documents"}:
        raise I7Error("ENGINEERING_COMMAND_DISABLED_IN_FOCUSED_PROFILE",
                      "bulk scan, legacy scan recovery, and prior-snapshot integration routes are disabled in this focused CLI")
    flags = {"data_digest": getattr(args, "data_digest", False),
             "causal_data": getattr(args, "causal_data", False),
             "provenance": getattr(args, "provenance", False)}
    provenance_mode = getattr(args, "provenance_mode", None)
    mode = provenance_mode or "formal"
    strict_formal = provenance_mode == "formal"
    if args.command == "documents":
        if args.documents_action == "inspect":
            return i7_api.inspect_document_selection(workspace_dir=str(WORKSPACE), policy_id=args.policy_id)
        if args.documents_action == "prepare":
            return i7_api.prepare_document_selection(workspace_dir=str(WORKSPACE), policy_id=args.policy_id,
                                                     relative_paths=args.relative_path,
                                                     selection_id=args.selection_id, output_path=args.output)
        if args.documents_action == "validate":
            return i7_api.validate_document_selection(workspace_dir=str(WORKSPACE),
                                                      selection_manifest=args.selection_manifest)
        raise I7Error("UNSUPPORTED_OPERATION", "unsupported documents action")
    if args.command == "inspect":
        result = i7_api.inspect(workspace_dir=str(WORKSPACE), **flags)
        result["provenance_mode"] = mode
        result["prospective_backend"] = {"available": True, "source_sha256": "1fdbf50fe56e82ec86e96dff3039a0bf5d8cfbddc217d9f2d928b7a62bd62568", "authority": "ENGINEERING_ONLY"}
        return result
    if args.command == "demo":
        return i7_api.run_provider(workspace_dir=str(WORKSPACE), provider_id=args.provider, input="<demo>",
                                   output_dir=args.output_dir, negative=getattr(args, "negative", False), provenance_mode=mode,
                                   strict_formal=strict_formal, **flags)
    if args.command == "run":
        if args.provider in {"safe.documents.metadata.v1", "safe.documents.metadata.v2"}:
            if args.negative or args.data_digest or args.causal_data or args.provenance:
                raise I7Error("PROVIDER_OPTION_UNSUPPORTED", "document metadata providers only scan the selected manifest and return a read ledger")
            return i7_api.run_provider(workspace_dir=str(WORKSPACE), provider_id=args.provider,
                                       input=args.input, output_dir=args.output_dir,
                                       input_sha256=args.input_sha256)
        return i7_api.run_provider(workspace_dir=str(WORKSPACE), provider_id=args.provider, input=args.input,
                                   output_dir=args.output_dir, negative=args.negative,
                                   input_sha256=args.input_sha256, provenance_mode=mode,
                                   strict_formal=strict_formal, **flags)
    if args.command == "pipeline":
        if args.pipeline_action and args.pipeline_flag and args.pipeline_action != args.pipeline_flag:
            raise I7Error("CLI_ARGUMENT_ERROR", "positional and --pipeline actions conflict")
        if not (args.pipeline_action or args.pipeline_flag):
            raise I7Error("CLI_ARGUMENT_ERROR", "pipeline requires documents-to-totals")
        return i7_api.run_pipeline(workspace_dir=str(WORKSPACE), selection_manifest=args.selection_manifest,
                                   output_dir="pipeline-" + uuid.uuid4().hex,
                                   data_digest=args.data_digest, causal_data=args.causal_data,
                                   provenance=args.provenance, provenance_mode=args.provenance_mode)
    if args.command == "graph":
        response = i7_api.get_graph(workspace_dir=str(WORKSPACE), from_run=args.from_run,
                                    graph_format=args.graph_format, expected_operation_id=args.expected_operation_id)
        if mode == "prospective" and "prospective_provenance" not in response:
            run_dir, record = _load_run(args.from_run, args.expected_operation_id)
            response["prospective_provenance"] = _verify_prospective_run(run_dir, record["operation_id"])
        return response
    if args.command == "verify":
        response = i7_api.verify(workspace_dir=str(WORKSPACE), from_run=args.from_run,
                                 input_sha256=args.input_sha256, expected_operation_id=args.expected_operation_id)
        if mode == "prospective" and "prospective_provenance" not in response:
            run_dir, record = _load_run(args.from_run, args.expected_operation_id)
            response["prospective_provenance"] = _verify_prospective_run(run_dir, record["operation_id"])
        return response
    if args.command == "recover":
        response = i7_api.recover(workspace_dir=str(WORKSPACE), from_run=args.from_run,
                                  input_sha256=args.input_sha256, expected_operation_id=args.expected_operation_id)
        if mode == "prospective" and "prospective_provenance" not in response:
            run_dir, record = _load_run(args.from_run, args.expected_operation_id)
            response["prospective_provenance"] = _verify_prospective_run(run_dir, record["operation_id"])
        return response
    if args.command == "query":
        return i7_api.query(workspace_dir=str(WORKSPACE), from_run=args.from_run,
                            expected_operation_id=args.expected_operation_id)
    if args.command == "engineering-scan":
        return _engineering_scan(output_dir=args.output_dir, max_files=args.max_files,
                                 resume=args.resume, flags=flags,
                                 owner_checkpoint_seal=args.owner_checkpoint_seal)
    if args.command == "engineering-documents":
        return _engineering_documents(output_dir=args.output_dir,
                                      selection_manifest=args.selection_manifest, flags=flags)
    if args.command == "engineering-adapt-documents":
        return _engineering_adapt_documents(scan_dir=args.scan_dir,
                                            independent_receipt=args.independent_receipt,
                                            output_dir=args.output_dir, require_i5=args.require_i5,
                                            provenance_mode=mode, strict_formal=strict_formal)
    if args.command == "engineering-verify-documents":
        return _engineering_verify_documents(graph_dir=args.graph_dir,
                                             expected_snapshot_id=args.expected_snapshot_id,
                                             provenance_mode=mode)
    if args.command == "engineering-recover-documents":
        return _engineering_verify_documents(graph_dir=args.graph_dir,
                                             expected_snapshot_id=args.expected_snapshot_id, recovery=True,
                                             provenance_mode=mode)
    if args.command == "engineering-query-documents":
        return _engineering_verify_documents(graph_dir=args.graph_dir,
                                             expected_snapshot_id=args.expected_snapshot_id, include_graph=True,
                                             provenance_mode=mode)
    if args.command == "engineering-inspect":
        return _engineering_inspect(output_dir=args.output_dir, expected_snapshot_id=args.expected_snapshot_id)
    if args.command == "engineering-summarize":
        return _engineering_summarize(scan_dir=args.scan_dir, output_dir=args.output_dir,
                                      expected_snapshot_id=args.expected_snapshot_id,
                                      repair_dir=args.repair_dir)
    if args.command == "engineering-integrate":
        return _engineering_integrate(scan_dir=args.scan_dir, summary_dir=args.summary_dir,
                                      output_dir=args.output_dir, expected_snapshot_id=args.expected_snapshot_id,
                                      verification_receipt=args.verification_receipt,
                                     independent_verification=args.independent_verification,
                                     repair_dir=args.repair_dir)
    if args.command == "engineering-verify":
        return _engineering_verify(output_dir=args.output_dir, expected_snapshot_id=args.expected_snapshot_id,
                                   receipt_path=args.receipt)
    if args.command == "engineering-recover":
        return _engineering_recover(output_dir=args.output_dir, expected_snapshot_id=args.expected_snapshot_id,
                                    owner_checkpoint_seal=args.owner_checkpoint_seal)
    raise I7Error("UNSUPPORTED_OPERATION", "unsupported command")


def main(argv: list[str] | None = None) -> int:
    global ACTIVE_OUTPUT_DIR
    ACTIVE_OUTPUT_DIR = None
    parser = _parser()
    arg_values = argv if argv is not None else sys.argv[1:]
    json_mode = "--json" in arg_values
    parser.json_help = json_mode
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                child.json_help = json_mode
    try:
        args = parser.parse_args(argv)
        if FOCUSED_PROFILE_ERROR is not None:
            raise I7Error(FOCUSED_PROFILE_ERROR[0], FOCUSED_PROFILE_ERROR[1])
        if (args.command.startswith("engineering-") and args.command not in {
                "engineering-documents", "engineering-adapt-documents", "engineering-verify-documents",
                "engineering-recover-documents", "engineering-query-documents"}):
            raise I7Error("ENGINEERING_COMMAND_DISABLED_IN_FOCUSED_PROFILE",
                          "bulk scan, legacy scan recovery, and prior-snapshot integration routes are disabled in this focused CLI")
        if args.command == "engineering-documents":
            selection_path = _checked_absolute(args.selection_manifest, base=FOCUSED_ROOT, must_exist=True)
            if not _same_path(selection_path, REAL_DOCUMENT_SELECTION):
                raise I7Error("DOCUMENT_SELECTION_NOT_ALLOWLISTED", "only the root-selected focused document manifest is accepted")
            if _sha(selection_path.read_bytes()) != REAL_DOCUMENT_SELECTION_SHA256:
                raise I7Error("DOCUMENT_SELECTION_PIN_MISMATCH", "root-selected document manifest changed")
        route_code = _route_workspace(args, list(arg_values))
        if route_code is not None:
            return route_code
        response = _dispatch(args)
        body = json.dumps(response, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        print(body if args.json else json.dumps(response, ensure_ascii=True, sort_keys=True, indent=2))
        if response.get("status") == "EXPECTED_FAILURE":
            return 3
        if response.get("status") == "REJECTED_REQUIRED_I5":
            return 4
        return 0
    except I7Error as exc:
        error = {"schema": "pg_i7.error.v1", "status": "ERROR", "code": exc.code, "message": str(exc)}
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        error = {"schema": "pg_i7.error.v1", "status": "ERROR", "code": "OPERATION_FAILED", "message": str(exc)}
    except Exception as exc:
        import traceback
        traceback.print_exc(file=sys.stderr)
        error = {"schema": "pg_i7.error.v1", "status": "ERROR",
                 "code": "INTERNAL_ERROR", "message": type(exc).__name__}
    if ACTIVE_OUTPUT_DIR is not None:
        try:
            _write_new(ACTIVE_OUTPUT_DIR / "failure.json", error)
        except OSError:
            pass
    if json_mode:
        print(json.dumps(error, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
        print(f"{error['code']}: {error['message']}", file=sys.stderr)
    else:
        print(f"{error['code']}: {error['message']}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
