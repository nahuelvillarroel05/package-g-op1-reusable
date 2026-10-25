# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Independent allow-root and v2 selection helpers for inert document metadata."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import ctypes
from pathlib import Path, PureWindowsPath
from typing import Any


SCHEMA = "pg_i7.documents.selection.v2"
POLICY_VERSION = "1"
POLICY_MANIFEST_SHA256 = "d2ceab5e3ec67c26da186862a7537b01f04669a6338e87b75800adf54fae66d0"
MAX_DOCUMENTS = 64
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_SELECTION_BYTES = 1024 * 1024
MAX_TOTAL_DOCUMENT_BYTES = 64 * 1024 * 1024
POLICY_IDS = ("engineering", "package-fixtures")
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
             *(f"LPT{i}" for i in range(1, 10)),
             *(f"COM{i}{suffix}" for i in range(1, 10) for suffix in ("¹", "²", "³")),
             *(f"LPT{i}{suffix}" for i in range(1, 10) for suffix in ("¹", "²", "³"))}


def allowed_root(cli: Any, policy_id: str) -> Path:
    policy_path = cli._checked_absolute(cli.FOCUSED_ROOT / "candidate" / "documents_policy_manifest.json",
                                        base=cli.FOCUSED_ROOT, must_exist=True)
    policy_raw = _bounded_read(cli, cli._engineering_api(), policy_path, 4096)
    if hashlib.sha256(policy_raw).hexdigest() != POLICY_MANIFEST_SHA256:
        raise cli.I7Error("DOCUMENT_POLICY_MANIFEST_PIN_MISMATCH", "fixed document policy manifest is not pinned")
    root = _policy_root_path(cli, policy_id)
    root = cli._checked_absolute(root, base=cli.FOCUSED_ROOT, must_exist=True)
    if not root.is_dir():
        raise cli.I7Error("DOCUMENT_POLICY_ROOT_INVALID", "fixed document root is not a directory")
    return root


def _policy_root_path(cli: Any, policy_id: str) -> Path:
    """Return the independent fixed root path without touching that root."""
    if policy_id == "engineering":
        raise cli.I7Error("DOCUMENT_POLICY_DISABLED_PUBLIC_EXPORT", "private engineering corpus is not distributed")
    if policy_id == "package-fixtures":
        return cli.FOCUSED_ROOT / "candidate" / "fixtures" / "Engineering"
    raise cli.I7Error("DOCUMENT_POLICY_NOT_ALLOWLISTED", "policy_id is not in the fixed document-root policy")


def _safe_relative(cli: Any, value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise cli.I7Error("DOCUMENT_SELECTION_PATH_INVALID", "document paths must be nonempty slash-separated relative paths")
    win = PureWindowsPath(value)
    parts = value.split("/")
    if win.is_absolute() or win.drive or any(part in {"", ".", ".."} for part in parts):
        raise cli.I7Error("DOCUMENT_SELECTION_PATH_INVALID", "absolute, traversal, or empty document path components are rejected")
    for part in parts:
        stem = part.split(".", 1)[0].upper()
        if (part.endswith((".", " ")) or any(ch in part for ch in '<>:"|?*')
                or stem in _RESERVED):
            raise cli.I7Error("DOCUMENT_SELECTION_PATH_INVALID", "reserved, ADS, or ambiguous Windows path components are rejected")
    return "/".join(parts)


def _bounded_read(cli: Any, scanner: Any, path: Path, limit: int) -> bytes:
    """Read a regular file in bounded chunks with held-handle/path identity checks."""
    checked = cli._checked_absolute(path, base=cli.FOCUSED_ROOT, must_exist=True)
    try:
        before = checked.lstat()
        if (not stat.S_ISREG(before.st_mode) or int(getattr(before, "st_nlink", 1)) != 1
                or scanner._path_has_reparse_ancestor(checked)):
            raise cli.I7Error("DOCUMENT_FILE_TYPE_REJECTED", "document or selection manifest is linked, reparse, or non-regular")
        stream, held_before, opened, held_path = scanner._open_verified(checked)
    except cli.I7Error:
        raise
    except Exception as exc:
        raise cli.I7Error("DOCUMENT_FILE_OPEN_REJECTED", "document or selection manifest could not be opened safely") from exc
    chunks: list[bytes] = []
    total = 0
    try:
        while total <= limit:
            chunk = stream.read(min(65536, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        opened_after = os.fstat(stream.fileno())
        after = checked.lstat()
        final_after = scanner._final_path_from_handle(stream.fileno())
        if (total > limit or scanner._cross_api_stat_tuple(held_before) != scanner._cross_api_stat_tuple(opened)
                or scanner._stat_tuple(opened) != scanner._stat_tuple(opened_after)
                or scanner._cross_api_stat_tuple(opened_after) != scanner._cross_api_stat_tuple(after)
                or int(getattr(opened_after, "st_nlink", 1)) != 1
                or int(getattr(after, "st_nlink", 1)) != 1
                or scanner._path_has_reparse_ancestor(checked) or final_after != held_path):
            raise cli.I7Error("DOCUMENT_FILE_CHANGED", "document or selection manifest changed during bounded read")
        return b"".join(chunks)
    finally:
        stream.close()


def _hold_parent(path: Path):
    """Hold a directory identity stable while creating a child file."""
    if os.name == "nt":
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [("attributes", wintypes.DWORD), ("creation", FILETIME),
                        ("access", FILETIME), ("write", FILETIME),
                        ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                        ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                        ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel32.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        get_info = kernel32.GetFileInformationByHandle
        get_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(BY_HANDLE_FILE_INFORMATION)]
        get_info.restype = wintypes.BOOL
        close = kernel32.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL
        handle = create(str(path), 0x80 | 0x20, 0x1 | 0x2, None, 3, 0x02000000 | 0x00200000, None)
        if handle == wintypes.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), "cannot hold output parent without delete sharing", str(path))
        info = BY_HANDLE_FILE_INFORMATION()
        if not get_info(handle, ctypes.byref(info)) or info.attributes & 0x400:
            close(handle)
            raise OSError(ctypes.get_last_error(), "output parent handle is unavailable or reparse", str(path))
        return ("nt", handle, None, close)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        os.close(fd)
        raise OSError("output parent is not a directory")
    return ("posix", fd, (int(info.st_dev), int(info.st_ino)), os.close)


def _open_exclusive_child(parent_guard, name: str) -> int:
    """Create a child relative to the held parent object, never by re-resolving its path."""
    if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise OSError("output child name is not a single path component")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if parent_guard[0] == "posix":
        return os.open(name, flags, 0o600, dir_fd=parent_guard[1])
    if os.name != "nt" or parent_guard[0] != "nt":
        raise OSError("held parent handle type is unsupported")
    from ctypes import wintypes

    class UNICODE_STRING(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                    ("Buffer", wintypes.LPWSTR)]

    class OBJECT_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
                    ("ObjectName", ctypes.POINTER(UNICODE_STRING)), ("Attributes", wintypes.ULONG),
                    ("SecurityDescriptor", wintypes.LPVOID), ("SecurityQualityOfService", wintypes.LPVOID)]

    class IO_STATUS_BLOCK(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

    encoded = name.encode("utf-16-le")
    if len(encoded) > 0xFFFC:
        raise OSError("output child name is too long")
    buffer = ctypes.create_unicode_buffer(name)
    unicode_name = UNICODE_STRING(len(encoded), len(encoded) + 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = OBJECT_ATTRIBUTES(ctypes.sizeof(OBJECT_ATTRIBUTES), wintypes.HANDLE(parent_guard[1]),
                                   ctypes.pointer(unicode_name), 0x40, None, None)
    io_status = IO_STATUS_BLOCK()
    native_handle = wintypes.HANDLE()
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    create = ntdll.NtCreateFile
    create.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.ULONG,
                       ctypes.POINTER(OBJECT_ATTRIBUTES), ctypes.POINTER(IO_STATUS_BLOCK),
                       ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
                       wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]
    create.restype = ctypes.c_long
    # GENERIC_WRITE, share read/write (no delete), FILE_CREATE, and a synchronous
    # non-directory open that never follows a reparse point at the leaf.
    status = int(create(ctypes.byref(native_handle), 0x40000000 | 0x00100000 | 0x80, ctypes.byref(attributes),
                        ctypes.byref(io_status), None, 0x80, 0x3, 0x2,
                        0x40 | 0x20 | 0x00200000, None, 0)) & 0xFFFFFFFF
    if status == 0xC0000035:
        raise FileExistsError("selection output already exists")
    if status & 0x80000000:
        raise OSError(status, "relative exclusive Windows child creation failed")
    try:
        import msvcrt
        return msvcrt.open_osfhandle(native_handle.value, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    except BaseException:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        close = kernel32.CloseHandle
        close.argtypes = [wintypes.HANDLE]
        close.restype = wintypes.BOOL
        close(native_handle)
        raise


def _write_manifest_new(cli: Any, scanner: Any, path: Path, body: bytes) -> None:
    """Create a selection only through an exclusively opened, path-verified handle."""
    runs = cli._checked_absolute(cli.WORKSPACE / "runs", base=cli.WORKSPACE, must_exist=False)
    if not runs.exists():
        workspace_id = cli._object_id(cli.WORKSPACE)
        cli._write_probe(cli.WORKSPACE)
        try:
            runs.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_COLLISION", "runs directory appeared during exclusive creation") from exc
        if cli._object_id(cli.WORKSPACE) != workspace_id or scanner._path_has_reparse_ancestor(runs):
            raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_CHANGED", "runs directory changed during creation")
    parent = cli._checked_absolute(path.parent, base=cli.WORKSPACE, must_exist=True)
    target = cli._checked_absolute(path, base=cli.WORKSPACE, must_exist=False)
    if (not cli._same_path(parent, runs) or not cli._same_path(parent, target.parent)
            or scanner._path_has_reparse_ancestor(parent)):
        raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_SCOPE", "selection output parent changed or contains a reparse point")
    parent_identity = cli._object_id(parent)
    try:
        parent_guard = _hold_parent(parent)
    except OSError as exc:
        raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_PARENT_UNAVAILABLE", "selection output parent could not be held safely") from exc
    parent_before = parent_identity
    if cli._object_id(parent) != parent_identity:
        parent_guard[3](parent_guard[1])
        raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_CHANGED", "selection output parent changed while its handle was acquired")
    fd = -1
    try:
        fd = _open_exclusive_child(parent_guard, target.name)
        stream = os.fdopen(fd, "wb", buffering=0)
        fd = -1
    except FileExistsError as exc:
        if fd >= 0:
            os.close(fd)
        parent_guard[3](parent_guard[1])
        raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_EXISTS", "selection output must be a fresh file") from exc
    except BaseException:
        if fd >= 0:
            os.close(fd)
        parent_guard[3](parent_guard[1])
        raise
    try:
        opened = os.fstat(stream.fileno())
        named = target.lstat()
        final_path = scanner._final_path_from_handle(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or int(getattr(opened, "st_nlink", 1)) != 1
                or scanner._cross_api_stat_tuple(opened) != scanner._cross_api_stat_tuple(named)
                or int(getattr(named, "st_nlink", 1)) != 1
                or cli._object_id(parent) != parent_before
                or scanner._path_has_reparse_ancestor(target)
                or final_path is None or os.path.normcase(os.path.normpath(final_path)) != os.path.normcase(os.path.normpath(str(target)))):
            raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_REDIRECTED", "exclusive selection output handle is not bound to its verified workspace path")
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())
        after_fd = os.fstat(stream.fileno())
        after_path = target.lstat()
        final_after = scanner._final_path_from_handle(stream.fileno())
        if ((opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode), opened.st_nlink)
                != (after_fd.st_dev, after_fd.st_ino, stat.S_IFMT(after_fd.st_mode), after_fd.st_nlink)
                or int(after_fd.st_size) != len(body)
                or scanner._cross_api_stat_tuple(after_fd) != scanner._cross_api_stat_tuple(after_path)
                or int(getattr(after_fd, "st_nlink", 1)) != 1
                or cli._object_id(parent) != parent_before
                or scanner._path_has_reparse_ancestor(target)
                or final_after != final_path):
            raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_CHANGED", "selection output path or identity changed during write")
    finally:
        stream.close()
        parent_guard[3](parent_guard[1])


def _inspect(cli: Any, scanner: Any, root: Path, relative: str, expected_sha: str | None = None,
             expected_bytes: int | None = None,
             expected_identity: list[int] | None = None) -> dict[str, Any]:
    path = cli._checked_absolute(root / relative, base=root, must_exist=True)
    if not cli._beneath(path, root) or not path.is_file():
        raise cli.I7Error("DOCUMENT_SELECTION_PATH_INVALID", "selected document is not a regular file under the fixed root")
    before = path.lstat()
    identity = [int(before.st_dev), int(before.st_ino)]
    if (int(getattr(before, "st_nlink", 1)) != 1 or scanner._path_has_reparse_ancestor(path)
            or scanner._is_reparse(path, before)):
        raise cli.I7Error("DOCUMENT_FILE_TYPE_REJECTED", "hard-linked or reparse documents are rejected")
    if expected_identity is not None and identity != expected_identity:
        raise cli.I7Error("DOCUMENT_SELECTION_FILE_IDENTITY_MISMATCH", "document file identity differs from the prepared selection")
    if scanner._metadata_only_reason(relative):
        raise cli.I7Error("DOCUMENT_SELECTION_PROTECTED_PATH", "protected document paths are metadata-only and cannot be opened")
    if before.st_size > MAX_DOCUMENT_BYTES:
        raise cli.I7Error("DOCUMENT_SIZE_LIMIT", "document exceeds the fixed bounded source size")
    entry = scanner.Entry(relative, "file", "HASHED", int(before.st_size), int(before.st_mtime_ns),
                          int(before.st_dev), int(before.st_ino), int(before.st_mode))
    digest, status, _, bytes_read = scanner._stable_hash_details(path, entry)
    after = path.lstat()
    if status == "INACCESSIBLE":
        raise cli.I7Error("DOCUMENT_SELECTION_INACCESSIBLE", "selected document could not be read under the current file access state")
    if status == "READ_ERROR":
        raise cli.I7Error("DOCUMENT_FILE_OPEN_REJECTED", "selected document read failed during bounded verification")
    if (status != "HASHED" or digest is None or bytes_read != before.st_size
            or (expected_sha is not None and digest != expected_sha)
            or (expected_bytes is not None and int(before.st_size) != expected_bytes)
            or scanner._stat_tuple(before) != scanner._stat_tuple(after)
            or int(getattr(after, "st_nlink", 1)) != 1
            or scanner._path_has_reparse_ancestor(path)):
        raise cli.I7Error("DOCUMENT_SELECTION_CHANGED", "document failed bounded stable-read verification")
    path_id = scanner._path_token(relative)
    document = {"path_id": path_id, "kind": path.suffix.lower().lstrip("."),
                "status": "HASHED", "byte_count": int(before.st_size)}
    return {"path_id": path_id, "relative_path": relative,
            "path": str(path), "bytes": int(before.st_size), "sha256": digest,
            "file_identity": identity,
            "document": document}


def _preflight(cli: Any, scanner: Any, root: Path, relative: str) -> tuple[int, list[int]]:
    path = cli._checked_absolute(root / relative, base=root, must_exist=True)
    before = path.lstat()
    if (not cli._beneath(path, root) or not stat.S_ISREG(before.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
            or scanner._is_reparse(path, before) or scanner._path_has_reparse_ancestor(path)):
        raise cli.I7Error("DOCUMENT_FILE_TYPE_REJECTED", "hard-linked, redirected, or non-regular documents are rejected")
    if scanner._metadata_only_reason(relative):
        raise cli.I7Error("DOCUMENT_SELECTION_PROTECTED_PATH", "protected document paths are metadata-only and cannot be opened")
    if before.st_size < 0 or before.st_size > MAX_DOCUMENT_BYTES:
        raise cli.I7Error("DOCUMENT_SIZE_LIMIT", "document exceeds the fixed bounded source size")
    return int(before.st_size), [int(before.st_dev), int(before.st_ino)]


def inspect_document_selection(cli: Any, policy_id: str) -> dict[str, Any]:
    root = allowed_root(cli, policy_id)
    return {"schema": "i7_api.document_selection_policy.v1", "status": "PASS",
            "policy_id": policy_id, "source_root": str(root), "selection_schema": SCHEMA,
            "maximum_documents": MAX_DOCUMENTS, "maximum_document_bytes": MAX_DOCUMENT_BYTES,
            "maximum_total_document_bytes": MAX_TOTAL_DOCUMENT_BYTES,
            "manifest_controls_source_root": False, "read_only": True, "authority_effect": "NONE"}


def prepare_document_selection(cli: Any, *, policy_id: str, relative_paths: list[str] | tuple[str, ...],
                               selection_id: str, output_path: str) -> dict[str, Any]:
    if not isinstance(selection_id, str) or not _SAFE_ID.fullmatch(selection_id):
        raise cli.I7Error("DOCUMENT_SELECTION_ID_INVALID", "selection_id must be a short stable public identifier")
    if type(relative_paths) not in {list, tuple} or not 1 <= len(relative_paths) <= MAX_DOCUMENTS:
        raise cli.I7Error("DOCUMENT_SELECTION_COUNT_INVALID", "relative_paths must be a list or tuple of 1 to 64 paths")
    paths = [_safe_relative(cli, value) for value in relative_paths]
    if not 1 <= len(paths) <= MAX_DOCUMENTS:
        raise cli.I7Error("DOCUMENT_SELECTION_COUNT_INVALID", "selection must contain between 1 and 64 documents")
    keys = [value.casefold() for value in paths]
    if len(set(keys)) != len(keys):
        raise cli.I7Error("DOCUMENT_SELECTION_DUPLICATE", "selection contains a case-insensitive duplicate path")
    root = allowed_root(cli, policy_id)
    scanner = cli._engineering_api()
    preflight = [_preflight(cli, scanner, root, relative) for relative in paths]
    total = sum(size for size, _ in preflight)
    if total > MAX_TOTAL_DOCUMENT_BYTES:
        raise cli.I7Error("DOCUMENT_SELECTION_TOTAL_SIZE", "selection exceeds its bounded aggregate source size")
    rows = [_inspect(cli, scanner, root, relative, expected_bytes=size, expected_identity=identity)
            for relative, (size, identity) in zip(paths, preflight)]
    manifest = {"schema": SCHEMA, "selection_id": selection_id, "policy_id": policy_id,
                "policy_version": POLICY_VERSION,
                "policy_manifest_sha256": POLICY_MANIFEST_SHA256,
                "authorization_status": "DECLARED_REQUIRES_INDEPENDENT_POLICY_CHECK",
                "source_root": str(root),
                "limits": {"max_documents": MAX_DOCUMENTS, "max_document_bytes": MAX_DOCUMENT_BYTES,
                           "max_total_document_bytes": MAX_TOTAL_DOCUMENT_BYTES,
                           "max_input_bytes": 16384, "max_values": 64,
                           "min_value": -(2**31), "max_value": 2**31 - 1},
                "documents": rows}
    manifest["selection_commitment_sha256"] = hashlib.sha256(cli._json_bytes(manifest)).hexdigest()
    body = cli._json_bytes(manifest)
    if len(body) > MAX_SELECTION_BYTES:
        raise cli.I7Error("DOCUMENT_SELECTION_MANIFEST_SIZE", "selection manifest exceeds its bounded size")
    target = cli._checked_absolute(output_path, base=cli.WORKSPACE, must_exist=False)
    if (not cli._same_path(target.parent, cli.WORKSPACE / "runs") or not target.name.endswith(".json")):
        raise cli.I7Error("DOCUMENT_SELECTION_OUTPUT_SCOPE", "selection output must be a new direct JSON child of workspace runs/")
    _write_manifest_new(cli, scanner, target, body)
    return {"schema": "i7_api.document_selection_prepare.v1", "status": "PASS",
            "selection_id": selection_id, "policy_id": policy_id, "selection_manifest": str(target),
            "selection_sha256": hashlib.sha256(body).hexdigest(), "document_count": len(rows),
            "document_bytes": total, "read_only_source": True, "provider_dispatched": False,
            "pipeline_dispatched": False, "authority_effect": "NONE"}


def validate_selection_bytes(cli: Any, scanner: Any, raw: bytes) -> tuple[dict[str, Any], list[dict[str, Any]], Path]:
    """Validate an embedded selection contract without opening its source files."""
    if type(raw) is not bytes or len(raw) > MAX_SELECTION_BYTES:
        raise cli.I7Error("DOCUMENT_SELECTION_MANIFEST_SIZE", "selection manifest exceeds its bounded size")
    value = cli._parse_json(raw, "document selection")
    required = {"schema", "selection_id", "policy_id", "policy_version", "policy_manifest_sha256", "authorization_status",
                "source_root", "limits", "documents", "selection_commitment_sha256"}
    if (type(value) is not dict or value.get("schema") != SCHEMA or set(value) != required
            or not isinstance(value.get("selection_id"), str) or not _SAFE_ID.fullmatch(value["selection_id"])
            or value.get("policy_version") != POLICY_VERSION
            or value.get("policy_manifest_sha256") != POLICY_MANIFEST_SHA256
            or value.get("authorization_status") != "DECLARED_REQUIRES_INDEPENDENT_POLICY_CHECK"
            or type(value.get("documents")) is not list
            or not 1 <= len(value["documents"]) <= MAX_DOCUMENTS):
        raise cli.I7Error("DOCUMENT_SELECTION_INVALID", "v2 selection manifest has invalid schema, fields, or row count")
    root = _policy_root_path(cli, value["policy_id"])
    scanner_limits = {"max_documents": MAX_DOCUMENTS, "max_document_bytes": MAX_DOCUMENT_BYTES,
                      "max_total_document_bytes": MAX_TOTAL_DOCUMENT_BYTES,
                      "max_input_bytes": 16384, "max_values": 64,
                      "min_value": -(2**31), "max_value": 2**31 - 1}
    if value.get("limits") != scanner_limits:
        raise cli.I7Error("DOCUMENT_SELECTION_LIMITS_MISMATCH", "manifest limits differ from fixed runtime limits")
    commitment = value.pop("selection_commitment_sha256")
    expected_commitment = hashlib.sha256(cli._json_bytes(value)).hexdigest()
    value["selection_commitment_sha256"] = commitment
    if not isinstance(commitment, str) or commitment != expected_commitment:
        raise cli.I7Error("DOCUMENT_SELECTION_COMMITMENT_MISMATCH", "selection commitment does not bind the canonical manifest")
    if type(value.get("source_root")) is not str or not value["source_root"]:
        raise cli.I7Error("DOCUMENT_SELECTION_ROOT_NOT_ALLOWLISTED", "manifest source_root must be a nonempty string")
    claimed_root = os.path.normcase(os.path.normpath(value["source_root"]))
    expected_root = os.path.normcase(os.path.normpath(str(root)))
    if claimed_root != expected_root:
        raise cli.I7Error("DOCUMENT_SELECTION_ROOT_NOT_ALLOWLISTED", "manifest source_root differs from independent fixed policy")
    rows = value["documents"]
    seen: set[str] = set()
    total = 0
    for row in rows:
        if (type(row) is not dict or set(row) != {"path_id", "relative_path", "path", "bytes", "sha256", "file_identity", "document"}
                or type(row.get("bytes")) is not int or not 0 <= row["bytes"] <= MAX_DOCUMENT_BYTES
                or not isinstance(row.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or not isinstance(row.get("path_id"), str) or not re.fullmatch(r"[0-9a-f]{64}", row["path_id"])
                or type(row.get("document")) is not dict or type(row.get("file_identity")) is not list
                or len(row["file_identity"]) != 2 or any(type(x) is not int or x < 0 for x in row["file_identity"])):
            raise cli.I7Error("DOCUMENT_SELECTION_ROW_INVALID", "v2 selection row is malformed")
        relative = _safe_relative(cli, row["relative_path"])
        key = relative.casefold()
        if key in seen:
            raise cli.I7Error("DOCUMENT_SELECTION_DUPLICATE", "selection contains a case-insensitive duplicate path")
        seen.add(key)
        path = os.path.normcase(os.path.normpath(str(root / relative)))
        declared = os.path.normcase(os.path.normpath(row["path"])) if isinstance(row.get("path"), str) else ""
        expected_path_id = hashlib.sha256(relative.encode("utf-8", "surrogatepass")).hexdigest()
        expected_document = {"path_id": expected_path_id, "kind": Path(relative).suffix.lower().lstrip("."),
                             "status": "HASHED", "byte_count": row["bytes"]}
        if (declared != path or row["path_id"] != expected_path_id or row["document"] != expected_document
                or scanner._metadata_only_reason(relative)):
            raise cli.I7Error("DOCUMENT_SELECTION_PATH_MISMATCH", "document path differs from fixed-root relative path")
        total += row["bytes"]
    if total > MAX_TOTAL_DOCUMENT_BYTES:
        raise cli.I7Error("DOCUMENT_SELECTION_TOTAL_SIZE", "selection exceeds its bounded aggregate source size")
    return value, rows, root


def _manifest(cli: Any, scanner: Any, selection_manifest: str) -> tuple[dict[str, Any], list[dict[str, Any]], Path, bytes]:
    path = cli._checked_absolute(selection_manifest, base=cli.CAMPAIGN_ROOT, must_exist=True)
    relative_to_campaign = path.relative_to(cli.CAMPAIGN_ROOT)
    if (len(relative_to_campaign.parts) < 3 or relative_to_campaign.parts[1].casefold() != "runs"
            or path.suffix.casefold() != ".json" or not path.is_file()):
        raise cli.I7Error("DOCUMENT_SELECTION_MANIFEST_SCOPE", "selection manifest must be a regular JSON file under a focused campaign workspace runs/")
    raw = _bounded_read(cli, scanner, path, MAX_SELECTION_BYTES)
    value, rows, policy_root = validate_selection_bytes(cli, scanner, raw)
    root = allowed_root(cli, value["policy_id"])
    if not cli._same_path(root, policy_root):
        raise cli.I7Error("DOCUMENT_SELECTION_ROOT_NOT_ALLOWLISTED", "live policy root differs from the independently validated selection root")
    for row in rows:
        source_path = cli._checked_absolute(root / row["relative_path"], base=root, must_exist=True)
        declared = cli._checked_absolute(row["path"], base=root, must_exist=True)
        if not cli._same_path(source_path, declared) or not cli._beneath(source_path, root):
            raise cli.I7Error("DOCUMENT_SELECTION_PATH_MISMATCH", "document path differs from fixed-root relative path")
    return value, rows, root, raw


def validate_document_selection(cli: Any, selection_manifest: str) -> dict[str, Any]:
    scanner = cli._engineering_api()
    value, rows, root, raw = _manifest(cli, scanner, selection_manifest)
    for row in rows:
        current = _inspect(cli, scanner, root, row["relative_path"], row["sha256"], row["bytes"], row["file_identity"])
        if (current["path_id"] != row["path_id"] or current["path"] != row["path"]
                or current["file_identity"] != row["file_identity"]
                or current["document"] != row["document"]):
            raise cli.I7Error("DOCUMENT_SELECTION_COMMITMENT_MISMATCH", "document metadata differs from selection commitments")
    return {"schema": "i7_api.document_selection_validate.v1", "status": "PASS",
            "selection_id": value["selection_id"], "policy_id": value["policy_id"],
            "selection_manifest": str(Path(selection_manifest)), "selection_sha256": hashlib.sha256(raw).hexdigest(),
            "document_count": len(rows), "document_bytes": sum(row["bytes"] for row in rows),
            "read_only_source": True, "provider_dispatched": False,
            "pipeline_dispatched": False, "authority_effect": "NONE"}
