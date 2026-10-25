"""Deterministic, fail-closed I1 paths for synthetic local NTFS storage."""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from .identity import parse_id, validate_id
from . import native_ntfs

MAX_PATH_UNITS = 240
CLASSES = frozenset({
    "events", "raw", "derived", "findings", "errors", "decisions",
    "audits", "actor_tool_reports", "manifests", "closures",
})
_SCOPE = (
    ("product_id", "PRODUCT", "p"),
    ("lineage_id", "LINEAGE", "l"),
    ("version_id", "VERSION", "v"),
    ("session_id", "SESSION", "s"),
    ("run_id", "RUN", "r"),
    ("attempt_id", "ATTEMPT", "a"),
)
_RESERVED = {"CON", "PRN", "AUX", "NUL", *{f"COM{i}" for i in range(1, 10)}, *{f"LPT{i}" for i in range(1, 10)}}
_SAFE_PART = re.compile(r"[A-Za-z0-9_.-]+\Z")


class StoragePathError(ValueError):
    """The configured root, identity, or relative path is unsafe."""


class LocatorCollision(StoragePathError):
    """A 16-hex locator already belongs to another full typed ID."""


def utf16_units(value: str) -> int:
    try:
        return len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError as exc:
        raise StoragePathError("malformed Unicode path") from exc


def validate_relative_path(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or value.startswith(("/", "\\")):
        raise StoragePathError("relative path required")
    if "\\" in value or ":" in value or "//" in value or "\x00" in value:
        raise StoragePathError("separator, device, or alternate stream rejected")
    parts = value.split("/")
    if any(not part or part in {".", ".."} or part.endswith((" ", ".")) for part in parts):
        raise StoragePathError("dot, empty, or trailing-space component")
    for part in parts:
        if not _SAFE_PART.fullmatch(part) or part.split(".", 1)[0].upper() in _RESERVED:
            raise StoragePathError("unsafe path component")
    return PurePosixPath(*parts)


def _windows_attributes(path: Path) -> int | None:
    if os.name != "nt":
        return 0 if path.exists() or path.is_symlink() else None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    method = kernel.GetFileAttributesW
    method.argtypes = [ctypes.c_wchar_p]
    method.restype = ctypes.c_uint32
    value = method(str(path))
    return None if value == 0xFFFFFFFF else value


def is_reparse(path: Path) -> bool:
    if os.name != "nt":
        return path.is_symlink()
    attrs = _windows_attributes(path)
    return attrs is not None and bool(attrs & 0x400)


def check_ancestors(path: Path, *, include_final: bool = True) -> None:
    candidate = path if include_final else path.parent
    chain = list(reversed((candidate, *candidate.parents)))
    for entry in chain:
        attrs = _windows_attributes(entry)
        if attrs is not None and is_reparse(entry):
            raise StoragePathError(f"reparse point in path: {entry}")




class DirectoryPins:
    """Held directory handles keyed by their validated lexical absolute paths."""

    def __init__(self, handles: dict[str, tuple[int, tuple[int, bytes]]]) -> None:
        self._handles = handles

    def handle_for(self, directory: Path) -> int:
        try:
            return self._handles[str(directory).casefold()][0]
        except KeyError as exc:
            raise StoragePathError("directory was not pinned") from exc

    def identity_for(self, directory: Path) -> tuple[int, bytes]:
        try:
            return self._handles[str(directory).casefold()][1]
        except KeyError as exc:
            raise StoragePathError("directory was not pinned") from exc

    def assert_unchanged(self) -> None:
        for handle, original in self._handles.values():
            if native_ntfs.inspect_handle(handle, directory=True) != original:
                raise StoragePathError("pinned directory identity changed")


@contextmanager
def pin_parent_directories(
    *file_paths: Path,
    create: bool = False,
    expected_root: tuple[Path, int, bytes] | None = None,
):
    """Open every ancestor parent-first through held NTFS handles, never a path race."""
    if os.name != "nt":
        raise StoragePathError("Windows directory handle pinning required")
    entries: dict[str, Path] = {}
    for file_path in file_paths:
        path = Path(file_path)
        if not path.is_absolute():
            raise StoragePathError("absolute file path required for pinning")
        parent = path.parent
        for entry in reversed((parent, *parent.parents)):
            entries[str(entry).casefold()] = entry
    ordered = sorted(entries.values(), key=lambda item: (len(item.parts), str(item).casefold()))
    handles: dict[str, tuple[int, tuple[int, bytes]]] = {}
    try:
        for entry in ordered:
            key = str(entry).casefold()
            if entry == Path(entry.anchor):
                handle = native_ntfs.open_volume_root(entry.anchor)
            else:
                parent_handle = handles[str(entry.parent).casefold()][0]
                allow_create = create and (
                    expected_root is None
                    or (entry.is_relative_to(expected_root[0]) and entry != expected_root[0])
                )
                handle = native_ntfs.open_directory(
                    parent_handle, entry.name, create=allow_create,
                )
            identity = native_ntfs.inspect_handle(handle, directory=True)
            handles[key] = (handle, identity)
            if expected_root is not None and key == str(expected_root[0]).casefold():
                if identity != expected_root[1:]:
                    raise StoragePathError("authoritative root identity changed")
        pins = DirectoryPins(handles)
        yield pins
        pins.assert_unchanged()
    except native_ntfs.NativePathError as exc:
        raise StoragePathError(str(exc)) from exc
    finally:
        for handle, _ in reversed(tuple(handles.values())):
            native_ntfs.close_handle(handle)


def _local_ntfs(root: Path) -> None:
    if os.name != "nt":
        raise StoragePathError("I1 authoritative storage requires Windows NTFS")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes = [ctypes.c_wchar_p]
    drive_type.restype = ctypes.c_uint
    if drive_type(root.anchor) != 3:
        raise StoragePathError("fixed local drive required")
    get_volume = kernel.GetVolumeInformationW
    get_volume.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_wchar_p, ctypes.c_uint32,
    ]
    get_volume.restype = ctypes.c_int
    fs_name = ctypes.create_unicode_buffer(64)
    if not get_volume(root.anchor, None, 0, None, None, None, fs_name, len(fs_name)):
        raise StoragePathError("cannot identify volume filesystem")
    if fs_name.value.upper() != "NTFS":
        raise StoragePathError("NTFS required")


@dataclass(frozen=True)
class Scope:
    project_id: str
    product_id: str
    lineage_id: str
    version_id: str
    session_id: str
    run_id: str
    attempt_id: str

    def __post_init__(self) -> None:
        validate_id(self.project_id, "PROJECT")
        for field, kind, _ in _SCOPE:
            validate_id(getattr(self, field), kind)

    def items(self) -> tuple[tuple[str, str, str, str], ...]:
        return tuple((field, kind, label, getattr(self, field)) for field, kind, label in _SCOPE)


class StoragePaths:
    """Pure path derivation plus immutable full-ID-to-locator reservation."""

    def __init__(self, root: Path) -> None:
        root = Path(root)
        if not root.is_absolute() or not root.exists() or not root.is_dir():
            raise StoragePathError("existing absolute storage root required")
        check_ancestors(root)
        if any(part.casefold() == "onedrive" for part in root.parts):
            raise StoragePathError("OneDrive cannot be authoritative storage")
        _local_ntfs(root)
        self.root = root
        stable = root.stat(follow_symlinks=False)
        self._root_identity = (root, stable.st_dev, stable.st_ino)
        with pin_parent_directories(root / "_identity_") as pins:
            self._native_root_identity = (root, *pins.identity_for(root))

    @contextmanager
    def guard_paths(self, *file_paths: Path, create: bool = False):
        with pin_parent_directories(*file_paths, create=create, expected_root=self._native_root_identity) as pins:
            yield pins

    def _checked(self, relative: str) -> Path:
        rel = validate_relative_path(relative)
        candidate = self.root.joinpath(*rel.parts)
        if utf16_units(str(candidate)) >= MAX_PATH_UNITS:
            raise StoragePathError("path exceeds 239 UTF-16 code units")
        return candidate

    def object_relative(self, scope: Scope, class_name: str, entity_id: str, extension: str) -> str:
        if class_name not in CLASSES or extension not in {"bin", "json"}:
            raise StoragePathError("unknown storage class or extension")
        if class_name in {"raw", "derived"}:
            validate_id(entity_id, "EVIDENCE")
        elif class_name == "events":
            validate_id(entity_id, "EVENT")
        else:
            validate_id(entity_id)
        segments = ["h"]
        for _, _, label, entity in scope.items():
            segments.append(f"{label}-{parse_id(entity)[1][:16]}")
        segments.extend((class_name, f"{entity_id}.{extension}"))
        relative = "/".join(segments)
        self._checked(relative)
        return relative

    def checked_path(self, relative: str, *, require_existing: bool = False) -> Path:
        path = self._checked(relative)
        check_ancestors(path, include_final=require_existing)
        if require_existing and (not path.exists() or is_reparse(path)):
            raise StoragePathError("missing or reparse final path")
        return path

    def ensure_parents(self, relative: str) -> Path:
        path = self._checked(relative)
        with self.guard_paths(path, create=True):
            pass
        return path

    def locator_relative(self, label: str, entity_id: str) -> str:
        validate_id(entity_id)
        if label not in {item[2] for item in _SCOPE}:
            raise StoragePathError("unknown locator class")
        return f"registry/locators/{label}-{parse_id(entity_id)[1][:16]}.json"

    def expected_locator_rows(self, scope: Scope) -> tuple[dict, ...]:
        ancestry: dict[str, str] = {"project_id": scope.project_id}
        rows = []
        for field, kind, label, entity in scope.items():
            rows.append({
                "kind": kind, "label": label, "entity_id": entity,
                "ancestry": dict(ancestry),
                "relative_path": self.locator_relative(label, entity),
            })
            ancestry[field] = entity
        return tuple(rows)

    def reserve_scope(self, scope: Scope, write_new) -> tuple[str, ...]:
        """Caller holds the store lock; write_new uses exclusive create + readback."""
        locations = []
        for expected in self.expected_locator_rows(scope):
            rel = expected["relative_path"]
            path = self.ensure_parents(rel)
            with self.guard_paths(path) as pins:
                try:
                    import json
                    existing = json.loads(native_ntfs.read_file(
                        pins.handle_for(path.parent), path.name,
                    ))
                except FileNotFoundError:
                    write_new(rel, expected)
                except (ValueError, OSError) as exc:
                    raise StoragePathError("corrupt locator map") from exc
                else:
                    if any(existing.get(key) != expected[key] for key in ("kind", "label", "entity_id", "ancestry", "relative_path")):
                        raise LocatorCollision("locator belongs to another ID or scope")
            locations.append(rel)
        return tuple(locations)
