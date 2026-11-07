"""Exact-path read gate for trusted Python code in the current process only.

The guard observes CPython ``open`` audit events. It is not an OS sandbox,
producer authenticator, or control over native code and child processes.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
import sys
from typing import NamedTuple


class DeniedRead(NamedTuple):
    path: str
    mode: str | int | None
    flags: int | None
    reason: str


def _has_reparse_component(path: Path) -> bool:
    """Check existing components without opening file contents."""
    components = (*reversed(path.parents), path)
    for component in components:
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if component.is_symlink() or getattr(component, "is_junction", lambda: False)():
            return True
        reparse_bit = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if getattr(info, "st_file_attributes", 0) & reparse_bit:
            return True
    return False


def _normalize_install_path(value, *, directory: bool) -> Path:
    if not isinstance(value, (str, bytes, os.PathLike)):
        raise TypeError("scope paths must be strings or path-like values")
    path = Path(os.fsdecode(os.fspath(value))).absolute()
    if _has_reparse_component(path):
        raise ValueError("reparse path component rejected")
    resolved = path.resolve(strict=True)
    if directory and not resolved.is_dir():
        raise ValueError("protected root must be an existing directory")
    if not directory and not resolved.is_file():
        raise ValueError("allowed source must be an existing regular file")
    return resolved


def _normalize_open_path(value) -> tuple[Path, Path, bool]:
    if not isinstance(value, (str, bytes, os.PathLike)):
        raise TypeError("open target is not a path")
    path = Path(os.fsdecode(os.fspath(value))).absolute()
    has_reparse = _has_reparse_component(path)
    return path, path.resolve(strict=False), has_reparse


def _is_read_open(mode, flags) -> bool:
    if isinstance(flags, int):
        access_mask = getattr(os, "O_ACCMODE", os.O_WRONLY | os.O_RDWR)
        access = flags & access_mask
        if access == os.O_WRONLY:
            return False
        if access in {os.O_RDONLY, os.O_RDWR}:
            return True
        # Unknown access flags are conservatively treated as reads.
        return True
    if isinstance(mode, str):
        return mode.startswith("r") or "+" in mode
    # Integer ``mode`` is the permission argument used by os.open; without
    # integer flags the access class is unknown, so do not bypass the gate.
    return True


def _is_ipc_descriptor(value) -> bool:
    """Permit only metadata-proven pipe/socket descriptors used by IPC."""
    if type(value) is not int:
        return False
    try:
        mode = os.fstat(value).st_mode
    except OSError:
        return False
    is_socket = getattr(stat, "S_ISSOCK", lambda _mode: False)
    return stat.S_ISFIFO(mode) or is_socket(mode)


class ReadScopeGuard:
    """Immutable path metadata plus an append-only denied-event tuple."""

    __slots__ = ("_protected_roots", "_allowed_sources", "_denied_events", "_sealed")

    def __init__(self, protected_roots: frozenset[Path], allowed_sources: frozenset[Path]):
        object.__setattr__(self, "_protected_roots", protected_roots)
        object.__setattr__(self, "_allowed_sources", allowed_sources)
        object.__setattr__(self, "_denied_events", ())
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name, value):
        if getattr(self, "_sealed", False):
            raise AttributeError("read-scope metadata is immutable")
        object.__setattr__(self, name, value)

    @property
    def protected_roots(self) -> frozenset[Path]:
        return self._protected_roots

    @property
    def allowed_sources(self) -> frozenset[Path]:
        return self._allowed_sources

    @property
    def denied_events(self) -> tuple[DeniedRead, ...]:
        return self._denied_events

    def _record_denial(self, event: DeniedRead) -> None:
        object.__setattr__(self, "_denied_events", (*self._denied_events, event))

    def _audit(self, event, args) -> None:
        if event != "open" or not args:
            return
        target = args[0]
        mode = args[1] if len(args) > 1 else None
        flags = args[2] if len(args) > 2 and isinstance(args[2], int) else None
        if not _is_read_open(mode, flags):
            return

        if type(target) is int:
            if _is_ipc_descriptor(target):
                return
            shown = f"<fd:{target}>"
            self._record_denial(DeniedRead(shown, mode, flags,
                                           "unresolved or non-IPC file descriptor"))
            raise PermissionError(errno.EACCES, "read scope denied unclassified descriptor", shown)

        try:
            lexical_path, path, has_reparse = _normalize_open_path(target)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            shown = os.fsdecode(target) if isinstance(target, (str, bytes, os.PathLike)) else repr(target)
            self._record_denial(DeniedRead(shown, mode, flags, str(exc)))
            raise PermissionError(errno.EACCES, "read scope denied unclassifiable open", shown) from exc

        is_protected = any(
            candidate == root or root in candidate.parents
            for candidate in (lexical_path, path)
            for root in self._protected_roots
        )
        if is_protected:
            if has_reparse:
                self._record_denial(DeniedRead(str(lexical_path), mode, flags,
                                               "reparse path component rejected"))
                raise PermissionError(errno.EACCES, "read scope denied reparse path", str(lexical_path))
            if path not in self._allowed_sources:
                self._record_denial(DeniedRead(str(path), mode, flags, "path is not exactly allowlisted"))
                raise PermissionError(errno.EACCES, "read scope denied protected path", str(path))


def install_read_scope(protected_roots, allowed_sources) -> ReadScopeGuard:
    """Install a process-local CPython open gate for exact source files.

    Paths are checked as metadata only. This function does not read source
    bodies, verify their hashes, or grant any external processing rights.
    """
    if isinstance(protected_roots, (str, bytes, os.PathLike)):
        raise TypeError("protected_roots must be a nonempty path sequence")
    if isinstance(allowed_sources, (str, bytes, os.PathLike)):
        raise TypeError("allowed_sources must be a path sequence")
    try:
        roots = frozenset(_normalize_install_path(value, directory=True)
                          for value in protected_roots)
        sources = frozenset(_normalize_install_path(value, directory=False)
                            for value in allowed_sources)
    except TypeError:
        raise
    if not roots:
        raise ValueError("at least one protected root is required")
    if any(not any(source == root or root in source.parents for root in roots)
           for source in sources):
        raise ValueError("every allowed source must be inside a protected root")

    guard = ReadScopeGuard(roots, sources)
    sys.addaudithook(guard._audit)
    return guard
