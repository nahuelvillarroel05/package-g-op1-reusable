"""Handle-relative NTFS operations for the synthetic I1 object store.

Every caller supplies a validated single leaf and a held immediate-parent handle.
These native calls belong to the reusable control plane, never to protected runtime.
"""
from __future__ import annotations

import ctypes as C
import msvcrt
import os
import re
from pathlib import Path
from typing import BinaryIO

_LIST = 0x00000001
_READ = 0x00000001
_WRITE = 0x00000002
_READ_ATTRIBUTES = 0x00000080
_DELETE = 0x00010000
_SYNCHRONIZE = 0x00100000
_SHARE_READ_WRITE = 0x3
_OPEN_REPARSE = 0x00200000
_SYNC_IO = 0x00000020
_DIRECTORY = 0x00000001
_NON_DIRECTORY = 0x00000040
_FILE_OPEN = 1
_FILE_CREATE = 2
_REPARSE_ATTRIBUTE = 0x00000400
_DIRECTORY_ATTRIBUTE = 0x00000010
_LEAF = re.compile(r"[^\\/:\x00]+\Z")
_RESERVED = {"CON", "PRN", "AUX", "NUL", *{f"COM{i}" for i in range(1, 10)}, *{f"LPT{i}" for i in range(1, 10)}}
_FORBIDDEN = frozenset('\\/:<>?*|"')
_BIDI = frozenset(chr(code) for code in (*range(0x202A, 0x202F), *range(0x2066, 0x206A)))

_STATUS_COLLISION = 0xC0000035
_STATUS_MISSING = frozenset({0xC0000034, 0xC000003A})


class NativePathError(OSError):
    """A handle-relative filesystem operation did not satisfy its contract."""


class UnicodeString(C.Structure):
    _fields_ = [("Length", C.c_uint16), ("MaximumLength", C.c_uint16), ("Buffer", C.c_void_p)]


class ObjectAttributes(C.Structure):
    _fields_ = [
        ("Length", C.c_uint32), ("RootDirectory", C.c_void_p),
        ("ObjectName", C.POINTER(UnicodeString)), ("Attributes", C.c_uint32),
        ("SecurityDescriptor", C.c_void_p), ("SecurityQualityOfService", C.c_void_p),
    ]


class IoStatusBlock(C.Structure):
    _fields_ = [("Status", C.c_void_p), ("Information", C.c_size_t)]


class AttributeTag(C.Structure):
    _fields_ = [("attributes", C.c_uint32), ("tag", C.c_uint32)]


class FileIdInfo(C.Structure):
    _fields_ = [("volume_serial", C.c_uint64), ("file_id", C.c_ubyte * 16)]


class RenameInfo(C.Structure):
    _fields_ = [
        ("replace_if_exists", C.c_ubyte), ("root_directory", C.c_void_p),
        ("file_name_length", C.c_uint32), ("file_name", C.c_wchar * 1),
    ]


class FullDirectoryInfo(C.Structure):
    _fields_ = [
        ("next_offset", C.c_uint32), ("file_index", C.c_uint32),
        ("creation_time", C.c_int64), ("last_access_time", C.c_int64),
        ("last_write_time", C.c_int64), ("change_time", C.c_int64),
        ("end_of_file", C.c_int64), ("allocation_size", C.c_int64),
        ("attributes", C.c_uint32), ("file_name_length", C.c_uint32),
        ("ea_size", C.c_uint32), ("file_name", C.c_wchar * 1),
    ]


if os.name == "nt":
    _kernel = C.WinDLL("kernel32", use_last_error=True)
    _ntdll = C.WinDLL("ntdll")
    _kernel.CreateFileW.argtypes = [
        C.c_wchar_p, C.c_uint32, C.c_uint32, C.c_void_p,
        C.c_uint32, C.c_uint32, C.c_void_p,
    ]
    _kernel.CreateFileW.restype = C.c_void_p
    _kernel.CloseHandle.argtypes = [C.c_void_p]
    _kernel.CloseHandle.restype = C.c_int
    _kernel.GetFileInformationByHandleEx.argtypes = [
        C.c_void_p, C.c_int, C.c_void_p, C.c_uint32,
    ]
    _kernel.GetFileInformationByHandleEx.restype = C.c_int
    _kernel.FlushFileBuffers.argtypes = [C.c_void_p]
    _kernel.FlushFileBuffers.restype = C.c_int
    _ntdll.NtCreateFile.argtypes = [
        C.POINTER(C.c_void_p), C.c_uint32, C.POINTER(ObjectAttributes),
        C.POINTER(IoStatusBlock), C.c_void_p, C.c_uint32,
        C.c_uint32, C.c_uint32, C.c_uint32, C.c_void_p, C.c_uint32,
    ]
    _ntdll.NtCreateFile.restype = C.c_int32
    _ntdll.NtSetInformationFile.argtypes = [
        C.c_void_p, C.POINTER(IoStatusBlock), C.c_void_p,
        C.c_uint32, C.c_int,
    ]
    _ntdll.NtSetInformationFile.restype = C.c_int32


def _require_windows() -> None:
    if os.name != "nt":
        raise NativePathError("I1 authoritative storage requires Windows NTFS")


def _leaf(name: str) -> None:
    if (
        not isinstance(name, str)
        or name in {"", ".", ".."}
        or name.endswith((" ", "."))
        or not _LEAF.fullmatch(name)
        or name.split(".", 1)[0].upper() in _RESERVED
        or any(char in _FORBIDDEN or char in _BIDI or ord(char) < 32 for char in name)
    ):
        raise NativePathError("single safe leaf name required")
    try:
        encoded = name.encode("utf-16-le")
    except UnicodeEncodeError as exc:
        raise NativePathError("malformed Unicode leaf") from exc
    if len(encoded) > 65532:
        raise NativePathError("leaf exceeds UNICODE_STRING limit")


def _status_error(status: int, operation: str) -> None:
    code = status & 0xFFFFFFFF
    if code == _STATUS_COLLISION:
        raise FileExistsError(f"{operation}: native collision 0x{code:08x}")
    if code in _STATUS_MISSING:
        raise FileNotFoundError(f"{operation}: native missing 0x{code:08x}")
    raise NativePathError(f"{operation}: NTSTATUS 0x{code:08x}")


def close_handle(handle: int) -> None:
    _require_windows()
    if not _kernel.CloseHandle(handle):
        raise NativePathError(f"CloseHandle failed: {C.get_last_error()}")


def _native_open(
    parent: int, name: str, access: int, disposition: int,
    options: int, *, share: int = _SHARE_READ_WRITE,
) -> tuple[int, int]:
    _require_windows()
    _leaf(name)
    encoded = name.encode("utf-16-le")
    buffer = C.create_unicode_buffer(name)
    unicode_name = UnicodeString(len(encoded), len(encoded) + 2, C.cast(buffer, C.c_void_p))
    attrs = ObjectAttributes(
        C.sizeof(ObjectAttributes), parent, C.pointer(unicode_name),
        0x1040, None, None,  # OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
    )
    status_block = IoStatusBlock()
    handle = C.c_void_p()
    status = _ntdll.NtCreateFile(
        C.byref(handle), access, C.byref(attrs), C.byref(status_block),
        None, 0x80, share, disposition, options | _OPEN_REPARSE | _SYNC_IO,
        None, 0,
    )
    if status != 0:
        if handle.value:
            close_handle(handle.value)
        _status_error(status, f"NtCreateFile {name}")
    expected = 2 if disposition == _FILE_CREATE else 1  # FILE_CREATED/FILE_OPENED
    if status_block.Information != expected or not handle.value:
        if handle.value:
            close_handle(handle.value)
        raise NativePathError("NtCreateFile disposition was not create/open as requested")
    return handle.value, status_block.Information


def open_volume_root(anchor: str) -> int:
    _require_windows()
    if not re.fullmatch(r"[A-Za-z]:\\", anchor):
        raise NativePathError("fixed local drive anchor required")
    handle = _kernel.CreateFileW(
        anchor, _LIST | _READ_ATTRIBUTES | _SYNCHRONIZE,
        _SHARE_READ_WRITE, None, 3, 0x02000000 | _OPEN_REPARSE, None,
    )
    if handle in (None, C.c_void_p(-1).value):
        raise NativePathError(f"cannot open volume root: {C.get_last_error()}")
    try:
        inspect_handle(handle, directory=True)
        return handle
    except BaseException:
        close_handle(handle)
        raise


def inspect_handle(handle: int, *, directory: bool | None = None) -> tuple[int, bytes]:
    _require_windows()
    tag = AttributeTag()
    if not _kernel.GetFileInformationByHandleEx(
        handle, 9, C.byref(tag), C.sizeof(tag),
    ):
        raise NativePathError(f"FileAttributeTagInfo failed: {C.get_last_error()}")
    if tag.attributes & _REPARSE_ATTRIBUTE:
        raise NativePathError("reparse object rejected")
    if directory is not None and bool(tag.attributes & _DIRECTORY_ATTRIBUTE) != directory:
        raise NativePathError("directory/file type mismatch")
    info = FileIdInfo()
    if not _kernel.GetFileInformationByHandleEx(
        handle, 18, C.byref(info), C.sizeof(info),
    ):
        raise NativePathError(f"FileIdInfo failed: {C.get_last_error()}")
    return info.volume_serial, bytes(info.file_id)


def open_directory(parent: int, name: str, *, create: bool = False) -> int:
    access = _LIST | _READ_ATTRIBUTES | _SYNCHRONIZE
    try:
        handle, _ = _native_open(parent, name, access, _FILE_OPEN, _DIRECTORY)
    except FileNotFoundError:
        if not create:
            raise
        try:
            handle, _ = _native_open(parent, name, access, _FILE_CREATE, _DIRECTORY)
        except FileExistsError:
            handle, _ = _native_open(parent, name, access, _FILE_OPEN, _DIRECTORY)
    try:
        inspect_handle(handle, directory=True)
        return handle
    except BaseException:
        close_handle(handle)
        raise



def create_directory_new(parent: int, name: str) -> None:
    """Create an empty directory only if the leaf is absent."""
    access = _LIST | _READ_ATTRIBUTES | _SYNCHRONIZE
    handle, _ = _native_open(parent, name, access, _FILE_CREATE, _DIRECTORY)
    try:
        inspect_handle(handle, directory=True)
    finally:
        close_handle(handle)

def open_file(
    parent: int, name: str, *, create: bool = False,
    read: bool = False, write: bool = False, delete: bool = False,
    share: int = _SHARE_READ_WRITE,
) -> int:
    access = _READ_ATTRIBUTES | _SYNCHRONIZE
    if read:
        access |= _READ
    if write:
        access |= _WRITE
    if delete:
        access |= _DELETE
    handle, _ = _native_open(
        parent, name, access, _FILE_CREATE if create else _FILE_OPEN,
        _NON_DIRECTORY, share=share,
    )
    try:
        inspect_handle(handle, directory=False)
        return handle
    except BaseException:
        close_handle(handle)
        raise


def file_object(handle: int, mode: str) -> BinaryIO:
    """Transfer ownership of one native file handle to a Python binary file."""
    _require_windows()
    flags = {"rb": os.O_RDONLY, "wb": os.O_WRONLY, "r+b": os.O_RDWR}.get(mode)
    if flags is None:
        raise ValueError("binary file mode required")
    try:
        fd = msvcrt.open_osfhandle(handle, flags | os.O_BINARY)
    except BaseException:
        close_handle(handle)
        raise
    return os.fdopen(fd, mode)


def read_file(parent: int, name: str) -> bytes:
    handle = open_file(parent, name, read=True)
    with file_object(handle, "rb") as source:
        before = inspect_handle(handle, directory=False)
        data = source.read()
        if inspect_handle(handle, directory=False) != before:
            raise NativePathError("file identity changed during read")
    return data


def rename_no_replace(source_parent: int, source_name: str, target_parent: int, target_name: str) -> None:
    _leaf(target_name)
    handle = open_file(source_parent, source_name, read=True, write=True, delete=True, share=7)
    try:
        source_identity = inspect_handle(handle, directory=False)
        if source_identity[0] != inspect_handle(target_parent, directory=True)[0]:
            raise NativePathError("cross-volume rename rejected")
        encoded = target_name.encode("utf-16-le")
        size = C.sizeof(RenameInfo) + len(encoded) + 2
        buffer = C.create_string_buffer(size)
        info = RenameInfo.from_buffer(buffer)
        info.replace_if_exists = 0
        info.root_directory = target_parent
        info.file_name_length = len(encoded)
        C.memmove(C.addressof(buffer) + RenameInfo.file_name.offset, encoded, len(encoded))
        result = IoStatusBlock()
        status = _ntdll.NtSetInformationFile(
            handle, C.byref(result), buffer, size, 10,  # FileRenameInformation
        )
        if status != 0:
            _status_error(status, f"NtSetInformationFile {target_name}")
        if inspect_handle(handle, directory=False) != source_identity:
            raise NativePathError("file identity changed during rename")
        if not _kernel.FlushFileBuffers(handle):
            raise NativePathError(f"post-rename file flush failed: {C.get_last_error()}")
    finally:
        close_handle(handle)


def list_directory(handle: int) -> tuple[tuple[str, int], ...]:
    """Enumerate one held directory handle without following a path string."""
    before = inspect_handle(handle, directory=True)
    rows: list[tuple[str, int]] = []
    seen: set[str] = set()
    info_class = 15  # FileFullDirectoryRestartInfo
    while True:
        buffer = C.create_string_buffer(65536)
        C.set_last_error(0)
        ok = _kernel.GetFileInformationByHandleEx(
            handle, info_class, buffer, len(buffer),
        )
        if not ok:
            error = C.get_last_error()
            if error == 18:  # ERROR_NO_MORE_FILES
                break
            raise NativePathError(f"directory enumeration failed: {error}")
        offset = 0
        while True:
            entry = FullDirectoryInfo.from_buffer_copy(buffer.raw, offset)
            start = offset + FullDirectoryInfo.file_name.offset
            end = start + entry.file_name_length
            if entry.file_name_length % 2 or end > len(buffer):
                raise NativePathError("malformed directory enumeration")
            name = buffer.raw[start:end].decode("utf-16-le")
            if name not in {".", ".."}:
                _leaf(name)
                if name.casefold() in seen:
                    raise NativePathError("case-insensitive directory entry collision")
                seen.add(name.casefold())
                rows.append((name, entry.attributes))
            if entry.next_offset == 0:
                break
            if entry.next_offset % 8 or offset + entry.next_offset >= len(buffer):
                raise NativePathError("malformed directory entry offset")
            offset += entry.next_offset
        info_class = 14  # FileFullDirectoryInfo, resume same handle
    if inspect_handle(handle, directory=True) != before:
        raise NativePathError("directory identity changed during enumeration")
    return tuple(sorted(rows, key=lambda item: item[0].casefold()))
