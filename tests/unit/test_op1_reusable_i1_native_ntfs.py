"""Native I1 NTFS containment tests use only disposable synthetic directories."""
from __future__ import annotations

import ctypes
import os
import struct
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

from package_g.op1_reusable.native_ntfs import (
    NativePathError, close_handle, file_object, list_directory,
    open_directory, open_file, open_volume_root, read_file, rename_no_replace,
)


@contextmanager
def synthetic_root():
    home = Path.home().resolve()
    with tempfile.TemporaryDirectory(prefix="i1-native-test-", dir=home) as name:
        root = Path(name).resolve()
        assert root.is_relative_to(home)
        yield root


@contextmanager
def held_directory(path: Path):
    with ExitStack() as stack:
        parts = path.resolve().parts
        handle = open_volume_root(parts[0])
        stack.callback(close_handle, handle)
        for part in parts[1:]:
            handle = open_directory(handle, part)
            stack.callback(close_handle, handle)
        yield handle


@contextmanager
def reparse_to(directory: Path, target: Path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    io = kernel.DeviceIoControl
    io.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    io.restype = ctypes.c_int
    close = kernel.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = ctypes.c_int
    handle = create(
        str(directory), 0x100, 3, None, 3, 0x02000000 | 0x00200000, None,
    )
    assert handle not in (None, ctypes.c_void_p(-1).value)
    tag = 0xA0000003
    substitute = (chr(92) + "??" + chr(92) + str(target)).encode("utf-16-le")
    display = str(target).encode("utf-16-le")
    names = substitute + bytes(2) + display + bytes(2)
    payload = struct.pack(
        "<IHHHHHH", tag, 8 + len(names), 0, 0,
        len(substitute), len(substitute) + 2, len(display),
    ) + names
    returned = ctypes.c_uint32()
    try:
        assert io(
            handle, 0x000900A4, ctypes.c_char_p(payload), len(payload),
            None, 0, ctypes.byref(returned), None,
        ), ctypes.get_last_error()
        yield
    finally:
        delete = struct.pack("<IHH", tag, 0, 0)
        assert io(
            handle, 0x000900AC, ctypes.c_char_p(delete), len(delete),
            None, 0, ctypes.byref(returned), None,
        ), ctypes.get_last_error()
        close(handle)


def test_create_read_rename_and_no_replace_are_handle_relative():
    with synthetic_root() as root, held_directory(root) as parent:
        destination = open_directory(parent, "dest", create=True)
        try:
            stage = open_file(parent, "stage.partial", create=True, write=True)
            with file_object(stage, "wb") as output:
                output.write(b"original")
                output.flush()
                os.fsync(output.fileno())
            assert read_file(parent, "stage.partial") == b"original"
            rename_no_replace(parent, "stage.partial", destination, "final.bin")
            assert read_file(destination, "final.bin") == b"original"
            with pytest.raises(FileExistsError):
                open_file(destination, "final.bin", create=True, write=True)
            colliding = open_file(parent, "collision.partial", create=True, write=True)
            with file_object(colliding, "wb") as output:
                output.write(b"later")
                output.flush()
                os.fsync(output.fileno())
            with pytest.raises(FileExistsError):
                rename_no_replace(parent, "collision.partial", destination, "final.bin")
            with pytest.raises(FileExistsError):
                rename_no_replace(parent, "collision.partial", destination, "FINAL.BIN")
            assert read_file(destination, "final.bin") == b"original"
            assert read_file(parent, "collision.partial") == b"later"
            assert [name for name, _ in list_directory(destination)] == ["final.bin"]
        finally:
            close_handle(destination)


def test_in_place_reparse_cannot_redirect_handle_relative_create():
    with synthetic_root() as root:
        guard = root / "guard"
        outside = root / "outside"
        guard.mkdir()
        outside.mkdir()
        with held_directory(guard) as parent, reparse_to(guard, outside):
            with pytest.raises(NativePathError):
                open_file(parent, "escaped.bin", create=True, write=True)
            assert not (outside / "escaped.bin").exists()
        assert not (guard / "escaped.bin").exists()


def test_in_place_reparse_cannot_redirect_handle_relative_rename():
    with synthetic_root() as root:
        guard = root / "guard"
        outside = root / "outside"
        guard.mkdir()
        outside.mkdir()
        source = root / "stage.partial"
        source.write_bytes(b"preserve")
        with held_directory(root) as source_parent, held_directory(guard) as target_parent:
            with reparse_to(guard, outside):
                with pytest.raises(NativePathError):
                    rename_no_replace(source_parent, source.name, target_parent, "escaped.bin")
                assert not (outside / "escaped.bin").exists()
            assert source.read_bytes() == b"preserve"
            assert not (guard / "escaped.bin").exists()


def test_held_directory_enumeration_rejects_in_place_reparse():
    with synthetic_root() as root:
        guard = root / "guard"
        outside = root / "outside"
        guard.mkdir()
        outside.mkdir()
        (outside / "foreign.bin").write_bytes(b"foreign")
        with held_directory(guard) as parent, reparse_to(guard, outside):
            with pytest.raises(NativePathError):
                list_directory(parent)
        assert not (guard / "foreign.bin").exists()


@pytest.mark.parametrize("leaf", [
    "../outside", "h/inside", r"C:\\absolute", r"\\\\server\\share",
    "payload:stream", "CON", "NUL.txt", "name.", "name ", "..", ".",
    "q?mark", "star*name", "less<name", "pipe|name", "line\nfeed",
    "\u202e",
    "\ud800",
])
def test_native_file_create_rejects_unsafe_leaf(leaf):
    with synthetic_root() as root, held_directory(root) as parent:
        with pytest.raises(NativePathError):
            open_file(parent, leaf, create=True, write=True)
        assert list_directory(parent) == ()


def test_handle_relative_read_does_not_follow_mutated_parent():
    with synthetic_root() as root:
        guard = root / "guard"
        outside = root / "outside"
        guard.mkdir()
        outside.mkdir()
        (outside / "foreign.bin").write_bytes(b"foreign")
        with held_directory(guard) as parent, reparse_to(guard, outside):
            with pytest.raises(NativePathError):
                read_file(parent, "foreign.bin")


def test_native_read_rejects_final_file_symlink():
    with synthetic_root() as root:
        target = root / "target.bin"
        link = root / "link.bin"
        target.write_bytes(b"target")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        with held_directory(root) as parent:
            with pytest.raises(NativePathError):
                read_file(parent, link.name)
        assert target.read_bytes() == b"target"
