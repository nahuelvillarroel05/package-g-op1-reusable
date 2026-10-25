"""I1 fail-closed NTFS path derivation and namespace safety tests."""
from __future__ import annotations

import os
import tempfile
import ctypes
import struct
import shutil
from pathlib import Path

import pytest

from op1_reusable_i1_helpers import event_record, evidence_record, synthetic_store
from package_g.op1_reusable.append_only import ObjectExists
from package_g.op1_reusable.identity import generate_id
from package_g.op1_reusable.storage_paths import LocatorCollision, Scope, StoragePathError, StoragePaths, validate_relative_path, is_reparse


@pytest.mark.parametrize("value", [
    "../outside", "h/../outside", "/absolute", r"C:\\outside", r"\\server\\share",
    "h//file", "h/file:stream", "h/CON.txt", "h/LPT9", "h/name.",
    "h/name ", "h/\\u202e", "h/\ud800", "h/..", "h/.",
])
def test_malformed_relative_paths_rejected(value):
    with pytest.raises(StoragePathError):
        validate_relative_path(value)


def test_root_must_exist_and_be_local_outside_onedrive():
    with synthetic_store() as (store, scope, actor, key):
        with pytest.raises(StoragePathError):
            StoragePaths(store.root / "missing")
        with pytest.raises(StoragePathError):
            StoragePaths(Path("relative"))


def test_typed_scope_and_entity_placement_rejected():
    with synthetic_store() as (store, scope, actor, key):
        with pytest.raises(ValueError):
            Scope(scope.project_id, scope.product_id, scope.lineage_id, scope.version_id, scope.session_id, generate_id("EVENT"), scope.attempt_id)
        with pytest.raises(ValueError):
            store.paths.object_relative(scope, "raw", generate_id("ARTIFACT"), "bin")
        with pytest.raises(ValueError):
            store.paths.object_relative(scope, "events", generate_id("EVIDENCE"), "json")
        with pytest.raises(StoragePathError):
            store.paths.object_relative(scope, "unknown", generate_id("EVENT"), "json")


def test_length_limit_and_absolute_path_escape_rejected():
    with synthetic_store() as (store, scope, actor, key):
        with pytest.raises(StoragePathError):
            store.paths.checked_path("a" * 240)
        with pytest.raises(StoragePathError):
            store.paths.checked_path(str(store.root / "outside"))
        assert len(str(store.paths.checked_path(store.paths.object_relative(scope, "events", generate_id("EVENT"), "json"))).encode("utf-16-le")) // 2 < 240


def test_locator_prefix_collision_fails_without_reassignment():
    with synthetic_store() as (store, scope, actor, key):
        store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        original = scope.version_id
        suffix = "0" if original[-1] != "0" else "1"
        other = original[:-1] + suffix
        alternative = Scope(scope.project_id, scope.product_id, scope.lineage_id, other, scope.session_id, scope.run_id, scope.attempt_id)
        before = (store.root / store.paths.locator_relative("v", original)).read_bytes()
        with pytest.raises(LocatorCollision):
            store.paths.reserve_scope(alternative, store._write_locator)
        assert (store.root / store.paths.locator_relative("v", original)).read_bytes() == before


def test_reparse_ancestor_escape_rejected_when_supported():
    with tempfile.TemporaryDirectory(prefix="i1-external-", dir=Path.home()) as external_name:
        with synthetic_store() as (store, scope, actor, key):
            external = Path(external_name)
            link = store.root / "escape"
            try:
                os.symlink(external, link, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                pytest.skip(f"symlink creation unavailable: {exc}")
            with pytest.raises(StoragePathError):
                store.paths.ensure_parents("escape/payload.bin")
            assert not (external / "payload.bin").exists()


def test_case_insensitive_foreign_final_rejected():
    with synthetic_store() as (store, scope, actor, key):
        store._write_exclusive("records/CASE.json", b"foreign")
        with pytest.raises(ObjectExists):
            store._write_exclusive("records/case.json", b"new")
        assert (store.root / "records/CASE.json").read_bytes() == b"foreign"



def test_directory_rename_is_blocked_during_publication_window():
    with synthetic_store() as (store, scope, actor, key):
        action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        data = b"guarded"
        record = evidence_record(store, scope, actor, action["event_id"], data)
        publication = event_record(store, scope, actor, "PUBLICATION", [record["evidence_id"]])
        attempted = []
        def swap(name, final):
            if name == "evidence_blob.before_publish":
                backup = final.parent.with_name("raw-swapped")
                with pytest.raises(OSError):
                    os.rename(final.parent, backup)
                attempted.append(True)
                assert not backup.exists()
        store.publish_evidence(record, data, publication, scope, producer_kind="ACTOR", fault=swap)
        assert attempted == [True]
        assert (store.root / record["relative_path"]).read_bytes() == data

def test_regular_directory_root_substitution_is_rejected_by_file_identity():
    with synthetic_store() as (store, scope, actor, key):
        store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        original_root = store.root
        retained = original_root.with_name("retained-original")
        os.rename(original_root, retained)
        shutil.copytree(retained, original_root)
        assert store.paths._root_identity[1:] != (original_root.stat().st_dev, original_root.stat().st_ino)
        with pytest.raises(StoragePathError, match="root identity changed"):
            store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
        assert store._quarantined is True


def test_in_place_reparse_during_publish_fails_without_external_write():
    home = Path.home().resolve()
    with tempfile.TemporaryDirectory(prefix="i1-reparse-publish-", dir=home) as external_name:
        external = Path(external_name).resolve()
        assert external.is_relative_to(home)
        with synthetic_store() as (store, scope, actor, key):
            action = store.commit_action_event(event_record(store, scope, actor, "ACTION"), scope)
            data = b"guarded-original"
            record = evidence_record(store, scope, actor, action["event_id"], data)
            publication = event_record(store, scope, actor, "PUBLICATION", [record["evidence_id"]])
            prior_count = len(store.manifest_rows())
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            create = kernel.CreateFileW
            create.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
            create.restype = ctypes.c_void_p
            io = kernel.DeviceIoControl
            io.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
            io.restype = ctypes.c_int
            close = kernel.CloseHandle
            close.argtypes = [ctypes.c_void_p]
            close.restype = ctypes.c_int
            substitute = (chr(92) + "??" + chr(92) + str(external)).encode("utf-16-le")
            display = str(external).encode("utf-16-le")
            names = substitute + bytes(2) + display + bytes(2)
            tag = 0xA0000003
            payload = struct.pack("<IHHHHHH", tag, 8 + len(names), 0, 0, len(substitute), len(substitute) + 2, len(display)) + names
            mutable_handle = [None]
            attempted = []
            def mutate(name, final):
                if name != "evidence_blob.before_publish":
                    return
                handle = create(str(final.parent), 0x100, 3, None, 3, 0x02000000 | 0x00200000, None)
                assert handle not in (None, ctypes.c_void_p(-1).value)
                mutable_handle[0] = handle
                returned = ctypes.c_uint32()
                assert io(handle, 0x000900A4, ctypes.c_char_p(payload), len(payload), None, 0, ctypes.byref(returned), None)
                assert is_reparse(final.parent)
                attempted.append(final)
            try:
                with pytest.raises(StoragePathError):
                    store.publish_evidence(record, data, publication, scope, producer_kind="ACTOR", fault=mutate)
            finally:
                if mutable_handle[0] is not None:
                    delete = struct.pack("<IHH", tag, 0, 0)
                    returned = ctypes.c_uint32()
                    assert io(mutable_handle[0], 0x000900AC, ctypes.c_char_p(delete), len(delete), None, 0, ctypes.byref(returned), None)
                    close(mutable_handle[0])
            assert len(attempted) == 1
            assert not (external / attempted[0].name).exists()
            assert not attempted[0].exists()
            assert len(store.manifest_rows()) == prior_count
            assert store._quarantined is True
