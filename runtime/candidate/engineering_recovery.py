# Modified for public export: private host paths removed; private corpus policy disabled.
# SPDX-License-Identifier: Apache-2.0
"""Explicit dead-owner review for a crashed Engineering scanner lock.

The frozen scanner deliberately leaves its lock behind on process termination.
This adapter preserves that lock as evidence, proves its recorded owner is gone,
and only then calls the scanner's ordinary same-snapshot recovery API.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

import engineering_corpus as scanner

VALIDATION_ROOT = Path(r"PRIVATE_VALIDATION_NOT_DISTRIBUTED")
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
SYNCHRONIZE = 0x00100000


def _canonical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _inside(path: Path, root: Path) -> bool:
    try:
        _canonical(path).relative_to(_canonical(root))
        return True
    except ValueError:
        return False


def _check_paths(root: Path, output: Path, *, test_api: bool) -> tuple[Path, Path]:
    root, output = _canonical(root), _canonical(output)
    if not _inside(output, VALIDATION_ROOT):
        raise ValueError("OUTPUT_MUST_BE_UNDER_VALIDATION")
    if not root.is_dir() or not output.is_dir():
        raise ValueError("ROOT_AND_OUTPUT_MUST_EXIST")
    if _inside(output, root) or _inside(root, output):
        raise ValueError("SOURCE_OUTPUT_OVERLAP")
    if not test_api and root != _canonical(scanner.PRODUCTION_ROOT):
        raise ValueError("PRODUCTION_ROOT_MUST_MATCH_EXACTLY")
    scanner._validate_input_ancestors(root)
    scanner._validate_output(root, output)
    return root, output


def _read_lock(lock: Path) -> tuple[bytes, int, int]:
    stream, before, opened, held_path = scanner._open_verified(lock)
    try:
        raw = stream.read()
        after = os.fstat(stream.fileno())
        path_after = lock.lstat()
        final_after = scanner._final_path_from_handle(stream.fileno())
        if (scanner._stat_tuple(opened) != scanner._stat_tuple(after)
                or scanner._stat_tuple(after) != scanner._stat_tuple(path_after)
                or final_after != held_path or scanner._path_has_reparse_ancestor(lock)):
            raise ValueError("LOCK_CHANGED_DURING_REVIEW")
    finally:
        stream.close()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("LOCK_OWNER_UNREADABLE_BLOCK") from exc
    pid_match = re.search(r"(?m)^pid=([0-9]+)\s*$", text)
    started_match = re.search(r"(?m)^started_ns=([0-9]+)\s*$", text)
    if not pid_match or not started_match:
        raise ValueError("LOCK_OWNER_UNKNOWN_BLOCK")
    return raw, int(pid_match.group(1)), int(started_match.group(1))


def _owner_state(pid: int):
    """Return (state, live handle) using a stable Windows process object when available."""
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel.WaitForSingleObject.restype = ctypes.c_ulong
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(SYNCHRONIZE, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # ERROR_INVALID_PARAMETER: no process with this PID.
                return "DEAD", None
            return "UNKNOWN", None
        wait = kernel.WaitForSingleObject(handle, 0)
        if wait == WAIT_OBJECT_0:
            return "DEAD", (kernel, handle)
        if wait == WAIT_TIMEOUT:
            return "ACTIVE", (kernel, handle)
        kernel.CloseHandle(handle)
        return "UNKNOWN", None
    try:
        os.kill(pid, 0)
        return "ACTIVE", None
    except ProcessLookupError:
        return "DEAD", None
    except PermissionError:
        return "UNKNOWN", None


def _close_owner_handle(handle) -> None:
    if handle:
        kernel, h = handle
        kernel.CloseHandle(h)


def _write_new(path: Path, value: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def _assert_safe_path(path: Path, *, allow_missing_leaf: bool = False) -> None:
    """Check both ancestors and the leaf before any recovery output operation."""
    cursor = _canonical(path)
    try:
        leaf_stat = cursor.lstat()
    except FileNotFoundError:
        if not allow_missing_leaf:
            raise ValueError("RECOVERY_PATH_MISSING")
    except OSError as exc:
        raise ValueError("RECOVERY_PATH_INACCESSIBLE") from exc
    else:
        if scanner._is_reparse(cursor, leaf_stat):
            raise ValueError("RECOVERY_REPARSE_PATH_BLOCKED")
    for ancestor in cursor.parents:
        try:
            st = ancestor.lstat()
        except OSError as exc:
            raise ValueError("RECOVERY_PATH_ANCESTOR_INACCESSIBLE") from exc
        if scanner._is_reparse(ancestor, st):
            raise ValueError("RECOVERY_REPARSE_ANCESTOR_BLOCKED")


def _read_json_verified(path: Path) -> dict[str, Any]:
    _assert_safe_path(path)
    stream, _, opened, held = scanner._open_verified(path)
    try:
        value = json.load(stream)
        after = os.fstat(stream.fileno())
        path_after = path.lstat()
        if (scanner._stat_tuple(opened) != scanner._stat_tuple(after)
                or scanner._stat_tuple(after) != scanner._stat_tuple(path_after)
                or scanner._final_path_from_handle(stream.fileno()) != held):
            raise ValueError("RECOVERY_STATE_CHANGED_DURING_READ")
    finally:
        stream.close()
    if not isinstance(value, dict):
        raise ValueError("RECOVERY_STATE_INVALID")
    return value


def review_stale_lock(root: str | Path, output_dir: str | Path, *,
                      test_api: bool = False) -> dict[str, Any]:
    """Prove lock owner dead, preserve original lock bytes, and write review record.

    It never removes an active/unknown lock. A successful return means the original
    lock has been moved to a unique recovery-attempt directory under output only.
    """
    root, output = _check_paths(Path(root), Path(output_dir), test_api=test_api)
    lock = output / ".scan.lock"
    try:
        lock_stat = lock.lstat()
    except FileNotFoundError:
        raise FileNotFoundError("NO_STALE_SCAN_LOCK")
    if scanner._is_reparse(lock, lock_stat) or not lock.is_file():
        raise ValueError("LOCK_REPARSE_OR_NONREGULAR_BLOCK")
    raw, pid, started_ns = _read_lock(lock)
    owner_state, handle = _owner_state(pid)
    if owner_state != "DEAD":
        _close_owner_handle(handle)
        raise RuntimeError(f"LOCK_OWNER_{owner_state}_BLOCKED")
    state_path = output / "scan-state.json"
    _assert_safe_path(state_path)
    state = _read_json_verified(state_path)
    snapshot = state.get("snapshot_id")
    if not isinstance(snapshot, str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot):
        _close_owner_handle(handle)
        raise ValueError("DURABLE_SNAPSHOT_UNKNOWN_BLOCK")
    attempts = output / "recovery-attempts"
    _assert_safe_path(attempts, allow_missing_leaf=True)
    attempts.mkdir(exist_ok=True)
    _assert_safe_path(attempts)
    attempt = attempts / f"{time.time_ns()}-pid{pid}"
    _assert_safe_path(attempt, allow_missing_leaf=True)
    attempt.mkdir()
    _assert_safe_path(attempt)
    lock_digest = hashlib.sha256(raw).hexdigest()
    record = {"schema": "i7-engineering-stale-lock-review@1", "review_status": "OWNER_PROVED_DEAD",
              "source_root": str(root), "output_dir": str(output), "snapshot_id": snapshot,
              "durable_completed_count": state.get("completed_count"), "owner_pid": pid,
              "owner_started_ns": started_ns, "lock_sha256": lock_digest,
              "lock_byte_count": len(raw), "lock_preserved_at": "stale-scan.lock",
              "reviewed_at_ns": time.time_ns(), "recovery_status": "NOT_STARTED"}
    _write_new(attempt / "RECOVERY_REVIEW.json", record)
    preserved = attempt / "stale-scan.lock"
    if preserved.exists():
        _close_owner_handle(handle)
        raise FileExistsError("STALE_LOCK_EVIDENCE_COLLISION")
    # A held process object ensures the PID cannot be reused between proof and move.
    if handle:
        kernel, h = handle
        if kernel.WaitForSingleObject(h, 0) != WAIT_OBJECT_0:
            _close_owner_handle(handle)
            raise RuntimeError("LOCK_OWNER_NO_LONGER_PROVED_DEAD")
    current, current_pid, current_started = _read_lock(lock)
    if current != raw or current_pid != pid or current_started != started_ns:
        _close_owner_handle(handle)
        raise RuntimeError("LOCK_BYTES_CHANGED_DURING_REVIEW")
    os.replace(lock, preserved)
    _close_owner_handle(handle)
    record["lock_preserved_at"] = str(preserved.relative_to(output))
    record["recovery_status"] = "LOCK_PRESERVED_RECOVERY_ALLOWED"
    _write_new(attempt / "RECOVERY_REVIEW_FINAL.json", record)
    return {**record, "attempt_dir": str(attempt)}


def recover_after_crash(root: str | Path, output_dir: str | Path, *,
                        test_api: bool = False,
                        expected_owner_anchor_sha256: str | None = None) -> dict[str, Any]:
    """Review stale lock, then call ordinary scanner recovery for same snapshot."""
    review = review_stale_lock(root, output_dir, test_api=test_api)
    result = scanner.recover_scan(root, output_dir, test_api=test_api,
                                  expected_owner_anchor_sha256=expected_owner_anchor_sha256)
    review["recovery_status"] = result.get("coverage_status", "UNKNOWN")
    review["recovery_result"] = result
    _write_new(Path(review["attempt_dir"]) / "RECOVERY_RESULT.json", review)
    return review
