"""Read-only adapter around the existing engine recovery verifier.

The engine's historical replay check uses DurableRegistry methods which create
and remove a lock file. This wrapper keeps its validators while replacing only
those methods with in-memory journal reads for verification calls.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def _guarded_path(value: str | Path, *, must_exist: bool) -> Path:
    import sys
    cli = sys.modules.get("__main__")
    if cli is None or not callable(getattr(cli, "_require_bound_workspace", None)):
        cli = sys.modules.get("pg_i7")
    if cli is None or not callable(getattr(cli, "_require_bound_workspace", None)):
        raise ValueError("read-only recovery requires the pinned workspace path guard")
    cli._require_bound_workspace()
    path = cli._checked_absolute(value, base=cli.WORKSPACE, must_exist=must_exist)
    if not cli._within(path, cli.WORKSPACE):
        raise ValueError("journal path is outside the bound workspace")
    if must_exist and not path.is_file():
        raise ValueError("journal is not a regular workspace file")
    return path


def recover(engine: Any, directory: str, request_hash: str, result_hash: str) -> dict[str, Any]:
    original = getattr(engine, "DurableRegistry", None)
    if original is None:
        raise ValueError("pinned engine recovery registry is unavailable")

    class ReadOnlyRegistry:
        def __init__(self, path: str):
            self.path = _guarded_path(path, must_exist=True)
            self.lock_path = _guarded_path(self.path.with_name(self.path.name + ".lock"), must_exist=False)
            self.delegate = original(str(self.path))

        def _check(self):
            _guarded_path(self.path, must_exist=True)
            self.lock_path = _guarded_path(self.path.with_name(self.path.name + ".lock"), must_exist=False)
            if self.lock_path.exists():
                _guarded_path(self.lock_path, must_exist=True)
                raise ValueError("journal lock exists; read-only recovery deferred")
            return self.delegate._load()

        def snapshot(self):
            before = hashlib.sha256(self.path.read_bytes()).hexdigest()
            state, _, _ = self._check()
            result = state.snapshot()
            if (hashlib.sha256(self.path.read_bytes()).hexdigest() != before
                    or self.lock_path.exists()):
                raise ValueError("journal changed during read-only recovery")
            return result

        def admit(self, receipt, outputs):
            before = hashlib.sha256(self.path.read_bytes()).hexdigest()
            state, _, event_ids = self._check()
            plain = original.__module__
            modules = __import__(plain, fromlist=["MODULES"])
            snapshot = modules.MODULES["security.receipt_registry"]._plain_snapshot
            copied_receipt, copied_outputs = snapshot(receipt), snapshot(outputs)
            state.admit(copied_receipt, copied_outputs)
            replay = {event["id"] for event in copied_receipt["events"]} & event_ids
            if replay:
                raise ValueError("cross-receipt event replay")
            if (hashlib.sha256(self.path.read_bytes()).hexdigest() != before
                    or self.lock_path.exists()):
                raise ValueError("journal changed during read-only recovery")
            return True

    try:
        engine.DurableRegistry = ReadOnlyRegistry
        return engine.recover(directory, request_hash, result_hash)
    finally:
        engine.DurableRegistry = original

