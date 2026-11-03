"""Campaign-local byte, duration, unit, error, and stop enforcement.

Accounting covers every regular file beneath ``campaign_root`` and the
explicit ``accounted_paths`` (for example, this attempt's registry markers).
It does not traverse reparse points or follow symlinks. The byte ceiling is a
hard 20 GiB scale cap; the stop record has a separately reserved fixed budget.
Callers must reserve each whole publication transaction before writing any of
its files, then account each completed file. Periodic scans and explicit shard
boundary/recovery refreshes catch unexpected files. Read-only recovery may
inspect files but must not redispatch work. Hard-linked file names count once
by filesystem identity, matching physical storage use.

This guard does not supervise processes or account writes outside the listed
paths, including shared storage or uncooperative concurrent writers.
"""
from __future__ import annotations

import json
import math
import os
import stat
import time
from pathlib import Path
from typing import Callable, Iterable


MAX_SCALE_BYTES = 20 * 1024**3
STOP_RECORD = ".resource-stop.json"
DEFAULT_STOP_RESERVE_BYTES = 2048


class ResourceLimitStop(RuntimeError):
    """Raised when a resource boundary requires the campaign to stop."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


class ResourceGuard:
    def __init__(self, campaign_root, *, max_bytes=None, max_seconds=None,
                 max_units=None, max_errors=None,
                 stop_reserve_bytes=DEFAULT_STOP_RESERVE_BYTES,
                 rescan_every=4096, clock: Callable[[], float] = time.monotonic,
                 accounted_paths: Iterable[os.PathLike | str] = (), read_only=False):
        self.root = Path(campaign_root).absolute()
        self._clock = clock
        self._started = clock()
        self.max_bytes = MAX_SCALE_BYTES if max_bytes is None else self._positive_int(max_bytes, "max_bytes")
        if self.max_bytes > MAX_SCALE_BYTES:
            raise ValueError("max_bytes exceeds the hard 20 GiB scale cap")
        self.max_seconds = self._optional_positive(max_seconds, "max_seconds")
        self.max_units = self._optional_positive_int(max_units, "max_units")
        self.max_errors = self._optional_positive_int(max_errors, "max_errors")
        self.stop_reserve_bytes = self._positive_int(stop_reserve_bytes, "stop_reserve_bytes")
        self.rescan_every = self._positive_int(rescan_every, "rescan_every")
        if self.stop_reserve_bytes >= self.max_bytes:
            raise ValueError("stop record reserve must be smaller than max_bytes")
        if self.stop_reserve_bytes < 96:
            raise ValueError("stop record reserve must be at least 96 bytes")
        self.accounted_paths = tuple(Path(p).absolute() for p in accounted_paths)
        self.read_only = bool(read_only)
        self._reservations = 0
        self._transaction_open = False
        self._writes_since_scan = 0
        self._stopped = False
        self._stopped_reason = None
        self._stop_record_written = False
        self._actual_bytes = self._scan()
        stop_path = self.root / STOP_RECORD
        if stop_path.exists():
            try:
                stop = json.loads(stop_path.read_text(encoding="utf-8"))
                if not isinstance(stop, dict) or stop.get("schema") != "pgop1.campaign-stop.v2" or not isinstance(stop.get("reason"), str):
                    raise ValueError("invalid stop record")
                self._stopped = True
                self._stopped_reason = stop["reason"]
                self._stop_record_written = True
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                self._stopped = True
                self._stopped_reason = "INTEGRITY_FAILURE"
                self._stop_record_written = True
        if not self.read_only and not self._stopped and self._actual_bytes + self.stop_reserve_bytes > self.max_bytes:
            self.request_stop("BYTE_BUDGET_EXHAUSTED", {"actual_bytes": self._actual_bytes,
                                                         "max_bytes": self.max_bytes})
        if not self.read_only and not self._stopped:
            self.check_limits()

    @staticmethod
    def _positive_int(value, name):
        if type(value) is not int or value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return value

    @classmethod
    def _optional_positive_int(cls, value, name):
        return None if value is None else cls._positive_int(value, name)

    @staticmethod
    def _optional_positive(value, name):
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be a positive number")
        return float(value)

    @staticmethod
    def _is_reparse(path: Path) -> bool:
        return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())

    @classmethod
    def _has_reparse_component(cls, path: Path) -> bool:
        return any(cls._is_reparse(part) for part in (path, *path.parents))

    def _safe_path(self, value) -> Path:
        path = Path(value)
        if not path.is_absolute():
            path = self.root / path
        path = Path(os.path.abspath(path))
        if self._has_reparse_component(path):
            raise ResourceLimitStop("INTEGRITY_FAILURE", f"reparse path rejected: {path}")
        if path != self.root and self.root not in path.parents and not any(
                p == path or p in path.parents for p in self.accounted_paths):
            raise ValueError("accounted path is outside campaign_root/accounted_paths")
        return path

    def _walk(self, path: Path, seen: set[tuple[int, int]]) -> int:
        if not path.exists():
            return 0
        if self._is_reparse(path):
            raise ResourceLimitStop("INTEGRITY_FAILURE", f"reparse path rejected: {path}")
        st = path.lstat()
        if stat.S_ISREG(st.st_mode):
            key = (st.st_dev, st.st_ino)
            if key in seen:
                return 0
            seen.add(key)
            return st.st_size
        if not stat.S_ISDIR(st.st_mode):
            raise ResourceLimitStop("INTEGRITY_FAILURE", f"non-regular campaign entry: {path}")
        total = 0
        with os.scandir(path) as entries:
            for entry in entries:
                child = Path(entry.path)
                if self._is_reparse(child):
                    raise ResourceLimitStop("INTEGRITY_FAILURE", f"reparse path rejected: {child}")
                total += self._walk(child, seen)
        return total

    def _scan(self) -> int:
        if self._has_reparse_component(self.root) or not self.root.exists() or not self.root.is_dir():
            raise ResourceLimitStop("INTEGRITY_FAILURE", "campaign root missing, non-directory, or reparse")
        seen: set[tuple[int, int]] = set()
        total = self._walk(self.root, seen)
        for path in self.accounted_paths:
            safe = self._safe_path(path)
            total += self._walk(safe, seen)
        return total

    @property
    def actual_bytes(self) -> int:
        return self._actual_bytes

    @property
    def remaining_bytes(self) -> int:
        return max(0, self.max_bytes - self.stop_reserve_bytes - self._actual_bytes - self._reservations)

    @property
    def stopped(self) -> bool:
        return self._stopped

    def before_publication(self, total_projected_bytes: int) -> None:
        """Atomically reserve the full byte estimate for one publication batch."""
        self._ensure_writable()
        if type(total_projected_bytes) is not int or total_projected_bytes < 0:
            raise ValueError("total_projected_bytes must be a nonnegative integer")
        self.check_limits()
        if total_projected_bytes >= 64 * 1024**2:
            self.refresh_usage()
        if total_projected_bytes > self.remaining_bytes:
            self.request_stop("BYTE_BUDGET_EXHAUSTED", {
                "projected_bytes": total_projected_bytes,
                "remaining_bytes": self.remaining_bytes,
            })
        self._reservations += total_projected_bytes
        self._transaction_open = True

    def refresh_usage(self) -> int:
        """Perform a full bounded-root scan, suitable at shard/recovery boundaries."""
        self._actual_bytes = self._scan()
        self._writes_since_scan = 0
        if not self.read_only and not self._stopped and self._actual_bytes + self._reservations + self.stop_reserve_bytes > self.max_bytes:
            self.request_stop("BYTE_BUDGET_EXHAUSTED", {"actual_bytes": self._actual_bytes,
                                                         "max_bytes": self.max_bytes})
        return self._actual_bytes

    def account_write(self, path, actual_bytes=None) -> int:
        """Verify a completed file's on-disk size and refresh usage as needed."""
        self._ensure_writable()
        target = self._safe_path(path)
        if self._is_reparse(target) or not target.exists():
            self.request_stop("INTEGRITY_FAILURE", {"path": str(target), "issue": "missing_or_reparse"})
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode):
            self.request_stop("INTEGRITY_FAILURE", {"path": str(target), "issue": "not_regular"})
        measured = st.st_size
        if actual_bytes is not None and (type(actual_bytes) is not int or actual_bytes != measured):
            self.request_stop("INTEGRITY_FAILURE", {"path": str(target), "expected_bytes": actual_bytes,
                                                       "measured_bytes": measured})
        self._reservations = max(0, self._reservations - measured)
        self._writes_since_scan += 1
        if self._writes_since_scan >= self.rescan_every:
            self._actual_bytes = self._scan()
            self._writes_since_scan = 0
        else:
            self._actual_bytes += measured
        if self._actual_bytes + self._reservations + self.stop_reserve_bytes > self.max_bytes:
            self.request_stop("BYTE_BUDGET_EXHAUSTED", {"measured_bytes": measured})
        return measured

    def finish_publication(self) -> None:
        """Release unused estimate only after every file in the transaction landed."""
        self._ensure_writable()
        if not self._transaction_open:
            raise RuntimeError("no publication transaction is open")
        self._reservations = 0
        self._transaction_open = False
        self.check_limits()

    def account_existing(self, path) -> int:
        """Account an already-created lock/owner/registry artifact by its bytes."""
        self._ensure_writable()
        target = self._safe_path(path)
        if not target.exists() or self._is_reparse(target):
            self.request_stop("INTEGRITY_FAILURE", {"path": str(target), "issue": "missing_or_reparse"})
        st = target.lstat()
        if not stat.S_ISREG(st.st_mode):
            self.request_stop("INTEGRITY_FAILURE", {"path": str(target), "issue": "not_regular"})
        self._actual_bytes = self._scan()
        if self._actual_bytes + self._reservations + self.stop_reserve_bytes > self.max_bytes:
            self.request_stop("BYTE_BUDGET_EXHAUSTED", {"actual_bytes": self._actual_bytes})
        return st.st_size

    def check_limits(self, *, unit_count=None, error_count=None) -> None:
        self._ensure_writable()
        if unit_count is not None:
            if type(unit_count) is not int or unit_count < 0:
                raise ValueError("unit_count must be a nonnegative integer")
            if self.max_units is not None and unit_count >= self.max_units:
                self.request_stop("UNIT_LIMIT_REACHED", {"unit_count": unit_count, "max_units": self.max_units})
        if error_count is not None:
            if type(error_count) is not int or error_count < 0:
                raise ValueError("error_count must be a nonnegative integer")
            if self.max_errors is not None and error_count >= self.max_errors:
                self.request_stop("ERROR_LIMIT_REACHED", {"error_count": error_count, "max_errors": self.max_errors})
        elapsed = self._clock() - self._started
        if self.max_seconds is not None and elapsed >= self.max_seconds:
            self.request_stop("DURATION_LIMIT_REACHED", {"elapsed_seconds": elapsed,
                                                           "max_seconds": self.max_seconds})

    def _ensure_writable(self):
        if self.read_only:
            raise ResourceLimitStop("READ_ONLY", "resource guard is in read-only measurement mode")
        if self._stopped:
            raise ResourceLimitStop(self._stopped_reason or "STOPPED", "campaign resource guard is stopped; writes are forbidden")

    def request_stop(self, reason="EXPLICIT_REQUEST", details=None) -> None:
        """Persist one bounded stop record; after it, only read-only recovery is allowed."""
        if self._stopped:
            raise ResourceLimitStop(self._stopped_reason or "STOPPED", "campaign already stopped")
        if self.read_only:
            raise ResourceLimitStop("READ_ONLY", "resource guard is in read-only measurement mode")
        allowed = {"EXPLICIT_REQUEST", "BYTE_BUDGET_EXHAUSTED", "DURATION_LIMIT_REACHED",
                   "UNIT_LIMIT_REACHED", "ERROR_LIMIT_REACHED", "INTEGRITY_FAILURE",
                   "EXTERNAL_INTERRUPTION", "RESOURCE_LIMIT"}
        if reason not in allowed:
            raise ValueError("unsupported stop reason")
        payload = {"schema": "pgop1.campaign-stop.v2", "reason": reason,
                   "details": details if isinstance(details, (dict, list, str, int, bool)) or details is None
                   else str(details)}
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(raw) > self.stop_reserve_bytes:
            payload["details"] = "details omitted: stop record reserve"
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self._stopped = True
        self._stopped_reason = reason
        target = self.root / STOP_RECORD
        try:
            if target.exists() or self._is_reparse(target):
                raise OSError("stop record path already exists or is reparse")
            with target.open("xb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            self._stop_record_written = True
            self._actual_bytes += len(raw)
        except OSError:
            # Stopped in memory even if the reserved durable record cannot be published.
            raise ResourceLimitStop(reason, "stop required but durable stop record could not be written")
        raise ResourceLimitStop(reason, f"campaign stopped: {reason}")

    def snapshot(self) -> dict:
        """Return an advisory resource snapshot; no process-level claims."""
        return {"schema": "pgop1.resource-guard-snapshot.v2", "actual_bytes": self._actual_bytes,
                "reserved_bytes": self._reservations, "max_bytes": self.max_bytes,
                "remaining_bytes": self.remaining_bytes,
                "elapsed_milliseconds": max(0, int((self._clock() - self._started) * 1000)),
                "max_duration_milliseconds": None if self.max_seconds is None else int(self.max_seconds * 1000),
                "max_units": self.max_units,
                "max_errors": self.max_errors, "stopped": self._stopped,
                "stop_record_written": self._stop_record_written}
