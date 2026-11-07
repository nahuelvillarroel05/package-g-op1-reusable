"""Stable, sanitized diagnostic classification for bounded Git preflight probes."""
from __future__ import annotations

import errno
import subprocess


def classify_probe_exception(exc: BaseException, *, elapsed_ms: int) -> dict:
    """Return a path- and stderr-free classification for a failed Git probe."""
    if type(elapsed_ms) is not int or elapsed_ms < 0:
        raise ValueError("elapsed_ms must be a nonnegative integer")
    code = "GIT_EXECUTION_ERROR"
    if isinstance(exc, subprocess.TimeoutExpired):
        code = "GIT_TIMEOUT"
        return {"schema": "pgop1.preflight-diagnostic.v1", "code": code,
                "exception_class": "TimeoutExpired", "returncode": None,
                "duration_ms": elapsed_ms}
    if isinstance(exc, PermissionError) or (
            isinstance(exc, OSError) and exc.errno in (errno.EACCES, errno.EPERM)):
        code = "GIT_PERMISSION_DENIED"
    elif isinstance(exc, FileNotFoundError) or (
            isinstance(exc, OSError) and exc.errno == errno.ENOENT):
        code = "GIT_EXECUTABLE_NOT_FOUND"
    elif isinstance(exc, subprocess.CalledProcessError):
        code = "GIT_COMMAND_FAILED"
    return {"schema": "pgop1.preflight-diagnostic.v1", "code": code,
            "exception_class": type(exc).__name__,
            "returncode": getattr(exc, "returncode", None),
            "duration_ms": elapsed_ms}


def git_inventory_warning(*, elapsed_ms: int) -> dict:
    if type(elapsed_ms) is not int or elapsed_ms < 0:
        raise ValueError("elapsed_ms must be a nonnegative integer")
    return {"schema": "pgop1.preflight-diagnostic.v1",
            "code": "GIT_INVENTORY_WARNING", "exception_class": None,
            "returncode": 0, "duration_ms": elapsed_ms}


