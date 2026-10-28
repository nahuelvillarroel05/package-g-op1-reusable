"""Single-writer, bounded-file campaign driver; external artifacts remain inert.

The frozen plan supplies source commitments and explicit execution joins. This
module never discovers a run identity from matching instance names alone.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import time

from .adapter import AuditError, _checked_root, _reparse, _safe_path
from .generalized import audit_evidence, audit_file


SCHEMA = "pgop1.swebench.campaign-plan.v1"
MIN_FREE_BYTES = 70_000_000_000


def _raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _append(path, value):
    with path.open("ab") as stream:
        stream.write(_raw(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def _write_new(path, value):
    with path.open("xb") as stream:
        stream.write(_raw(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def _alive(pid):
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            # Access denied is ambiguous, so do not take over that writer.
            return ctypes.get_last_error() != 87
        try:
            code = wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def run_campaign(data_root, plan, output_root, *, resume=False, min_free_bytes=MIN_FREE_BYTES,
                 development=False):
    """Process every plan entry, preserving exact failures and completed units.

    Recovery checks all committed input hashes and completed output hashes. It
    only repeats units lacking a durable completion record. A plan change, source
    change or corrupt completed result blocks recovery instead of starting over.
    """
    root = _checked_root(data_root)
    if plan.get("schema") != SCHEMA or plan.get("campaign_id") != "PGOP1_RUN_001":
        raise AuditError("CAMPAIGN_PLAN_INVALID", "versioned RUN-001 plan required")
    sources = plan.get("sources")
    requests = plan.get("requests")
    if not isinstance(sources, list) or not isinstance(requests, list):
        raise AuditError("CAMPAIGN_PLAN_INVALID", "sources and requests must be arrays")
    if not development:
        import re
        code_pin = plan.get("code_commit", "")
        required = {"runtime/candidate/swebench_claim_audit/" + name for name in
                    ("generalized.py", "generalized_bridge.py", "campaign.py", "prepare_plan.py")}
        if not re.fullmatch(r"[0-9a-f]{40}", code_pin) or not required.issubset(plan.get("code_sha256", {})):
            raise AuditError("CAMPAIGN_CODE_NOT_FROZEN", "full commit and implementation hashes required")
        repo = Path(__file__).resolve().parents[3]
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        if head != code_pin:
            raise AuditError("CAMPAIGN_CODE_COMMIT", "checkout HEAD differs from frozen code commit")
    ids = [s.get("source_id") for s in sources]
    if any(not isinstance(s, str) or not s for s in ids) or len(set(ids)) != len(ids):
        raise AuditError("CAMPAIGN_DUPLICATE_SOURCE", "source IDs must be unique")
    keys = [(r.get("run_id"), r.get("instance_id")) for r in requests]
    if len(set(keys)) != len(keys):
        raise AuditError("CAMPAIGN_DUPLICATE_EXECUTION", "execution joins must be unique")
    declared = {s["path"]: s for s in sources}
    physical_keys = {p.casefold() if os.name == "nt" else p for p in declared}
    if len(declared) != len(sources) or len(physical_keys) != len(sources):
        raise AuditError("CAMPAIGN_DUPLICATE_PATH", "one source commitment per path required")
    for name in declared:
        if (not isinstance(name, str) or "\\" in name or ":" in name
                or any(p in {"", ".", ".."} for p in name.split("/"))
                or PureWindowsPath(name).drive):
            raise AuditError("CAMPAIGN_SOURCE_PATH", "canonical relative source paths required")
    for request in requests:
        for ref in request.get("evidence", []):
            expected = declared.get(ref.get("path"))
            if expected is None or any(ref.get(k) != expected.get(k) for k in ("sha256", "bytes")):
                raise AuditError("CAMPAIGN_UNDECLARED_SOURCE", "audit request escapes frozen sources")
    out = Path(output_root).absolute()
    cursor = Path(out.anchor)
    for part in out.parts[1:]:
        cursor /= part
        if part in {".", ".."} or _reparse(cursor):
            raise AuditError("CAMPAIGN_OUTPUT_PATH", "output path must not contain aliases or reparse points")
    # Output guards mirror source guards; the output must not overwrite sources.
    exclusions = plan.get("excluded_output_subtrees", [])
    allowed_inside = False
    for relative in exclusions:
        if (not isinstance(relative, str) or "\\" in relative or ":" in relative
                or any(p in {"", ".", ".."} for p in relative.split("/"))):
            raise AuditError("CAMPAIGN_OUTPUT_EXCLUSION", "canonical output exclusion required")
        excluded = root.joinpath(*relative.split("/"))
        if any(p == relative or p.startswith(relative + "/") for p in declared):
            raise AuditError("CAMPAIGN_OUTPUT_EXCLUSION", "excluded output contains an input source")
        allowed_inside |= out == excluded or excluded in out.parents
    if out == root or (root in out.parents and not allowed_inside):
        raise AuditError("CAMPAIGN_OUTPUT_IN_SOURCE", "output must be outside declared source root")
    out.mkdir(parents=True, exist_ok=True)
    _checked_root(out)
    if shutil.disk_usage(out).free < min_free_bytes:
        raise AuditError("CAMPAIGN_DISK_RESERVE", "free storage reserve would be violated")
    lock = out / "writer.json"
    if lock.exists():
        previous = json.loads(lock.read_text(encoding="utf-8"))
        if not resume or _alive(previous["pid"]):
            raise AuditError("CAMPAIGN_WRITER_PRESENT", "existing writer requires a dead-process resume")
        lock.rename(out / ("abandoned-writer-" + str(time.time_ns()) + ".json"))
    _write_new(lock, {"pid": os.getpid(), "time_ns": time.time_ns()})
    try:
        code_hashes = plan.get("code_sha256", {})
        repo = Path(__file__).resolve().parents[3]
        for relative, expected in code_hashes.items():
            path = _safe_path(repo, relative)
            if _digest(path) != expected:
                raise AuditError("CAMPAIGN_CODE_CHANGED", "code differs from frozen plan")
        pin = {"plan_sha256": hashlib.sha256(_raw(plan)).hexdigest(),
               "code_commit": plan.get("code_commit", "UNFROZEN_DEVELOPMENT")}
        binding = out / "binding.json"
        if binding.exists():
            if not resume or json.loads(binding.read_text(encoding="utf-8")) != pin:
                raise AuditError("CAMPAIGN_RESUME_BINDING", "existing campaign has a different binding")
        else:
            if resume:
                raise AuditError("CAMPAIGN_RESUME_MISSING_BINDING", "cannot resume an unbound directory")
            if any(path != lock for path in out.iterdir()):
                raise AuditError("CAMPAIGN_OUTPUT_NOT_FRESH", "unbound output directory must be empty")
            _write_new(binding, pin)
        # Before accepting any completed units, remeasure the declared snapshot.
        for source in sources:
            path = _safe_path(root, source["path"])
            if path.stat().st_size != source["bytes"] or _digest(path) != source["sha256"]:
                raise AuditError("CAMPAIGN_SOURCE_CHANGED", "source differs from frozen commitment")
        journal = out / "attempts.jsonl"
        completed = {}
        if journal.exists():
            for line in journal.read_bytes().splitlines():
                event = json.loads(line)
                if event["event"] == "COMPLETE":
                    if event["unit"] in completed:
                        raise AuditError("CAMPAIGN_DUPLICATE_COMPLETION", "duplicate completed unit")
                    completed[event["unit"]] = event
        for event in completed.values():
            path = _safe_path(out, event["result_path"])
            if _digest(path) != event["sha256"]:
                raise AuditError("CAMPAIGN_RESULT_CHANGED", "completed result hash differs")
        units = [("file", str(i), source) for i, source in enumerate(sources)]
        units += [("audit", str(i), request) for i, request in enumerate(requests)]
        counts = {"files": len(sources), "audits": len(requests), "recovered": 0, "executed": 0}
        for kind, number, item in units:
            unit = kind + "-" + number
            if unit in completed:
                counts["recovered"] += 1
                continue
            if shutil.disk_usage(out).free < min_free_bytes:
                raise AuditError("CAMPAIGN_DISK_RESERVE", "free storage reserve reached")
            attempt = str(time.time_ns())
            _append(journal, {"event": "START", "unit": unit, "attempt": attempt})
            try:
                result = audit_file(root, item) if kind == "file" else audit_evidence(root, item)
            except Exception as exc:
                result = {"status": "ERROR", "AUDIT_VERDICT": "VERIFICATION_ERROR",
                          "reason_codes": ["UNHANDLED_" + type(exc).__name__],
                          "error_type": type(exc).__name__}
            result_path = kind + "-" + number + "-" + attempt + ".json"
            path = out / result_path
            _write_new(path, result)
            _append(journal, {"event": "COMPLETE", "unit": unit, "attempt": attempt,
                              "result_path": result_path, "sha256": _digest(path)})
            counts["executed"] += 1
        return {"schema": "pgop1.swebench.campaign-execution.v1", "campaign_id": "PGOP1_RUN_001",
                **pin, **counts, "status": "COMPLETED_PLAN_UNITS",
                "dispatch": "NOT_PERFORMED", "independent_custody": "NOT_PROVEN"}
    finally:
        lock.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    print(json.dumps(run_campaign(args.data_root, plan, args.output, resume=args.resume), sort_keys=True))


if __name__ == "__main__":
    main()
