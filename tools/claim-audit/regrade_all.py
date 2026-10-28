#!/usr/bin/env python3
"""Prepare and run a hash-bound, local Level-B SWE-bench log regrade.

The script intentionally refuses to grade until a code-freeze manifest is
present. It calls the unmodified official SWE-bench `_grade` function against
the frozen local test split and archived test log; it does not execute patches.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WORKSPACE = Path(r"D:\PGOP1_DATA\SWEbench\Engineering\PGOP1_RUN_001")
DATA_ROOT = Path(r"D:\PGOP1_DATA\SWEbench")
INVENTORY_PATH = WORKSPACE / "INPUT_INVENTORY.json"
UPSTREAM_PATH = WORKSPACE / "UPSTREAM_VERIFICATION.json"
DATASET_PATH = DATA_ROOT / "multilingual" / "data" / "test-00000-of-00001.parquet"
OFFICIAL_SOURCE = DATA_ROOT / "SWE-bench-main"
EXPECTED_INVENTORY_SHA256 = "6ff897fb78cd6622a2fc76d8b04a2ef810fa2b4aee178d1b0520d69fe8f81e94"
EXPECTED_UPSTREAM_MANIFEST_SHA256 = "ffbb0f169c08c066b0ae91405e7cce842229205af0c8505c46aff2794e5935f4"
EXPECTED_DATASET_SHA256 = "92abca7cb527b41a9f66d03a26ce441ff7319e3a49f985998fd56be4bb9b08b2"
EXPECTED_PACKAGE_SHA256 = "83423d149c51d01a9eb526ac4bc2f9418b2428528cd24d5f6d9998f3d77dcc85"
EXPECTED_UPSTREAM_COMMIT = "02e7a74ffd0b707aab73d203fe87bdc7c76afc8e"
EXPECTED_CASES = 258
MAX_GZIP_EXPANDED_BYTES = 64 * 1024 * 1024
FREEZE_SCHEMA = "pgop1.run001.code-freeze.v1"
RESULT_SCHEMA = "pgop1.run001.level-b-case-event.v1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fail(message: str) -> None:
    raise RuntimeError(message)


def require_file_hash(path: Path, expected: str, label: str) -> None:
    if not path.is_file():
        fail(f"{label} missing: {path}")
    actual = sha256_file(path)
    if actual != expected:
        fail(f"{label} hash mismatch: expected {expected}, observed {actual}")


def contained_path(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        fail(f"unsafe inventory relative path: {relative!r}")
    candidate = (root / rel).resolve(strict=True)
    resolved_root = root.resolve(strict=True)
    if candidate != resolved_root and resolved_root not in candidate.parents:
        fail(f"inventory path escapes source root: {relative!r}")
    if not candidate.is_file():
        fail(f"inventory source is not a regular file: {relative!r}")
    return candidate


def load_pins() -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, str]]:
    require_file_hash(INVENTORY_PATH, EXPECTED_INVENTORY_SHA256, "INPUT_INVENTORY")
    require_file_hash(UPSTREAM_PATH, EXPECTED_UPSTREAM_MANIFEST_SHA256, "UPSTREAM_VERIFICATION")
    require_file_hash(DATASET_PATH, EXPECTED_DATASET_SHA256, "multilingual test parquet")
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    upstream = json.loads(UPSTREAM_PATH.read_text(encoding="utf-8"))
    if upstream.get("commit") != EXPECTED_UPSTREAM_COMMIT:
        fail("upstream verification commit does not match the pinned revision")
    files = upstream.get("files")
    if not isinstance(files, list) or len(files) != 16:
        fail("upstream verification manifest must contain the 16 pinned source files")
    upstream_file_hashes: dict[str, str] = {}
    for item in files:
        if item.get("status") != "MATCH" or item.get("local_sha256") != item.get("upstream_sha256"):
            fail(f"upstream source identity is not MATCH: {item.get('path')!r}")
        relative = item.get("path")
        digest = item.get("local_sha256")
        if not isinstance(relative, str) or not isinstance(digest, str):
            fail("malformed upstream source identity entry")
        source_file = contained_path(OFFICIAL_SOURCE, relative)
        if sha256_file(source_file) != digest:
            fail(f"official source hash changed: {relative}")
        upstream_file_hashes[relative] = digest
    package_hash = upstream_file_hashes.get("swebench/submit/package.py")
    if package_hash != EXPECTED_PACKAGE_SHA256:
        fail("pinned official package.py identity is unexpected")
    return inventory, files, upstream_file_hashes


def select_cases(inventory: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    by_case: dict[str, dict[str, dict[str, Any]]] = {}
    traj_count = 0
    for item in inventory.get("files", []):
        rel = item.get("relative_path", "")
        if rel.startswith("logs/trajs/") and item.get("evidence_role") == "agent_trajectory":
            traj_count += 1
        if not rel.startswith("logs/logs/"):
            continue
        pieces = rel.split("/")
        if len(pieces) != 4:
            fail(f"unexpected logs/logs path shape: {rel!r}")
        case_id, name = pieces[2], pieces[3]
        if name not in {"report.json", "patch.diff", "test_output.txt.gz"}:
            fail(f"unexpected file in regrade case directory: {rel!r}")
        if item.get("processing_eligibility") not in {
            "CANDIDATE_AGENT_EVIDENCE", "CANDIDATE_PATCH_EVIDENCE_NO_EXECUTION"
        }:
            fail(f"case file is not marked as candidate evidence: {rel!r}")
        by_case.setdefault(case_id, {})[name] = item
    if len(by_case) != EXPECTED_CASES:
        fail(f"expected {EXPECTED_CASES} logs/logs cases, found {len(by_case)}")
    if traj_count != 264:
        fail(f"expected 264 trajectory evidence files, found {traj_count}")
    cases: list[dict[str, Any]] = []
    for case_id, entries in sorted(by_case.items()):
        if set(entries) != {"report.json", "patch.diff", "test_output.txt.gz"}:
            fail(f"incomplete archived evidence triplet for {case_id}")
        cases.append({"instance_id": case_id, "sources": entries})
    return cases, traj_count


def read_freeze(path: Path) -> tuple[dict[str, Any], str]:
    if not path.is_file():
        fail(f"code-freeze manifest missing: {path}")
    freeze_hash = sha256_file(path)
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema") != FREEZE_SCHEMA or manifest.get("status") != "FROZEN":
        fail("code-freeze manifest must have expected schema and status FROZEN")
    if manifest.get("working_tree_clean") is not True:
        fail("code-freeze must assert working_tree_clean=true")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("commit", ""))):
        fail("code-freeze commit must be a full lowercase 40-hex commit")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("tree", ""))):
        fail("code-freeze tree must be a full lowercase 40-hex tree")
    code_files = manifest.get("files")
    if not isinstance(code_files, list) or not code_files:
        fail("code-freeze must enumerate frozen code files and hashes")
    git_head = subprocess.run(
        ["git", "-C", str(WORKSPACE / "repo"), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    git_tree = subprocess.run(
        ["git", "-C", str(WORKSPACE / "repo"), "rev-parse", "HEAD^{tree}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    git_status = subprocess.run(
        ["git", "-C", str(WORKSPACE / "repo"), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    git_branch = subprocess.run(
        ["git", "-C", str(WORKSPACE / "repo"), "branch", "--show-current"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if git_head != manifest["commit"] or git_tree != manifest["tree"]:
        fail("code-freeze commit/tree do not match the repository HEAD")
    if git_branch != "feat/pgop1-run-001" or manifest.get("branch") != git_branch:
        fail("code-freeze must bind the feat/pgop1-run-001 branch")
    if git_status.strip():
        fail("repository is not clean at code-freeze validation")
    for entry in code_files:
        relative, digest = entry.get("path"), entry.get("sha256")
        if not isinstance(relative, str) or not re.fullmatch(r"[0-9a-f]{64}", str(digest or "")):
            fail("malformed code-freeze file entry")
        code_path = contained_path(WORKSPACE / "repo", relative)
        if sha256_file(code_path) != digest:
            fail(f"frozen code file hash mismatch: {relative}")
    return manifest, freeze_hash


def append_event(path: Path, event: dict[str, Any]) -> None:
    data = (json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    with path.open("ab") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                fail(f"append-only event log has malformed line {number}; refusing repair/retry: {exc}")
            if event.get("schema") != RESULT_SCHEMA:
                fail(f"event log line {number} has an unknown schema")
            events.append(event)
    return events


def extract_gzip_bounded(source: Path, destination: Path) -> int:
    expanded = 0
    with gzip.open(source, "rb") as src, destination.open("xb") as dst:
        while True:
            block = src.read(1024 * 1024)
            if not block:
                break
            expanded += len(block)
            if expanded > MAX_GZIP_EXPANDED_BYTES:
                raise ValueError(f"GZIP_EXPANSION_LIMIT:{expanded}>{MAX_GZIP_EXPANDED_BYTES}")
            dst.write(block)
    return expanded


def event_base(case_id: str, freeze_hash: str, pin_hash: str) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "timestamp_utc": utc_now(),
        "instance_id": case_id,
        "code_freeze_manifest_sha256": freeze_hash,
        "run_pin_sha256": pin_hash,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze-manifest", required=True, type=Path)
    parser.add_argument("--attempt-id", default="attempt-001")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", args.attempt_id):
        fail("attempt-id must be a safe 1-64 character identifier")

    freeze, freeze_hash = read_freeze(args.freeze_manifest.resolve(strict=True))
    inventory, upstream_files, upstream_hashes = load_pins()
    cases, trajectory_count = select_cases(inventory)
    dataset_hash = sha256_file(DATASET_PATH)
    package_path = OFFICIAL_SOURCE / "swebench" / "submit" / "package.py"
    regrade_script = Path(__file__).resolve(strict=True)
    code_hashes = {
        "inventory_sha256": EXPECTED_INVENTORY_SHA256,
        "upstream_verification_sha256": EXPECTED_UPSTREAM_MANIFEST_SHA256,
        "dataset_sha256": dataset_hash,
        "official_package_sha256": sha256_file(package_path),
        "regrade_script_sha256": sha256_file(regrade_script),
        "code_freeze_manifest_sha256": freeze_hash,
        "code_commit": freeze["commit"],
        "code_tree": freeze["tree"],
    }
    pin_hash = hashlib.sha256(json.dumps(code_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    # All outputs are private and confined to the selected attempt folder.
    output_dir = WORKSPACE / "runs" / "run-001" / "verification" / "official-regrade-level-b" / args.attempt_id
    output_dir.mkdir(parents=True, exist_ok=True)
    run_manifest_path = output_dir / "RUN_MANIFEST.json"
    events_path = output_dir / "CASE_EVENTS.jsonl"
    run_manifest = {
        "schema": "pgop1.run001.level-b-run-manifest.v1",
        "created_utc": utc_now(),
        "status": "EXECUTION_STARTED_AFTER_CODE_FREEZE",
        "level": "B",
        "method": "Unmodified local SWE-bench 5.0.2 _grade; archived test logs, patch text, and local pinned test-row metadata only; no patch execution.",
        "scope": {"logs_log_cases": len(cases), "trajectory_files_in_inventory": trajectory_count, "trajectory_files_regraded": 0},
        "pins": code_hashes,
        "regrade_script": str(regrade_script),
        "pin_sha256": pin_hash,
        "python": {"executable": sys.executable, "version": sys.version},
        "offline": {"HF_HUB_OFFLINE": "1", "HF_DATASETS_OFFLINE": "1"},
    }
    if run_manifest_path.exists():
        existing = json.loads(run_manifest_path.read_text(encoding="utf-8"))
        if existing.get("pin_sha256") != pin_hash or existing.get("pins") != code_hashes:
            fail("attempt folder already exists with different pins; select a new attempt-id")
    else:
        with run_manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(run_manifest, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

    events = read_events(events_path)
    started: set[str] = set()
    terminal: set[str] = set()
    for event in events:
        case_id = event.get("instance_id")
        if event.get("event") == "CASE_STARTED":
            if case_id in started:
                fail(f"duplicate start record for {case_id}; refusing a retry")
            started.add(case_id)
        elif event.get("event") in {"CASE_COMPLETED", "CASE_FAILED", "INTERRUPTED_NO_RETRY"}:
            if case_id not in started or case_id in terminal:
                fail(f"invalid terminal event for {case_id}; refusing a retry")
            terminal.add(case_id)
    if not terminal.issubset(started):
        fail("internal event log inconsistency")

    # A start without a terminal event means work may have begun before a crash.
    # Mark it indeterminate and never grade it again in this attempt.
    for case_id in sorted(started - terminal):
        append_event(events_path, {**event_base(case_id, freeze_hash, pin_hash), "event": "INTERRUPTED_NO_RETRY", "status": "UNKNOWN_AFTER_INTERRUPTION"})
        terminal.add(case_id)

    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["HF_DATASETS_OFFLINE"] = "1"
    os.environ["HF_HOME"] = str(output_dir / "hf-cache")
    os.environ["HF_DATASETS_CACHE"] = str(output_dir / "datasets-cache")
    sys.path.insert(0, str(OFFICIAL_SOURCE))
    from datasets import load_dataset
    from swebench.submit.package import _grade

    rows = load_dataset(
        "parquet",
        data_files={"test": str(DATASET_PATH)},
        split="test",
        cache_dir=str(output_dir / "datasets-cache"),
    )
    row_by_id = {row["instance_id"]: dict(row) for row in rows}
    if len(rows) != 300 or len(row_by_id) != 300:
        fail(f"pinned local test split shape mismatch: rows={len(rows)}, unique={len(row_by_id)}")

    # Recheck sources against the inventory immediately before grading.
    for case in cases:
        for source in case["sources"].values():
            item = source
            path = contained_path(DATA_ROOT, item["relative_path"])
            if sha256_file(path) != item["sha256"]:
                fail(f"input source hash drift before grading: {item['relative_path']}")

    for case in cases:
        instance_id = case["instance_id"]
        if instance_id in terminal:
            continue
        source_items = case["sources"]
        start = {
            **event_base(instance_id, freeze_hash, pin_hash),
            "event": "CASE_STARTED",
            "source_sha256": {name: item["sha256"] for name, item in sorted(source_items.items())},
        }
        append_event(events_path, start)
        started.add(instance_id)
        try:
            if instance_id not in row_by_id:
                raise KeyError("INSTANCE_NOT_IN_PINNED_TEST_SPLIT")
            row = row_by_id[instance_id]
            row_hash = hashlib.sha256(
                json.dumps(row, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
            ).hexdigest()
            paths = {
                name: contained_path(DATA_ROOT, item["relative_path"])
                for name, item in source_items.items()
            }
            # Verify all three originals again immediately before their use.
            for name, item in source_items.items():
                if sha256_file(paths[name]) != item["sha256"]:
                    raise ValueError(f"INPUT_HASH_DRIFT:{name}")
            with tempfile.TemporaryDirectory(prefix="pgop1_run001_grade_", dir=str(output_dir)) as tmp:
                expanded_path = Path(tmp) / "archived-test-output.txt"
                expanded_bytes = extract_gzip_bounded(paths["test_output.txt.gz"], expanded_path)
                resolved = bool(_grade(row, paths["patch.diff"], expanded_path, "submission"))
            # Detect concurrent mutation after grading; never silently accept it.
            for name, item in source_items.items():
                if sha256_file(paths[name]) != item["sha256"]:
                    raise ValueError(f"INPUT_HASH_DRIFT_AFTER_GRADE:{name}")
            append_event(events_path, {
                **event_base(instance_id, freeze_hash, pin_hash),
                "event": "CASE_COMPLETED",
                "status": "GRADED",
                "dataset_row_sha256": row_hash,
                "test_log_expanded_bytes": expanded_bytes,
                "resolved": resolved,
                "method": "official _grade against local frozen test row, archived patch text and archived test log; no report.json used as grade input",
            })
            terminal.add(instance_id)
        except Exception as exc:  # record the exact error class/message, then continue once
            append_event(events_path, {
                **event_base(instance_id, freeze_hash, pin_hash),
                "event": "CASE_FAILED",
                "status": "ERROR_NO_RETRY",
                "error_type": type(exc).__name__,
                "error": str(exc),
            })
            terminal.add(instance_id)

    completed = sum(1 for event in read_events(events_path) if event.get("event") == "CASE_COMPLETED")
    failed = sum(1 for event in read_events(events_path) if event.get("event") == "CASE_FAILED")
    interrupted = sum(1 for event in read_events(events_path) if event.get("event") == "INTERRUPTED_NO_RETRY")
    print(json.dumps({
        "attempt_id": args.attempt_id,
        "scope_cases": len(cases),
        "completed": completed,
        "failed": failed,
        "interrupted_unknown": interrupted,
        "results_file": str(events_path),
        "pin_sha256": pin_hash,
    }, sort_keys=True))
    return 0 if completed == len(cases) and failed == 0 and interrupted == 0 else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2)
