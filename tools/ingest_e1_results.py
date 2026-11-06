"""Post-execution RUN004 receipt provenance through the existing Context Engine.

Only explicitly indexed first-party terminal receipts are read. Referenced
benchmark paths remain inert strings. This never dispatches benchmark work.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE))
from runtime.candidate.context_engine import Engine, canonical_json, sha256_bytes
from runtime.candidate.run_framework.core import FrameworkError, PATH_ID, _path, _write_immutable, _git_read

MAX_SOURCE_BYTES = 256 * 1024
MAX_DERIVED_SOURCE_BYTES = 8 * 1024**2
MAX_UNITS = 10096
MAX_BYTES = 20 * 1024**3
MODE = "POST_EXECUTION_RESULT_PROVENANCE_INGESTION"


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def binding(path):
    path = _path(path, True)
    return {"path": str(path), "sha256": sha256_bytes(path.read_bytes())}


def clean_code():
    result = _git_read(CODE, "status", "--porcelain", "--untracked-files=normal")
    if result.stdout.strip() or result.stderr.strip():
        raise FrameworkError("PROVENANCE_CLEAN_CODE_REQUIRED")


def authoritative_snapshot(store):
    return {str(p.relative_to(store)): binding(p)["sha256"]
            for part in ("versions", "objects", "sources")
            for p in sorted((store / part).rglob("*")) if p.is_file()}


def write(path, value, workspace, owned):
    raw = canonical_json(value)
    if output_bytes(workspace, owned) + len(raw) + 16 * 1024**2 > MAX_BYTES:
        raise FrameworkError("PROVENANCE_SHARED_OUTPUT_BUDGET_EXHAUSTED")
    _write_immutable(Path(path), raw)


def stage_paths(workspace, stage_id):
    if not PATH_ID.fullmatch(stage_id) or stage_id in {".", ".."}:
        raise FrameworkError("PROVENANCE_UNSAFE_STAGE_ID")
    workspace = _path(workspace, True)
    owned = _path(workspace / "result-provenance", False)
    return workspace, owned, _path(owned / "stages" / stage_id, False), _path(owned / "context-engine", False)


def owned_receipt(workspace, path, expected_hash, unit_id):
    path = _path(path, True)
    parts = path.relative_to(workspace).parts
    if (len(parts) != 8 or parts[0] != "attempts" or parts[2] != "stores"
            or parts[4] != "attempts" or parts[6] != "receipts" or parts[1] != parts[5]
            or path.suffix != ".json"):
        raise FrameworkError("PROVENANCE_SOURCE_NOT_OWNED_TERMINAL_RECEIPT")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_SOURCE_BYTES or st.st_nlink != 1:
        raise FrameworkError("PROVENANCE_SOURCE_SIZE_OR_TYPE_REJECTED")
    raw = path.read_bytes()
    if len(raw) > MAX_SOURCE_BYTES or sha256_bytes(raw) != expected_hash:
        raise FrameworkError("PROVENANCE_RECEIPT_HASH_MISMATCH")
    receipt = json.loads(raw)
    if (receipt.get("schema") != "pgop1.reusable-run-receipt.v2" or receipt.get("phase") != "terminal"
            or receipt.get("unit_id") != unit_id or receipt.get("run_id") != parts[3]
            or receipt.get("campaign_id") != "RUN004-E1"):
        raise FrameworkError("PROVENANCE_TERMINAL_IDENTITY_MISMATCH")
    disposition = receipt["payload"]["result_payload"]["audit_disposition"]
    if not isinstance(disposition, str):
        raise FrameworkError("PROVENANCE_DISPOSITION_NOT_STRING")
    return raw, disposition


def store_parent(store):
    if not store.exists():
        return None, set()
    versions = store / "versions"
    paths = sorted(versions.glob("*/manifest.json"))
    if not paths:
        return None, set()
    last = paths[-1]
    manifest = load(last)
    graph = load(last.parent / "graph.json")
    return manifest, {r["task_id"] for r in graph["observations"]
                      if r.get("kind") == "run004_e1_terminal_disposition"}


def output_bytes(workspace, owned):
    total = 0
    for root in (workspace / "attempts", owned):
        if not root.exists():
            continue
        for folder, directories, files in os.walk(root, followlinks=False):
            for name in [*directories, *files]:
                p = _path(Path(folder) / name, True)
                if p.is_file():
                    total += p.stat().st_size
    return total


def prepare(workspace, stage_id, source_index):
    clean_code()
    workspace, owned, stage, store = stage_paths(workspace, stage_id)
    source_index = _path(source_index, True)
    if not source_index.is_relative_to(workspace):
        raise FrameworkError("PROVENANCE_INDEX_OUTSIDE_WORKSPACE")
    if source_index.stat().st_size > MAX_DERIVED_SOURCE_BYTES:
        raise FrameworkError("PROVENANCE_INDEX_SIZE_LIMIT")
    rows = load(source_index)["rows"]
    if not 1 <= len(rows) <= MAX_UNITS:
        raise FrameworkError("PROVENANCE_STAGE_UNIT_BOUND")
    parent, old_units = store_parent(store)
    sources = []
    seen = set()
    for row in rows:
        uid = row["UNIT_ID"]
        if uid in seen or uid in old_units:
            raise FrameworkError("PROVENANCE_DUPLICATE_COMPLETED_UNIT")
        raw, disposition = owned_receipt(workspace, row["RECEIPT_PATH"], row["RECEIPT_SHA256"], uid)
        seen.add(uid)
        sources.append({"unit_id": uid, "path": str(Path(row["RECEIPT_PATH"]).resolve()),
            "sha256": row["RECEIPT_SHA256"], "byte_length": len(raw), "disposition": disposition,
            "observation_id": "run004-e1-terminal-" + row["RECEIPT_SHA256"]})
    commit = _git_read(CODE, "rev-parse", "HEAD").stdout.strip()
    tree = _git_read(CODE, "rev-parse", "HEAD^{tree}").stdout.strip()
    driver = binding(__file__)
    committed = _git_read(CODE, "show", commit + ":tools/ingest_e1_results.py", binary=True).stdout
    if sha256_bytes(committed) != driver["sha256"]:
        raise FrameworkError("PROVENANCE_DRIVER_MUST_BE_COMMITTED")
    engine_code = binding(CODE / "runtime/candidate/context_engine.py")
    if sha256_bytes(_git_read(CODE, "show", commit + ":runtime/candidate/context_engine.py", binary=True).stdout) != engine_code["sha256"]:
        raise FrameworkError("PROVENANCE_ENGINE_MUST_BE_COMMITTED")
    helper_code = binding(CODE / "runtime/candidate/run_framework/core.py")
    if sha256_bytes(_git_read(CODE, "show", commit + ":runtime/candidate/run_framework/core.py", binary=True).stdout) != helper_code["sha256"]:
        raise FrameworkError("PROVENANCE_HELPERS_MUST_BE_COMMITTED")
    stage.mkdir(parents=True, exist_ok=False)
    evidence = {"schema": "pgop1.e1.verified-terminal-receipt-projection.v1",
        "representation": "DERIVED_RESULT_OBSERVATIONS_FROM_VERIFIED_TERMINAL_RECEIPTS",
        "mode": MODE, "stage_id": stage_id,
        "rows": [{"unit_id": r["unit_id"], "receipt_path": r["path"], "receipt_sha256": r["sha256"],
                  "audit_disposition": r["disposition"]} for r in sources],
        "semantic_audits": 0, "raw_source_authentication_claim": False}
    if len(canonical_json(evidence)) > MAX_DERIVED_SOURCE_BYTES:
        raise FrameworkError("PROVENANCE_DERIVED_SOURCE_SIZE_LIMIT")
    write(stage / "EVIDENCE_SOURCE.json", evidence, workspace, owned)
    evidence_binding = binding(stage / "EVIDENCE_SOURCE.json")
    write(stage / "FREEZE.json", {"schema": "pgop1.e1.result-provenance-freeze.v1", "mode": MODE,
        "stage_id": stage_id, "code_root": str(CODE), "candidate_commit": commit, "candidate_tree": tree,
        "driver": driver, "context_engine": engine_code, "framework_helpers": helper_code,
        "python_version": sys.version, "source_index": binding(source_index),
        "sources": sources, "evidence_source": evidence_binding,
        "evidence_source_id": "run004-e1-derived-" + evidence_binding["sha256"],
        "representation": evidence["representation"], "expected_parent": parent, "store": str(store),
        "maximum_source_bytes": MAX_SOURCE_BYTES, "maximum_derived_source_bytes": MAX_DERIVED_SOURCE_BYTES,
        "maximum_units": MAX_UNITS,
        "max_shared_output_bytes": MAX_BYTES, "benchmark_redispatch": 0, "semantic_audits": 0,
        "identity_policy": {"declared_actor_identity": "PGOP1-RUN004-E1", "provider_identity": "UNKNOWN",
                            "process_identity": "UNKNOWN", "independent_custody": "NOT_PROVEN"}}, workspace, owned)
    print("PREPARED", stage_id, len(sources), flush=True)


def run(workspace, stage_id, recover=False):
    clean_code()
    workspace, owned, stage, store = stage_paths(workspace, stage_id)
    freeze = load(stage / "FREEZE.json")
    for field in ("driver", "context_engine", "framework_helpers", "source_index", "evidence_source"):
        if binding(freeze[field]["path"]) != freeze[field]:
            raise FrameworkError("PROVENANCE_FROZEN_BINDING_CHANGED")
    if _git_read(CODE, "rev-parse", "HEAD").stdout.strip() != freeze["candidate_commit"]:
        raise FrameworkError("PROVENANCE_CODE_COMMIT_CHANGED")
    if freeze["store"] != str(store):
        raise FrameworkError("PROVENANCE_STORE_REBOUND")
    grants = [{**freeze["evidence_source"], "scope": "ENGINEERING_RESULT"}]
    # Reserve source objects, complete cumulative graph/provenance, and index
    # growth conservatively before any Engine writes. Reports are included.
    existing_parent, old_units = store_parent(store)
    reserve = Path(freeze["evidence_source"]["path"]).stat().st_size + (len(old_units) + len(freeze["sources"])) * 16384 + 32 * 1024**2
    if output_bytes(workspace, owned) + reserve > MAX_BYTES:
        raise FrameworkError("PROVENANCE_SHARED_OUTPUT_BUDGET_EXHAUSTED")
    if not recover and existing_parent != freeze["expected_parent"]:
        raise FrameworkError("PROVENANCE_STORE_PARENT_CHANGED")
    if recover and not (stage / "INGEST.json").exists():
        raise FrameworkError("PROVENANCE_RECOVERY_REQUIRES_COMPLETED_INGEST")
    engine = Engine(store, grants=grants)
    if not recover:
        if (stage / "INGEST.json").exists():
            raise FrameworkError("PROVENANCE_STAGE_ALREADY_INGESTED_NO_REPLAY")
        if engine.latest() != freeze["expected_parent"]:
            raise FrameworkError("PROVENANCE_VERIFIED_PARENT_CHANGED")
        engine.admit_source(freeze["evidence_source"]["path"], freeze["evidence_source"]["sha256"],
                            scope="ENGINEERING_RESULT", source_id=freeze["evidence_source_id"])
        observations = []
        for index, row in enumerate(freeze["sources"]):
            owned_receipt(workspace, row["path"], row["sha256"], row["unit_id"])
            observations.append({"id": row["observation_id"], "kind": "run004_e1_terminal_disposition",
                "task_id": row["unit_id"], "run_id": "RUN004", "session_id": stage_id,
                "value": row["disposition"], "evidence_binding": {"source_id": freeze["evidence_source_id"],
                    "sha256": freeze["evidence_source"]["sha256"], "pointer": f"/rows/{index}/audit_disposition"}})
        parent_hash = freeze["expected_parent"]["graph_sha256"] if freeze["expected_parent"] else None
        manifest = engine.ingest(observations, edges=(), expected_parent=parent_hash,
            provenance={"declared_actor_identity": "PGOP1-RUN004-E1", "provider_identity": "UNKNOWN",
                        "process_identity": "UNKNOWN", "tool_identity": "ingest_e1_results.py",
                        "invocation_evidence": binding(stage / "FREEZE.json")["sha256"]})
        write(stage / "INGEST.json", {"schema": "pgop1.e1.result-provenance-ingest.v1", "mode": MODE,
            "pid": os.getpid(), "stage_id": stage_id, "units": len(observations), "manifest": manifest,
            "graph_schema": "I4-NEXT-v0.1", "provenance_schema": "I5-NEXT-v0.1",
            "representation": freeze["representation"], "raw_source_authentication_claim": False,
            "freeze": binding(stage / "FREEZE.json"), "benchmark_redispatch": 0, "semantic_audits": 0,
            "causal_edges_added": 0, "retroactive_runtime_integration_claim": False}, workspace, owned)
        print("INGESTED", stage_id, len(observations), flush=True)
        return
    before = authoritative_snapshot(store)
    verification = engine.verify()
    raw = engine.read_source(freeze["evidence_source_id"])
    if sha256_bytes(raw) != freeze["evidence_source"]["sha256"]:
        raise FrameworkError("PROVENANCE_DERIVED_SOURCE_READBACK_MISMATCH")
    receipts = []
    for row in freeze["sources"]:
        observed = engine.query(task_id=row["unit_id"], kind="run004_e1_terminal_disposition", limit=2)
        if (len(observed) != 1
                or observed[0]["id"] != row["observation_id"] or observed[0]["value"] != row["disposition"]):
            raise FrameworkError("PROVENANCE_EXACT_READBACK_MISMATCH")
        receipts.append({"unit_id": row["unit_id"], "receipt_sha256": row["sha256"],
                         "observation_id": row["observation_id"], "derived_disposition_verified": True})
    if authoritative_snapshot(store) != before:
        raise FrameworkError("PROVENANCE_AUTHORITATIVE_RECORDS_CHANGED_DURING_READBACK")
    write(stage / "RECOVERY.json", {"schema": "pgop1.e1.result-provenance-recovery.v1", "mode": MODE,
        "status": "VERIFIED", "pid": os.getpid(), "stage_id": stage_id, "verification": verification,
        "units": len(receipts), "readbacks": receipts, "benchmark_redispatch": 0, "semantic_audits": 0,
        "representation": freeze["representation"], "exact_derived_source_bytes_verified": True,
        "raw_source_authentication_claim": False,
        "authoritative_records_read_only": True,
        "derived_index_reconstruction_required": engine.metrics.get("RECONSTRUCTION_REQUIRED", False),
        "derived_index_repair_is_separate_from_authoritative_recovery": True,
        "freeze": binding(stage / "FREEZE.json"), "ingest": binding(stage / "INGEST.json")}, workspace, owned)
    print("RECOVERED", stage_id, len(receipts), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "ingest", "recover"])
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--stage-id", required=True)
    parser.add_argument("--source-index", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        if args.source_index is None:
            parser.error("prepare requires --source-index")
        prepare(args.workspace, args.stage_id, args.source_index)
    else:
        run(args.workspace, args.stage_id, args.mode == "recover")


if __name__ == "__main__":
    main()
