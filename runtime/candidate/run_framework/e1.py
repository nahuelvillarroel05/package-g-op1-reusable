"""Closed, inert RUN004 E1 definition processor over GenericCaller/Checkpoint V2.

No benchmark code, model, command, evaluator, or downloaded callback executes.
Unknown/restricted sources are never included in framework source bindings.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
import tomllib

from .core import FrameworkError, PATH_ID, canonical, digest, _git_read, _path, _write_immutable
from . import load_config
from .caller import GenericCaller
from .predicates import build_audit_payload
from .resources import ResourceLimitStop

ATTEMPT = "RUN004_E1_ATTEMPT_001"
PRODUCER = "PGOP1-RUN004-E1"
MAX_INPUT = 4 * 1024**2
MAX_BYTES = 20 * 1024**3
BATCH_RESERVE = 16 * 1024**2
SHARD_MAX_BYTES = 14 * 1024**2
WRITER_MAX_BYTES = 2 * 1024**2


def validate_attempt_id(value):
    if not isinstance(value, str) or not PATH_ID.fullmatch(value) or value in {".", ".."}:
        raise FrameworkError("E1_UNSAFE_ATTEMPT_ID")


def check_prior_state(state):
    if state["inflight"]:
        raise FrameworkError("E1_PRIOR_INFLIGHT_REQUIRES_REVIEW")


def write_writer(path, value):
    raw = canonical(value)
    if len(raw) > WRITER_MAX_BYTES:
        raise FrameworkError("E1_WRITER_BYTE_BUDGET_EXHAUSTED")
    _write_immutable(Path(path), raw)


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def ref(path):
    path = _path(path, True)
    return {"path": str(path), "sha256": digest(path.read_bytes())}


def verified_receipt_reference(campaign, summary, unit_id, phase="terminal"):
    """Bind derived references to persisted receipt bytes, never a summary hash."""
    relative = Path(summary["path"])
    if relative.is_absolute() or len(relative.parts) != 2 or relative.parts[0] != "receipts":
        raise FrameworkError("E1_RECEIPT_REFERENCE_PATH_INVALID")
    actual = ref(campaign.output / relative)
    receipt = read(actual["path"])
    if (actual["sha256"] != summary["sha256"] or summary.get("unit_id") != unit_id
            or summary.get("phase") != phase or receipt.get("unit_id") != unit_id
            or receipt.get("phase") != phase or receipt.get("run_id") != campaign.run_id
            or receipt.get("campaign_id") != campaign.config["campaign_id"]
            or not receipt.get("attempt_id", "").startswith(
                f"{campaign.config['campaign_id']}:{campaign.run_id}:{campaign.config['campaign_attempt_id']}:{unit_id}:")):
        raise FrameworkError("E1_RECEIPT_REFERENCE_IDENTITY_OR_HASH_MISMATCH")
    return actual


def write(path, value):
    _write_immutable(Path(path), canonical(value))


def bounded(path, expected=None):
    path = _path(path, True)
    if not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise ValueError("SOURCE_SIZE_OR_TYPE_LIMIT")
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("SOURCE_SIZE_LIMIT")
    if expected is not None and digest(raw) != expected:
        raise FrameworkError("E1_SOURCE_HASH_MISMATCH")
    return raw


def process_definition(unit, references):
    """Parse one exact selected identity; never interpret content as code."""
    from runtime.candidate.multibenchmark.calling import _strict_json_loads
    raw = bounded(unit["source_path"], unit["source_sha256"])
    family = unit["benchmark_id"]
    if family == "bfcl_v4":
        text = raw.decode("utf-8-sig")
        try:
            rows = _strict_json_loads(text)
        except json.JSONDecodeError:
            rows = [_strict_json_loads(line) for line in text.splitlines() if line.strip()]
        index = unit["source_row_index"]
        if (not isinstance(rows, list) or type(index) is not int or not 0 <= index < len(rows)
                or not isinstance(rows[index], dict) or rows[index].get("id") != unit["task_id"]):
            raise ValueError("BFCL_SELECTED_ROW_ID_MISMATCH")
    elif family == "mcpmark_verified":
        if not isinstance(_strict_json_loads(raw.decode("utf-8-sig")), dict):
            raise ValueError("MCP_METADATA_NOT_OBJECT")
    elif family == "terminal_bench_2":
        if not isinstance(tomllib.loads(raw.decode("utf-8-sig")), dict):
            raise ValueError("TERMINAL_METADATA_NOT_OBJECT")
    else:
        raise ValueError("E1_CLOSED_PRODUCER_FAMILY_NOT_ALLOCATED")
    return {"definition": True}


def prepare(workspace, code_root, rights_path, contract_path, attempt_id=ATTEMPT, prior_attempt=None):
    for value in (attempt_id, prior_attempt):
        if value is not None:
            validate_attempt_id(value)
    if attempt_id == prior_attempt:
        raise FrameworkError("E1_PRIOR_ATTEMPT_MUST_BE_DISTINCT")
    workspace = _path(workspace, True)
    code_root = _path(code_root, True)
    root = workspace.parents[1]
    population_path = root / "Engineering/PGOP1_RUN004_FINAL_ENGINEERING_CONVERGENCE_001/run004/DATASET_MANIFEST.json"
    previous_path = root / "Engineering/PGOP1_RUN004_FINAL_ENGINEERING_CONVERGENCE_001/RUN004_EXECUTION_CANDIDATE_CONFIG.json"
    matrix = root / "Engineering/PGOP1_RUN004_FINAL_ENGINEERING_CONVERGENCE_001/predicates/PREDICATE_MATRIX.json"
    exclusions = root / "Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/RUN004_EXCLUSION_LEDGER.json"
    units = {u["unit_id"]: u for u in read(population_path)["units"]}
    previous = read(previous_path)
    ordered = previous["expected_units"]
    rights = {u["unit_id"]: u for u in read(rights_path)["units"]}
    if len(units) != 10096 or len(ordered) != 10096 or set(ordered) != set(units) or set(rights) != set(units):
        raise FrameworkError("E1_POPULATION_OR_RIGHTS_MEMBERSHIP_MISMATCH")
    commit = _git_read(code_root, "rev-parse", "HEAD").stdout.strip()
    tree = _git_read(code_root, "rev-parse", "HEAD^{tree}").stdout.strip()
    status = _git_read(code_root, "status", "--porcelain", "--untracked-files=normal")
    if status.stdout.strip() or status.stderr.strip():
        raise FrameworkError("E1_COMMITTED_CLEAN_CODE_REQUIRED")
    contract = read(contract_path)
    if PRODUCER not in contract.get("producers", {}):
        raise FrameworkError("E1_DECLARED_PRODUCER_REQUIRED")
    code_files = [ref(code_root / p) for p in _git_read(code_root, "ls-files", "runtime/candidate").stdout.splitlines()]
    prior_completed = {}
    prior_binding = None
    if prior_attempt is not None:
        prior = _path(workspace / "attempts" / prior_attempt, True)
        prior_plan_path = prior / "ATTEMPT_PLAN.json"
        prior_plan = read(prior_plan_path)
        if prior_plan["population"] != ref(population_path):
            raise FrameworkError("E1_PRIOR_POPULATION_MISMATCH")
        # Read verification only: instantiate no caller and dispatch no callback.
        recovered = []
        for row in prior_plan["batches"]:
            if row["config"] is None:
                continue
            c = campaign_for(prior, row)
            if not c.output.exists():
                continue
            c.preflight()
            state = c.recover()
            check_prior_state(state)
            recovered.append({"batch_id": row["batch_id"], "completed": sorted(state["completed"]),
                              "pending": sorted(state["pending"]), "inflight": sorted(state["inflight"]), "redispatch": 0})
            terminals = {r["unit_id"]: r for r in state["receipts"] if r["phase"] == "terminal"}
            for uid in state["completed"]:
                if uid in prior_completed:
                    raise FrameworkError("E1_DUPLICATE_PRIOR_COMPLETED_UNIT")
                evidence = ref(c.output / terminals[uid]["path"])
                if evidence["sha256"] != terminals[uid]["sha256"]:
                    raise FrameworkError("E1_PRIOR_TERMINAL_RECEIPT_CHANGED")
                prior_completed[uid] = {"prior_attempt_id": prior_attempt, "terminal_receipt": evidence}
        prior_binding = {"plan": ref(prior_plan_path), "read_recovery": recovered,
                         "completed_units": len(prior_completed), "redispatch": 0}
    attempt = workspace / "attempts" / attempt_id
    attempt.mkdir(parents=True, exist_ok=False)
    stores = attempt / "stores"
    stores.mkdir()
    plan = []
    disposition_rows = []
    version = "sha256:" + ref(Path(__file__))["sha256"]
    matrix_ref = ref(matrix)
    # Existing sorted membership order and original 50-unit shard boundaries.
    for start in range(0, len(ordered), 50):
        batch_id = "shard-%06d" % (start // 50 + 1)
        batch_dir = attempt / "batches" / batch_id
        batch_dir.mkdir(parents=True)
        members = ordered[start:start + 50]
        permitted = []
        for uid in members:
            unit = deepcopy(units[uid])
            permission = rights[uid]
            if uid in prior_completed:
                disposition_rows.append({"UNIT_ID": uid, "BATCH_ID": batch_id,
                    "EXECUTION_ATTEMPTED": False, "SOURCE_STATUS": "PRIOR_ATTEMPT_COMPLETED",
                    "OUTPUT_STATUS": "PRIOR_RESULT_PRESERVED", "PREDICATE_STATUS": "NOT_EVALUATED_THIS_ATTEMPT",
                    "AUDIT_DISPOSITION": "PRIOR_ATTEMPT_COMPLETED", "ERROR_STATUS": None,
                    "RECEIPT_SHA256": prior_completed[uid]["terminal_receipt"]["sha256"],
                    "CHECKPOINT_REFERENCE": None, "prior_evidence": prior_completed[uid]})
                continue
            allowed = permission.get("allowed_source_references", [])
            exact = {"path": unit["source_path"], "sha256": unit["source_sha256"]}
            reason = permission.get("reason", "RIGHTS_UNRESOLVED")
            eligible = permission["processing_status"] == "PROCESSING_PERMITTED" and exact in allowed
            if eligible:
                # Stat/reparse checking reads no source body.
                try:
                    p = _path(unit["source_path"], True)
                    if not p.is_file() or p.stat().st_size > MAX_INPUT:
                        eligible, reason = False, "NOT_ATTEMPTED_UNSAFE_EXECUTION_SOURCE_SIZE_OR_TYPE"
                except (OSError, FrameworkError) as exc:
                    eligible, reason = False, "NOT_ATTEMPTED_SOURCE_UNAVAILABLE_OR_UNSAFE_" + type(exc).__name__
            if not eligible:
                disposition_rows.append({"UNIT_ID": uid, "BATCH_ID": batch_id,
                    "EXECUTION_ATTEMPTED": False, "SOURCE_STATUS": permission["processing_status"],
                    "OUTPUT_STATUS": "NOT_READ", "PREDICATE_STATUS": "NOT_EVALUATED",
                    "AUDIT_DISPOSITION": reason, "ERROR_STATUS": None,
                    "RECEIPT_SHA256": None, "CHECKPOINT_REFERENCE": None})
                continue
            unit.update(adapter_id="pgop1.e1.closed-definition." + unit["benchmark_id"],
                        adapter_version=version, predicate_profile="DEFINITION_ONLY",
                        predicate_contract={"contract_id": "pgop1.modality-a.predicate-applicability.v1",
                                            "version": "1.0.0", "sha256": matrix_ref["sha256"]},
                        authentic_output_references=[], evidence_references=[exact, matrix_ref])
            permitted.append(unit)
        record = {"batch_id": batch_id, "selected_unit_ids": members,
                  "permitted_unit_ids": [u["unit_id"] for u in permitted], "config": None}
        if permitted:
            expected = record["permitted_unit_ids"]
            sources = {u["source_id"]: {"source_id": u["source_id"], "path": u["source_path"],
                        "sha256": u["source_sha256"], "role": "PRIMARY"} for u in permitted}
            norm_id = "normative-e1-predicates"
            sources[norm_id] = {"source_id": norm_id, **matrix_ref, "role": "NORMATIVE_COMPANION"}
            registry = {"families": {u["benchmark_id"]: {"adapter_id": u["adapter_id"],
                "adapter_version": version,
                "versions": sorted({x["benchmark_version"] for x in permitted if x["benchmark_id"] == u["benchmark_id"]})} for u in permitted}}
            write(batch_dir / "DATASET.json", {"units": permitted})
            write(batch_dir / "SOURCES.json", {"schema": "pgop1.source-manifest.v1", "sources": list(sources.values())})
            write(batch_dir / "DEPENDENCIES.json", {"schema": "pgop1.unit-source-dependencies.v1",
                "source_manifest_sha256": ref(batch_dir / "SOURCES.json")["sha256"],
                "expected_units_sha256": digest(canonical(sorted(expected))), "groups": {},
                "units": [{"unit_id": u["unit_id"], "primary_source_id": u["source_id"],
                    "dependency_group_ids": [], "supporting_source_ids": [], "normative_companion_ids": [norm_id]} for u in permitted]})
            write(batch_dir / "ADAPTERS.json", registry)
            write(batch_dir / "SELECTION.json", {"expected_units": expected, "parent_population": ref(population_path),
                "original_shard_members": members, "full_population_not_reduced": True})
            cfg = deepcopy(previous)
            cfg.update(run_id="RUN004-E1-" + batch_id, campaign_id="RUN004-E1", campaign_attempt_id=attempt_id,
                run_purpose="STRESS_TEST_AND_EVIDENCE_GENERATION", code_root=str(code_root), code_files=code_files,
                candidate_commit=commit, candidate_tree=tree, allowlisted_roots=[str(root)], expected_units=expected,
                contract_path=str(Path(contract_path).resolve()), contract_sha256=ref(contract_path)["sha256"],
                contract_version="pgop1.run004.experimental-e1.contract.v1", dataset_manifest_path=str(batch_dir / "DATASET.json"),
                input_manifest_sha256=ref(batch_dir / "DATASET.json")["sha256"],
                input_bindings=[{"path": r["path"], "sha256": r["sha256"]} for r in sources.values()],
                adapter_registry=ref(batch_dir / "ADAPTERS.json"), predicate_contracts=matrix_ref,
                selection_manifest=ref(batch_dir / "SELECTION.json"), exclusion_ledger=ref(exclusions),
                checkpoint_policy={"schema": "pgop1.reusable-run-checkpoint.v2", "interval": 1, "receipt_parent_chain": True},
                resource_budget={"max_units_per_shard": 50, "max_bytes": SHARD_MAX_BYTES, "max_seconds": 28800,
                    "max_units": len(expected), "max_errors": 10096, "max_payload_bytes": 65536},
                execution_modes=["E1_AUTHENTIC_DEFINITION_PROCESSING"], recovery_policy={"mode": "READ_ONLY_NO_RESUME"},
                stop_criteria={"integrity": "STOP", "authority": "STOP", "budget": "STOP", "ordinary_parse_error": "ISOLATE_BATCH"},
                audit_policy={"engineering_mode": "E1", "generic_caller": {"schema": "pgop1.generic-caller-config.v1",
                    "source_manifest": ref(batch_dir / "SOURCES.json"), "dependency_manifest": ref(batch_dir / "DEPENDENCIES.json"),
                    "predicate_validation": "pgop1.predicate-evidence.v1"}})
            write(batch_dir / "CONFIG.json", cfg)
            record["config"] = ref(batch_dir / "CONFIG.json")
        plan.append(record)
    write(attempt / "NO_BODY_DISPOSITIONS.json", {"rows": disposition_rows, "scope": "Planned no-read dispositions; not executed audits or receipts"})
    normative = Path(contract_path).parent / contract.get("normative_text", "RUN_CONTRACT.md")
    write(attempt / "ATTEMPT_PLAN.json", {"attempt_id": attempt_id, "selected_units": 10096,
        "predicate_pairs": 80768, "planned_shards": 202, "batches": plan, "max_bytes": MAX_BYTES,
        "batch_reserved_bytes": BATCH_RESERVE, "shard_max_bytes": SHARD_MAX_BYTES, "writer_max_bytes": WRITER_MAX_BYTES,
        "code_root": str(code_root), "candidate_commit": commit, "candidate_tree": tree,
        "rights": ref(rights_path), "contract": ref(contract_path), "normative_contract": ref(normative), "population": ref(population_path),
        "prior_attempt": prior_binding, "created_utc": datetime.now(timezone.utc).isoformat()})
    freeze_path = workspace / "RUN004_E1_OPERATIONAL_FREEZE.json" if attempt_id == ATTEMPT else attempt / "OPERATIONAL_FREEZE.json"
    write(freeze_path, {"schema": "pgop1.e1.operational-freeze.v1",
        "attempt_id": attempt_id, "plan": ref(attempt / "ATTEMPT_PLAN.json"),
        "bindings": [ref(p) for p in sorted(attempt.rglob("*.json"))],
        "formal_qualification": False, "producer": PRODUCER, "maximum_input_file_bytes": MAX_INPUT,
        "stop_conditions": ["integrity", "unauthorized_operation", "budget", "evidence_loss", "historical_corruption"],
        "source_bodies_read_by_prepare": 0})
    print(attempt, flush=True)


def campaign_for(attempt, row):
    binding = row["config"]
    if ref(binding["path"]) != binding:
        raise FrameworkError("E1_FROZEN_BATCH_CONFIG_MISMATCH")
    cfg = read(binding["path"])
    root = attempt.parents[3]
    stores = attempt / "stores"
    output = stores / cfg["run_id"] / "attempts" / cfg["campaign_attempt_id"]
    return load_config(binding["path"], [root], output, [root], [stores])


def execute(workspace, max_batches=None, recover_only=False, attempt_id=ATTEMPT):
    validate_attempt_id(attempt_id)
    workspace = _path(workspace, True)
    attempt = workspace / "attempts" / attempt_id
    plan = read(attempt / "ATTEMPT_PLAN.json")
    freeze = read(workspace / "RUN004_E1_OPERATIONAL_FREEZE.json" if attempt_id == ATTEMPT else attempt / "OPERATIONAL_FREEZE.json")
    for binding in freeze["bindings"]:
        if ref(binding["path"]) != binding:
            raise FrameworkError("E1_OPERATIONAL_FREEZE_CHANGED")
    for key in ("rights", "contract", "normative_contract", "population"):
        if ref(plan[key]["path"]) != plan[key]:
            raise FrameworkError("E1_FROZEN_AUTHORITY_CHANGED")
    if plan.get("prior_attempt") is not None:
        binding = plan["prior_attempt"]["plan"]
        if ref(binding["path"]) != binding:
            raise FrameworkError("E1_PRIOR_PLAN_CHANGED")
    results = []
    completed_batches = 0
    for row in plan["batches"]:
        if row["config"] is None:
            continue
        batch_dir = Path(row["config"]["path"]).parent
        writer = batch_dir / "WRITER.json"
        if not recover_only and writer.exists():
            continue
        if not recover_only and max_batches is not None and completed_batches >= max_batches:
            break
        # A read-only recovery allocates no batch output and needs no repeated
        # global writer-budget scan. Journal recovery verifies its own artifacts.
        size = 0
        for folder, dirs, files in (() if recover_only else os.walk(workspace / "attempts", followlinks=False)):
            for name in [*dirs, *files]:
                p = _path(Path(folder) / name, True)
                if p.is_file():
                    size += p.stat().st_size
        if not recover_only and size + BATCH_RESERVE > MAX_BYTES:
            raise FrameworkError("E1_SHARED_OUTPUT_BUDGET_EXHAUSTED")
        c = campaign_for(attempt, row)
        if recover_only:
            if not c.output.exists():
                continue
            c.preflight()
            state = c.recover()
            results.append({"batch_id": row["batch_id"], "completed": sorted(state["completed"]),
                "pending": sorted(state["pending"]), "inflight": sorted(state["inflight"]),
                "receipt_count": len(state["receipts"]), "checkpoint_count": len(state["checkpoints"]), "redispatch": 0})
            continue
        if c.output.exists():
            raise FrameworkError("E1_EXISTING_INCOMPLETE_BATCH_IS_READ_ONLY_NO_REDISPATCH")
        started = time.monotonic()
        c.preflight()
        registry = read(c.config["adapter_registry"]["path"])
        caller = GenericCaller(c, {(r["adapter_id"], r["adapter_version"]): process_definition for r in registry["families"].values()},
            lambda unit, adapted: build_audit_payload(unit, adapted), producer_id=PRODUCER)
        operations = []
        for uid in c.config["expected_units"]:
            try:
                receipt = caller.execute(uid)
            except (FrameworkError, ResourceLimitStop, OSError):
                # Admission/integrity/resource failures are material; preserve the
                # journal and stop. They are never disguised as ordinary defects.
                raise
            except Exception as exc:
                state = c.recover()
                start_receipt = next((r for r in reversed(state["receipts"]) if r["unit_id"] == uid), None)
                operations.append({"UNIT_ID": uid, "EXECUTION_ATTEMPTED": True,
                    "SOURCE_STATUS": "PROCESSING_PERMITTED", "OUTPUT_STATUS": "PROCESSOR_ERROR",
                    "PREDICATE_STATUS": "NOT_EVALUATED", "AUDIT_DISPOSITION": "ERROR",
                    "ERROR_STATUS": {"type": type(exc).__name__, "message": str(exc)},
                    "RECEIPT_SHA256": start_receipt["sha256"] if start_receipt else None,
                    "RECEIPT_PHASE": "start" if start_receipt else None,
                    "CHECKPOINT_REFERENCE": str(c.output / "checkpoints"),
                    "recovery_disposition": "INFLIGHT_NO_REDISPATCH"})
                continue
            operations.append({"UNIT_ID": uid, "EXECUTION_ATTEMPTED": True,
                "SOURCE_STATUS": "PROCESSING_PERMITTED", "OUTPUT_STATUS": "MISSING_AUTHENTIC_AGENT_OUTPUT",
                "PREDICATE_STATUS": "NOT_EVALUATED", "AUDIT_DISPOSITION": "NOT_AUDITED_MISSING_AGENT_OUTPUT",
                "ERROR_STATUS": None, "RECEIPT_SHA256": verified_receipt_reference(c, receipt, uid)["sha256"], "CHECKPOINT_REFERENCE": str(c.output / "checkpoints")})
        state = c.recover()
        write_writer(writer, {"schema": "pgop1.run004.e1.batch-result.v1", "batch_id": row["batch_id"],
            "pid": os.getpid(), "operations": operations, "completed_units": sorted(state["completed"]),
            "receipts": state["receipts"], "pending": sorted(state["pending"]), "inflight": sorted(state["inflight"]),
            "checkpoint_count": len(state["checkpoints"]), "resources": c.resources_report(),
            "duration_ms": int((time.monotonic() - started) * 1000), "semantic_audits": 0, "auditor_abstentions": 0})
        print("COMPLETED", row["batch_id"], len(operations), flush=True)
        completed_batches += 1
    if recover_only:
        tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        write(attempt / ("RECOVERY-" + tag + ".json"), {"status": "VERIFIED", "pid": os.getpid(),
            "read_only": True, "redispatch": 0, "batches": results})
        print("RECOVERED", sum(len(x["completed"]) for x in results), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "execute", "recover"])
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--code-root", type=Path)
    parser.add_argument("--rights", type=Path)
    parser.add_argument("--contract", type=Path)
    parser.add_argument("--max-batches", type=int)
    parser.add_argument("--attempt-id", default=ATTEMPT)
    parser.add_argument("--prior-attempt")
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.workspace, args.code_root, args.rights, args.contract, args.attempt_id, args.prior_attempt)
    else:
        execute(args.workspace, args.max_batches, args.mode == "recover", args.attempt_id)


if __name__ == "__main__":
    main()
