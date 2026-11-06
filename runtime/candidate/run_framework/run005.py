"""Bounded E1 output runner over the existing caller, Engine and V2 journal.

Admission is an external, operation-specific decision. This module neither
grants rights nor converts source metadata into producer authentication.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import time

from .core import FrameworkError, canonical, digest, load_config, _write_immutable, _loads
from .caller import GenericCaller, validate_configuration
from .predicates import build_audit_payload
from .provenance import _read_bound_file
from .resources import ResourceGuard, ResourceLimitStop

PRODUCER = "PGOP1-RUN005-E1"
MAX_UNITS = 128
ENGINE_BYTES = 16 * 1024**2
PROFILES = {"BFCL_STRUCTURAL_V2", "BFCL_ARCHIVED_ROW_PAIR_V1", "SWE_ARCHIVED_COMPLETION_V1"}


def adapter_read_references(unit):
    """Enumerate the closed adapter's complete read set without opening bodies."""
    evidence = {r["path"]: r["sha256"] for r in unit.get("evidence_references", [])}
    source = unit.get("predicate_input", {})
    if unit.get("predicate_profile") == "BFCL_STRUCTURAL_V2":
        required = [source.get("path")]
        if evidence.get(source.get("path")) != source.get("sha256"):
            raise FrameworkError("RUN005_ADAPTER_INPUT_NOT_BOUND")
    elif unit.get("predicate_profile") == "BFCL_ARCHIVED_ROW_PAIR_V1":
        refs = [source.get("task"), source.get("response")]
        if (not all(isinstance(ref, dict) and set(ref) == {"path", "sha256"} for ref in refs)
                or any(evidence.get(ref["path"]) != ref["sha256"] for ref in refs)):
            raise FrameworkError("RUN006_ROW_PAIR_INPUT_NOT_BOUND")
        required = [ref["path"] for ref in refs]
    elif unit.get("predicate_profile") == "SWE_ARCHIVED_COMPLETION_V1":
        from runtime.candidate.swebench_claim_audit.adapter import RUN_REPO, INSTANCE_RE
        task = unit.get("task_id")
        if (not isinstance(task, str) or not INSTANCE_RE.fullmatch(task)
                or source.get("task_id") != task or not isinstance(source.get("data_root"), str)):
            raise FrameworkError("RUN005_ADAPTER_INPUT_IDENTITY_INVALID")
        root = Path(source["data_root"])
        relative = ["logs/all_preds.jsonl", "logs/trajs/" + task + ".traj.json",
                    *["logs/logs/" + task + "/" + name for name in ("report.json", "patch.diff", "test_output.txt.gz")],
                    *[(RUN_REPO / name).as_posix() for name in ("per_instance_details.json", "results/results.json", "metadata.yaml", "README.md")]]
        required = [str((root / name).resolve()) for name in relative]
    else:
        raise FrameworkError("RUN005_ADAPTER_PROFILE_UNKNOWN")
    if any(not path or path not in evidence for path in required):
        raise FrameworkError("RUN005_ADAPTER_READ_SET_NOT_BOUND")
    return {(path, evidence[path]) for path in required}


def admission_gate(admission, units, bindings):
    """Check metadata before any selected output body is opened.

    Permission references must already be hash-bound by the caller's config.
    Their substantive authorization is established by the admission review;
    this gate only enforces that reviewed decision and its exact membership.
    """
    rows = admission.get("outputs", [])
    admitted = [r for r in rows if r.get("AUDIT_DISPOSITION") == "ADMITTED_AUTHENTIC_OUTPUT"]
    if not admitted:
        raise FrameworkError("RUN005_NO_ADMISSIBLE_AUTHENTIC_OUTPUTS")
    if not 1 <= len(units) <= MAX_UNITS:
        raise FrameworkError("RUN005_BOUNDED_OUTPUT_SELECTION_REQUIRED")
    by_id = {r.get("OUTPUT_ID"): r for r in admitted}
    if (len(by_id) != len(admitted) or len({u["unit_id"] for u in units}) != len(units)
            or set(by_id) != {u["unit_id"] for u in units}):
        raise FrameworkError("RUN005_ADMISSION_MEMBERSHIP_MISMATCH")
    bound = {(r["path"], r["sha256"]) for r in bindings}
    allowed = {(r["path"], r["sha256"]) for r in admission.get("allowed_read_references", [])}
    # Every configured input can be opened by preflight, independently from
    # whether an adapter needs it. Thus the complete set needs exact grants.
    if not bound <= allowed:
        raise FrameworkError("RUN005_INPUT_READ_PERMISSION_NOT_BOUND")
    for unit in units:
        row = by_id[unit["unit_id"]]
        refs = row.get("permission_references", [])
        if (row.get("processing_status") != "PROCESSING_PERMITTED" or row.get("reserved", True)
                or not refs or any((r["path"], r["sha256"]) not in bound for r in refs)):
            raise FrameworkError("RUN005_PROCESSING_PERMISSION_NOT_BOUND")
        if (unit.get("predicate_profile") not in PROFILES or not unit.get("authentic_output_references")
                or row.get("TASK_ID") != unit.get("task_id")):
            raise FrameworkError("RUN005_OUTPUT_PROFILE_OR_IDENTITY_INVALID")
        outputs = unit["authentic_output_references"]
        if (len(outputs) != 1 or row.get("OUTPUT_SHA256") != outputs[0]["sha256"]
                or (outputs[0]["path"], outputs[0]["sha256"]) not in bound):
            raise FrameworkError("RUN005_AUTHENTIC_OUTPUT_HASH_NOT_BOUND")
        reads = adapter_read_references(unit)
        evidence = {(r["path"], r["sha256"]) for r in unit.get("evidence_references", [])}
        primary = (unit.get("source_path"), unit.get("source_sha256"))
        if not (reads | evidence | {primary}) <= (bound & allowed):
            raise FrameworkError("RUN005_COMPLETE_BODY_READ_PERMISSION_NOT_BOUND")
    return {"admitted_outputs": len(admitted), "rights_granted_by_runner": False}


def source_manifest_read_gate(admission, bindings, policy, roots):
    """Close SourceBindings.verify_all's transitive read set before it runs.

    These two manifests are explicitly granted metadata. Reading their
    declarations does not grant reads of any source bodies they enumerate.
    """
    bound = {(r["path"], r["sha256"]) for r in bindings}
    allowed = {(r["path"], r["sha256"]) for r in admission.get("allowed_read_references", [])}
    documents = {}
    for field in ("source_manifest", "dependency_manifest"):
        ref = policy.get(field, {})
        pair = (ref.get("path"), ref.get("sha256"))
        if pair not in allowed:
            raise FrameworkError("RUN005_SOURCE_METADATA_READ_PERMISSION_NOT_BOUND")
        _, raw = _read_bound_file(pair[0], pair[1], roots, "granted " + field)
        documents[field] = _loads(raw)
    sources = documents["source_manifest"].get("sources", [])
    if (not isinstance(sources, list)
            or any(not isinstance(r, dict) or (r.get("path"), r.get("sha256")) not in (bound & allowed)
                   for r in sources)):
        raise FrameworkError("RUN005_TRANSITIVE_SOURCE_READ_PERMISSION_NOT_BOUND")
    return {"source_manifest_reads_permitted": len(sources)}


def adapter(unit, references):
    supplied = {(r["path"], r["sha256"]) for r in references.get("all", [])}
    if not adapter_read_references(unit) <= supplied:
        raise FrameworkError("RUN005_ADAPTER_READ_PERMISSION_NOT_BOUND")
    if unit["predicate_profile"] == "SWE_ARCHIVED_COMPLETION_V1":
        from runtime.candidate.swebench_claim_audit.adapter import audit_instance
        return audit_instance(unit["predicate_input"]["data_root"], unit["task_id"])
    if unit["predicate_profile"] == "BFCL_ARCHIVED_ROW_PAIR_V1":
        from .run006 import bfcl_row_adapter
        return bfcl_row_adapter(unit, references)
    from runtime.candidate.bfcl_structured_audit_v2 import audit
    source = unit["predicate_input"]
    records = json.loads(Path(source["path"]).read_text(encoding="utf-8-sig"))
    matches = [r for r in records if r.get("task_id") == unit["task_id"]]
    if len(matches) != 1:
        raise FrameworkError("RUN005_BFCL_OUTPUT_IDENTITY_AMBIGUOUS")
    return audit(matches[0]["task"], matches[0]["response"])


def _serial(value):
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {k: _serial(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_serial(v) for v in value]
    return value


def record_engine_result(engine, guard, unit, result, run_id, *, producer_id=PRODUCER,
                         event_kind="RUN005_AUDIT_RESULT"):
    """Persist an own-result observation without changing the auditor payload."""
    path = engine.root / (digest(canonical(unit["unit_id"])) + ".json")
    payload = canonical(result)
    guard.refresh_usage()
    if len(payload) > 65536:
        raise FrameworkError("RUN005_ENGINE_RESULT_SIZE_LIMIT")
    guard.before_publication(2 * 1024**2)
    _write_immutable(path, payload)
    source = engine.admit_source(path, digest(payload), scope="ENGINEERING_RESULT", source_id=unit["unit_id"])
    manifest = engine.ingest([{"id": unit["unit_id"], "task_id": unit["task_id"],
        "run_id": run_id, "kind": event_kind, "source_id": source["source_id"],
        "evidence_pointer": ""}], provenance={"declared_actor_identity": producer_id})
    guard.finish_publication()
    guard.refresh_usage()
    return {"unit_id": unit["unit_id"], "source_sha256": source["sha256"], "manifest": manifest}


def run(args, *, adapter_overrides=None, producer_id=PRODUCER,
        engine_event_kind="RUN005_AUDIT_RESULT", _run006_context=None):
    # The legacy CLI remains a RUN005 entrypoint. RUN006 must arrive through
    # its own rights, Owner-authorization, and freeze dispatcher first.
    try:
        runner_config_raw = Path(args.config).read_bytes()
        runner_config_header = _loads(runner_config_raw)
    except (OSError, TypeError) as exc:
        raise FrameworkError("RUNNER_CONFIGURATION_UNAVAILABLE") from exc
    run_id = runner_config_header.get("run_id") if isinstance(runner_config_header, dict) else None
    run006_run_id = isinstance(run_id, str) and run_id.upper().startswith("RUN006")
    if run006_run_id:
        from .run006 import _ValidatedDispatchContext
        if (not isinstance(_run006_context, _ValidatedDispatchContext)
                or _run006_context.config_sha256 != digest(runner_config_raw)
                or _run006_context.campaign_attempt_id != runner_config_header.get("campaign_attempt_id")
                or _run006_context.run_id != run_id
                or _run006_context.candidate_commit != runner_config_header.get("candidate_commit")
                or _run006_context.candidate_tree != runner_config_header.get("candidate_tree")):
            raise FrameworkError("RUN006_REQUIRES_DISABLED_AND_OWNER_AUTHORIZED_DISPATCH")
    elif _run006_context is not None:
        raise FrameworkError("RUN006_CONTEXT_ON_NON_RUN006_CONFIG")
    campaign = load_config(args.config, args.config_root, args.output,
                           args.trusted_root, args.output_root)
    cfg = campaign.config
    if not run006_run_id:
        # Read only the already hash-bound dataset metadata to prevent a
        # profile rename from exposing the RUN006 row adapter through RUN005.
        _, dataset_header = _read_bound_file(cfg["dataset_manifest_path"], cfg["input_manifest_sha256"],
                                             [Path(root) for root in cfg["allowlisted_roots"]],
                                             "dataset metadata")
        dataset_index = _loads(dataset_header)
        if (isinstance(dataset_index, dict) and isinstance(dataset_index.get("units"), list)
                and any(isinstance(unit, dict)
                        and unit.get("predicate_profile") == "BFCL_ARCHIVED_ROW_PAIR_V1"
                        for unit in dataset_index["units"])):
            raise FrameworkError("RUN006_ROW_PROFILE_REQUIRES_DISABLED_AND_OWNER_AUTHORIZED_DISPATCH")
    # Loading config reads metadata only. Do not call preflight (which rehashes
    # selected bodies) until the admission review has passed.
    admission_path = str(Path(args.admission).resolve(strict=True))
    bound = {r["path"]: r["sha256"] for r in cfg["input_bindings"]}
    if admission_path not in bound:
        raise FrameworkError("RUN005_ADMISSION_NOT_FROZEN")
    roots = [Path(r) for r in cfg["allowlisted_roots"]]
    _, raw = _read_bound_file(admission_path, bound[admission_path], roots, "admission metadata")
    _, dataset = _read_bound_file(cfg["dataset_manifest_path"], cfg["input_manifest_sha256"], roots, "selection metadata")
    # This exact admission metadata file is an explicit CLI input already read
    # under its frozen config hash. It cannot contain its own hash recursively.
    body_bindings = [r for r in cfg["input_bindings"] if r["path"] != admission_path]
    admission = _loads(raw)
    gate = admission_gate(admission, _loads(dataset)["units"], body_bindings)
    source_manifest_read_gate(admission, body_bindings,
                             cfg["audit_policy"].get("generic_caller", {}), roots)
    if cfg["checkpoint_policy"].get("schema") != "pgop1.reusable-run-checkpoint.v2":
        raise FrameworkError("RUN005_CHECKPOINT_V2_REQUIRED")
    campaign.preflight()
    validate_configuration(campaign)
    if args.action == "prepare":
        return {"status": "PREPARED_NOT_EXECUTED", "admission": gate, "source_bodies_copied": 0}
    if args.action == "recover":
        state = campaign.recover()
        return {"status": "RECOVERED_READ_ONLY", "pid": os.getpid(), "redispatch": 0,
                "state": _serial(state)}
    if campaign.output.exists():
        raise FrameworkError("RUN005_EXISTING_ATTEMPT_NO_REDISPATCH")
    if cfg["resource_budget"].get("max_bytes", 20 * 1024**3) > 20 * 1024**3 - ENGINE_BYTES:
        raise FrameworkError("RUN005_ENGINE_BUDGET_RESERVE_REQUIRED")
    from runtime.candidate.context_engine import Engine
    engine_root = campaign.output.parent / (cfg["campaign_attempt_id"] + "-context")
    if engine_root.exists():
        raise FrameworkError("RUN005_EXISTING_ENGINE_ATTEMPT_NO_REDISPATCH")
    engine = Engine(engine_root)
    guard = ResourceGuard(engine_root, max_bytes=ENGINE_BYTES)
    engine_events = []

    def auditor(unit, adapted):
        result = build_audit_payload(unit, adapted)
        # Store own result, not a second copy of original agent output. This
        # occurs after the auditor and before terminal receipt/checkpoint.
        engine_events.append(record_engine_result(engine, guard, unit, result, cfg["run_id"],
            producer_id=producer_id, event_kind=engine_event_kind))
        return result

    units = json.loads(dataset)["units"]
    adapters = {(u["adapter_id"], u["adapter_version"]): adapter for u in units}
    if any(u.get("predicate_profile") == "BFCL_ARCHIVED_ROW_PAIR_V1" for u in units):
        from .run006 import bfcl_row_adapter
        row_roots = [Path(r) for r in cfg["allowlisted_roots"]]
        for unit in units:
            if unit.get("predicate_profile") == "BFCL_ARCHIVED_ROW_PAIR_V1":
                key = (unit["adapter_id"], unit["adapter_version"])
                adapters[key] = lambda row, refs, roots=row_roots: bfcl_row_adapter(row, refs, roots)
    if adapter_overrides:
        if any(not isinstance(key, tuple) or len(key) != 2 or not callable(value)
               for key, value in adapter_overrides.items()):
            raise FrameworkError("RUN005_ADAPTER_OVERRIDE_INVALID")
        adapters.update(adapter_overrides)
    caller = GenericCaller(campaign, adapters, auditor, producer_id=producer_id)
    operations = []
    started = time.monotonic()
    for unit in units:
        try:
            receipt = caller.execute(unit["unit_id"])
            from .e1 import verified_receipt_reference
            ref = verified_receipt_reference(campaign, receipt, unit["unit_id"])
            operations.append({"unit_id": unit["unit_id"], "terminal_receipt": ref, "error": None})
        except (FrameworkError, ResourceLimitStop, OSError):
            raise  # material failures stop, preserving journal/Engine bytes
        except Exception as exc:
            operations.append({"unit_id": unit["unit_id"], "terminal_receipt": None,
                               "error": {"type": type(exc).__name__, "message": str(exc)}})
    state = campaign.recover()
    return {"pid": os.getpid(), "operations": operations, "state": _serial(state),
            "engine_events": engine_events, "engine_verify": engine.verify(),
            "duration_seconds": time.monotonic() - started, "resources": campaign.resources_report(),
            "engine_scope": "Own auditor result provenance before terminal checkpoint; no upstream producer authentication"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "execute", "recover"))
    for name in ("config", "admission", "output"):
        parser.add_argument("--" + name, required=True)
    for name in ("config-root", "trusted-root", "output-root"):
        parser.add_argument("--" + name, action="append", required=True)
    args = parser.parse_args()
    print(json.dumps(_serial(run(args)), sort_keys=True, ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
