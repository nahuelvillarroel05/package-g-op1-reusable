"""Bind completed campaign units and their original bytes in bounded PGOP1 stores."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

from .adapter import AuditError, _checked_root, _reparse, _safe_path
from .campaign import MIN_FREE_BYTES, _append, _digest, _raw, _write_new
from .generalized_bridge import bind_generalized_audit, recover_generalized_audit


def bind_campaign(data_root, plan, campaign_root, context_parent, *, min_free_bytes=MIN_FREE_BYTES):
    root = _checked_root(data_root)
    completed_root = _checked_root(campaign_root)
    binding = json.loads((completed_root / "binding.json").read_text(encoding="utf-8"))
    if binding["plan_sha256"] != hashlib.sha256(_raw(plan)).hexdigest():
        raise AuditError("CONTEXT_CAMPAIGN_PLAN", "campaign and context plans differ")
    repo = Path(__file__).resolve().parents[3]
    for name, expected in plan.get("code_sha256", {}).items():
        if _digest(_safe_path(repo, name)) != expected:
            raise AuditError("CONTEXT_CAMPAIGN_CODE", "code differs from frozen campaign")
    parent = Path(context_parent).absolute()
    if parent == root or not (root in parent.parents):
        raise AuditError("CONTEXT_CAMPAIGN_OUTPUT", "context parent must be in the frozen output exclusion")
    relative = parent.relative_to(root).as_posix()
    if not any(relative == p or relative.startswith(p + "/") for p in plan.get("excluded_output_subtrees", [])):
        raise AuditError("CONTEXT_CAMPAIGN_OUTPUT", "context parent is outside the output exclusion")
    cursor = Path(parent.anchor)
    for part in parent.parts[1:]:
        cursor /= part
        if part in {".", ".."} or _reparse(cursor):
            raise AuditError("CONTEXT_CAMPAIGN_OUTPUT", "context parent contains an unsafe alias")
    parent.mkdir(parents=True, exist_ok=True)
    _checked_root(parent)
    events = [json.loads(line) for line in (completed_root / "attempts.jsonl").read_bytes().splitlines()]
    done = [e for e in events if e["event"] == "COMPLETE"]
    expected_units = {"file-" + str(i) for i in range(len(plan["sources"]))}
    expected_units |= {"audit-" + str(i) for i in range(len(plan["requests"]))}
    if len(done) != len(expected_units) or {e["unit"] for e in done} != expected_units:
        raise AuditError("CONTEXT_CAMPAIGN_INCOMPLETE", "all plan units must have exactly one completion")

    batches, refs, observations, size = [], {}, [], 0
    for event in done:
        result_path = _safe_path(completed_root, event["result_path"])
        if _digest(result_path) != event["sha256"]:
            raise AuditError("CONTEXT_CAMPAIGN_RESULT", "completed output differs from its commitment")
        result = json.loads(result_path.read_bytes())
        kind, number = event["unit"].split("-")
        member_refs = ([plan["sources"][int(number)]] if kind == "file" else
                       plan["requests"][int(number)]["evidence"])
        original_refs = {r["path"]: r for r in member_refs}
        derived = {"path": result_path.relative_to(root).as_posix(), "sha256": event["sha256"],
                   "bytes": result_path.stat().st_size, "role": "ADAPTER_RESULT",
                   "parser_id": result.get("schema", "pgop1.campaign.error.v1"), "parser_version": "1.0.0"}
        original_refs[derived["path"]] = derived
        value_size = len(_raw(result))
        if observations and (len(set(refs) | set(original_refs)) > 56 or size + value_size > 2 * 1024 * 1024):
            batches.append((refs, observations))
            refs, observations, size = {}, [], 0
        if value_size > 3 * 1024 * 1024:
            # Exact full result bytes still enter the Engine; the graph holds a
            # bounded digest descriptor instead of repeating a huge value.
            result = {"status": result.get("status"), "AUDIT_VERDICT": result.get("AUDIT_VERDICT"),
                      "full_result_source": derived, "value_in_graph": "HASH_BOUND_SOURCE_OBJECT"}
            value_size = len(_raw(result))
        refs.update(original_refs)
        observations.append({"observation_id": "unit-" + hashlib.sha256(event["unit"].encode()).hexdigest(),
                             "kind": "adapter_file_result" if kind == "file" else "adapter_claim_audit",
                             "predicate": "ADAPTER_OUTPUT_RECORDED", "value": result,
                             "run_id": "PGOP1_RUN_001", "instance_id": "UNKNOWN",
                             "source_ref": {"path": derived["path"], "sha256": derived["sha256"], "pointer": ""}})
        size += value_size
    if observations:
        batches.append((refs, observations))
    summary = {"schema": "pgop1.run001.context-coverage.v1", "campaign_id": "PGOP1_RUN_001",
               "code_commit": plan["code_commit"], "plan_sha256": binding["plan_sha256"],
               "units": len(done), "batches": len(batches), "bound_units": 0, "recovered_units": 0,
               "semantic_checks": "ADAPTER_OWNED", "provider_dispatch": "NOT_PERFORMED", "results": []}
    batch_events = []
    if (parent / "attempts.jsonl").exists():
        batch_events = [json.loads(line) for line in (parent / "attempts.jsonl").read_bytes().splitlines()]
    terminals = [e for e in batch_events if e["event"] == "COMPLETE"]
    if len({e["batch"] for e in terminals}) != len(terminals):
        raise AuditError("CONTEXT_DUPLICATE_COMPLETION", "duplicate completed context batch")
    committed_receipts = {e["batch"]: e for e in terminals}
    for number, (batch_refs, batch_observations) in enumerate(batches):
        if shutil.disk_usage(parent).free < min_free_bytes:
            raise AuditError("CONTEXT_DISK_RESERVE", "free storage reserve reached")
        payload = {"schema": "pgop1.swebench.generalized-audit.v1", "result_scope": "BATCH_AGGREGATE",
                   "batch_id": "batch-" + str(number), "run_id": "PGOP1_RUN_001",
                   "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE",
                   "reason_codes": ["STORAGE_AGGREGATE_NOT_A_SEMANTIC_VERDICT"],
                   "SOURCE_PROVENANCE": {"evidence_references": list(batch_refs.values())},
                   "EXECUTION_EVIDENCE": [], "observations": batch_observations}
        audit_hash = hashlib.sha256(_raw(payload)).hexdigest()
        context = parent / ("batch-" + str(number) + "-" + audit_hash[:16])
        if context.exists():
            capsule_path = _safe_path(context, "normalized-audit-capsule.json")
            capsule = json.loads(capsule_path.read_bytes())
            if hashlib.sha256(_raw(capsule["audit_result"])).hexdigest() != audit_hash:
                raise AuditError("CONTEXT_BATCH_CHANGED", "existing batch has different normalized data")
            recovery = recover_generalized_audit(context)
            bound = "RECOVERED_EXISTING"
        else:
            _append(parent / "attempts.jsonl", {"event": "START", "batch": number, "audit_sha256": audit_hash})
            bound = bind_generalized_audit(payload, root, context)
            recovery = recover_generalized_audit(context)
        if recovery["status"] != "PASS":
            raise AuditError("CONTEXT_RECOVERY_FAILED", "recorded batch could not be recovered")
        receipt = {"batch": number, "units": len(batch_observations), "audit_sha256": audit_hash,
                   "context_directory": context.name, "binding": bound, "recovery": recovery}
        receipt_path = parent / ("batch-" + str(number) + "-result.json")
        prior = committed_receipts.get(number)
        if receipt_path.exists():
            saved = json.loads(receipt_path.read_bytes())
            if (any(saved.get(k) != receipt[k] for k in ("batch", "units", "audit_sha256", "context_directory"))
                    or saved.get("recovery") != recovery):
                raise AuditError("CONTEXT_RECEIPT_CHANGED", "saved batch receipt differs from verified batch")
            if prior is not None and (prior.get("audit_sha256") != audit_hash
                                      or prior.get("receipt_sha256") != _digest(receipt_path)):
                raise AuditError("CONTEXT_RECEIPT_CHANGED", "saved batch receipt differs from completed commitment")
            if prior is None:
                _append(parent / "attempts.jsonl", {"event": "COMPLETE", "batch": number,
                                                    "audit_sha256": audit_hash,
                                                    "receipt_sha256": _digest(receipt_path),
                                                    "recovery": "VERIFIED_RECEIPT_AFTER_INTERRUPTED_JOURNAL"})
        else:
            if prior is not None:
                raise AuditError("CONTEXT_RECEIPT_MISSING", "completed batch receipt is missing")
            _write_new(receipt_path, receipt)
            _append(parent / "attempts.jsonl", {"event": "COMPLETE", "batch": number,
                                                "audit_sha256": audit_hash, "receipt_sha256": _digest(receipt_path)})
        summary["bound_units"] += len(batch_observations)
        summary["recovered_units"] += len(batch_observations)
        summary["results"].append({"batch": number, "units": len(batch_observations),
                                   "receipt": receipt_path.name, "sha256": _digest(receipt_path)})
    summary["status"] = "PASS" if summary["bound_units"] == len(done) else "NOT_PROVEN"
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data-root", required=True)
    p.add_argument("--plan", required=True)
    p.add_argument("--campaign-root", required=True)
    p.add_argument("--context-parent", required=True)
    a = p.parse_args()
    plan = json.loads(Path(a.plan).read_text(encoding="utf-8"))
    result = bind_campaign(a.data_root, plan, a.campaign_root, a.context_parent)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
