"""Build an explicit plan for the inventoried local SWE-bench archive layout.

This discovery profile is versioned separately from the generic parsers. It
associates only the local logs collection; it never joins an experiment entry
to that collection merely because their instance IDs match.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .adapter import AuditError, INSTANCE_RE, MAX_JSONL_BYTES, _checked_root, _json, _read_bytes
from .campaign import SCHEMA


PREFIX = "pgop1.swebench."
LOCAL_RUN = "LOCAL_ARCHIVE_LOGS_COLLECTION"


def classify(path):
    parts = path.split("/")
    name = parts[-1]
    run = "UNKNOWN"
    instance = "UNKNOWN"
    role, parser = "AUXILIARY", "unsupported.v1"
    if path == "logs/all_preds.jsonl":
        return "PREDICTION", PREFIX + "prediction.miniswe_jsonl.v1", LOCAL_RUN, instance
    if path.startswith("logs/trajs/") and name.endswith(".traj.json"):
        return "AGENT_TRAJECTORY", PREFIX + "trajectory.miniswe_json.v1", LOCAL_RUN, name[:-10]
    if len(parts) == 4 and parts[:2] == ["logs", "logs"]:
        run, instance = LOCAL_RUN, parts[2]
        if name == "report.json":
            role, parser = "EVALUATOR_REPORT", "evaluator_report.resolved_map_json.v1"
        elif name.endswith(".diff"):
            role, parser = "PATCH_ARTIFACT", "patch.unified_diff.v1"
        elif name.endswith(".txt.gz"):
            role, parser = "EXECUTION_LOG", "log.gzip_text_unattributed.v1"
        elif name.endswith(".txt"):
            role, parser = "EXECUTION_LOG", "log.text_unattributed.v1"
    elif path.startswith("experiments-main/evaluation/") and len(parts) >= 5:
        # One submission identifier can appear in multiple dataset partitions.
        # Preserve partition membership in the source path, not another run ID.
        run = "submission-" + hashlib.sha256(parts[3].encode("utf-8")).hexdigest()[:32]
        if name == "per_instance_details.json":
            role, parser = "EVALUATOR_CATALOG", "catalog.per_instance_details_json.v1"
        elif path.endswith("/results/results.json"):
            role, parser = "EVALUATOR_SUMMARY", "results.resolved_list_json.v1"
        elif name in {"metadata.yaml", "metadata.yml"}:
            role, parser = "RUN_METADATA", "metadata.yaml.v1"
        elif "chat-transcripts" in parts:
            role, parser = "AGENT_TRAJECTORY", "trajectory.aider_markdown.unsupported.v1"
            instance = Path(name).stem
        elif name.endswith(".json"):
            role = "EVALUATOR_AUXILIARY"
        elif name.endswith(".md"):
            role = "RUN_DOCUMENTATION"
    elif (len(parts) == 3 and parts[0] in {"full", "lite", "verified", "multilingual"}
          and parts[1] == "data" and name.endswith(".parquet")):
        role, parser = "DATASET_INDEX", "dataset.parquet.external_identity_index.v1"
    return role, PREFIX + parser, run, instance


def build_plan(data_root, inventory, *, code_commit, code_sha256):
    root = _checked_root(data_root)
    rows = inventory["files"]
    sources, disposition, local = [], [], {}
    pred_ids = set()
    for row in rows:
        path = row["relative_path"]
        role, parser, run, iid = classify(path)
        relevant = (path.startswith("logs/") or
                    (path.startswith("experiments-main/evaluation/") and
                     Path(path).suffix.lower() in {".json", ".jsonl", ".yaml", ".yml", ".md", ".txt", ".gz", ".diff"}) or
                    role == "DATASET_INDEX")
        disposition.append({"source_id": row["source_id"], "relevant": relevant,
                            "role": role if relevant else row["evidence_role"],
                            "reason": "PROCESS_OR_EXPLICIT_UNSUPPORTED" if relevant else "REFERENCE_OR_AUXILIARY_NOT_EVALUATION_INPUT"})
        if not relevant:
            continue
        ref = {"source_id": row["source_id"], "path": path, "sha256": row["sha256"],
               "bytes": row["size_bytes"], "role": role, "parser_id": parser,
               "run_id": run}
        if iid != "UNKNOWN":
            ref["instance_id"] = iid
        sources.append(ref)
        if run == LOCAL_RUN and iid != "UNKNOWN":
            local.setdefault(iid, []).append(ref)
        if path == "logs/all_preds.jsonl":
            raw, measured = _read_bytes(root, path, MAX_JSONL_BYTES)
            if measured["bytes"] != ref["bytes"] or measured["sha256"] != ref["sha256"]:
                raise AuditError("PLAN_SOURCE_CHANGED", "prediction index differs from inventory")
            for line in raw.splitlines():
                if line.strip():
                    value = _json(line, "prediction identity index")
                    if not isinstance(value, dict):
                        raise AuditError("PLAN_PREDICTION_ID", "prediction row must be an object")
                    identifier = value.get("instance_id")
                    if not isinstance(identifier, str) or not INSTANCE_RE.fullmatch(identifier) or identifier in pred_ids:
                        raise AuditError("PLAN_PREDICTION_ID", "invalid or duplicate prediction ID")
                    pred_ids.add(identifier)
    prediction = next((s for s in sources if s["path"] == "logs/all_preds.jsonl"), None)
    requests = []
    for iid in sorted(set(local) | pred_ids):
        refs = list(local.get(iid, []))
        if prediction is not None and iid in pred_ids:
            refs.append(prediction)
        requests.append({"run_id": LOCAL_RUN, "instance_id": iid, "evidence": refs})
    return {"schema": SCHEMA, "campaign_id": "PGOP1_RUN_001", "discovery_profile": "local-archive-layout.v1",
            "code_commit": code_commit, "code_sha256": code_sha256,
            "excluded_output_subtrees": ["Engineering/PGOP1_RUN_001"],
            "sources": sources, "requests": requests, "inventory_disposition": disposition,
            "join_limit": "Local archive collection only; experiment submission association UNKNOWN; no cross-submission joins"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data-root", required=True)
    p.add_argument("--inventory", required=True)
    p.add_argument("--code-freeze", required=True)
    p.add_argument("--output", required=True)
    a = p.parse_args()
    inventory = json.loads(Path(a.inventory).read_text(encoding="utf-8"))
    freeze = json.loads(Path(a.code_freeze).read_text(encoding="utf-8"))
    plan = build_plan(a.data_root, inventory, code_commit=freeze["commit"], code_sha256=freeze["code_sha256"])
    with Path(a.output).open("x", encoding="utf-8") as stream:
        json.dump(plan, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({"sources": len(plan["sources"]), "requests": len(plan["requests"])}))


if __name__ == "__main__":
    main()
