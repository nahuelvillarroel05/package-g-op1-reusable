"""Independent READ-ONLY candidate probes; all synthetic data stay in audit/."""
import hashlib
import json
from pathlib import Path
import sys
import pytest

REPO = Path(r"D:\PGOP1_DATA\SWEbench\Engineering\PGOP1_RUN_001\repo")
sys.path.insert(0, str(REPO))
from runtime.candidate.swebench_claim_audit.generalized import audit_evidence, audit_file

PREFIX = "pgop1.swebench."
IID = "synthetic__repo-1"
RUN = "synthetic-audit-a"

def write(root, path, value, role, parser):
    raw = json.dumps(value).encode() if not isinstance(value, bytes) else value
    p = root / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(raw)
    return {"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "role": role, "parser_id": PREFIX + parser, "run_id": RUN}

def fixture(root, text="I resolved the issue."):
    root.mkdir(parents=True, exist_ok=True)
    t = write(root, "trajectory.json", {"instance_id": IID, "messages": [{"role": "assistant", "content": text}]},
              "AGENT_TRAJECTORY", "trajectory.miniswe_json.v1")
    r = write(root, "report.json", {IID: {"resolved": True}}, "EVALUATOR_REPORT", "evaluator_report.resolved_map_json.v1")
    return t, r

def test_simple_task_resolution_still_supported(tmp_path):
    t, r = fixture(tmp_path, "I resolved the task.")
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": IID, "evidence": [t, r]})
    assert result["AUDIT_VERDICT"] == "SUPPORTED", result

def test_duplicate_descriptor_has_no_duplicate_normalized_identifiers(tmp_path):
    t, r = fixture(tmp_path)
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": IID, "evidence": [t, t, r]})
    ids = [o["observation_id"] for o in result["observations"]]
    assert len(ids) == len(set(ids)), result

def test_duplicate_windows_case_alias_is_rejected(tmp_path):
    t, r = fixture(tmp_path, "I resolved the task.")
    alias = {**t, "path": "TRAJECTORY.JSON"}
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": IID, "evidence": [t, alias, r]})
    assert result["AUDIT_VERDICT"] == "INTEGRITY_FAILURE", result

def test_windows_alternate_stream_is_rejected(tmp_path):
    (tmp_path / "container.txt").write_bytes(b"ordinary visible file")
    d = write(tmp_path, "container.txt:hidden", b"unlisted alternate stream", "EXECUTION_LOG", "log.text_unattributed.v1")
    result = audit_file(tmp_path, d)
    assert result["status"] == "ERROR", result

def test_windows_trailing_dot_alias_is_rejected(tmp_path):
    d = write(tmp_path, "visible.txt", b"same physical file", "EXECUTION_LOG", "log.text_unattributed.v1")
    d["path"] = "visible.txt."
    result = audit_file(tmp_path, d)
    assert result["status"] == "ERROR", result

def test_direct_bridge_rejects_alternate_stream_source(tmp_path):
    from runtime.candidate.swebench_claim_audit.generalized_bridge import bind_generalized_audit
    data = tmp_path / "data"
    data.mkdir()
    (data / "container.txt").write_bytes(b"ordinary visible file")
    source = write(data, "container.txt:hidden", b"unlisted alternate stream", "EXECUTION_LOG", "log.text_unattributed.v1")
    audit = {"schema": "pgop1.swebench.generalized-audit.v1", "run_id": RUN, "instance_id": IID,
             "AUDIT_VERDICT": "INSUFFICIENT_EVIDENCE", "observations": [], "EXECUTION_EVIDENCE": [],
             "SOURCE_PROVENANCE": {"evidence_references": [source]}}
    try:
        bound = bind_generalized_audit(audit, data, tmp_path / "context")
    except ValueError:
        return
    assert bound["context_engine"]["status"] != "PASS", bound

def test_scoped_resolution_does_not_claim_whole_task(tmp_path):
    t, r = fixture(tmp_path, "I fixed the bug in the logging helper. The original task remains unresolved.")
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": IID, "evidence": [t, r]})
    assert result["AUDIT_VERDICT"] != "SUPPORTED", result

def test_cross_message_retraction_does_not_keep_positive_claim(tmp_path):
    t, r = fixture(tmp_path)
    t = write(tmp_path, "trajectory.json", {"instance_id": IID, "messages": [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "Correction: the task remains unresolved."}]},
        "AGENT_TRAJECTORY", "trajectory.miniswe_json.v1")
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": IID, "evidence": [t, r]})
    assert result["AUDIT_VERDICT"] != "SUPPORTED", result

@pytest.mark.parametrize("text", [
    "I never claimed that I resolved the task.",
    "I didn't say that I resolved the task.",
    "I resolved the task description formatting.",
    "I resolved the task's logging subproblem.",
])
def test_negated_or_scoped_task_phrase_is_not_benchmark_claim(tmp_path, text):
    t, r = fixture(tmp_path, text)
    result = audit_evidence(tmp_path, {"run_id": RUN, "instance_id": IID, "evidence": [t, r]})
    assert result["AUDIT_VERDICT"] != "SUPPORTED", result

def test_recovery_rejects_receipt_identity_tampering(tmp_path):
    from runtime.candidate.context_engine import canonical_json
    from runtime.candidate.swebench_claim_audit.generalized_bridge import bind_generalized_audit, recover_generalized_audit
    data = tmp_path / "data"
    t, r = fixture(data)
    result = audit_evidence(data, {"run_id": RUN, "instance_id": IID, "evidence": [t, r]})
    context = tmp_path / "context"
    bind_generalized_audit(result, data, context)
    p = context / "generalized-bridge-receipt.json"
    receipt = json.loads(p.read_bytes())
    receipt["identity"] = "another__repo-99"
    p.write_bytes(canonical_json(receipt))
    try:
        recovered = recover_generalized_audit(context)
    except ValueError:
        return
    assert recovered["status"] != "PASS", recovered

def test_campaign_context_recovery_rejects_changed_batch_receipt(tmp_path):
    from runtime.candidate.swebench_claim_audit.campaign import run_campaign
    from runtime.candidate.swebench_claim_audit.bind_campaign import bind_campaign
    root = tmp_path / "data"
    root.mkdir()
    source = write(root, "run.log", b"ordinary synthetic log", "EXECUTION_LOG", "log.text_unattributed.v1")
    source["source_id"] = "source-log"
    plan = {"schema": "pgop1.swebench.campaign-plan.v1", "campaign_id": "PGOP1_RUN_001",
            "code_commit": "SYNTHETIC", "code_sha256": {}, "sources": [source], "requests": [],
            "excluded_output_subtrees": ["engineering"]}
    campaign = root / "engineering" / "campaign"
    contexts = root / "engineering" / "contexts"
    run_campaign(root, plan, campaign, development=True, min_free_bytes=0)
    bind_campaign(root, plan, campaign, contexts, min_free_bytes=0)
    receipt = contexts / "batch-0-result.json"
    receipt.write_bytes(b'{"tampered":"wrong batch receipt"}')
    try:
        recovered = bind_campaign(root, plan, campaign, contexts, min_free_bytes=0)
    except ValueError:
        return
    assert recovered["status"] != "PASS", recovered
