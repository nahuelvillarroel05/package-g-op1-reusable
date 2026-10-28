"""Durable recovery must reject changed source, result, plan and writer state."""
import hashlib
import json

import pytest

from runtime.candidate.swebench_claim_audit.adapter import AuditError
from runtime.candidate.swebench_claim_audit.campaign import run_campaign as _run_campaign


def run_campaign(*args, **kwargs):
    # All campaign fixtures are explicitly unfrozen synthetic development data.
    return _run_campaign(*args, development=True, **kwargs)


def fixture(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    raw = b"Unattributed execution text, not an assistant claim.\n"
    (root / "output.txt").write_bytes(raw)
    source = {"source_id": "source-a", "path": "output.txt",
              "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
              "role": "EXECUTION_LOG", "parser_id": "pgop1.swebench.log.text_unattributed.v1"}
    plan = {"schema": "pgop1.swebench.campaign-plan.v1", "campaign_id": "PGOP1_RUN_001",
            "sources": [source], "requests": [], "code_commit": "SYNTHETIC"}
    return root, plan, tmp_path / "campaign"


def test_resume_keeps_completed_bytes_and_does_not_duplicate_units(tmp_path):
    root, plan, out = fixture(tmp_path)
    first = run_campaign(root, plan, out, min_free_bytes=0)
    results = list(out.glob("file-*.json"))
    original = results[0].read_bytes()
    second = run_campaign(root, plan, out, resume=True, min_free_bytes=0)
    assert first["executed"] == 1
    assert second["executed"] == 0 and second["recovered"] == 1
    assert results[0].read_bytes() == original
    events = [json.loads(line) for line in (out / "attempts.jsonl").read_text().splitlines()]
    assert sum(e["event"] == "COMPLETE" for e in events) == 1


def test_resume_blocks_changed_input_instead_of_restarting(tmp_path):
    root, plan, out = fixture(tmp_path)
    run_campaign(root, plan, out, min_free_bytes=0)
    (root / "output.txt").write_bytes(b"different")
    with pytest.raises(AuditError, match="source differs"):
        run_campaign(root, plan, out, resume=True, min_free_bytes=0)


def test_resume_blocks_corrupt_completed_result(tmp_path):
    root, plan, out = fixture(tmp_path)
    run_campaign(root, plan, out, min_free_bytes=0)
    next(out.glob("file-*.json")).write_bytes(b"{}")
    with pytest.raises(AuditError, match="completed result hash differs"):
        run_campaign(root, plan, out, resume=True, min_free_bytes=0)


def test_resume_blocks_plan_change(tmp_path):
    root, plan, out = fixture(tmp_path)
    run_campaign(root, plan, out, min_free_bytes=0)
    plan["code_commit"] = "OTHER"
    with pytest.raises(AuditError, match="different binding"):
        run_campaign(root, plan, out, resume=True, min_free_bytes=0)


def test_duplicate_execution_keys_and_source_path_aliases_rejected(tmp_path):
    root, plan, out = fixture(tmp_path)
    plan["requests"] = [{"run_id": "a", "instance_id": "b"}] * 2
    with pytest.raises(AuditError) as exc:
        run_campaign(root, plan, out, min_free_bytes=0)
    assert exc.value.code == "CAMPAIGN_DUPLICATE_EXECUTION"
    plan["requests"] = []
    plan["sources"][0]["path"] = "dir//output.txt"
    with pytest.raises(AuditError) as exc:
        run_campaign(root, plan, out, min_free_bytes=0)
    assert exc.value.code == "CAMPAIGN_SOURCE_PATH"


def test_disk_reserve_and_live_writer_fail_closed(tmp_path):
    root, plan, out = fixture(tmp_path)
    with pytest.raises(AuditError) as exc:
        run_campaign(root, plan, out, min_free_bytes=10**30)
    assert exc.value.code == "CAMPAIGN_DISK_RESERVE"
    import os
    (out / "writer.json").write_text(json.dumps({"pid": os.getpid()}))
    with pytest.raises(AuditError) as exc:
        run_campaign(root, plan, out, resume=True, min_free_bytes=0)
    assert exc.value.code == "CAMPAIGN_WRITER_PRESENT"


def test_outputs_inside_source_require_frozen_exclusion_without_inputs(tmp_path):
    root, plan, _ = fixture(tmp_path)
    out = root / "engineering" / "run-001"
    with pytest.raises(AuditError) as exc:
        run_campaign(root, plan, out, min_free_bytes=0)
    assert exc.value.code == "CAMPAIGN_OUTPUT_IN_SOURCE"
    plan["excluded_output_subtrees"] = ["engineering"]
    result = run_campaign(root, plan, out, min_free_bytes=0)
    assert result["executed"] == 1


def test_discovery_preserves_all_predictions_and_separates_submission_joins(tmp_path):
    from runtime.candidate.swebench_claim_audit.prepare_plan import build_plan
    root = tmp_path / "data"
    root.mkdir()
    rows = []
    values = {
        "logs/all_preds.jsonl": b'{"instance_id":"sample__repo-1","model_patch":""}\n'
                                  b'{"instance_id":"sample__repo-2","model_patch":""}\n',
        "logs/trajs/sample__repo-1.traj.json": b'{"instance_id":"sample__repo-1","messages":[]}',
        "experiments-main/evaluation/lite/other-submission/results/results.json":
            b'{"resolved":["sample__repo-1"]}',
    }
    for n, (name, raw) in enumerate(values.items()):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        rows.append({"source_id": "src-" + str(n), "relative_path": name,
                     "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw),
                     "evidence_role": "fixture"})
    plan = build_plan(root, {"files": rows}, code_commit="SYNTHETIC", code_sha256={})
    assert len(plan["requests"]) == 2
    prediction = next(s for s in plan["sources"] if s["role"] == "PREDICTION")
    assert "instance_id" not in prediction  # Do not filter a whole-run index to UNKNOWN.
    assert all(ref["run_id"] == request["run_id"]
               for request in plan["requests"] for ref in request["evidence"])
    assert all("other-submission" not in ref["path"]
               for request in plan["requests"] for ref in request["evidence"])


def test_unbound_old_completions_cannot_be_adopted_as_fresh_campaign(tmp_path):
    root, plan, out = fixture(tmp_path)
    run_campaign(root, plan, out, min_free_bytes=0)
    (out / "binding.json").unlink()
    with pytest.raises(AuditError) as exc:
        run_campaign(root, plan, out, min_free_bytes=0)
    assert exc.value.code == "CAMPAIGN_OUTPUT_NOT_FRESH"


def test_production_requires_commit_and_all_implementation_hashes(tmp_path):
    root, plan, out = fixture(tmp_path)
    with pytest.raises(AuditError) as exc:
        _run_campaign(root, plan, out, min_free_bytes=0)
    assert exc.value.code == "CAMPAIGN_CODE_NOT_FROZEN"


def test_submission_identity_handles_real_slug_characters_and_dataset_overlap():
    from runtime.candidate.swebench_claim_audit.prepare_plan import classify
    first = classify("experiments-main/evaluation/lite/agent+model (test)/results/results.json")
    second = classify("experiments-main/evaluation/verified/agent+model (test)/results/results.json")
    assert first[2] == second[2]
    assert first[2].startswith("submission-") and len(first[2]) == 43


def test_all_completed_units_can_be_bound_and_recovered_in_real_engine(tmp_path):
    from runtime.candidate.swebench_claim_audit.bind_campaign import bind_campaign
    root, plan, _ = fixture(tmp_path)
    plan["excluded_output_subtrees"] = ["engineering"]
    out = root / "engineering" / "campaign"
    run_campaign(root, plan, out, min_free_bytes=0)
    contexts = root / "engineering" / "context"
    bound = bind_campaign(root, plan, out, contexts, min_free_bytes=0)
    recovered = bind_campaign(root, plan, out, contexts, min_free_bytes=0)
    assert bound["status"] == "PASS" and bound["bound_units"] == 1
    assert recovered["recovered_units"] == 1
    assert len(list(contexts.glob("batch-*-result.json"))) == 1
    next(contexts.glob("batch-*-result.json")).write_text('{"tampered":true}')
    with pytest.raises(AuditError) as exc:
        bind_campaign(root, plan, out, contexts, min_free_bytes=0)
    assert exc.value.code == "CONTEXT_RECEIPT_CHANGED"
