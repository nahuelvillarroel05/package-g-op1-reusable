"""RUN011 prospective recovery checks for committed Engine evidence."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from runtime.candidate.context_engine import canonical_json
from runtime.candidate.run_framework import semantic_e1
from runtime.candidate.run_framework.core import FrameworkError, canonical, digest


CLAIM_ID = "RUN011-test-claim"


def _recovery_fixture(tmp_path, monkeypatch, *, tamper=None):
    output = tmp_path / "attempt"
    (output / "receipts").mkdir(parents=True)
    capsule = {
        "claim_id": CLAIM_ID,
        "selected_claim": {"predicate": "TASK_RESOLVED", "span": [0, 1]},
        "audit": {"AUDIT_VERDICT": "SUPPORTED"},
        "disposition": "SUPPORTED",
    }
    capsule_raw = canonical(capsule)
    capsule_path = output / "capsules" / f"{CLAIM_ID}.json"
    capsule_path.parent.mkdir()
    capsule_path.write_bytes(capsule_raw)
    capsule_sha256 = digest(capsule_raw)
    receipt_path = output / "receipts" / f"{CLAIM_ID}.json"
    receipt_value = {
        "disposition": capsule["disposition"],
        "payload": {"capsule_sha256": capsule_sha256, "capsule_path": str(capsule_path)},
    }
    if tamper == "receipt":
        receipt_value["disposition"] = "CONTRADICTED"
    receipt_path.write_bytes(canonical(receipt_value))
    receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    observations = []
    for key in ("selected_claim", "audit", "disposition"):
        binding = {
            "source_id": CLAIM_ID,
            "sha256": capsule_sha256,
            "pointer": "/" + key,
            "value_sha256": digest(canonical_json(capsule[key])),
        }
        obs = {"id": CLAIM_ID + ":" + key, "evidence_binding": binding}
        if key != "selected_claim":
            obs["value"] = capsule[key]
        if tamper == "binding_sha" and key == "audit":
            binding["sha256"] = "0" * 64
        elif tamper == "binding_value" and key == "audit":
            binding["value_sha256"] = "0" * 64
        elif tamper == "binding_missing" and key == "audit":
            binding.pop("value_sha256")
        elif tamper == "inline_value" and key == "audit":
            obs["value"] = {"AUDIT_VERDICT": "CONTRADICTED"}
        observations.append(obs)

    edge_binding = {
        "source_id": CLAIM_ID,
        "sha256": capsule_sha256,
        "pointer": "",
        "value_sha256": digest(canonical_json(capsule)),
    }
    edge = {"id": CLAIM_ID + ":association", "from": CLAIM_ID + ":selected_claim",
            "to": CLAIM_ID + ":audit", "relationship": "DERIVED_ASSOCIATION",
            "evidence_bindings": [edge_binding]}
    if tamper == "edge":
        edge["to"] = CLAIM_ID + ":disposition"

    ledger = {"rows": [{"claim_id": CLAIM_ID, "capsule_path": str(capsule_path),
                        "capsule_sha256": capsule_sha256, "receipt_sha256": receipt_sha256,
                        "disposition": capsule["disposition"]}],
              "engine_root": str(tmp_path / "engine")}
    (output / "LEDGER.json").write_bytes(canonical(ledger))

    class Campaign:
        config = {"expected_units": [CLAIM_ID]}

        def recover(self):
            return {"complete": True, "completed": [CLAIM_ID], "pending": [], "inflight": [],
                    "receipts": [{"unit_id": CLAIM_ID, "phase": "start", "sha256": "a" * 64,
                                  "path": "receipts/start.json"},
                                 {"unit_id": CLAIM_ID, "phase": "terminal", "sha256": receipt_sha256,
                                  "path": "receipts/" + CLAIM_ID + ".json"}],
                    "checkpoints": [{"unit_id": CLAIM_ID}, {"unit_id": CLAIM_ID}]}

    class Engine:
        def __init__(self, _root):
            self._graph = {"edges": [edge]}

        def verify(self):
            return {"status": "PASS", "versions": 1, "sources": 1}

        def query(self, *, task_id, limit):
            assert task_id == CLAIM_ID and limit == 10
            return observations

        def read_source(self, source_id):
            assert source_id == CLAIM_ID
            if tamper == "source_hash":
                return canonical({"claim_id": CLAIM_ID, "tampered": True})
            return capsule_raw

    monkeypatch.setattr(semantic_e1, "bootstrap", lambda _args: (None, None, Campaign()))
    monkeypatch.setattr(semantic_e1, "Engine", Engine)
    return SimpleNamespace(output=output, workspace=tmp_path)


def test_recovery_verifies_four_field_bindings_and_optional_inline_values(tmp_path, monkeypatch):
    args = _recovery_fixture(tmp_path, monkeypatch)

    semantic_e1.recover(args)

    report = json.loads((tmp_path / "FRESH_RECOVERY.json").read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert report["recovered"] == 1
    assert report["producer_redispatch"] is False


@pytest.mark.parametrize(("tamper", "reason"), [
    ("binding_sha", "SEMANTIC_E1_OBSERVATION_BINDING_MISMATCH"),
    ("binding_value", "SEMANTIC_E1_OBSERVATION_BINDING_MISMATCH"),
    ("binding_missing", "SEMANTIC_E1_OBSERVATION_BINDING_MISMATCH"),
    ("source_hash", "SEMANTIC_E1_SOURCE_HASH_MISMATCH"),
    ("inline_value", "SEMANTIC_E1_RECOVERY_VALUE_MISMATCH"),
    ("edge", "SEMANTIC_E1_RECOVERY_EDGE_BINDING"),
    ("receipt", "SEMANTIC_E1_RECOVERY_RECEIPT_PAYLOAD"),
])
def test_recovery_fails_closed_on_binding_value_or_edge_tampering(tmp_path, monkeypatch, tamper, reason):
    args = _recovery_fixture(tmp_path, monkeypatch, tamper=tamper)

    with pytest.raises(FrameworkError, match=reason):
        semantic_e1.recover(args)


def test_recovery_runs_in_fresh_process_with_real_campaign_and_engine(tmp_path):
    from test_reusable_run_framework import fixture_config

    config_path, config = fixture_config(tmp_path)
    data_root = tmp_path / "protected"
    data_root.mkdir()
    source = data_root / "input.json"
    source_raw = b'{"source":"synthetic"}'
    source.write_bytes(source_raw)
    policy_path = tmp_path / "policy.json"
    policy = {
        "schema": "pgop1.read-protection-policy.v1",
        "classification": "public",
        "policy_id": "RUN010_E1_READ_PROTECTION",
        "version": 1,
        "read_scope": {"protected_root_ids": ["SYNTHETIC_TEST_ROOT"],
                       "allowed_source_ids": ["SYNTHETIC_INPUT"]},
        "reserved_data": {"gold": "NEVER_OPEN", "credentials": "NEVER_OPEN",
                           "protected_directories": "NEVER_OPEN"},
        "runtime_limits": {"equivalent_to_os_sandbox": False,
                           "child_process_access": "PROHIBITED_UNLESS_EXPLICITLY_SCOPED"},
    }
    policy_raw = canonical(policy)
    policy_path.write_bytes(policy_raw)
    scope_path = tmp_path / "scope.json"
    scope = {
        "policy": {"path": str(policy_path), "sha256": digest(policy_raw)},
        "protected_roots": [str(data_root)],
        "allowed_sources": [str(source)],
        "source_references": [{"path": str(source), "sha256": digest(source_raw),
                               "bytes": len(source_raw)}],
    }
    scope_raw = canonical(scope)
    scope_path.write_bytes(scope_raw)
    config["input_bindings"] = [
        *config["input_bindings"],
        {"path": str(source), "sha256": digest(source_raw)},
        {"path": str(policy_path), "sha256": digest(policy_raw)},
        {"path": str(scope_path), "sha256": digest(scope_raw)},
    ]
    config_path.write_bytes(canonical(config))

    from runtime.candidate.context_engine import Engine
    from runtime.candidate.run_framework.core import load_config

    output = tmp_path / "run-001" / "attempts" / "attempt-001"
    campaign = load_config(config_path, [tmp_path], output, [tmp_path], [tmp_path])
    campaign.preflight()
    engine_root = tmp_path / "engine"
    engine = Engine(engine_root)
    rows = []
    for unit in config["expected_units"]:
        capsule = {"claim_id": unit,
                   "selected_claim": {"predicate": "TASK_RESOLVED", "span": [0, 1]},
                   "audit": {"AUDIT_VERDICT": "SUPPORTED"},
                   "disposition": "SUPPORTED"}
        capsule_raw = canonical(capsule)
        capsule_path = engine_root / "capsules" / f"{unit}.json"
        capsule_path.parent.mkdir(parents=True, exist_ok=True)
        capsule_path.write_bytes(capsule_raw)
        capsule_sha = digest(capsule_raw)
        engine.admit_source(capsule_path, capsule_sha, "ENGINEERING_RESULT", source_id=unit)
        campaign.begin_unit(unit, {"claim_id": unit})
        nodes = [{"id": unit + ":" + key, "task_id": unit, "run_id": "RUN011",
                  "kind": "RUN011_" + key.upper(), "source_id": unit,
                  "evidence_pointer": "/" + key}
                 for key in ("selected_claim", "audit", "disposition")]
        edges = [{"id": unit + ":association", "from": unit + ":selected_claim",
                  "to": unit + ":audit", "relationship": "DERIVED_ASSOCIATION",
                  "evidence_bindings": [{"source_id": unit, "pointer": ""}]}]
        manifest = engine.ingest(nodes, edges)
        receipt = campaign.complete_unit(unit, capsule["disposition"], {
            "capsule_path": str(capsule_path), "capsule_sha256": capsule_sha,
            "engine_manifest": manifest,
        })
        rows.append({"claim_id": unit, "capsule_path": str(capsule_path),
                     "capsule_sha256": capsule_sha,
                     "receipt_sha256": receipt["receipt_sha256"],
                     "disposition": capsule["disposition"]})
    engine.verify()
    (output / "LEDGER.json").write_bytes(canonical({"rows": rows, "engine_root": str(engine_root)}))

    command = [
        "python", "-B", "-m", "runtime.candidate.run_framework.semantic_e1",
        "--scope", str(scope_path), "--scope-sha256", digest(scope_raw),
        "--config", str(config_path), "--workspace", str(tmp_path),
        "--output", str(output), "--data-root", str(tmp_path),
        "--output-root", str(tmp_path), "--recover",
    ]
    import subprocess
    repo = Path(__file__).resolve().parents[1]
    recovered = subprocess.run(command, cwd=repo, capture_output=True, text=True, timeout=30)
    assert recovered.returncode == 0, recovered.stderr
    report = json.loads((tmp_path / "FRESH_RECOVERY.json").read_text(encoding="utf-8"))
    assert report["status"] == "PASS"
    assert report["recovered"] == len(config["expected_units"]) == 2
    assert report["framework_receipts"] == report["framework_checkpoints"] == 4
    assert report["producer_redispatch"] is False
