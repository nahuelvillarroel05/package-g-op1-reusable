import errno
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from runtime.candidate.run_framework.classification import verify_manifest_classification
from runtime.candidate.run_framework import core
from runtime.candidate.run_framework.core import FrameworkError, PreflightDiagnosticError, load_config
from runtime.candidate.run_framework.preflight_diagnostics import classify_probe_exception
from runtime.candidate.run_framework.protection_policy import load_protection_policy
from runtime.candidate.run_framework.registry_links import verify_run_registry_links
from runtime.candidate.run_framework.run010_summary import SCHEMA, SummaryValidationError, validate_summary


def test_preflight_diagnostic_distinguishes_timeout_permission_and_command_failure():
    timeout = classify_probe_exception(subprocess.TimeoutExpired(["git", "status"], 1), elapsed_ms=1010)
    denied = classify_probe_exception(PermissionError(errno.EACCES, "secret path"), elapsed_ms=4)
    failed = classify_probe_exception(subprocess.CalledProcessError(128, ["git", "rev-parse"]), elapsed_ms=7)
    absent = classify_probe_exception(FileNotFoundError("private executable path"), elapsed_ms=1)
    assert [timeout["code"], denied["code"], failed["code"], absent["code"]] == [
        "GIT_TIMEOUT", "GIT_PERMISSION_DENIED", "GIT_COMMAND_FAILED", "GIT_EXECUTABLE_NOT_FOUND"]
    assert denied["returncode"] is None and failed["returncode"] == 128
    assert all(set(row) == {"schema", "code", "exception_class", "returncode", "duration_ms"}
               for row in (timeout, denied, failed, absent))
    assert "secret path" not in repr(denied) and "private executable" not in repr(absent)


@pytest.mark.parametrize(("exc", "code"), [
    (subprocess.TimeoutExpired(["git", "status"], 1), "GIT_TIMEOUT"),
    (PermissionError(errno.EACCES, "sensitive path"), "GIT_PERMISSION_DENIED"),
    (subprocess.CalledProcessError(128, ["git", "rev-parse"], stderr="private stderr"),
     "GIT_COMMAND_FAILED"),
])
def test_campaign_preflight_exposes_sanitized_diagnostic_and_remains_framework_error(
        tmp_path, monkeypatch, exc, code):
    # Reuse the framework's synthetic, committed input fixture. Only the Git
    # probe fails; no benchmark or adapter code is executed.
    from test_reusable_run_framework import fixture_config
    config_path, config = fixture_config(tmp_path)
    campaign = load_config(config_path, [tmp_path],
                           tmp_path / config["run_id"] / "attempts" / config["campaign_attempt_id"],
                           [tmp_path], [tmp_path])
    monkeypatch.setattr(core, "_git_read", lambda *args, **kwargs: (_ for _ in ()).throw(exc))
    with pytest.raises(PreflightDiagnosticError) as captured:
        campaign.preflight()
    error = captured.value
    assert isinstance(error, FrameworkError)
    assert error.diagnostic["code"] == code
    assert error.diagnostic["schema"] == "pgop1.preflight-diagnostic.v1"
    assert "sensitive path" not in repr(error.diagnostic)
    assert "private stderr" not in repr(error.diagnostic)
    assert error.diagnostic["duration_ms"] >= 0


def test_read_scope_install_is_idempotent_but_rejects_incompatible_scope(tmp_path):
    root = tmp_path / "protected"
    root.mkdir()
    allowed = root / "allowed.txt"
    allowed.write_text("fixture", encoding="utf-8")
    sibling = root / "sibling.txt"
    sibling.write_text("fixture", encoding="utf-8")
    script = r"""
import importlib, sys
from runtime.candidate.run_framework.read_scope import install_read_scope, require_read_scope
root, allowed, sibling = sys.argv[1:]
first = install_read_scope([root], [allowed])
module = importlib.reload(sys.modules['runtime.candidate.run_framework.read_scope'])
second = module.install_read_scope([root], [allowed])
assert first is second
assert module.require_read_scope([root], [allowed]) is first
try:
    module.install_read_scope([root], [sibling])
except RuntimeError:
    pass
else:
    raise AssertionError('incompatible scope was installed')
try:
    module.require_read_scope([root], [sibling])
except RuntimeError:
    pass
else:
    raise AssertionError('entrypoint accepted a different scope')
"""
    result = subprocess.run([sys.executable, "-c", script, str(root), str(allowed), str(sibling)],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr


def test_run010_summary_separates_structural_overlap_and_terminal_outcomes():
    summary = {"schema": SCHEMA, "run_id": "RUN010-E1-test",
               "counts": {"selected": 5, "attempted": 4, "processed": 3,
                          "structural": 2, "semantic": 1, "abstained": 1,
                          "verification_error": 0, "not_evaluable": 1},
               "by_provenance_level": {"SOURCE_EVIDENCE_REVIEW": 3},
               "by_reference_type": {"UNAVAILABLE": 1, "OFFICIAL_ARCHIVED_TASK_RESULT": 2}}
    assert validate_summary(summary) is summary
    summary["counts"]["semantic"] = 2
    with pytest.raises(SummaryValidationError, match="partition"):
        validate_summary(summary)


def test_protection_policy_is_explicit_and_bound_by_sha256():
    path = Path(__file__).parents[1] / "experiments" / "policies" / "run010-read-protection-v1.json"
    raw = path.read_bytes()
    policy = load_protection_policy(path, hashlib.sha256(raw).hexdigest())
    assert policy["reserved_data"]["gold"] == "NEVER_OPEN"
    with pytest.raises(ValueError, match="digest mismatch"):
        load_protection_policy(path, "0" * 64)


def test_registry_links_accept_old_and_explicit_shapes_and_report_missing(tmp_path):
    (tmp_path / "runs" / "run-002").mkdir(parents=True)
    (tmp_path / "experiments" / "runs" / "run-004" / "results").mkdir(parents=True)
    registry = {"runs": [
        {"ID": "RUN-002", "directory": "runs/run-002", "public_evidence_path": "runs/run-002"},
        {"ID": "RUN-004", "directory": "experiments/runs/run-004",
         "result_paths": ["experiments/runs/run-004/results", "experiments/runs/run-004/missing"]},
        {"ID": "RUN-003", "directory": "../outside"},
    ]}
    report = verify_run_registry_links(registry, tmp_path)
    assert len(report["checked"]) == 4
    assert report["missing"] == [{"run_id": "RUN-004", "field": "result_paths",
                                  "path": "experiments/runs/run-004/missing"}]
    assert report["invalid"] == [{"run_id": "RUN-003", "field": "directory"}]
    assert report["status"] == "FAIL"


@pytest.mark.parametrize(("declared", "expected", "status"), [
    ("private", "private", "PASS"), ("public", "private", "MISMATCH"),
    (None, "public", "UNKNOWN"),
])
def test_manifest_classification_is_checked_without_side_effects(declared, expected, status):
    manifest = {"classification": declared} if declared else {}
    assert verify_manifest_classification(manifest, expected)["status"] == status

