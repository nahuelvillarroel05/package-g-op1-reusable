"""Fail-closed successor guard around the preserved Fiveflow engine."""
from __future__ import annotations
import hashlib
import os
import re
import stat
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
CASE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{0,63}$")
SCHEMA_RE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*\.v[1-9][0-9]*$")
VARIANTS = frozenset({"CLEAN_A", "CLEAN_B", "NEGATIVE"})
NEGATIVE_MODES = frozenset({"OUTPUT_TAMPER", "PROCESS_FAILURE", "TEST_FAILURE", "INVENTORY_BINDING", "REVOCATION"})
EXPECTED_FAILURE_TEXT = {
    "OUTPUT_TAMPER": ("output hash mismatch",),
    "PROCESS_FAILURE": ("producer process failure",),
    "TEST_FAILURE": ("JUnit accounting failed",),
    "INVENTORY_BINDING": ("inventory source tampering",),
    "REVOCATION": ("durable event run unavailable",),
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _has_reparse_attribute(path: Path) -> bool:
    try:
        attrs = path.lstat().st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _lexical_source(path_value: str, role: str) -> Path:
    if not isinstance(path_value, str) or not path_value:
        raise ValueError("source path must be a nonempty string")
    lexical = Path(os.path.abspath(path_value))
    if lexical.parent != ROOT:
        raise ValueError("source must be an immediate lexical child of the fresh engine root")
    if lexical.name.casefold() not in {f"provider_{role}.py", f"consumer_{role}.py"} and not re.fullmatch(r"(?:provider|consumer)_[a-z][a-z0-9_]*\.py", lexical.name, re.I):
        raise ValueError("source filename is outside the provider/consumer namespace")
    # Check every lexical component before resolve(), stat-following reads, or hashing.
    cursor = Path(lexical.anchor)
    for component in lexical.parts[1:]:
        cursor = cursor / component
        if os.path.lexists(cursor) and _has_reparse_attribute(cursor):
            raise ValueError("reparse point in source path: " + str(cursor))
    if not lexical.is_file():
        raise ValueError("source must be an existing regular file")
    if lexical.resolve(strict=True) != lexical:
        raise ValueError("resolved source differs from lexical path")
    return lexical


def validate_case(case_id: str) -> str:
    if not isinstance(case_id, str) or not CASE_RE.fullmatch(case_id):
        raise ValueError("CASE_ID must be a simple bounded identifier")
    return case_id


def register_relationship(case_id, provider_source, consumer_source, output_schema, negative_mode):
    validate_case(case_id)
    if not isinstance(output_schema, str) or not SCHEMA_RE.fullmatch(output_schema):
        raise ValueError("unsupported output schema identifier")
    if negative_mode not in NEGATIVE_MODES:
        raise ValueError("unsupported negative mode")
    p = _lexical_source(provider_source, "provider")
    c = _lexical_source(consumer_source, "consumer")
    p_hash, c_hash = _sha(p), _sha(c)
    # The preserved API reads the exact copies; verify its resulting bindings before use.
    from reusable_api_v2 import register_relationship as original_register
    relationship = original_register(case_id, str(p), str(c), output_schema, negative_mode)
    if relationship["PROVIDER_SHA256"] != p_hash or relationship["CONSUMER_SHA256"] != c_hash:
        raise ValueError("source changed during registration")
    return relationship


def validate_relationship(relationship):
    if not isinstance(relationship, dict):
        raise ValueError("relationship must be an object")
    validate_case(relationship.get("CASE_ID"))
    if relationship.get("CLASSIFICATION") != "ENGINEERING_LIVE":
        raise ValueError("only Engineering-owned relationships are accepted")
    from runtime import CONFIG
    if relationship.get("AUTHORITY_SCOPE") != CONFIG["authority_scope"]:
        raise ValueError("authority scope mismatch")
    if relationship.get("INPUT_CONTRACT") != relationship.get("OUTPUT_SCHEMA") or not SCHEMA_RE.fullmatch(str(relationship.get("OUTPUT_SCHEMA", ""))):
        raise ValueError("input/output schema contract mismatch")
    if relationship.get("NEGATIVE_MODE") not in NEGATIVE_MODES:
        raise ValueError("unsupported negative mode")
    for role in ("PROVIDER", "CONSUMER"):
        p = _lexical_source(relationship.get(role + "_SOURCE"), role.lower())
        if not p.name.casefold().startswith(role.lower() + "_"):
            raise ValueError("source does not match its relationship role")
        if _sha(p) != relationship.get(role + "_SHA256"):
            raise ValueError("source binding mismatch")
    for key in ("RELATIONSHIP_ID", "PROVIDER_ID", "CONSUMER_ID", "OUTPUT_ID", "SOURCE_ID"):
        if not isinstance(relationship.get(key), str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,100}", relationship[key]):
            raise ValueError("malformed relationship identity: " + key)
    if relationship.get("EXECUTION_METHOD") != "ISOLATED_PYTHON_PINNED_WORKER_DIRECT_POPEN":
        raise ValueError("unsupported execution method")
    if relationship.get("VERIFICATION_METHOD") != "ACTUAL_CONSUMER_RECOMPUTATION_AND_FRESH_PROCESS_RECOVERY":
        raise ValueError("unsupported verification method")
    from runtime import validate_relationship as original_validate
    return original_validate(relationship)


def _negative_cause_matches(directory: Path, mode: str) -> bool:
    expected = EXPECTED_FAILURE_TEXT[mode]
    provider_err = (directory / "provider.stderr").read_bytes().decode("utf-8", "replace")
    consumer_err = (directory / "consumer.stderr").read_bytes().decode("utf-8", "replace")
    proc = json.loads((directory / "provider.process.json").read_bytes())
    consumer = json.loads((directory / "consumer.process.json").read_bytes())
    request = json.loads((directory / "request.json").read_bytes())
    if proc["timed_out"] or consumer["timed_out"] or not proc["terminal_observed"] or not consumer["terminal_observed"]:
        return False
    if mode == "PROCESS_FAILURE":
        return request.get("force_failure") is True and proc["exit_code"] == 7 and consumer["exit_code"] != 0 and any(s in consumer_err for s in expected)
    if proc["exit_code"] != 0 or consumer["exit_code"] == 0 or provider_err:
        return False
    if mode == "OUTPUT_TAMPER":
        tampered = directory / "controlled-tamper" / "provider.stdout"
        original = (directory / "provider.stdout").read_bytes()
        command = consumer.get("command", [])
        return (tampered.is_file() and tampered.read_bytes() == original + b"CONTROLLED_TAMPER"
                and command[-1:] == [str(directory / "controlled-tamper")]
                and any(s in consumer_err for s in expected))
    if mode == "TEST_FAILURE":
        return request.get("expected_sum") == sum(request["values"]) + 1 and any(s in consumer_err for s in expected)
    if mode == "INVENTORY_BINDING":
        bad = [k for k, v in request["inventory_sources"].items() if v == "0" * 64]
        return len(bad) == 1 and any(s in consumer_err for s in expected)
    if mode == "REVOCATION":
        from runtime import DurableRegistry
        state = DurableRegistry(request["journal"]).snapshot()
        return request["RUN_ID"] in state["revoked_runs"] and any(s in consumer_err for s in expected)
    return False


def _validate_parent(relationship, parent):
    if parent is None:
        return
    if not isinstance(parent, str) or not re.fullmatch(r"ATT-[A-Za-z0-9T+_.-]{1,100}", parent):
        raise ValueError("parent attempt identifier is malformed")
    from runtime import ROOT, read
    registry_path = ROOT / "ATTEMPT_REGISTRY.jsonl"
    if not registry_path.is_file():
        raise ValueError("parent registry missing")
    rows = [json.loads(line) for line in registry_path.read_bytes().splitlines()]
    matches = [row for row in rows if row.get("record_type") == "BEFORE_EXECUTION" and row.get("ATTEMPT_ID") == parent]
    if len(matches) != 1 or matches[0].get("CASE_ID") != relationship["CASE_ID"]:
        raise ValueError("parent attempt absent, ambiguous, or cross-case")
    parent_request = read(Path(matches[0]["directory"]) / "request.json")
    if parent_request.get("relationship") != relationship:
        raise ValueError("parent relationship binding mismatch")


def execute(relationship, variant, parent=None):
    if variant not in VARIANTS:
        raise ValueError("unsupported execution variant")
    validate_relationship(relationship)
    _validate_parent(relationship, parent)
    from engine import execute as original_execute
    result = original_execute(relationship, variant, parent)
    directory = Path(result["directory"])
    expected_root = (ROOT / "cases" / relationship["CASE_ID"] / "attempts").resolve()
    if directory.parent.resolve() != expected_root or directory.is_symlink():
        raise ValueError("engine returned an attempt outside the registered case")
    if variant == "NEGATIVE":
        exact = _negative_cause_matches(directory, relationship["NEGATIVE_MODE"])
        result["BOUNDED_ADAPTER_EXPECTED_FAILURE"] = "PASS" if exact else "NOT_PROVEN"
        result["BOUNDED_ADAPTER_EXPECTED_FAILURE_MODE"] = relationship["NEGATIVE_MODE"]
        result["BOUNDED_ADAPTER_VERDICT"] = "PASS_EXPECTED_FAILURE" if exact else "UNEXPECTED_FAILURE_CAUSE"
    else:
        result["BOUNDED_ADAPTER_VERDICT"] = "PASS_CLEAN" if result.get("FINAL_STATUS") == "CLEAN_EXECUTION_PASS" and result.get("VERIFICATION_RESULT") == "PASS" else "UNEXPECTED_FAILURE"
    return result
