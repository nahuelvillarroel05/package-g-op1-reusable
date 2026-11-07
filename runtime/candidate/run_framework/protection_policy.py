"""Load an explicit, versioned read-protection policy by its pinned digest."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


class ProtectionPolicyError(ValueError):
    pass


def load_protection_policy(path, expected_sha256: str) -> dict:
    """Read and verify a RUN-010 policy file without inferring paths from IDs."""
    if (not isinstance(expected_sha256, str) or len(expected_sha256) != 64
            or any(ch not in "0123456789abcdef" for ch in expected_sha256)):
        raise ProtectionPolicyError("expected policy SHA-256 is malformed")
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ProtectionPolicyError("protection policy digest mismatch")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtectionPolicyError("protection policy is not UTF-8 JSON") from exc
    required = {"schema", "classification", "policy_id", "version", "read_scope", "reserved_data", "runtime_limits"}
    if not isinstance(value, dict) or set(value) != required:
        raise ProtectionPolicyError("protection policy fields are invalid")
    if value["schema"] != "pgop1.read-protection-policy.v1" or value["version"] != 1:
        raise ProtectionPolicyError("unsupported protection policy version")
    if value["classification"] != "public":
        raise ProtectionPolicyError("protection policy must be explicitly classified public")
    if value["policy_id"] not in {"RUN010_E1_READ_PROTECTION", "RUN011_E1_READ_PROTECTION"}:
        raise ProtectionPolicyError("protection policy identity is invalid")
    scope = value["read_scope"]
    if (not isinstance(scope, dict) or set(scope) != {"protected_root_ids", "allowed_source_ids"}
            or not isinstance(scope["protected_root_ids"], list) or not scope["protected_root_ids"]
            or not isinstance(scope["allowed_source_ids"], list)):
        raise ProtectionPolicyError("read scope policy is invalid")
    if not all(isinstance(x, str) and x for x in (*scope["protected_root_ids"], *scope["allowed_source_ids"])):
        raise ProtectionPolicyError("read scope identifiers must be nonempty strings")
    if len(set(scope["protected_root_ids"])) != len(scope["protected_root_ids"]):
        raise ProtectionPolicyError("protected root identifiers must be unique")
    if len(set(scope["allowed_source_ids"])) != len(scope["allowed_source_ids"]):
        raise ProtectionPolicyError("allowed source identifiers must be unique")
    if not isinstance(value["reserved_data"], dict) or not isinstance(value["runtime_limits"], dict):
        raise ProtectionPolicyError("reserved data and runtime limits must be explicit objects")
    return value
