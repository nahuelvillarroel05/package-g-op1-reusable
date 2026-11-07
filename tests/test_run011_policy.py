import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.run_framework.protection_policy import (
    ProtectionPolicyError,
    load_protection_policy,
)


def test_run011_policy_is_versioned_and_keeps_reserved_sources_closed():
    path = Path(__file__).parents[1] / "experiments" / "policies" / "run011-read-protection-v1.json"
    raw = path.read_bytes()

    policy = load_protection_policy(path, hashlib.sha256(raw).hexdigest())

    assert policy["policy_id"] == "RUN011_E1_READ_PROTECTION"
    assert policy["reserved_data"]["gold"] == "NEVER_OPEN"
    assert policy["reserved_data"]["credentials"] == "NEVER_OPEN"
    with pytest.raises(ProtectionPolicyError, match="digest mismatch"):
        load_protection_policy(path, "0" * 64)
