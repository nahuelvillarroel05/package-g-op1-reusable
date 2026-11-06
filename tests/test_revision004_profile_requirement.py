"""A required V3 profile cannot be downgraded to legacy descriptive checks."""
import pytest
import shutil

from test_revision004_observer import configured, typed_caller
from test_revision004_sidecar import _make_sidecar
from runtime.candidate.run_framework.revision004_sidecar import (
    INDEX_V1, INDEX_V2, INDEX_V3, SidecarVerificationError, verify_revision004_sidecar,
)


@pytest.mark.parametrize("legacy_profile", [INDEX_V1, INDEX_V2])
def test_required_v3_rejects_legacy_metadata_bypass(tmp_path, legacy_profile):
    campaign = configured(tmp_path)
    caller = typed_caller(campaign, lambda unit, refs: {"definition": True})
    caller.execute("u1")
    actual = verify_revision004_sidecar(campaign.output / "REV004_WIRE", campaign)
    assert actual["index_profile"] == INDEX_V3
    assert actual["unit_metadata_verification"] == "FROZEN_TYPED_UNIT_AND_EVIDENCE_BYTES"
    legacy = _make_sidecar(campaign, profile=legacy_profile,
                           metadata_mutator=lambda p: p.update(logical_id="forged", source_uri="synthetic://forged"))
    with pytest.raises(SidecarVerificationError, match="CONFIGURED_LITERAL_PROFILE_MISMATCH"):
        verify_revision004_sidecar(legacy, campaign)


def test_required_profile_cannot_verify_unaccounted_external_sidecar(tmp_path):
    campaign = configured(tmp_path)
    caller = typed_caller(campaign, lambda unit, refs: {"definition": True})
    caller.execute("u1")
    external = tmp_path / "outside-attempt"
    shutil.copytree(campaign.output / "REV004_WIRE", external)
    with pytest.raises(SidecarVerificationError, match="CONFIGURED_LITERAL_DIRECTORY_MISMATCH"):
        verify_revision004_sidecar(external, campaign)
