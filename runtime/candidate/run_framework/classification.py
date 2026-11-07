"""Check a source manifest's declared privacy class without changing it."""
from __future__ import annotations


def verify_manifest_classification(manifest: dict, expected: str) -> dict:
    """Require an explicit private/public classification; never publish or remove files."""
    if expected not in {"private", "public"}:
        raise ValueError("expected classification must be private or public")
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    declared = manifest.get("classification")
    if declared not in {"private", "public"}:
        return {"schema": "pgop1.manifest-classification-check.v1",
                "status": "UNKNOWN", "expected": expected, "declared": None}
    return {"schema": "pgop1.manifest-classification-check.v1",
            "status": "PASS" if declared == expected else "MISMATCH",
            "expected": expected, "declared": declared}
