"""Literal unit metadata derived from the existing frozen typed/source bindings."""
from .caller import _unit
from .core import FrameworkError
from .provenance import _read_bound_file
from .source_bindings import SourceBindings


def project_unit_metadata(campaign, unit_id):
    """Reverify declared bytes; do not authenticate a source or infer its rights.

    Missing logical/revision/locale metadata remains explicit UNKNOWN. Declared
    output references are not called authentic merely because bytes match.
    """
    unit, index = _unit(campaign, unit_id)
    refs = SourceBindings(campaign).verify_unit(unit_id, unit)
    all_refs = [refs["primary"], *refs["supporting"], *refs["normative"], *unit["evidence_references"]]
    available = sorted({(row["path"], row["sha256"]) for row in all_refs})
    for path, sha in available:
        _read_bound_file(path, sha, index["roots"], "literal available evidence")
    outputs = unit.get("authentic_output_references", [])
    if not isinstance(outputs, list):
        raise FrameworkError("LITERAL_OUTPUT_REFERENCES_MALFORMED")
    for ref in outputs:
        if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
                or (ref["path"], ref["sha256"]) not in index["evidence"][unit_id]):
            raise FrameworkError("LITERAL_OUTPUT_REFERENCE_NOT_IN_BOUND_EVIDENCE")
        _read_bound_file(ref["path"], ref["sha256"], index["roots"], "literal declared output")
    cfg = campaign.config
    return {"schema": "pgop1.run004.unit-receipt-payload.rev004",
            "campaign_id": cfg["campaign_id"], "campaign_attempt_id": cfg["campaign_attempt_id"],
            "unit_id": unit_id, "logical_id": unit.get("logical_id", unit.get("canonical_task_id", unit.get("task_id", "UNKNOWN"))),
            "benchmark": unit["benchmark_id"], "version": unit["benchmark_version"],
            "revision": unit.get("revision", "UNKNOWN"), "split": unit.get("split", "UNKNOWN"),
            "locale": unit.get("locale", "UNKNOWN"), "modality": "A",
            "source_uri": refs["primary"]["path"], "source_sha256": unit["source_sha256"],
            "integrity_status": "SOURCE_AND_DECLARED_EVIDENCE_BYTES_REVERIFIED",
            "available_evidence": [{"source_uri": path, "sha256": sha} for path, sha in available],
            "missing_evidence": [] if outputs else [{"source_uri": "UNKNOWN", "sha256": None,
                                                     "reason": "NO_DECLARED_AGENT_OUTPUT_REFERENCE"}],
            "authentic_agent_output_status": "DECLARED_REFERENCE_BYTES_VERIFIED" if outputs else "NOT_PRESENT",
            "producer_provenance": "DECLARED_NOT_AUTHENTICATED",
            "contract_id": cfg["contract_version"], "contract_sha256": cfg["contract_sha256"],
            "contract_identity_source": "FROZEN_CONFIG_CONTRACT_VERSION_IDENTIFIER",
            "predicate_version": unit["predicate_contract"]["version"],
            "predicate_contract_sha256": unit["predicate_contract"]["sha256"],
            "bindings": {"source_sha256": unit["source_sha256"], "contract_sha256": cfg["contract_sha256"],
                         "config_sha256": campaign.config_sha256}}
