"""Reusable, opt-in typed modality-A caller over the existing V2 journal.

Only caller-supplied local functions run. Registry metadata never imports or
executes configured commands. Declared provenance is never authentication.
"""
from __future__ import annotations
from copy import deepcopy

from .core import FrameworkError, canonical, digest, _loads
from .provenance import _manifest_index, RESULT_SCHEMA, _read_bound_file
from .source_bindings import SourceBindings
from .resources import ResourceLimitStop

PAYLOAD_SCHEMA = "pgop1.modality-a-payload.v1"
_FIELDS = {"schema", "benchmark_id", "benchmark_version", "adapter_id", "adapter_version",
           "predicate_contract", "supporting_source_references", "normative_companion_references",
           "producer_provenance_status", "processing_disposition", "audit_disposition",
           "audit_result", "result_sha256"}


def _refs(rows):
    return [{"source_id": x["source_id"], "sha256": x["sha256"]} for x in rows]


def _authorities(campaign, index):
    documents = []
    for key in ("adapter_registry", "predicate_contracts"):
        binding = campaign.config[key]
        _, raw = _read_bound_file(binding["path"], binding["sha256"], index["roots"], key)
        documents.append(_loads(raw))
    return documents


def _validate_unit(campaign, unit, registry, matrix):
    for field in ("benchmark_id", "benchmark_version", "adapter_id", "adapter_version"):
        if not isinstance(unit.get(field), str) or not unit[field]:
            raise FrameworkError("TYPED_UNIT_BINDING_MISSING:" + field)
    contract = unit.get("predicate_contract")
    if (not isinstance(contract, dict) or set(contract) != {"contract_id", "version", "sha256"}
            or any(not isinstance(contract[x], str) or not contract[x] for x in contract)):
        raise FrameworkError("TYPED_PREDICATE_CONTRACT_MISSING")
    if contract["sha256"] != campaign.config["predicate_contracts"]["sha256"]:
        raise FrameworkError("TYPED_PREDICATE_AUTHORITY_MISMATCH")
    if (contract["contract_id"] != matrix.get("contract_id", matrix.get("schema"))
            or contract["version"] != matrix.get("version")):
        raise FrameworkError("TYPED_PREDICATE_IDENTITY_MISMATCH")
    registered = registry.get("families", {}).get(unit["benchmark_id"])
    if (not isinstance(registered, dict) or registered.get("adapter_id") != unit["adapter_id"]
            or registered.get("adapter_version") != unit["adapter_version"]
            or unit["benchmark_version"] not in registered.get("versions", [])):
        raise FrameworkError("TYPED_ADAPTER_NOT_IN_REGISTRY")


def _unit(campaign, unit_id):
    index = _manifest_index(campaign)
    if unit_id not in index["units"]:
        raise FrameworkError("TYPED_UNIT_NOT_IN_MANIFEST")
    unit = index["units"][unit_id]
    _validate_unit(campaign, unit, *_authorities(campaign, index))
    return unit, index


def validate_configuration(campaign):
    """Validate every selected unit against independent registry/matrix authority."""
    index = _manifest_index(campaign)
    registry, matrix = _authorities(campaign, index)
    sources = SourceBindings(campaign)
    for unit_id, unit in index["units"].items():
        _validate_unit(campaign, unit, registry, matrix)
        refs = sources.references(unit_id)
        if (refs["primary"]["source_id"] != unit["source_id"]
                or refs["primary"]["sha256"] != unit["source_sha256"]
                or refs["primary"]["path"] != unit.get("source_path", refs["primary"]["path"])):
            raise FrameworkError("SOURCE_DEPENDENCY_PRIMARY_MISMATCH")
    result = sources.verify_all()
    result["typed_units_validated"] = len(index["units"])
    return result


def validate_typed_result(campaign, unit_id, envelope):
    """Called by provenance validation during publication AND read recovery."""
    payload = envelope.get("result_payload")
    if not isinstance(payload, dict) or set(payload) != _FIELDS or payload.get("schema") != PAYLOAD_SCHEMA:
        raise FrameworkError("TYPED_PAYLOAD_REQUIRED")
    if envelope.get("result_type") != PAYLOAD_SCHEMA:
        raise FrameworkError("TYPED_RESULT_TYPE_MISMATCH")
    unit, index = _unit(campaign, unit_id)
    refs = SourceBindings(campaign).verify_unit(unit_id, unit)
    for field in ("benchmark_id", "benchmark_version", "adapter_id", "adapter_version", "predicate_contract"):
        if payload[field] != unit[field]:
            raise FrameworkError("TYPED_BINDING_MISMATCH:" + field)
    if (payload["supporting_source_references"] != _refs(refs["supporting"])
            or payload["normative_companion_references"] != _refs(refs["normative"])):
        raise FrameworkError("TYPED_DEPENDENCIES_MISMATCH")
    if payload["producer_provenance_status"] != "DECLARED":
        raise FrameworkError("TYPED_PRODUCER_NOT_AUTHENTICATED")
    if not isinstance(payload["audit_result"], dict) or payload["result_sha256"] != digest(canonical(payload["audit_result"])):
        raise FrameworkError("TYPED_AUDIT_RESULT_HASH_MISMATCH")
    operation, disposition = payload["processing_disposition"], payload["audit_disposition"]
    if operation == "TASK_DEFINITION_PROCESSED":
        if disposition != "NOT_AUDITED_MISSING_AGENT_OUTPUT":
            raise FrameworkError("TASK_DEFINITION_CANNOT_COUNT_AS_SEMANTIC_AUDIT")
    elif operation == "AGENT_OUTPUT_AUDITED":
        if disposition not in {"AUDITED", "ABSTAIN", "VERIFICATION_ERROR"}:
            raise FrameworkError("TYPED_AUDIT_DISPOSITION_INVALID")
        output_refs = unit.get("authentic_output_references")
        if not isinstance(output_refs, list) or not output_refs:
            raise FrameworkError("AUTHENTIC_AGENT_OUTPUT_MISSING")
        for ref in output_refs:
            if (not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
                    or (ref["path"], ref["sha256"]) not in index["evidence"][unit_id]):
                raise FrameworkError("AUTHENTIC_OUTPUT_NOT_IN_UNIT_EVIDENCE")
            _read_bound_file(ref["path"], ref["sha256"], index["roots"], "authentic output")
    else:
        raise FrameworkError("TYPED_PROCESSING_DISPOSITION_INVALID")
    policy = campaign.config["audit_policy"]["generic_caller"]
    if operation == "AGENT_OUTPUT_AUDITED" and "predicate_validation" not in policy:
        raise FrameworkError("SEMANTIC_AUDIT_REQUIRES_QUALIFIED_PREDICATE_VALIDATION")
    if "predicate_validation" in policy:
        if policy["predicate_validation"] != "pgop1.predicate-evidence.v1":
            raise FrameworkError("TYPED_PREDICATE_VALIDATION_POLICY_UNKNOWN")
        from .predicates import validate_audit_payload
        validate_audit_payload(unit, payload["audit_result"], operation, disposition, index)
    return {"processing_disposition": operation, "audit_disposition": disposition}


def make_envelope(campaign, unit_id, audit_result, *, processing_disposition, audit_disposition,
                  producer_id, result_id=None):
    unit, _ = _unit(campaign, unit_id)
    refs = SourceBindings(campaign).verify_unit(unit_id, unit)
    payload = {"schema": PAYLOAD_SCHEMA,
               **{field: deepcopy(unit[field]) for field in ("benchmark_id", "benchmark_version", "adapter_id", "adapter_version", "predicate_contract")},
               "supporting_source_references": _refs(refs["supporting"]),
               "normative_companion_references": _refs(refs["normative"]),
               "producer_provenance_status": "DECLARED",
               "processing_disposition": processing_disposition, "audit_disposition": audit_disposition,
               "audit_result": audit_result, "result_sha256": digest(canonical(audit_result))}
    cfg = campaign.config
    envelope = {"schema": RESULT_SCHEMA, "run_id": cfg["run_id"],
                "campaign_attempt_id": cfg["campaign_attempt_id"], "campaign_id": cfg["campaign_id"],
                "unit_id": unit_id, "source_id": unit["source_id"], "source_sha256": unit["source_sha256"],
                "contract_sha256": cfg["contract_sha256"], "candidate_commit": cfg["candidate_commit"],
                "candidate_tree": cfg["candidate_tree"], "producer_id": producer_id,
                "producer_identity_status": "DECLARED", "result_id": result_id or digest(canonical([cfg["run_id"], cfg["campaign_attempt_id"], unit_id])),
                "result_type": PAYLOAD_SCHEMA, "evidence_references": deepcopy(unit["evidence_references"]),
                "result_payload_sha256": digest(canonical(payload)), "result_payload": payload}
    validate_typed_result(campaign, unit_id, envelope)
    return envelope


class GenericCaller:
    """Execute a single bounded unit; never auto-resume or redispatch units.

    Adapters are injected as trusted Python functions, keyed by exact ID/version.
    They receive manifest metadata and verified references. A caller's auditor
    returns a typed decision, which is validated before durable admission.
    """
    def __init__(self, campaign, adapters, auditor, *, producer_id):
        self.campaign, self.adapters, self.auditor = campaign, dict(adapters), auditor
        self.producer_id = producer_id
        self._prestarted = {}
        SourceBindings(campaign)  # validate authoritative complete graph eagerly

    def _resolve(self, unit_id):
        unit, _ = _unit(self.campaign, unit_id)
        key = (unit["adapter_id"], unit["adapter_version"])
        adapter = self.adapters.get(key)
        if not callable(adapter) or not callable(self.auditor):
            raise FrameworkError("CALLER_ADAPTER_OR_AUDITOR_UNAVAILABLE")
        refs = SourceBindings(self.campaign).verify_unit(unit_id, unit)
        return unit, key, adapter, refs

    def begin_unit(self, unit_id):
        """Publish one typed start and retain same-object intent for execute_started."""
        unit, key, _adapter, refs = self._resolve(unit_id)
        self.campaign.begin_unit(unit_id, {"adapter_id": key[0], "adapter_version": key[1], "caller_schema": PAYLOAD_SCHEMA})
        state = self.campaign.recover()
        summary = state["receipts"][-1]
        if summary["phase"] != "start" or summary["unit_id"] != unit_id:
            raise FrameworkError("CALLER_START_RECEIPT_NOT_PUBLISHED")
        self._prestarted[unit_id] = summary["sha256"]
        return dict(summary)

    def execute_started(self, unit_id):
        """Execute only a start published by this caller object in this process."""
        started = self._prestarted.pop(unit_id, None)
        if not started:
            raise FrameworkError("CALLER_STARTED_UNIT_REQUIRED; recovery never redispatches")
        state = self.campaign.recover()
        if unit_id not in state["inflight"] or not state["receipts"] or state["receipts"][-1]["sha256"] != started:
            raise FrameworkError("CALLER_START_OWNERSHIP_OR_STATE_CHANGED")
        unit, _key, adapter, refs = self._resolve(unit_id)
        # A failure remains inflight; there is deliberately no retry path.
        try:
            adapted = adapter(deepcopy(unit), deepcopy(refs))
            result = self.auditor(deepcopy(unit), adapted)
            if not isinstance(result, dict) or set(result) != {"audit_result", "processing_disposition", "audit_disposition"}:
                raise FrameworkError("CALLER_AUDITOR_RESULT_INVALID")
            envelope = make_envelope(self.campaign, unit_id, producer_id=self.producer_id, **result)
        except (MemoryError, KeyboardInterrupt) as exc:
            reason = "RESOURCE_LIMIT" if isinstance(exc, MemoryError) else "EXTERNAL_INTERRUPTION"
            try:
                self.campaign.request_stop(reason, {"unit_id": unit_id, "stage": "caller_callback_or_publication",
                                                    "exception_type": type(exc).__name__})
            except ResourceLimitStop as stopped:
                raise exc from stopped
            raise
        return self.campaign.complete_unit(unit_id, result["processing_disposition"], envelope)

    def execute(self, unit_id):
        """Publish one typed start, then execute its callbacks exactly once."""
        self.begin_unit(unit_id)
        return self.execute_started(unit_id)

    def recover(self):
        # Campaign recovery invokes the same strict typed and source validators.
        return self.campaign.recover()
