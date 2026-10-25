"""Synthetic-only validation of frozen Session and Run authority records."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .i2_contract import I2ContractError, validate_budget
from .identity import canonical_json, sha256_bytes, strict_json_loads, validate_id
from .schema_registry import SchemaRegistry


_SCHEMAS = SchemaRegistry()


def _validate_schema(document: str, value: Mapping[str, Any]) -> None:
    entry = _SCHEMAS.find_document(document)
    result = _SCHEMAS.validate(entry.schema_id, entry.version, value)
    if not result.valid:
        raise I2ContractError(f"{document} rejected: " + "; ".join(result.errors))


def _utc(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise I2ContractError("UTC Z timestamp required")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise I2ContractError("invalid UTC timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise I2ContractError("non-UTC timestamp")
    return parsed


def require_time_window(issued: str, expires: str, now: str, *, prior_observed: str | None = None) -> None:
    issue_time, expiry_time, current = _utc(issued), _utc(expires), _utc(now)
    if issue_time >= expiry_time or current < issue_time or current >= expiry_time:
        raise I2ContractError("authority not currently valid")
    if prior_observed is not None and current < _utc(prior_observed):
        raise I2ContractError("clock moved backward or became ambiguous")


def _verify_proof(
    record: Mapping[str, Any], field: str, proof: bytes,
    public_key: Ed25519PublicKey,
) -> None:
    if not isinstance(proof, bytes) or sha256_bytes(proof) != record.get(field):
        raise I2ContractError("authority proof digest mismatch")
    unsigned = dict(record)
    unsigned.pop(field, None)
    try:
        public_key.verify(proof, canonical_json(unsigned))
    except InvalidSignature as exc:
        raise I2ContractError("authority issuer proof invalid") from exc


def _bound_identity(record: Mapping[str, Any], kind: str, entity_id: str, context: Mapping[str, str]) -> None:
    identity = record["identity"]
    if identity["entity_type"] != kind or identity["entity_id"] != entity_id:
        raise I2ContractError("authority identity type or ID mismatch")
    for field, expected in context.items():
        if identity.get(field) != expected:
            raise I2ContractError(f"authority identity {field} mismatch")


def verify_session_authority(
    record: Mapping[str, Any], proof: bytes, trusted_issuers: Mapping[str, Ed25519PublicKey],
    now: str, *, prior_observed: str | None = None,
) -> bytes:
    """Validate a supplied synthetic authority. An ID or schema alone is no grant."""
    _validate_schema("OP1_SESSION_AUTHORITY_SCHEMA.json", record)
    issuer = validate_id(record["issuer_actor_id"], "ACTOR")
    key = trusted_issuers.get(issuer)
    if not isinstance(key, Ed25519PublicKey):
        raise I2ContractError("untrusted Session authority issuer")
    _verify_proof(record, "authority_proof_sha256", proof, key)
    _bound_identity(record, "AUTHORITY", record["authority_id"], {
        field: record[field] for field in ("product_id", "lineage_id", "version_id", "freeze_id")
    } | {"session_id": record["session_id"]})
    require_time_window(record["issued_at_utc"], record["expires_at_utc"], now,
                        prior_observed=prior_observed)
    if record["run_authorization_required"] is not True:
        raise I2ContractError("Session authority cannot execute a Run")
    if record["max_runs"] < 1:
        raise I2ContractError("Session max_runs invalid")
    validate_budget(record["resource_ceilings"])
    return canonical_json(record)


def verify_run_authority(
    record: Mapping[str, Any], proof: bytes, trusted_issuers: Mapping[str, Ed25519PublicKey],
    session: Mapping[str, Any], session_bytes: bytes, now: str,
    read_exact_binding: Callable[[str], bytes], *,
    prior_observed: str | None = None,
) -> bytes:
    """Rehash immutable child bindings immediately before synthetic claim consideration."""
    _validate_schema("OP1_RUN_AUTHORITY_SCHEMA.json", record)
    issuer = validate_id(record["issuer_actor_id"], "ACTOR")
    key = trusted_issuers.get(issuer)
    if not isinstance(key, Ed25519PublicKey):
        raise I2ContractError("untrusted Run authority issuer")
    _verify_proof(record, "proof_sha256", proof, key)
    context = {field: session[field] for field in ("product_id", "lineage_id", "version_id", "freeze_id")}
    context.update(session_id=session["session_id"], run_id=record["run_id"])
    _bound_identity(record, "AUTHORITY", record["authority_id"], context)
    require_time_window(session["issued_at_utc"], session["expires_at_utc"], now,
                        prior_observed=prior_observed)
    require_time_window(record["issued_at_utc"], record["expires_at_utc"], now,
                        prior_observed=prior_observed)
    if _utc(record["expires_at_utc"]) > _utc(session["expires_at_utc"]):
        raise I2ContractError("Run authority exceeds Session expiry")
    if record["session_authority_sha256"] != sha256_bytes(session_bytes):
        raise I2ContractError("wrong parent Session authority")
    if record["session_id"] != session["session_id"] or record["owner_actor_id"] != session["owner_actor_id"]:
        raise I2ContractError("cross-Session or owner authority")
    if record["freeze_manifest_sha256"] != session["freeze_manifest_sha256"]:
        raise I2ContractError("cross-freeze authority")
    if record["operation_class"] not in session["allowed_operation_classes"]:
        raise I2ContractError("unauthorized operation class")
    if record["target_class"] != session["target_class"]:
        raise I2ContractError("target class mismatch")
    if record["one_shot"] is not True:
        raise I2ContractError("Run authority is not one-shot")
    session_budget = validate_budget(session["resource_ceilings"])
    run_budget = validate_budget(record["resource_ceilings"])
    if any(run_budget[name] > session_budget[name] for name in run_budget):
        raise I2ContractError("Run budget exceeds Session")
    policy_bytes = canonical_json(session["policy_bindings"])
    if record["policy_manifest_sha256"] != sha256_bytes(policy_bytes):
        raise I2ContractError("Session policy digest mismatch")
    relative = record["exact_binding_manifest_relative_path"]
    if not isinstance(relative, str) or not relative or relative.startswith(("/", "\\")) or ".." in relative.split("/"):
        raise I2ContractError("unsafe exact binding path")
    try:
        exact_bytes = read_exact_binding(relative)
    except (OSError, ValueError) as exc:
        raise I2ContractError("exact binding unavailable") from exc
    if not isinstance(exact_bytes, bytes) or sha256_bytes(exact_bytes) != record["exact_binding_manifest_sha256"]:
        raise I2ContractError("exact binding bytes mismatch")
    manifest = strict_json_loads(exact_bytes)
    _validate_schema("OP1_RUN_EXACT_BINDING_SCHEMA.json", manifest)
    if canonical_json(manifest) != exact_bytes or manifest != record["exact_binding_manifest"]:
        raise I2ContractError("inline/external exact binding mismatch")
    if manifest["freeze_id"] != session["freeze_id"]:
        raise I2ContractError("exact binding freeze mismatch")
    if set(manifest["policy_ids"]) != {item["policy_id"] for item in session["policy_bindings"]}:
        raise I2ContractError("exact binding policy IDs mismatch")
    if set(manifest["tool_ids"]) - set(session["allowed_tool_ids"]):
        raise I2ContractError("exact binding tool outside Session scope")
    if manifest["operation_class"] != record["operation_class"] or manifest["target_class"] != record["target_class"]:
        raise I2ContractError("exact binding class mismatch")
    if manifest["command_request_sha256"] != record["command_sha256"]:
        raise I2ContractError("exact command mismatch")
    return canonical_json(record)


def verify_run_record(run: Mapping[str, Any], authority: Mapping[str, Any],
                      session: Mapping[str, Any], reservation_event_id: str) -> None:
    _validate_schema("OP1_RUN_SCHEMA.json", run)
    if run["identity"]["entity_type"] != "RUN" or run["identity"]["entity_id"] != run["run_id"]:
        raise I2ContractError("Run identity mismatch")
    for field in ("product_id", "lineage_id", "version_id", "session_id"):
        expected = session[field] if field != "session_id" else session["session_id"]
        if run["identity"].get(field) != expected:
            raise I2ContractError(f"Run {field} mismatch")
    for field in ("run_id", "session_id", "namespace_id", "claim_id", "operation_id"):
        if run[field] != authority[field]:
            raise I2ContractError(f"Run {field} differs from authority")
    if run["run_authority_id"] != authority["authority_id"]:
        raise I2ContractError("Run authority ID mismatch")
    if run["attempt_ids"] != [authority["attempt_id"]]:
        raise I2ContractError("one execution-bearing attempt required")
    if run["source_freeze_id"] != session["freeze_id"]:
        raise I2ContractError("Run source freeze mismatch")
    if set(run["policy_ids"]) != {item["policy_id"] for item in session["policy_bindings"]}:
        raise I2ContractError("Run policy mismatch")
    if run["authorized_command_sha256"] != authority["command_sha256"]:
        raise I2ContractError("Run authorized command mismatch")
    if run["budget_reservation_event_id"] != reservation_event_id:
        raise I2ContractError("Run missing prior reservation event")


# Engineering convention for the frozen schema's otherwise unspecified readback digest.
_CLAIM_SLOT_FIELDS = (
    "claim_id", "run_id", "session_id", "run_authority_id", "claim_slot",
    "claim_operation_id", "claimer_actor_id", "namespace_id",
    "authorization_exact_sha256", "created_at_utc", "reservation_event_id",
    "state",
)

def claim_slot_preimage(claim: Mapping[str, Any]) -> bytes:
    return canonical_json({
        "schema": "package-g-op1-i2-engineering-claim-slot-preimage@1",
        "slot": {name: claim[name] for name in _CLAIM_SLOT_FIELDS},
    })

def claim_content_sha256(claim: Mapping[str, Any]) -> str:
    value = deepcopy(dict(claim))
    value["identity"].pop("content_sha256", None)
    return sha256_bytes(canonical_json(value))


def verify_claim_record(
    claim: Mapping[str, Any], run: Mapping[str, Any], authority: Mapping[str, Any],
    authority_bytes: bytes, reservation_event_id: str,
) -> None:
    _validate_schema("OP1_RUN_CLAIM_SCHEMA.json", claim)
    if claim["identity"]["entity_type"] != "CLAIM" or claim["identity"]["entity_id"] != claim["claim_id"]:
        raise I2ContractError("Claim identity mismatch")
    if claim["identity"]["actor_id"] != authority["owner_actor_id"]:
        raise I2ContractError("Claim identity actor mismatch")
    for field in ("product_id", "lineage_id", "version_id", "session_id", "run_id"):
        if claim["identity"].get(field) != run["identity"].get(field):
            raise I2ContractError(f"Claim identity {field} mismatch")
    for field in ("claim_id", "run_id", "session_id", "namespace_id"):
        if claim[field] != run[field]:
            raise I2ContractError(f"Claim {field} differs from Run")
    if claim["claim_slot"] != run["claim_slot"]:
        raise I2ContractError("Claim slot differs from Run")
    if claim["claim_operation_id"] != run["operation_id"]:
        raise I2ContractError("Claim operation differs from Run")
    if claim["claimer_actor_id"] != authority["owner_actor_id"]:
        raise I2ContractError("Claim owner mismatch")
    if claim["run_authority_id"] != authority["authority_id"]:
        raise I2ContractError("Claim authority mismatch")
    if claim["reservation_event_id"] != reservation_event_id:
        raise I2ContractError("Claim reservation mismatch")
    if claim["authorization_exact_sha256"] != sha256_bytes(authority_bytes):
        raise I2ContractError("Claim exact authority mismatch")
    if claim["state"] not in {"CONSUMED", "AMBIGUOUS_CONSUMPTION"}:
        raise I2ContractError("Claim state invalid")
    if claim["durable_readback_sha256"] != sha256_bytes(claim_slot_preimage(claim)):
        raise I2ContractError("Claim durable readback digest differs from slot preimage")
    if claim["identity"].get("content_sha256") != claim_content_sha256(claim):
        raise I2ContractError("Claim identity content digest mismatch")
