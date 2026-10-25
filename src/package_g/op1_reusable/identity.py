"""Typed, random OP1 IDs. An ID has no authority or byte-identity meaning."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from importlib import resources
from typing import Any

SOURCE_FREEZE_ID = "PG-FRZ-e55f2e60890261eb8452d9168f776552"
IDENTITY_SCHEMA_SHA256 = "8f9888551d035d81f6d085eb6589a90ebffb868760869dcafcc0c5805b0e0b45"


class IdentityError(ValueError):
    """An ID or identity relationship violates the frozen contract."""


def strict_json_loads(data: bytes | str) -> Any:
    """Parse exact JSON without duplicate object keys or non-JSON numbers."""
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise IdentityError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def bad_constant(value: str) -> None:
        raise IdentityError(f"invalid JSON constant: {value}")

    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=bad_constant)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise IdentityError("invalid UTF-8 JSON") from exc


def canonical_json(value: Any) -> bytes:
    """Stable UTF-8 serialization for I0 manifests and receipts."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise IdentityError("value is not canonical JSON") from exc


def sha256_bytes(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise IdentityError("byte identity requires exact bytes")
    return hashlib.sha256(data).hexdigest()


def validate_sha256(value: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise IdentityError("malformed SHA-256")
    return value


_schema_bytes = resources.files(__package__).joinpath("schemas", "OP1_IDENTITY_ENVELOPE_SCHEMA.json").read_bytes()
if sha256_bytes(_schema_bytes) != IDENTITY_SCHEMA_SHA256:
    raise IdentityError("frozen identity schema hash mismatch")
_identity_schema = strict_json_loads(_schema_bytes)
TYPE_PREFIXES: dict[str, str] = dict(_identity_schema["x-identity-law"]["type_prefixes"])
if len(TYPE_PREFIXES) != 34 or len(set(TYPE_PREFIXES.values())) != 34:
    raise IdentityError("frozen identity type inventory mismatch")
PREFIX_TYPES = {prefix: kind for kind, prefix in TYPE_PREFIXES.items()}
REQUIRED_HIERARCHY: dict[str, tuple[str, ...]] = {
    clause["if"]["properties"]["entity_type"]["const"]: tuple(clause["then"].get("required", ()))
    for clause in _identity_schema["allOf"]
}
if set(REQUIRED_HIERARCHY) != set(TYPE_PREFIXES):
    raise IdentityError("frozen hierarchy inventory mismatch")

_ID_RE = re.compile(r"PG-([A-Z]+)-([0-9a-f]{32})\Z")
HIERARCHY_TYPES = {
    "project_id": "PROJECT", "product_id": "PRODUCT", "lineage_id": "LINEAGE",
    "version_id": "VERSION", "freeze_id": "FREEZE", "session_id": "SESSION", "run_id": "RUN",
}


def parse_id(value: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise IdentityError("ID must be a string")
    match = _ID_RE.fullmatch(value)
    if match is None or match.group(1) not in PREFIX_TYPES:
        raise IdentityError("malformed or unknown typed ID")
    return PREFIX_TYPES[match.group(1)], match.group(2)


def validate_id(value: str, expected_type: str | None = None) -> str:
    kind, _ = parse_id(value)
    if expected_type is not None and kind != expected_type:
        raise IdentityError(f"ID type {kind} does not match {expected_type}")
    return value


def generate_id(entity_type: str, *, entropy: bytes | None = None) -> str:
    """Allocate one candidate; callers reject a collision, never retry silently."""
    if entity_type not in TYPE_PREFIXES:
        raise IdentityError("unknown entity type")
    random_bytes = secrets.token_bytes(16) if entropy is None else entropy
    if not isinstance(random_bytes, bytes) or len(random_bytes) != 16:
        raise IdentityError("ID entropy must be exactly 16 bytes")
    return f"PG-{TYPE_PREFIXES[entity_type]}-{random_bytes.hex()}"
