"""Prospective ROOT_V2 declaration joins; no provider reads or admission.

The caller supplies an explicitly approved expected contract and observed
metadata. A successful join proves consistency of those declarations only,
not loaded bytes, process ownership, read authority, or historical events.
"""
from __future__ import annotations

import hashlib
import re


class BindingError(ValueError):
    """Missing, ambiguous, malformed, or inconsistent exact declaration."""


def _object(value, fields, label):
    if type(value) is not dict or set(value) != set(fields):
        raise BindingError(f"{label}: exact fields required")


def _name(value, label):
    if type(value) is not str or not value or value != value.strip():
        raise BindingError(f"{label}: nonempty exact string required")


def _roles(rows, label):
    if type(rows) is not list or not rows:
        raise BindingError(f"{label}: nonempty role list required")
    roles, providers = {}, set()
    for row in rows:
        _object(row, ("role", "provider_id", "source_id", "sha256", "inputs", "outputs"), label)
        for field in ("role", "provider_id"):
            _name(row[field], f"{label}.{field}")
        source = row["source_id"]
        if type(source) is not str or not re.fullmatch(r"source[0-9]{3}", source):
            raise BindingError(f"{label}: canonical source id required")
        if source == "source008":
            raise BindingError(f"{label}: source008 fallback prohibited")
        digest = row["sha256"]
        if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BindingError(f"{label}: exact lowercase SHA-256 required")
        for field in ("inputs", "outputs"):
            if type(row[field]) is not dict:
                raise BindingError(f"{label}.{field}: port/schema mapping required")
            for port, schema in row[field].items():
                _name(port, f"{label}.{field}.port")
                _name(schema, f"{label}.{field}.schema")
        role, provider = row["role"], row["provider_id"]
        if role in roles or provider in providers:
            raise BindingError(f"{label}: duplicate role/provider")
        roles[role] = row
        providers.add(provider)
    return roles


def validate_bindings(contract, observed):
    """Fail closed on exact role pins and every required input's schema join.

    No fallback or field inference is performed. Ports name role-specific
    artifact schemas; each required input has exactly one declared producer.
    ROOT_V2 here is a prospective Engineering interface, not a claim that a
    protected historical ROOT_V2 document or loaded provider was verified.
    """
    _object(contract, ("schema", "roles", "links"), "contract")
    _object(observed, ("schema", "roles"), "observed")
    if (type(contract["schema"]) is not str or type(observed["schema"]) is not str
            or contract["schema"] != "ROOT_V2" or observed["schema"] != "ROOT_V2"):
        raise BindingError("ROOT_V2 required; legacy fallback prohibited")
    expected = _roles(contract["roles"], "contract.roles")
    actual = _roles(observed["roles"], "observed.roles")
    if set(actual) != set(expected):
        raise BindingError("missing or unexpected observed role")
    for role, pin in expected.items():
        if actual[role] != pin:
            raise BindingError(f"{role}: provider/source/hash/input/output pin mismatch")
    links = contract["links"]
    if type(links) is not list:
        raise BindingError("contract.links: list required")
    covered = set()
    for link in links:
        _object(link, ("provider_role", "output", "consumer_role", "input"), "link")
        for field in link:
            _name(link[field], f"link.{field}")
        producer, consumer = link["provider_role"], link["consumer_role"]
        if producer not in expected or consumer not in expected:
            raise BindingError("link references unknown role")
        output, input_port = link["output"], link["input"]
        outputs, inputs = expected[producer]["outputs"], expected[consumer]["inputs"]
        if output not in outputs or input_port not in inputs:
            raise BindingError("link references unknown input/output port")
        if outputs[output] != inputs[input_port]:
            raise BindingError("producer/consumer artifact schema mismatch")
        target = (consumer, input_port)
        if target in covered:
            raise BindingError("duplicate producer for consumer input")
        covered.add(target)
    required = {(role, port) for role, row in expected.items() for port in row["inputs"]}
    if covered != required:
        raise BindingError("missing producer for required consumer input")
    return {
        "schema": "ENGINEERING_DECLARED_BINDING_RESULT_V1",
        "roles_verified": len(expected),
        "bindings_verified": len(covered),
        "operational_ownership": "NOT_PROVEN",
        "loaded_bytes_verified": False,
        "qualification_credit": 0,
    }


def validate_provider_bytes(contract, observed, provider_bytes):
    """Verify exact caller-supplied bytes after validating declaration joins.

    Inputs must be a complete provider-ID-to-bytes dict. No paths are accepted,
    opened, or imported. Byte identity alone does not prove these bytes were
    loaded by a runtime, came from an authorized read, or belong to an actor.
    """
    result = validate_bindings(contract, observed)
    pins = {row["provider_id"]: row["sha256"] for row in contract["roles"]}
    if type(provider_bytes) is not dict or set(provider_bytes) != set(pins):
        raise BindingError("exact complete provider-ID-to-bytes mapping required")
    for provider, digest in pins.items():
        payload = provider_bytes[provider]
        if type(payload) is not bytes:
            raise BindingError(f"{provider}: immutable bytes required")
        if hashlib.sha256(payload).hexdigest() != digest:
            raise BindingError(f"{provider}: supplied-byte SHA-256 mismatch")
    result.update(supplied_bytes_verified=True, provider_bytes_verified=len(pins))
    return result
