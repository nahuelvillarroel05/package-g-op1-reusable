"""Synthetic, provenance-tagged fixtures for all frozen I0 JSON schemas."""
from __future__ import annotations

import copy
import json
import re
from importlib import resources

import pytest

from package_g.op1_reusable.identity import TYPE_PREFIXES, canonical_json, generate_id, sha256_bytes
from package_g.op1_reusable.schema_registry import SchemaError, SchemaRegistry

REGISTRY = SchemaRegistry()
ENTRIES = REGISTRY.entries


def _value(spec, document, field="", depth=0):
    assert depth < 20
    if "$ref" in spec:
        target = spec["$ref"]
        if target.startswith("#/$defs/"):
            return _value(document["$defs"][target.rsplit("/", 1)[-1]], document, field, depth + 1)
        return _value(REGISTRY._documents[target], REGISTRY._documents[target], field, depth + 1)
    if "oneOf" in spec:
        return _value(spec["oneOf"][0], spec["oneOf"][0], field, depth + 1)
    if "const" in spec:
        return spec["const"]
    if "enum" in spec:
        return spec["enum"][0]
    typ = spec.get("type", "object" if "properties" in spec else "string")
    if isinstance(typ, list):
        typ = next(t for t in typ if t != "null")
    if typ == "object":
        if spec.get("$id") == "OP1_IDENTITY_ENVELOPE_SCHEMA.json":
            return {"entity_id": generate_id("PROJECT"), "entity_type": "PROJECT", "schema_id": generate_id("SCHEMA"), "schema_version": "1.0.0", "actor_id": generate_id("ACTOR"), "created_at_utc": "2026-09-23T00:00:00Z", "status": "CREATED"}
        props = spec.get("properties", {})
        return {key: _value(props[key], document, key, depth + 1) for key in spec.get("required", [])}
    if typ == "array":
        return [_value(spec.get("items", {"type": "string"}), document, field, depth + 1) for _ in range(spec.get("minItems", 0))]
    if typ == "integer":
        return max(1, spec.get("minimum", 0))
    if typ == "number":
        return max(1, spec.get("minimum", 0))
    if typ == "boolean":
        return True
    if typ == "null":
        return None
    pattern = spec.get("pattern", "")
    match = re.match(r"\^PG-([A-Z]+)-", pattern)
    if match:
        prefix = match.group(1)
        kind = next(k for k, p in TYPE_PREFIXES.items() if p == prefix)
        return generate_id(kind)
    if pattern == "^[0-9a-f]{64}$":
        return "a" * 64
    if "\\." in pattern and "[0-9]" in pattern:
        return "1.0.0"
    if spec.get("format") == "date-time":
        return "2026-09-23T00:00:00Z"
    if field.endswith("relative_path") or field == "relative_path":
        return "synthetic/artifact.json"
    return "synthetic"


def fixture_for(entry):
    document = REGISTRY._documents[entry.document_id]
    fixture = _value(document, document)
    return {"fixture_id": generate_id("ARTIFACT"), "schema_id": entry.schema_id, "schema_version": entry.version, "source_sha256": entry.sha256, "value": fixture, "value_sha256": sha256_bytes(canonical_json(fixture)), "provenance": "SYNTHETIC_I0_SCHEMA_TEST"}


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.document_id)
def test_all_frozen_schemas_accept_provenance_tagged_minimal_fixture(entry):
    fixture = fixture_for(entry)
    assert fixture["value_sha256"] == sha256_bytes(canonical_json(fixture["value"]))
    result = REGISTRY.validate(fixture["schema_id"], fixture["schema_version"], fixture["value"], expected_sha256=fixture["source_sha256"])
    assert result.valid, (entry.document_id, result.errors)


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.document_id)
def test_missing_required_and_unexpected_field_rejected_when_closed(entry):
    fixture = fixture_for(entry)
    doc = REGISTRY._documents[entry.document_id]
    branch = doc.get("oneOf", [doc])[0]
    for required in branch.get("required", []):
        bad = copy.deepcopy(fixture["value"])
        del bad[required]
        assert not REGISTRY.validate(entry.schema_id, entry.version, bad).valid, (entry.document_id, required)
    if branch.get("additionalProperties") is False:
        bad = copy.deepcopy(fixture["value"])
        bad["unexpected_I0_field"] = True
        assert not REGISTRY.validate(entry.schema_id, entry.version, bad).valid, entry.document_id


def test_exact_lookup_unknown_version_schema_and_hash_reject():
    entry = ENTRIES[0]
    for schema_id, version, digest in [(entry.schema_id, "9.9.9", None), (generate_id("SCHEMA"), entry.version, None), (entry.schema_id, entry.version, "0" * 64)]:
        with pytest.raises(SchemaError):
            REGISTRY.lookup(schema_id, version, expected_sha256=digest)


def test_registry_is_deterministic_and_frozen_bytes_match():
    second = SchemaRegistry()
    assert REGISTRY.canonical_manifest_bytes() == second.canonical_manifest_bytes()
    assert [(e.schema_id, e.version, e.sha256) for e in REGISTRY.entries] == [(e.schema_id, e.version, e.sha256) for e in second.entries]
    assert [e.relative_path for e in REGISTRY.entries] == sorted(e.relative_path for e in REGISTRY.entries)
    for entry in ENTRIES:
        raw = resources.files("package_g.op1_reusable").joinpath(*entry.relative_path.split("/")).read_bytes()
        assert sha256_bytes(raw) == entry.sha256
        value = fixture_for(entry)["value"]
        assert REGISTRY.validate(entry.schema_id, entry.version, value).as_dict() == second.validate(entry.schema_id, entry.version, value).as_dict()


def test_schema_hash_tamper_and_registry_order_reject():
    entry = ENTRIES[0]
    with pytest.raises(SchemaError):
        SchemaRegistry(schema_bytes_by_path={entry.relative_path: b"{}"})
    manifest = json.loads(resources.files("package_g.op1_reusable").joinpath("schema_registry_manifest.json").read_bytes())
    manifest["entries"].reverse()
    with pytest.raises(SchemaError):
        SchemaRegistry(manifest_bytes=canonical_json(manifest))


def test_duplicate_json_key_non_json_number_and_canonical_serialization():
    entry = REGISTRY.find_document("OP1_RESOURCE_BUDGET_SCHEMA.json")
    assert not REGISTRY.validate_bytes(entry.schema_id, entry.version, b'{"cpu_ms":1,"cpu_ms":2}').valid
    assert not REGISTRY.validate_bytes(entry.schema_id, entry.version, b'{"cpu_ms":NaN}').valid
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_identity_closed_schema_and_content_hash_malformed():
    entry = REGISTRY.find_document("OP1_IDENTITY_ENVELOPE_SCHEMA.json")
    fixture = fixture_for(entry)["value"]
    assert REGISTRY.validate(entry.schema_id, entry.version, fixture).valid
    bad = dict(fixture, extra="unexpected")
    assert not REGISTRY.validate(entry.schema_id, entry.version, bad).valid
    bad = dict(fixture, content_sha256="ABC")
    assert not REGISTRY.validate(entry.schema_id, entry.version, bad).valid

@pytest.mark.parametrize("branch_index", range(5))
def test_all_provenance_record_branches_validate(branch_index):
    entry = REGISTRY.find_document("OP1_ACTOR_MODEL_TOOL_PROVENANCE_SCHEMA.json")
    document = REGISTRY._documents[entry.document_id]
    branch = document["oneOf"][branch_index]
    fixture = _value(branch, branch)
    if branch_index == 4 and fixture["output_state"] == "PRESENT":
        fixture["output_sha256"] = "a" * 64
    fixture_provenance = {"fixture_id": generate_id("ARTIFACT"), "schema_id": entry.schema_id, "source_sha256": entry.sha256, "branch_index": branch_index, "fixture_sha256": sha256_bytes(canonical_json(fixture))}
    assert fixture_provenance["fixture_sha256"] == sha256_bytes(canonical_json(fixture))
    result = REGISTRY.validate(entry.schema_id, entry.version, fixture)
    assert result.valid, result.errors


def test_conditional_native_binding_and_event_publication_roles_reject():
    binding = REGISTRY.find_document("OP1_RUN_EXACT_BINDING_SCHEMA.json")
    value = fixture_for(binding)["value"]
    value["operation_class"] = "QUALIFIED_LOOPBACK_NATIVE"
    assert not REGISTRY.validate(binding.schema_id, binding.version, value).valid
    event = REGISTRY.find_document("OP1_EVENT_SCHEMA.json")
    value = fixture_for(event)["value"]
    value["produced_artifact_ids"] = [generate_id("ARTIFACT")]
    assert not REGISTRY.validate(event.schema_id, event.version, value).valid
    value["event_role"] = "PUBLICATION"
    assert REGISTRY.validate(event.schema_id, event.version, value).valid


def test_manifest_schema_id_swap_rejects_even_when_schema_bytes_match():
    from package_g.op1_reusable.schema_registry import REGISTRY_MANIFEST_SHA256
    raw = resources.files("package_g.op1_reusable").joinpath("schema_registry_manifest.json").read_bytes()
    assert sha256_bytes(raw) == REGISTRY_MANIFEST_SHA256
    manifest = json.loads(raw)
    manifest["entries"][0]["schema_id"] = generate_id("SCHEMA")
    with pytest.raises(SchemaError):
        SchemaRegistry(manifest_bytes=canonical_json(manifest))
