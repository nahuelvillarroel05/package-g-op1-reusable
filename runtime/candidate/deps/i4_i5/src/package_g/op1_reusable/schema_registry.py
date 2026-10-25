"""Exact frozen-schema lookup and offline Draft 2020-12 validation."""
from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from pathlib import PurePosixPath
from typing import Any, Mapping

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from .identity import (
    SOURCE_FREEZE_ID, canonical_json, generate_id, sha256_bytes,
    strict_json_loads, validate_id, validate_sha256,
)

SOURCE_FREEZE_SHA256 = "bbe63ee96d03712109da9f48f966a6b9c470c050092871cce3e330118ed89465"
SCHEMA_VERSION = "1.0.0"
REGISTRY_MANIFEST_SHA256 = "53586c1b5156738bf0e86dce4b23684dd04175e9218ae0f6ac9c855812c42a8d"


class SchemaError(ValueError):
    """A schema binding or validation is invalid or unavailable."""


@dataclass(frozen=True)
class SchemaEntry:
    schema_id: str
    version: str
    sha256: str
    source_freeze_id: str
    relative_path: str
    document_id: str
    status: str


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"valid": self.valid, "errors": list(self.errors)}


class SchemaRegistry:
    """Immutable 15-schema snapshot. Lookup is by exact ID and version."""

    def __init__(
        self,
        *,
        manifest_bytes: bytes | None = None,
        schema_bytes_by_path: Mapping[str, bytes] | None = None,
    ) -> None:
        package = resources.files(__package__)
        raw_manifest = manifest_bytes if manifest_bytes is not None else package.joinpath("schema_registry_manifest.json").read_bytes()
        if sha256_bytes(raw_manifest) != REGISTRY_MANIFEST_SHA256:
            raise SchemaError("registry manifest byte hash mismatch")
        manifest = strict_json_loads(raw_manifest)
        if not isinstance(manifest, dict) or manifest.get("source_freeze_id") != SOURCE_FREEZE_ID or manifest.get("source_freeze_sha256") != SOURCE_FREEZE_SHA256:
            raise SchemaError("schema registry source freeze mismatch")
        validate_id(manifest.get("artifact_id"), "ARTIFACT")
        rows = manifest.get("entries")
        if not isinstance(rows, list) or len(rows) != 15 or manifest.get("entry_count") != 15:
            raise SchemaError("schema registry must contain the 15 frozen schemas")
        if [row.get("relative_path") for row in rows] != sorted(row.get("relative_path") for row in rows):
            raise SchemaError("schema registry order is not deterministic")
        entries: dict[tuple[str, str], SchemaEntry] = {}
        documents: dict[str, dict[str, Any]] = {}
        for row in rows:
            try:
                entry = SchemaEntry(**row)
            except TypeError as exc:
                raise SchemaError("invalid schema registry entry") from exc
            validate_id(entry.schema_id, "SCHEMA")
            validate_sha256(entry.sha256)
            path = PurePosixPath(entry.relative_path)
            if len(path.parts) != 2 or path.parts[0] != "schemas" or path.suffix != ".json" or path.name != entry.document_id:
                raise SchemaError("unsafe or mismatched schema path")
            if entry.source_freeze_id != SOURCE_FREEZE_ID or entry.version != SCHEMA_VERSION or entry.status != "FROZEN":
                raise SchemaError("schema metadata mismatch")
            key = (entry.schema_id, entry.version)
            if key in entries or entry.document_id in documents:
                raise SchemaError("duplicate schema identity")
            raw_schema = (
                schema_bytes_by_path[entry.relative_path]
                if schema_bytes_by_path is not None and entry.relative_path in schema_bytes_by_path
                else package.joinpath(*path.parts).read_bytes()
            )
            if sha256_bytes(raw_schema) != entry.sha256:
                raise SchemaError(f"schema hash mismatch: {entry.relative_path}")
            schema = strict_json_loads(raw_schema)
            if schema.get("$id") != entry.document_id or schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                raise SchemaError("schema identifier or dialect mismatch")
            Draft202012Validator.check_schema(schema)
            entries[key] = entry
            documents[entry.document_id] = schema
        resolver = Registry().with_resources((name, Resource.from_contents(doc)) for name, doc in documents.items())
        self._manifest = manifest
        self._entries = entries
        self._documents = documents
        self._validators = {
            key: Draft202012Validator(documents[entry.document_id], registry=resolver, format_checker=Draft202012Validator.FORMAT_CHECKER)
            for key, entry in entries.items()
        }
        self._load_receipts = tuple(
            {
                "event_id": generate_id("EVENT"), "schema_id": entry.schema_id,
                "version": entry.version, "sha256": entry.sha256,
                "source_freeze_id": entry.source_freeze_id,
                "relative_path": entry.relative_path, "status": "LOADED",
            }
            for entry in self.entries
        )

    @property
    def entries(self) -> tuple[SchemaEntry, ...]:
        return tuple(sorted(self._entries.values(), key=lambda entry: entry.relative_path))

    @property
    def load_receipts(self) -> tuple[dict[str, str], ...]:
        return self._load_receipts

    def canonical_manifest_bytes(self) -> bytes:
        return canonical_json(self._manifest)

    def find_document(self, document_id: str) -> SchemaEntry:
        """Administrative inventory lookup; never an authoritative latest fallback."""
        matches = [entry for entry in self.entries if entry.document_id == document_id]
        if len(matches) != 1:
            raise SchemaError("unknown schema document")
        return matches[0]

    def lookup(self, schema_id: str, version: str, *, expected_sha256: str | None = None) -> SchemaEntry:
        validate_id(schema_id, "SCHEMA")
        entry = self._entries.get((schema_id, version))
        if entry is None:
            raise SchemaError("unknown schema ID or version")
        if expected_sha256 is not None and expected_sha256 != entry.sha256:
            raise SchemaError("schema hash mismatch")
        return entry

    def validate(self, schema_id: str, version: str, value: Any, *, expected_sha256: str | None = None) -> ValidationResult:
        entry = self.lookup(schema_id, version, expected_sha256=expected_sha256)
        errors = self._validators[(entry.schema_id, entry.version)].iter_errors(value)
        messages = tuple(sorted(f"{error.json_path}: {error.message}" for error in errors))
        return ValidationResult(not messages, messages)

    def validate_bytes(self, schema_id: str, version: str, raw_json: bytes, *, expected_sha256: str | None = None) -> ValidationResult:
        try:
            value = strict_json_loads(raw_json)
        except ValueError as exc:
            return ValidationResult(False, (str(exc),))
        return self.validate(schema_id, version, value, expected_sha256=expected_sha256)
