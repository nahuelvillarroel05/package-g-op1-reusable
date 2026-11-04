"""Authoritative, shared source dependencies; bodies remain outside checkpoints."""
from __future__ import annotations

from pathlib import Path

from .core import FrameworkError, canonical, digest, _loads, _path
from .provenance import _read_bound_file

SOURCE_SCHEMA = "pgop1.source-manifest.v1"
DEPENDENCY_SCHEMA = "pgop1.unit-source-dependencies.v1"


def _unique_strings(value, label):
    if (not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value)
            or len(set(value)) != len(value)):
        raise FrameworkError("SOURCE_DEPENDENCIES_INVALID:" + label)
    return value


class SourceBindings:
    """Read commitments independently from the externally bound configuration.

    Metadata is rehashed on every construction. Source bytes are rehashed when a
    dependency is used, including on recovery. No stat-based source cache.
    """
    def __init__(self, campaign):
        policy = campaign.config.get("audit_policy", {}).get("generic_caller")
        if not isinstance(policy, dict) or policy.get("schema") != "pgop1.generic-caller-config.v1":
            raise FrameworkError("GENERIC_CALLER_POLICY_REQUIRED")
        self.roots = [_path(x, True) for x in campaign.config["allowlisted_roots"]]
        documents = {}
        for field in ("source_manifest", "dependency_manifest"):
            ref = policy.get(field)
            if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
                raise FrameworkError("SOURCE_MANIFEST_COMMITMENT_REQUIRED:" + field)
            _, raw = _read_bound_file(ref["path"], ref["sha256"], self.roots, field)
            documents[field] = _loads(raw)
        source = documents["source_manifest"]
        deps = documents["dependency_manifest"]
        if source.get("schema") != SOURCE_SCHEMA or not isinstance(source.get("sources"), list):
            raise FrameworkError("SOURCE_MANIFEST_INVALID")
        if (deps.get("schema") != DEPENDENCY_SCHEMA
                or deps.get("source_manifest_sha256") != policy["source_manifest"]["sha256"]
                or deps.get("expected_units_sha256") != digest(canonical(sorted(campaign.config["expected_units"])))):
            raise FrameworkError("SOURCE_DEPENDENCY_AUTHORITY_MISMATCH")
        self.sources = {}
        paths = set()
        for row in source["sources"]:
            if (not isinstance(row, dict) or set(row) != {"source_id", "path", "sha256", "role"}
                    or not isinstance(row["source_id"], str) or not row["source_id"]
                    or row["source_id"] in self.sources or row["path"] in paths
                    or row["role"] not in {"PRIMARY", "SUPPORTING", "NORMATIVE_COMPANION"}):
                raise FrameworkError("SOURCE_MANIFEST_IDENTITY_INVALID")
            self.sources[row["source_id"]] = row
            paths.add(row["path"])
        self.groups = deps.get("groups", {})
        if not isinstance(self.groups, dict):
            raise FrameworkError("SOURCE_DEPENDENCY_GROUPS_INVALID")
        for name, group in self.groups.items():
            if (not isinstance(name, str) or not name or not isinstance(group, dict)
                    or set(group) != {"supporting_source_ids", "normative_companion_ids"}):
                raise FrameworkError("SOURCE_DEPENDENCY_GROUP_INVALID")
            for key in ("supporting_source_ids", "normative_companion_ids"):
                _unique_strings(group[key], key)
        if not isinstance(deps.get("units"), list):
            raise FrameworkError("SOURCE_DEPENDENCY_UNITS_INVALID")
        self.units = {}
        for row in deps["units"]:
            if (not isinstance(row, dict) or set(row) != {"unit_id", "primary_source_id", "dependency_group_ids", "supporting_source_ids", "normative_companion_ids"}
                    or not isinstance(row["unit_id"], str) or row["unit_id"] in self.units):
                raise FrameworkError("SOURCE_DEPENDENCY_UNIT_INVALID")
            for key in ("dependency_group_ids", "supporting_source_ids", "normative_companion_ids"):
                _unique_strings(row[key], key)
            self.units[row["unit_id"]] = row
        if set(self.units) != set(campaign.config["expected_units"]):
            raise FrameworkError("SOURCE_DEPENDENCY_POPULATION_MISMATCH")
        used = set()
        for unit_id in self.units:
            resolved = self.references(unit_id)
            used.update(x["source_id"] for x in resolved["all"])
        if used != set(self.sources):
            raise FrameworkError("SOURCE_MANIFEST_HAS_UNBOUND_MEMBERS")

    def references(self, unit_id):
        if unit_id not in self.units:
            raise FrameworkError("SOURCE_DEPENDENCY_UNIT_UNKNOWN")
        row = self.units[unit_id]
        supporting = set(row["supporting_source_ids"])
        normative = set(row["normative_companion_ids"])
        for group_id in row["dependency_group_ids"]:
            if group_id not in self.groups:
                raise FrameworkError("SOURCE_DEPENDENCY_GROUP_UNKNOWN")
            group = self.groups[group_id]
            supporting.update(group["supporting_source_ids"])
            normative.update(group["normative_companion_ids"])
        primary = row["primary_source_id"]
        if primary in supporting or primary in normative or supporting.intersection(normative):
            raise FrameworkError("SOURCE_DEPENDENCY_ROLES_OVERLAP")
        def get(source_id, role):
            ref = self.sources.get(source_id)
            if not ref or ref["role"] != role:
                raise FrameworkError("SOURCE_DEPENDENCY_MEMBER_OR_ROLE_MISMATCH")
            return dict(ref)
        result = {"primary": get(primary, "PRIMARY"),
                  "supporting": [get(s, "SUPPORTING") for s in sorted(supporting)],
                  "normative": [get(s, "NORMATIVE_COMPANION") for s in sorted(normative)]}
        result["all"] = [result["primary"], *result["supporting"], *result["normative"]]
        return result

    def verify_unit(self, unit_id, manifest_unit=None):
        refs = self.references(unit_id)
        if manifest_unit is not None and (refs["primary"]["source_id"] != manifest_unit["source_id"]
                or refs["primary"]["sha256"] != manifest_unit["source_sha256"]
                or ("source_path" in manifest_unit and refs["primary"]["path"] != manifest_unit["source_path"])):
            raise FrameworkError("SOURCE_DEPENDENCY_PRIMARY_MISMATCH")
        for ref in refs["all"]:
            _read_bound_file(ref["path"], ref["sha256"], self.roots, "source dependency")
        return refs

    def verify_all(self):
        for ref in self.sources.values():
            _read_bound_file(ref["path"], ref["sha256"], self.roots, "source dependency")
        return {"status": "PASS", "sources": len(self.sources), "units": len(self.units),
                "roles": {role: sum(x["role"] == role for x in self.sources.values())
                          for role in ("PRIMARY", "SUPPORTING", "NORMATIVE_COMPANION")},
                "source_bodies_copied": 0}
