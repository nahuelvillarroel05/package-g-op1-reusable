"""Prospective, disabled-by-default RUN006 rights and row-adapter helpers.

This module is an engineering boundary only. Rights evidence is external and
operation-specific; this code cannot grant rights or authenticate a producer.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .core import FrameworkError, canonical, digest
from .provenance import _read_bound_file

RUN006_SELECTION_SCHEMA = "pgop1.run006.selection.v1"
RUN006_RIGHTS_SCHEMA = "pgop1.run006.source-rights.v1"
RUN006_CONFIG_SCHEMA = "pgop1.run006.execution-config.v1"
RUN006_ASSESSMENT_SCHEMA = "pgop1.run006.rights-assessment.v1"
_HEX = set("0123456789abcdef")


def protected_row_run(run_id):
    """RUN007 reuses the exact bound row gate; no unrestricted RUN namespace."""
    return isinstance(run_id, str) and (run_id.upper().startswith("RUN006") or run_id == "RUN007")


@dataclass(frozen=True)
class _ValidatedDispatchContext:
    config_sha256: str
    campaign_attempt_id: str
    run_id: str
    candidate_commit: str
    candidate_tree: str


def _hash(value, label):
    if not isinstance(value, str) or len(value) != 64 or set(value) - _HEX:
        raise FrameworkError("RUN006_INVALID_SHA256:" + label)


def _git_sha1(value, label):
    if not isinstance(value, str) or len(value) != 40 or set(value) - _HEX:
        raise FrameworkError("RUN006_INVALID_GIT_BLOB_SHA1:" + label)


def assess_processing_rights(selection, evidence):
    """Match external rights rows to every selected source and exact operation.

    The result records evidence alignment only. It never synthesizes a grant
    from a repository name, benchmark family, URL, or producer declaration.
    """
    if not isinstance(selection, dict) or selection.get("schema") != RUN006_SELECTION_SCHEMA:
        raise FrameworkError("RUN006_SELECTION_SCHEMA_INVALID")
    if not isinstance(evidence, dict) or evidence.get("schema") != RUN006_RIGHTS_SCHEMA:
        raise FrameworkError("RUN006_RIGHTS_SCHEMA_INVALID")
    selection_id = selection.get("selection_id")
    if not isinstance(selection_id, str) or not selection_id:
        raise FrameworkError("RUN006_SELECTION_ID_REQUIRED")
    items = selection.get("items")
    grants = evidence.get("source_operations")
    excluded = evidence.get("excluded_output_ids", [])
    if (not isinstance(items, list) or not items or not isinstance(grants, list)
            or not isinstance(excluded, list) or any(not isinstance(x, str) for x in excluded)
            or len(excluded) != len(set(excluded))):
        raise FrameworkError("RUN006_RIGHTS_MEMBERSHIP_INVALID")
    evidence_refs = evidence.get("evidence_references")
    if not isinstance(evidence_refs, list) or not evidence_refs:
        raise FrameworkError("RUN006_RIGHTS_EVIDENCE_REFERENCES_REQUIRED")
    ref_pairs = set()
    for ref in evidence_refs:
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"} or not isinstance(ref["path"], str):
            raise FrameworkError("RUN006_RIGHTS_EVIDENCE_REFERENCE_INVALID")
        _hash(ref["sha256"], "evidence")
        pair = (ref["path"], ref["sha256"])
        if pair in ref_pairs:
            raise FrameworkError("RUN006_DUPLICATE_RIGHTS_EVIDENCE_REFERENCE")
        ref_pairs.add(pair)

    seen_output_ids = set()
    seen_selection_ids = set()
    seen_task_ids = set()
    assessments = []
    for item in items:
        if not isinstance(item, dict):
            raise FrameworkError("RUN006_SELECTION_ITEM_INVALID")
        item_id, output_id, task_id = (item.get("selection_id"), item.get("output_id"), item.get("task_id"))
        if (not all(isinstance(x, str) and x for x in (item_id, output_id, task_id))
                or item_id in seen_selection_ids or output_id in seen_output_ids
                or task_id in seen_task_ids):
            raise FrameworkError("RUN006_SELECTION_IDENTITY_DUPLICATE_OR_INVALID")
        seen_selection_ids.add(item_id)
        seen_output_ids.add(output_id)
        seen_task_ids.add(task_id)
        if output_id in excluded:
            raise FrameworkError("RUN006_SELECTED_OUTPUT_EXCLUDED")
        sources = item.get("sources")
        if not isinstance(sources, list) or not sources:
            raise FrameworkError("RUN006_SELECTED_SOURCE_REFS_REQUIRED")
        seen_roles = set()
        for source in sources:
            if not isinstance(source, dict):
                raise FrameworkError("RUN006_SELECTED_SOURCE_REF_INVALID")
            role, path = source.get("role"), source.get("path")
            source_hash = source.get("row_sha256", source.get("recorded_sha256"))
            operation, purpose = source.get("operation"), source.get("purpose")
            repository, commit = source.get("repository"), source.get("commit")
            repo_path, source_blob = source.get("repo_path"), source.get("source_blob_sha1")
            if (not isinstance(role, str) or not role or role in seen_roles
                    or not isinstance(path, str) or not path or not isinstance(operation, str) or not operation
                    or not isinstance(purpose, str) or not purpose
                    or not isinstance(repository, str) or not repository
                    or not isinstance(commit, str) or len(commit) != 40 or set(commit) - _HEX
                    or not isinstance(repo_path, str) or not repo_path):
                raise FrameworkError("RUN006_SELECTED_SOURCE_REF_INVALID")
            seen_roles.add(role)
            _hash(source_hash, "selected-source")
            _git_sha1(source_blob, "selected-source")
            candidates = [g for g in grants if isinstance(g, dict)
                          and g.get("selection_id") == item_id and g.get("output_id") == output_id
                          and g.get("task_id") == task_id and g.get("role") == role
                          and g.get("path") == path and g.get("sha256") == source_hash
                          and g.get("repository") == repository and g.get("commit") == commit
                          and g.get("repo_path") == repo_path and g.get("source_blob_sha1") == source_blob
                          and g.get("operation") == operation and g.get("purpose") == purpose]
            if len(candidates) != 1:
                status, grant_id = "RIGHTS_UNRESOLVED", None
                refs = []
                operation_scope_sha256 = None
            else:
                grant = candidates[0]
                grant_id = grant.get("grant_id")
                refs = grant.get("evidence_references")
                if (not isinstance(grant_id, str) or not grant_id
                        or not isinstance(refs, list) or not refs
                        or any(not isinstance(r, dict) or set(r) != {"path", "sha256"}
                               or (r.get("path"), r.get("sha256")) not in ref_pairs for r in refs)):
                    raise FrameworkError("RUN006_GRANT_EVIDENCE_BINDING_INVALID")
                status = grant.get("processing_status")
                if status not in {"PROCESSING_PERMITTED", "RIGHTS_UNRESOLVED", "PROCESSING_RESTRICTED"}:
                    raise FrameworkError("RUN006_GRANT_STATUS_INVALID")
                # Redistribution is separately reported and never implied by processing.
                if grant.get("redistribution_status") not in {"PERMITTED", "RESTRICTED", "UNRESOLVED"}:
                    raise FrameworkError("RUN006_REDISTRIBUTION_STATUS_INVALID")
                operation_scope = {"selection_id": item_id, "output_id": output_id,
                    "task_id": task_id, "role": role, "repository": repository,
                    "commit": commit, "repo_path": repo_path, "source_blob_sha1": source_blob,
                    "path": path, "sha256": source_hash, "operation": operation,
                    "purpose": purpose, "evidence_references": refs}
                operation_scope_sha256 = digest(canonical(operation_scope))
                if grant.get("operation_scope_sha256") != operation_scope_sha256:
                    raise FrameworkError("RUN006_OPERATION_SCOPE_HASH_MISMATCH")
            assessments.append({"selection_id": item_id, "output_id": output_id,
                                "task_id": task_id, "role": role, "repository": repository,
                                "commit": commit, "repo_path": repo_path,
                                "source_blob_sha1": source_blob, "path": path,
                                "sha256": source_hash, "operation": operation,
                                "purpose": purpose, "operation_scope_sha256": operation_scope_sha256,
                                "evidence_references": refs, "processing_status": status,
                                "redistribution_status": grant.get("redistribution_status") if len(candidates) == 1 else "UNRESOLVED",
                                "grant_id": grant_id})
    if (len(grants) != sum(1 for g in grants if isinstance(g, dict))
            or len(grants) != len(assessments)):
        raise FrameworkError("RUN006_RIGHTS_GRANT_INVALID")
    covered = {(r["selection_id"], r["output_id"], r["task_id"], r["role"], r["repository"],
                r["commit"], r["repo_path"], r["source_blob_sha1"], r["path"], r["sha256"],
                r["operation"], r["purpose"]) for r in assessments}
    for grant in grants:
        key = (grant.get("selection_id"), grant.get("output_id"), grant.get("task_id"),
               grant.get("role"), grant.get("repository"), grant.get("commit"),
               grant.get("repo_path"), grant.get("source_blob_sha1"),
               grant.get("path"), grant.get("sha256"),
               grant.get("operation"), grant.get("purpose"))
        if key not in covered:
            raise FrameworkError("RUN006_UNSELECTED_RIGHTS_GRANT")
    permitted = bool(assessments) and all(r["processing_status"] == "PROCESSING_PERMITTED" for r in assessments)
    return {"schema": RUN006_ASSESSMENT_SCHEMA, "selection_id": selection_id,
            "selection_sha256": digest(canonical(selection)),
            "rights_evidence_sha256": digest(canonical(evidence)),
            "status": "PROCESSING_PERMITTED" if permitted else "RIGHTS_UNRESOLVED",
            "rights_granted_by_runner": False,
            "redistribution_granted_by_processing": False,
            "sources": assessments}


def validate_dispatch_config(config, selection, assessment, launch_authorization=None, freeze=None):
    """Reject before runner import/construction unless a future grant is exact."""
    if not isinstance(config, dict) or config.get("schema") != RUN006_CONFIG_SCHEMA:
        raise FrameworkError("RUN006_CONFIG_SCHEMA_INVALID")
    if type(config.get("enabled")) is not bool:
        raise FrameworkError("RUN006_CONFIG_ENABLED_REQUIRED")
    if config["enabled"] is not True:
        raise FrameworkError("RUN006_EXECUTION_DISABLED")
    if not isinstance(selection, dict) or selection.get("schema") != RUN006_SELECTION_SCHEMA:
        raise FrameworkError("RUN006_SELECTION_SCHEMA_INVALID")
    if not isinstance(assessment, dict) or assessment.get("schema") != RUN006_ASSESSMENT_SCHEMA:
        raise FrameworkError("RUN006_ASSESSMENT_SCHEMA_INVALID")
    if (assessment.get("selection_id") != selection.get("selection_id")
            or assessment.get("selection_sha256") != digest(canonical(selection))
            or config.get("selection_sha256") != digest(canonical(selection))
            or config.get("rights_assessment_sha256") != digest(canonical(assessment))):
        raise FrameworkError("RUN006_FROZEN_RIGHTS_OR_SELECTION_BINDING_MISMATCH")
    if assessment.get("status") != "PROCESSING_PERMITTED" or not assessment.get("sources"):
        raise FrameworkError("RUN006_PROCESSING_RIGHTS_NOT_GRANTED")
    if assessment.get("rights_granted_by_runner") is not False:
        raise FrameworkError("RUN006_RUNNER_CANNOT_GRANT_RIGHTS")
    if any(not isinstance(row, dict) or row.get("processing_status") != "PROCESSING_PERMITTED"
           for row in assessment["sources"]):
        raise FrameworkError("RUN006_PROCESSING_RIGHTS_NOT_GRANTED")
    expected_sources = []
    for item in selection.get("items", []):
        if not isinstance(item, dict) or not isinstance(item.get("sources"), list):
            raise FrameworkError("RUN006_SELECTION_SOURCE_SET_INVALID")
        for source in item["sources"]:
            if not isinstance(source, dict):
                raise FrameworkError("RUN006_SELECTION_SOURCE_SET_INVALID")
            expected_sources.append((item.get("selection_id"), item.get("output_id"), item.get("task_id"),
                source.get("role"), source.get("repository"), source.get("commit"), source.get("repo_path"),
                source.get("source_blob_sha1"), source.get("path"), source.get("row_sha256", source.get("recorded_sha256")),
                source.get("operation"), source.get("purpose")))
    actual_sources = []
    for row in assessment["sources"]:
        actual_sources.append((row.get("selection_id"), row.get("output_id"), row.get("task_id"),
            row.get("role"), row.get("repository"), row.get("commit"), row.get("repo_path"),
            row.get("source_blob_sha1"), row.get("path"), row.get("sha256"), row.get("operation"), row.get("purpose")))
        scope = {key: row.get(key) for key in ("selection_id", "output_id", "task_id", "role", "repository",
            "commit", "repo_path", "source_blob_sha1", "path", "operation", "purpose", "evidence_references")}
        scope["sha256"] = row.get("sha256")
        if row.get("operation_scope_sha256") != digest(canonical(scope)):
            raise FrameworkError("RUN006_OPERATION_SCOPE_HASH_MISMATCH")
    if (len(expected_sources) != len(actual_sources) or len(set(expected_sources)) != len(expected_sources)
            or len(set(actual_sources)) != len(actual_sources) or set(expected_sources) != set(actual_sources)):
        raise FrameworkError("RUN006_ASSESSMENT_SOURCE_MEMBERSHIP_MISMATCH")
    if (not isinstance(launch_authorization, dict)
            or launch_authorization.get("schema") != "pgop1.run006.launch-authorization.v1"
            or launch_authorization.get("status") != "OWNER_AUTHORIZED"
            or launch_authorization.get("selection_sha256") != digest(canonical(selection))
            or launch_authorization.get("rights_assessment_sha256") != digest(canonical(assessment))
            or config.get("launch_authorization_sha256") != digest(canonical(launch_authorization))):
        raise FrameworkError("RUN006_OWNER_LAUNCH_AUTHORIZATION_REQUIRED")
    attempt_id = launch_authorization.get("campaign_attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        raise FrameworkError("RUN006_FRESH_ATTEMPT_ID_REQUIRED")
    if (not isinstance(freeze, dict) or freeze.get("schema") != "pgop1.run006.execution-freeze.v1"
            or freeze.get("status") != "FROZEN"
            or freeze.get("campaign_attempt_id") != attempt_id
            or freeze.get("candidate_commit") != config.get("candidate_commit")
            or freeze.get("candidate_tree") != config.get("candidate_tree")
            or freeze.get("selection_sha256") != digest(canonical(selection))
            or freeze.get("rights_assessment_sha256") != digest(canonical(assessment))
            or freeze.get("launch_authorization_sha256") != digest(canonical(launch_authorization))
            or freeze.get("runner_config_sha256") != config.get("runner_config_sha256")
            or config.get("execution_freeze_sha256") != digest(canonical(freeze))
            or freeze.get("fresh_attempt") is not True or freeze.get("reuse_prior_attempt") is not False):
        raise FrameworkError("RUN006_OPERATIONAL_FREEZE_REQUIRED")
    return {"dispatch": "ENABLED_BY_EXACT_BOUND_RIGHTS", "selected_sources": len(assessment["sources"]),
            "rights_granted_by_runner": False}


def validate_runner_scope(config, selection, assessment, runner_config, runner_args):
    """Join the frozen rights selection to runner metadata before any body read."""
    from .core import _loads
    from .provenance import _read_bound_file
    roots = runner_config.get("allowlisted_roots")
    if not isinstance(roots, list) or not roots:
        raise FrameworkError("RUN006_RUNNER_ROOTS_REQUIRED")
    from .core import _path
    roots = [_path(root, True) for root in roots]
    bindings = runner_config.get("input_bindings")
    metadata = config.get("metadata_bindings")
    if not isinstance(bindings, list) or not isinstance(metadata, list):
        raise FrameworkError("RUN006_METADATA_BINDINGS_REQUIRED")
    def pairs(rows, label):
        result = set()
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"path", "sha256"}
                    or not isinstance(row["path"], str)):
                raise FrameworkError("RUN006_BINDING_INVALID:" + label)
            _hash(row["sha256"], label)
            pair = (row["path"], row["sha256"])
            if pair in result:
                raise FrameworkError("RUN006_BINDING_DUPLICATE:" + label)
            result.add(pair)
        return result

    binding_pairs = pairs(bindings, "runner input")
    metadata_pairs = pairs(metadata, "metadata")
    selection_sources = {}
    expected_units = {}
    for item in selection["items"]:
        if item["output_id"] in expected_units or item["task_id"] in {x["task_id"] for x in expected_units.values()}:
            raise FrameworkError("RUN006_SELECTION_DUPLICATE_TASK_OR_OUTPUT")
        expected_units[item["output_id"]] = item
        by_role = {}
        for source in item["sources"]:
            ref = {"path": source["path"], "sha256": source["row_sha256"]}
            if source["role"] in by_role:
                raise FrameworkError("RUN006_SELECTION_DUPLICATE_SOURCE_ROLE")
            by_role[source["role"]] = ref
        if set(by_role) != {"task", "response"}:
            raise FrameworkError("RUN006_SELECTION_SOURCE_ROLES_INVALID")
        selection_sources[item["output_id"]] = by_role
    if (selection.get("expected_units") != list(expected_units)
            or len(selection.get("expected_units", [])) != len(expected_units)):
        raise FrameworkError("RUN006_SELECTION_EXPECTED_UNITS_MISMATCH")
    source_pairs = {(ref["path"], ref["sha256"]) for rows in selection_sources.values() for ref in rows.values()}
    if len(source_pairs) != sum(len(rows) for rows in selection_sources.values()):
        raise FrameworkError("RUN006_SELECTED_SOURCE_REUSED_ACROSS_OUTPUTS")
    if metadata_pairs & source_pairs:
        raise FrameworkError("RUN006_BODY_REFERENCE_MISCLASSIFIED_AS_METADATA")
    expected_bindings = source_pairs | metadata_pairs
    if binding_pairs != expected_bindings:
        raise FrameworkError("RUN006_RUNNER_INPUT_SET_DIFFERS_FROM_SELECTION_AND_METADATA")
    required_refs = {}
    for key in ("selection", "rights_evidence", "rights_assessment", "admission"):
        ref = config.get(key)
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
            raise FrameworkError("RUN006_METADATA_REFERENCE_REQUIRED:" + key)
        required_refs[key] = (ref["path"], ref["sha256"])
        if required_refs[key] not in metadata_pairs:
            raise FrameworkError("RUN006_METADATA_REFERENCE_NOT_BOUND:" + key)
    selection_ref = runner_config.get("selection_manifest")
    if (not isinstance(selection_ref, dict)
            or (selection_ref.get("path"), selection_ref.get("sha256")) != required_refs["selection"]):
        raise FrameworkError("RUN006_RUNNER_SELECTION_REF_MISMATCH")
    if (str(Path(config["runner_config"]["path"]).resolve()) != str(Path(runner_args.config).resolve())
            or config["runner_config"].get("sha256") != config.get("runner_config_sha256")):
        raise FrameworkError("RUN006_OUTER_RUNNER_CONFIG_REF_MISMATCH")
    _, selection_raw = _read_bound_file(selection_ref["path"], selection_ref["sha256"], roots, "selection manifest")
    if _loads(selection_raw) != selection:
        raise FrameworkError("RUN006_SELECTION_MANIFEST_CONTENT_MISMATCH")
    for key, expected in (("rights_assessment", assessment),):
        ref = config[key]
        _, raw = _read_bound_file(ref["path"], ref["sha256"], roots, key)
        if _loads(raw) != expected:
            raise FrameworkError("RUN006_RIGHTS_ASSESSMENT_CONTENT_MISMATCH")
    rights_ref = config["rights_evidence"]
    _, rights_raw = _read_bound_file(rights_ref["path"], rights_ref["sha256"], roots, "rights evidence")
    from .core import _loads
    rights_doc = _loads(rights_raw)
    if digest(canonical(rights_doc)) != assessment.get("rights_evidence_sha256"):
        raise FrameworkError("RUN006_RIGHTS_EVIDENCE_CONTENT_MISMATCH")
    dataset_ref = {"path": runner_config.get("dataset_manifest_path"),
                   "sha256": runner_config.get("input_manifest_sha256")}
    if (dataset_ref["path"], dataset_ref["sha256"]) not in binding_pairs:
        raise FrameworkError("RUN006_DATASET_METADATA_NOT_BOUND")
    _, dataset_raw = _read_bound_file(dataset_ref["path"], dataset_ref["sha256"], roots, "dataset manifest")
    dataset = _loads(dataset_raw)
    units = dataset.get("units") if isinstance(dataset, dict) else None
    if not isinstance(units, list) or len(units) != len(expected_units):
        raise FrameworkError("RUN006_DATASET_SELECTION_MEMBERSHIP_MISMATCH")
    units_by_id = {}
    for unit in units:
        if not isinstance(unit, dict) or unit.get("unit_id") not in expected_units or unit["unit_id"] in units_by_id:
            raise FrameworkError("RUN006_DATASET_UNIT_IDENTITY_MISMATCH")
        output_id = unit["unit_id"]
        item = expected_units[output_id]
        refs = selection_sources[output_id]
        if (unit.get("task_id") != item["task_id"]
                or unit.get("predicate_profile") != "BFCL_ARCHIVED_ROW_PAIR_V1"
                or unit.get("source_path") != refs["task"]["path"]
                or unit.get("source_sha256") != refs["task"]["sha256"]
                or unit.get("predicate_input") != refs
                or unit.get("authentic_output_references") != [refs["response"]]
                or {(r.get("path"), r.get("sha256")) for r in unit.get("evidence_references", [])
                    if isinstance(r, dict)} != {(r["path"], r["sha256"]) for r in refs.values()}):
            raise FrameworkError("RUN006_DATASET_SOURCE_BINDING_MISMATCH")
        units_by_id[output_id] = unit
    if (set(runner_config.get("expected_units", [])) != set(expected_units)
            or len(runner_config.get("expected_units", [])) != len(expected_units)):
        raise FrameworkError("RUN006_EXPECTED_UNITS_MISMATCH")

    source_policy = runner_config.get("audit_policy", {}).get("generic_caller", {})
    source_ref, dependency_ref = source_policy.get("source_manifest"), source_policy.get("dependency_manifest")
    if (not isinstance(source_ref, dict) or not isinstance(dependency_ref, dict)
            or (source_ref.get("path"), source_ref.get("sha256")) not in metadata_pairs
            or (dependency_ref.get("path"), dependency_ref.get("sha256")) not in metadata_pairs):
        raise FrameworkError("RUN006_SOURCE_GRAPH_METADATA_NOT_BOUND")
    _, source_raw = _read_bound_file(source_ref["path"], source_ref["sha256"], roots, "source manifest")
    _, dependency_raw = _read_bound_file(dependency_ref["path"], dependency_ref["sha256"], roots, "dependency manifest")
    source_doc, dependency_doc = _loads(source_raw), _loads(dependency_raw)
    source_rows = source_doc.get("sources", []) if isinstance(source_doc, dict) else []
    source_map = {}
    for row in source_rows:
        if (not isinstance(row, dict) or set(row) != {"source_id", "path", "sha256", "role"}
                or row["source_id"] in source_map):
            raise FrameworkError("RUN006_SOURCE_GRAPH_SCHEMA_INVALID")
        source_map[row["source_id"]] = (row["path"], row["sha256"], row["role"])
    source_roles = {"task": "PRIMARY", "response": "SUPPORTING"}
    expected_source_roles = {(ref["path"], ref["sha256"], source_roles[role])
                             for by_role in selection_sources.values() for role, ref in by_role.items()}
    if set(source_map.values()) != expected_source_roles:
        raise FrameworkError("RUN006_SOURCE_GRAPH_READ_SET_MISMATCH")
    if (not isinstance(dependency_doc, dict) or dependency_doc.get("groups") != {}
            or not isinstance(dependency_doc.get("units"), list)
            or dependency_doc.get("source_manifest_sha256") != source_ref["sha256"]):
        raise FrameworkError("RUN006_DEPENDENCY_GRAPH_INVALID")
    deps_by_unit = {row.get("unit_id"): row for row in dependency_doc["units"] if isinstance(row, dict)}
    if set(deps_by_unit) != set(expected_units) or len(deps_by_unit) != len(dependency_doc["units"]):
        raise FrameworkError("RUN006_DEPENDENCY_UNIT_MEMBERSHIP_MISMATCH")
    for output_id, by_role in selection_sources.items():
        unit = units_by_id[output_id]
        dep = deps_by_unit[output_id]
        primary = source_map.get(dep.get("primary_source_id"))
        supporting = [source_map.get(source_id) for source_id in dep.get("supporting_source_ids", [])]
        if (primary != (by_role["task"]["path"], by_role["task"]["sha256"], "PRIMARY")
                or supporting != [(by_role["response"]["path"], by_role["response"]["sha256"], "SUPPORTING")]
                or dep.get("normative_companion_ids") != [] or dep.get("dependency_group_ids") != []
                or dep.get("unit_id") != unit["unit_id"]):
            raise FrameworkError("RUN006_DEPENDENCY_SOURCE_BINDING_MISMATCH")

    admission_ref = required_refs["admission"]
    if str(Path(runner_args.admission).resolve()) != str(Path(admission_ref[0]).resolve()):
        raise FrameworkError("RUN006_ADMISSION_CLI_REF_MISMATCH")
    _, admission_raw = _read_bound_file(admission_ref[0], admission_ref[1], roots, "runtime admission")
    admission = _loads(admission_raw)
    expected_allowed = binding_pairs - {admission_ref}
    actual_allowed = pairs(admission.get("allowed_read_references", []), "admission allowed read")
    if actual_allowed != expected_allowed:
        raise FrameworkError("RUN006_ADMISSION_READ_SET_MISMATCH")
    outputs = admission.get("outputs") if isinstance(admission, dict) else None
    if not isinstance(outputs, list) or len(outputs) != len(expected_units):
        raise FrameworkError("RUN006_ADMISSION_OUTPUT_MEMBERSHIP_MISMATCH")
    output_map = {}
    for row in outputs:
        if (not isinstance(row, dict) or row.get("AUDIT_DISPOSITION") != "ADMITTED_AUTHENTIC_OUTPUT"
                or row.get("processing_status") != "PROCESSING_PERMITTED" or row.get("reserved") is not False
                or row.get("OUTPUT_ID") in output_map):
            raise FrameworkError("RUN006_ADMISSION_OUTPUT_INVALID")
        output_map[row["OUTPUT_ID"]] = row
    if set(output_map) != set(expected_units):
        raise FrameworkError("RUN006_ADMISSION_OUTPUT_MEMBERSHIP_MISMATCH")
    assessment_sources = assessment["sources"]
    for output_id, item in expected_units.items():
        response_ref = selection_sources[output_id]["response"]
        admission_row = output_map[output_id]
        if (admission_row.get("TASK_ID") != item["task_id"]
                or admission_row.get("OUTPUT_SHA256") != response_ref["sha256"]):
            raise FrameworkError("RUN006_ADMISSION_OUTPUT_BINDING_MISMATCH")
        expected_permissions = {(ref["path"], ref["sha256"]) for row in assessment_sources
                                if row.get("output_id") == output_id
                                for ref in row.get("evidence_references", [])}
        actual_permissions = pairs(admission_row.get("permission_references", []), "admission permission")
        if not expected_permissions or actual_permissions != expected_permissions:
            raise FrameworkError("RUN006_ADMISSION_PERMISSION_BINDING_MISMATCH")
    return {"runner_metadata_reads": "BOUND_AND_JOINED", "units": len(units),
            "source_rows": len(source_pairs), "metadata_bindings": len(metadata_pairs)}


def dispatch(config, selection, assessment, runner_args, *, launch_authorization=None,
             freeze=None, adapter_overrides=None, runner=None):
    """Call RUN005 only after the disabled/rights gate; blocked paths read no bodies."""
    gate = validate_dispatch_config(config, selection, assessment, launch_authorization, freeze)
    if config.get("runner_config_sha256") is None or not hasattr(runner_args, "config"):
        raise FrameworkError("RUN006_RUNNER_CONFIG_BINDING_REQUIRED")
    try:
        runner_config_raw = Path(runner_args.config).read_bytes()
    except (OSError, TypeError) as exc:
        raise FrameworkError("RUN006_RUNNER_CONFIG_UNAVAILABLE") from exc
    if digest(runner_config_raw) != config["runner_config_sha256"]:
        raise FrameworkError("RUN006_RUNNER_CONFIG_HASH_MISMATCH")
    from .core import _loads
    runner_config = _loads(runner_config_raw)
    attempt_id = launch_authorization["campaign_attempt_id"]
    if (not isinstance(runner_config, dict)
            or not protected_row_run(runner_config.get("run_id"))
            or runner_config.get("run_id") == "RUN007" and runner_config.get("campaign_id") != "PGOP1-RUN007-E1"
            or runner_config.get("campaign_attempt_id") != attempt_id
            or runner_config.get("candidate_commit") != config.get("candidate_commit")
            or runner_config.get("candidate_tree") != config.get("candidate_tree")):
        raise FrameworkError("RUN006_RUNNER_CONFIG_IDENTITY_MISMATCH")
    if config.get("runner_config") != {"path": str(Path(runner_args.config).resolve()),
                                       "sha256": config["runner_config_sha256"]}:
        raise FrameworkError("RUN006_OUTER_RUNNER_CONFIG_REF_MISMATCH")
    runner_scope = validate_runner_scope(config, selection, assessment, runner_config, runner_args)
    context = _ValidatedDispatchContext(config["runner_config_sha256"], attempt_id,
        runner_config["run_id"], runner_config.get("candidate_commit", ""),
        runner_config.get("candidate_tree", ""))
    if runner is None:
        from .run005 import run as runner
    producer = "PGOP1-RUN007-E1" if runner_config["run_id"] == "RUN007" else "PGOP1-RUN006-E1"
    event = "RUN007_AUDIT_RESULT" if runner_config["run_id"] == "RUN007" else "RUN006_AUDIT_RESULT"
    return {"gate": gate, "runner_scope": runner_scope, "runner_result": runner(
        runner_args, adapter_overrides=adapter_overrides,
        producer_id=producer, engine_event_kind=event,
        _run006_context=context)}


def _decode_row(raw, role, expected_task_id):
    from runtime.candidate.context_engine import strict_json_loads
    try:
        value = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise FrameworkError("RUN006_ROW_JSON_INVALID:" + role) from exc
    if not isinstance(value, dict) or value.get("id") != expected_task_id:
        raise FrameworkError("RUN006_ROW_IDENTITY_MISMATCH:" + role)
    return value


def _read_json_row(reference, roots, role, expected_task_id):
    if not isinstance(reference, dict) or set(reference) != {"path", "sha256"}:
        raise FrameworkError("RUN006_ROW_REFERENCE_INVALID:" + role)
    _hash(reference["sha256"], role)
    _path, raw = _read_bound_file(reference["path"], reference["sha256"], roots,
                                  "RUN006 selected " + role + " snapshot")
    return _decode_row(raw, role, expected_task_id)


def read_bfcl_row_pair(source, roots, task_id):
    if (not isinstance(source, dict) or set(source) != {"task", "response"}
            or any(not isinstance(source.get(role), dict) or set(source[role]) != {"path", "sha256"}
                   for role in ("task", "response"))):
        raise FrameworkError("RUN006_ROW_PAIR_BINDING_INVALID")
    task = _read_json_row(source["task"], roots, "task", task_id)
    response = _read_json_row(source["response"], roots, "response", task_id)
    return task, response


def bfcl_row_adapter(unit, references, roots=None):
    """Read two bound, byte-identical row snapshots and call the existing audit."""
    if not isinstance(unit, dict) or unit.get("predicate_profile") != "BFCL_ARCHIVED_ROW_PAIR_V1":
        raise FrameworkError("RUN006_ROW_PROFILE_INVALID")
    task_id = unit.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        raise FrameworkError("RUN006_TASK_ID_INVALID")
    source = unit.get("predicate_input")
    if not isinstance(source, dict) or set(source) != {"task", "response"}:
        raise FrameworkError("RUN006_ROW_PAIR_BINDING_INVALID")
    all_refs = references.get("all", []) if isinstance(references, dict) else []
    bound = {(r.get("path"), r.get("sha256")) for r in all_refs if isinstance(r, dict)}
    pairs = [source[role] for role in ("task", "response")]
    if any(not isinstance(ref, dict) or set(ref) != {"path", "sha256"}
           or (ref["path"], ref["sha256"]) not in bound for ref in pairs):
        raise FrameworkError("RUN006_ROW_PAIR_NOT_IN_SOURCE_BINDINGS")
    if roots is None:
        roots = references.get("roots", [])
    if not roots:
        raise FrameworkError("RUN006_TRUSTED_ROW_ROOTS_REQUIRED")
    task, response = read_bfcl_row_pair(source, roots, task_id)
    from runtime.candidate.bfcl_structured_audit_v2 import audit
    return audit(task, response)

