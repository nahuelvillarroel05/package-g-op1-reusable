"""Prospective, narrow modality-A predicate and abstention rules.

Rules describe domains independently from evidence availability. A task definition
without an authentic response never becomes a completed semantic output audit.
The BFCL abstention reviewer reruns the existing inert structural auditor; it
does not trust a producer's assertion that evidence was sufficient or missing.
"""
from __future__ import annotations

from copy import deepcopy

CONTRACT_ID = "pgop1.modality-a.predicate-applicability.v1"
CONTRACT_VERSION = "1.0.0"
PREDICATES = (
    "SOURCE_INTEGRITY", "TASK_BINDING", "OUTPUT_PROVENANCE",
    "FUNCTION_CALL_STRUCTURE", "FUNCTION_ARGUMENT_VALIDITY",
    "PREDICATE_COMPARABILITY", "CLAIM_EVIDENCE_SUPPORT", "RECOVERY_INTEGRITY",
)
FAMILY_VERSIONS = {
    "swebench": ("full", "lite", "verified", "multilingual"),
    "swebench_pro_v2": ("V2",), "terminal_bench_2": ("2.0",),
    "mcpmark_verified": ("Verified@cd45b7f57923",),
    "bfcl_v4": ("V4",), "tau_bench": ("2.0.0:text-v1",),
}
STRUCTURAL = {"SOURCE_INTEGRITY", "TASK_BINDING", "RECOVERY_INTEGRITY"}
BFCL_STRUCTURAL_SUBTYPES = {"simple_python", "live_simple", "multiple", "live_multiple"}
REQUIRED = {
    "SOURCE_INTEGRITY": ["committed_source_manifest", "original_source_bytes"],
    "TASK_BINDING": ["authoritative_unit_identity", "exact_version", "bound_dependencies"],
    "OUTPUT_PROVENANCE": ["authentic_output", "attribution_chain"],
    "FUNCTION_CALL_STRUCTURE": ["authentic_output", "function_schema", "supported_representation"],
    "FUNCTION_ARGUMENT_VALIDITY": ["authentic_output", "function_schema", "supported_argument_constraints"],
    "PREDICATE_COMPARABILITY": ["exact_predicate_contract", "exact_task_version", "comparison_evidence"],
    "CLAIM_EVIDENCE_SUPPORT": ["attributable_claim", "complete_bound_evidence", "qualified_claim_predicate"],
    "RECOVERY_INTEGRITY": ["authoritative_manifest", "journal", "recovered_source_bytes"],
}


def applicability_rule(family, version, subtype, predicate_id):
    """Return a versioned rule. Unknown domain/version does not mean false/NA."""
    if predicate_id not in PREDICATES:
        raise ValueError("unknown predicate")
    known_version = family in FAMILY_VERSIONS and version in FAMILY_VERSIONS[family]
    status = "UNKNOWN_APPLICABILITY"
    reason = "No qualified domain rule for this exact version/subtype"
    if known_version and predicate_id in STRUCTURAL:
        status, reason = "APPLICABLE", "Every selected unit has byte/identity/recovery obligations"
    elif (known_version and family == "bfcl_v4" and subtype in BFCL_STRUCTURAL_SUBTYPES
          and predicate_id in {"FUNCTION_CALL_STRUCTURE", "FUNCTION_ARGUMENT_VALIDITY"}):
        status, reason = "APPLICABLE", "Exact supported BFCL function-call subtype; evidence absence does not change domain"
    elif (known_version and family == "swebench" and version == "multilingual"
          and subtype == "archived_explicit_completion_statement"
          and predicate_id == "CLAIM_EVIDENCE_SUPPORT"):
        status, reason = "APPLICABLE", "Existing SWE completion-statement predicate against bound archived evaluator records only"
    return {
        "benchmark_family": family, "benchmark_version": version, "unit_subtype": subtype,
        "predicate_id": predicate_id, "contract_id": CONTRACT_ID,
        "contract_version": CONTRACT_VERSION, "domain_applicability": status,
        "required_input_types": list(REQUIRED[predicate_id]),
        "required_evidence": list(REQUIRED[predicate_id]),
        "sufficiency_rule": "All named prerequisites must be demonstrated by bound evidence and the selected exact auditor contract",
        "decision_rule": "Use the selected existing predicate auditor only within its declared domain; structural checks do not imply semantic truth",
        "abstention_rule": "Demonstrated missing necessary condition -> JUSTIFIED; demonstrated complete sufficiency plus mandatory rule violation -> UNJUSTIFIED; otherwise UNKNOWN_UNREVIEWABLE",
        "error_rule": "Identity/integrity/contract mismatch -> VERIFICATION_ERROR, never PASS",
        "reason": reason,
    }


def definition_disposition(family, version, subtype=None):
    """A no-output operation is processing, not an auditor abstention event."""
    return {
        "processing_disposition": "TASK_DEFINITION_PROCESSED",
        "audit_disposition": "NOT_AUDITED_MISSING_AGENT_OUTPUT",
        "authentic_output_present": False, "semantic_audits_completed": 0,
        "predicate_results": [
            {"predicate_id": predicate, "applicability": applicability_rule(
                family, version, subtype, predicate)["domain_applicability"],
             "decision": "NOT_EVALUATED", "reason": "No authentic output is bound"}
            for predicate in PREDICATES
        ],
        "abstentions": [],
        "missing_evidence": ["authentic_output"],
        "scope": "Missing-output disposition; not a justified semantic abstention by default",
    }


def qualify_bfcl_abstention(task, response, observed_audit, *, evidence_bound=False):
    """Review a BFCL structural abstention by deterministic independent replay.

    The caller must have validated exact task/response byte references. An
    unbound result cannot qualify. A replayed structural decision establishes
    sufficiency for that narrow rule, never for semantic/global BFCL predicates.
    """
    from runtime.candidate.bfcl_structured_audit_v2 import audit, CONTRACT
    result = {"classification": "UNKNOWN_UNREVIEWABLE", "contract": CONTRACT,
              "scope": "BFCL structural decision only", "reason": "Missing bound evidence or no reviewable abstention"}
    if (not evidence_bound or not isinstance(observed_audit, dict)
            or observed_audit.get("contract") != CONTRACT
            or not str(observed_audit.get("status", "")).startswith("ABSTAIN")):
        return result
    replay = audit(deepcopy(task), deepcopy(response))
    result["replayed_status"] = replay["status"]
    if replay["status"] in {"STRUCTURAL_PASS", "STRUCTURAL_REJECT"}:
        result.update(classification="UNJUSTIFIED", reason="Exact inert structural auditor makes a mandatory decision on the same sufficient inputs")
    elif replay["status"].startswith("ABSTAIN_"):
        result.update(classification="JUSTIFIED", reason="Existing auditor replay verifies a missing necessary structural precondition: " + replay["status"])
    else:
        result["reason"] = "Identity mismatch or other non-abstention error cannot prove justified abstention"
    return result


def population_baseline(unit_count):
    """Preserve the frozen eight-predicate denominator until subtype qualification."""
    if type(unit_count) is not int or unit_count < 0:
        raise ValueError("invalid unit count")
    return {"units": unit_count, "unit_predicate_pairs": unit_count * len(PREDICATES),
            "structural_applicability_determined": unit_count * len(STRUCTURAL),
            "unknown_applicability": unit_count * (len(PREDICATES) - len(STRUCTURAL)),
            "not_applicable": 0, "population_semantic_qualification": "NOT_INFERRED_FROM_DEVELOPMENT_RULES"}


def validate_audit_payload(unit, audit_result, processing_disposition, audit_disposition, index):
    """Reject unsupported domain assertions and fabricated narrow decisions.

    Opt-in qualification profiles bind existing inert auditors to exact source
    references. This is deliberately not a claim that arbitrary producer JSON
    establishes semantic truth. Unknown profiles remain unqualified.
    """
    from .core import FrameworkError, canonical
    from .provenance import _read_bound_file
    if not isinstance(audit_result, dict) or audit_result.get("schema") != "pgop1.predicate-evidence.v1":
        raise FrameworkError("PREDICATE_PAYLOAD_REQUIRED")
    profile = unit.get("predicate_profile", "DEFINITION_ONLY")
    subtype = unit.get("unit_subtype")
    rows = audit_result.get("predicate_results")
    if (not isinstance(rows, list) or len(rows) != len(PREDICATES)
            or {r.get("predicate_id") for r in rows if isinstance(r, dict)} != set(PREDICATES)):
        raise FrameworkError("PREDICATE_PAIR_DENOMINATOR_MISMATCH")
    actual = {}
    if profile == "DEFINITION_ONLY":
        if processing_disposition != "TASK_DEFINITION_PROCESSED" or audit_disposition != "NOT_AUDITED_MISSING_AGENT_OUTPUT":
            raise FrameworkError("PREDICATE_DEFINITION_IS_NOT_OUTPUT_AUDIT")
        expected_payload = {"schema": "pgop1.predicate-evidence.v1", **definition_disposition(
            unit["benchmark_id"], unit["benchmark_version"], subtype)}
        if canonical(audit_result) != canonical(expected_payload):
            raise FrameworkError("PREDICATE_PAYLOAD_NOT_EXACT_RECONSTRUCTION")
    elif profile in {"BFCL_STRUCTURAL_V2", "BFCL_ARCHIVED_ROW_PAIR_V1"}:
        from runtime.candidate.bfcl_structured_audit_v2 import audit
        source = unit.get("predicate_input")
        if profile == "BFCL_STRUCTURAL_V2":
            if (not isinstance(source, dict) or set(source) != {"path", "sha256", "task_id"}
                    or (source["path"], source["sha256"]) not in index["evidence"][unit["unit_id"]]):
                raise FrameworkError("PREDICATE_INPUT_NOT_BOUND")
            if {"path": source["path"], "sha256": source["sha256"]} not in unit.get("authentic_output_references", []):
                raise FrameworkError("PREDICATE_REPLAY_OUTPUT_REFERENCE_MISMATCH")
            _, raw = _read_bound_file(source["path"], source["sha256"], index["roots"], "predicate input")
            from runtime.candidate.context_engine import strict_json_loads
            records = strict_json_loads(raw)
            matches = [r for r in records if r.get("task_id") == source["task_id"]]
            if len(matches) != 1:
                raise FrameworkError("PREDICATE_INPUT_IDENTITY_AMBIGUOUS")
            case = matches[0]
            task, response = case.get("task"), case.get("response")
            task_id = source["task_id"]
        else:
            if (not isinstance(source, dict) or set(source) != {"task", "response"}
                    or any(not isinstance(source.get(role), dict)
                           or set(source[role]) != {"path", "sha256"} for role in ("task", "response"))):
                raise FrameworkError("PREDICATE_ROW_PAIR_INPUT_INVALID")
            task_id = unit.get("task_id")
            pairs = {(source[role]["path"], source[role]["sha256"]) for role in ("task", "response")}
            if not pairs <= index["evidence"][unit["unit_id"]]:
                raise FrameworkError("PREDICATE_ROW_PAIR_NOT_BOUND")
            if {"path": source["response"]["path"], "sha256": source["response"]["sha256"]} not in unit.get("authentic_output_references", []):
                raise FrameworkError("PREDICATE_REPLAY_OUTPUT_REFERENCE_MISMATCH")
            from .run006 import read_bfcl_row_pair
            task, response = read_bfcl_row_pair(source, index["roots"], task_id)
        if (not isinstance(task, dict) or not isinstance(response, dict)
                or task.get("id") != task_id or response.get("id") != task_id
                or task_id != unit.get("task_id")):
            raise FrameworkError("PREDICATE_INPUT_IDENTITY_MISMATCH")
        replay = audit(task, response)
        if replay.get("category") != subtype:
            raise FrameworkError("PREDICATE_SUBTYPE_NOT_REPRODUCIBLE")
        for predicate, narrow in [("FUNCTION_CALL_STRUCTURE", "FUNCTION_CALL_FORMAT_VALID"),
                                  ("FUNCTION_ARGUMENT_VALIDITY", "FUNCTION_ARGUMENTS_VALID")]:
            value = replay["predicates"][narrow]
            actual[predicate] = ("SUPPORTED" if value is True else "CONTRADICTED" if value is False else "ABSTAIN")
        if audit_result.get("auditor_status") != replay["status"]:
            raise FrameworkError("PREDICATE_REPLAY_STATUS_DIFFERS")
    elif profile == "SWE_ARCHIVED_COMPLETION_V1":
        from pathlib import Path
        from runtime.candidate.swebench_claim_audit.adapter import audit_instance, RUN_REPO, INSTANCE_RE
        source = unit.get("predicate_input")
        if not isinstance(source, dict) or set(source) != {"data_root", "task_id"}:
            raise FrameworkError("PREDICATE_INPUT_NOT_BOUND")
        if not isinstance(source["task_id"], str) or not INSTANCE_RE.fullmatch(source["task_id"]):
            raise FrameworkError("PREDICATE_INPUT_IDENTITY_INVALID")
        if source["task_id"] != unit.get("task_id"):
            raise FrameworkError("PREDICATE_INPUT_IDENTITY_MISMATCH")
        required = ["logs/all_preds.jsonl", "logs/trajs/" + source["task_id"] + ".traj.json",
                    *["logs/logs/" + source["task_id"] + "/" + name for name in ("report.json", "patch.diff", "test_output.txt.gz")],
                    *[(RUN_REPO / name).as_posix() for name in ("per_instance_details.json", "results/results.json", "metadata.yaml", "README.md")]]
        evidence = dict(index["evidence"][unit["unit_id"]])
        trajectory_path = str((Path(source["data_root"]) / ("logs/trajs/" + source["task_id"] + ".traj.json")).resolve())
        if {"path": trajectory_path, "sha256": evidence.get(trajectory_path)} not in unit.get("authentic_output_references", []):
            raise FrameworkError("PREDICATE_REPLAY_OUTPUT_REFERENCE_MISMATCH")
        for relative in required:
            path = str((Path(source["data_root"]) / relative).resolve())
            if path not in evidence:
                raise FrameworkError("PREDICATE_REPLAY_READ_UNBOUND_SOURCE")
            _read_bound_file(path, evidence[path], index["roots"], "SWE predicate prerequisite")
        replay = audit_instance(source["data_root"], source["task_id"])
        refs = [*replay.get("EXECUTION_EVIDENCE", []), *replay.get("SOURCE_PROVENANCE", {}).get("evidence_references", [])]
        for ref in refs:
            path = str((Path(source["data_root"]) / ref["path"]).resolve())
            if (path, ref["sha256"]) not in index["evidence"][unit["unit_id"]]:
                raise FrameworkError("PREDICATE_REPLAY_READ_UNBOUND_SOURCE")
        actual["CLAIM_EVIDENCE_SUPPORT"] = replay["AUDIT_VERDICT"]
        if audit_result.get("auditor_status") != replay["AUDIT_VERDICT"]:
            raise FrameworkError("PREDICATE_REPLAY_STATUS_DIFFERS")
    else:
        raise FrameworkError("PREDICATE_PROFILE_UNQUALIFIED")
    if profile != "DEFINITION_ONLY":
        if processing_disposition != "AGENT_OUTPUT_AUDITED" or audit_disposition != "AUDITED":
            raise FrameworkError("PREDICATE_OPERATION_DISPOSITION_MISMATCH")
        expected_result = build_audit_payload(unit, replay)
        if canonical(audit_result) != canonical(expected_result["audit_result"]):
            raise FrameworkError("PREDICATE_PAYLOAD_NOT_EXACT_RECONSTRUCTION")
    for row in rows:
        predicate = row["predicate_id"]
        rule = applicability_rule(unit["benchmark_id"], unit["benchmark_version"], subtype, predicate)
        if row.get("applicability") != rule["domain_applicability"]:
            raise FrameworkError("PREDICATE_DOMAIN_MISMATCH")
        expected = actual.get(predicate, "NOT_EVALUATED")
        if row.get("decision") != expected:
            raise FrameworkError("PREDICATE_DECISION_NOT_REPRODUCIBLE")
        if row["applicability"] != "APPLICABLE" and row["decision"] in {"SUPPORTED", "CONTRADICTED"}:
            raise FrameworkError("UNKNOWN_PREDICATE_CANNOT_DECIDE")
    return {"profile": profile, "replayed_predicates": sorted(actual), "scope": "Exact selected local auditor contract, not independent semantic truth"}


def build_audit_payload(unit, adapted=None):
    """Exact source-free payload derived from an existing narrow auditor result."""
    result = {"schema": "pgop1.predicate-evidence.v1", **definition_disposition(
        unit["benchmark_id"], unit["benchmark_version"], unit.get("unit_subtype"))}
    operation, disposition = result["processing_disposition"], result["audit_disposition"]
    profile = unit.get("predicate_profile", "DEFINITION_ONLY")
    if profile != "DEFINITION_ONLY":
        operation, disposition = "AGENT_OUTPUT_AUDITED", "AUDITED"
        result.update(processing_disposition=operation, audit_disposition=disposition,
                      authentic_output_present=True, semantic_audits_completed=0, missing_evidence=[])
        if profile in {"BFCL_STRUCTURAL_V2", "BFCL_ARCHIVED_ROW_PAIR_V1"}:
            from runtime.candidate.bfcl_structured_audit_v2 import CONTRACT
            if (adapted.get("contract") != CONTRACT or adapted.get("status") == "INCOMPATIBLE_ID"
                    or adapted.get("task_id") != unit.get("task_id", adapted.get("task_id"))):
                raise ValueError("BFCL identity/contract error is not a justified abstention")
            result["auditor_status"] = adapted["status"]
            decisions = {"FUNCTION_CALL_STRUCTURE": adapted["predicates"]["FUNCTION_CALL_FORMAT_VALID"],
                         "FUNCTION_ARGUMENT_VALIDITY": adapted["predicates"]["FUNCTION_ARGUMENTS_VALID"]}
            for row in result["predicate_results"]:
                if row["predicate_id"] in decisions:
                    value = decisions[row["predicate_id"]]
                    row.update(decision="SUPPORTED" if value is True else "CONTRADICTED" if value is False else "ABSTAIN",
                               reason="Exact existing inert BFCL structural auditor; no natural claim invented")
                    if value is None:
                        # The exact auditor cannot decide this predicate on the
                        # same inputs. Scope is its required parse/schema inputs,
                        # not independent global semantics or all missing outputs.
                        missing_prerequisite = (adapted["status"] in {"ABSTAIN_UNSUPPORTED_SCHEMA", "ABSTAIN_UNSUPPORTED_REPRESENTATION"}
                            or adapted["status"] == "STRUCTURAL_REJECT" and (
                                adapted["predicates"].get("FUNCTION_CALL_FORMAT_VALID") is False
                                or adapted["predicates"].get("FUNCTION_NAME_VALID") is False))
                        result["abstentions"].append({"predicate_id": row["predicate_id"],
                            "classification": "JUSTIFIED" if missing_prerequisite else "UNKNOWN_UNREVIEWABLE",
                            "reason": "Verified missing parse/schema prerequisite in exact structural auditor replay" if missing_prerequisite else "No verified missing necessary condition for this predicate",
                            "review_scope": "Bound exact BFCL structural inputs only"})
            result["scope"] = "Structural task-relative audit; no independent semantic verdict or official evaluation"
        elif profile == "SWE_ARCHIVED_COMPLETION_V1":
            result["auditor_status"] = adapted["AUDIT_VERDICT"]
            for row in result["predicate_results"]:
                if row["predicate_id"] == "CLAIM_EVIDENCE_SUPPORT":
                    row.update(decision=adapted["AUDIT_VERDICT"], reason="Existing archived completion-statement auditor, record-relative only")
            result["semantic_audits_completed"] = int(adapted["AUDIT_VERDICT"] in {"SUPPORTED", "CONTRADICTED"})
            result["scope"] = "Archived record-relative SWE claim; producer authentication, dataset snapshot and independent truth not established"
        else:
            raise ValueError("unqualified predicate profile")
        for row in result["predicate_results"]:
            if row["decision"] == "NOT_EVALUATED":
                row["reason"] = "Selected auditor did not evaluate this predicate"
    return {"audit_result": result, "processing_disposition": operation, "audit_disposition": disposition}
