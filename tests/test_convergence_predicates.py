from copy import deepcopy
import pytest

from runtime.candidate.bfcl_structured_audit_v2 import audit
from runtime.candidate.run_framework.predicates import (
    applicability_rule, definition_disposition, population_baseline,
    qualify_bfcl_abstention, PREDICATES, FAMILY_VERSIONS,
)


@pytest.mark.parametrize("family,versions", FAMILY_VERSIONS.items())
def test_domains_do_not_use_output_availability(family, versions):
    for version in versions:
        result = definition_disposition(family, version)
        assert result["semantic_audits_completed"] == 0
        assert result["abstentions"] == []
        assert result["audit_disposition"] == "NOT_AUDITED_MISSING_AGENT_OUTPUT"
        assert {r["predicate_id"] for r in result["predicate_results"]} == set(PREDICATES)
        assert sum(r["applicability"] == "APPLICABLE" for r in result["predicate_results"]) == 3
        assert not any(r["applicability"] == "NOT_APPLICABLE" for r in result["predicate_results"])


def test_population_denominator_remains_exact():
    assert population_baseline(10096) == {
        "units": 10096, "unit_predicate_pairs": 80768,
        "structural_applicability_determined": 30288,
        "unknown_applicability": 50480, "not_applicable": 0,
        "population_semantic_qualification": "NOT_INFERRED_FROM_DEVELOPMENT_RULES",
    }


@pytest.mark.parametrize("subtype", ["simple_python", "live_simple", "multiple", "live_multiple"])
def test_only_explicit_bfcl_subtypes_qualified(subtype):
    assert applicability_rule("bfcl_v4", "V4", subtype, "FUNCTION_ARGUMENT_VALIDITY")["domain_applicability"] == "APPLICABLE"
    assert applicability_rule("bfcl_v4", "V3", subtype, "FUNCTION_ARGUMENT_VALIDITY")["domain_applicability"] == "UNKNOWN_APPLICABILITY"
    assert applicability_rule("bfcl_v4", "V4", "multi_turn_base", "FUNCTION_ARGUMENT_VALIDITY")["domain_applicability"] == "UNKNOWN_APPLICABILITY"


def fixture():
    task = {"id": "simple_python_1", "function": [{"name": "count", "parameters": {
        "type": "dict", "properties": {"x": {"type": "integer"}}, "required": ["x"]}}]}
    return task, {"id": "simple_python_1", "result": [{"count": {"x": 1}}]}


def test_unjustified_requires_replayed_sufficient_evidence():
    task, response = fixture()
    observed = audit(task, response)
    assert observed["status"] == "STRUCTURAL_PASS"
    observed["status"] = "ABSTAIN_PRODUCER_WITHHELD_DECISION"
    reviewed = qualify_bfcl_abstention(task, response, observed, evidence_bound=True)
    assert reviewed["classification"] == "UNJUSTIFIED"
    assert qualify_bfcl_abstention(task, response, observed)["classification"] == "UNKNOWN_UNREVIEWABLE"


def test_justification_requires_reproduced_failure_not_reason_string():
    task, response = fixture()
    response["result"] = "unknown source dialect"
    observed = audit(task, response)
    assert observed["status"] == "ABSTAIN_UNSUPPORTED_REPRESENTATION"
    assert qualify_bfcl_abstention(task, response, observed, evidence_bound=True)["classification"] == "JUSTIFIED"
    different = deepcopy(observed); different["contract"] = "invented"
    assert qualify_bfcl_abstention(task, response, different, evidence_bound=True)["classification"] == "UNKNOWN_UNREVIEWABLE"


def test_identity_error_is_not_justified_abstention():
    task, response = fixture()
    observed = audit(task, response); observed["status"] = "ABSTAIN_PRODUCER"
    response["id"] = "foreign"
    assert qualify_bfcl_abstention(task, response, observed, evidence_bound=True)["classification"] == "UNKNOWN_UNREVIEWABLE"
    from runtime.candidate.run_framework.predicates import build_audit_payload
    with pytest.raises(ValueError, match="identity/contract"):
        build_audit_payload({"benchmark_id": "bfcl_v4", "benchmark_version": "V4",
            "unit_subtype": "simple_python", "predicate_profile": "BFCL_STRUCTURAL_V2"}, audit(task, response))


def test_unknown_predicate_rejected():
    with pytest.raises(ValueError):
        applicability_rule("bfcl_v4", "V4", "simple_python", "ALL_CLAIMS_TRUE")


def test_definition_cannot_forge_domain_or_decision():
    from runtime.candidate.run_framework.predicates import validate_audit_payload
    from runtime.candidate.run_framework.core import FrameworkError
    unit = {"unit_id": "d1", "benchmark_id": "bfcl_v4", "benchmark_version": "V4"}
    payload = {"schema": "pgop1.predicate-evidence.v1", **definition_disposition("bfcl_v4", "V4")}
    assert validate_audit_payload(unit, payload, "TASK_DEFINITION_PROCESSED", "NOT_AUDITED_MISSING_AGENT_OUTPUT", {})["profile"] == "DEFINITION_ONLY"
    payload["predicate_results"][2]["decision"] = "SUPPORTED"
    with pytest.raises(FrameworkError, match="NOT_EXACT_RECONSTRUCTION"):
        validate_audit_payload(unit, payload, "TASK_DEFINITION_PROCESSED", "NOT_AUDITED_MISSING_AGENT_OUTPUT", {})


def test_predicate_denominator_not_reduced():
    from runtime.candidate.run_framework.predicates import validate_audit_payload
    from runtime.candidate.run_framework.core import FrameworkError
    payload = {"schema": "pgop1.predicate-evidence.v1", **definition_disposition("bfcl_v4", "V4")}
    payload["predicate_results"].pop()
    with pytest.raises(FrameworkError, match="DENOMINATOR"):
        validate_audit_payload({}, payload, "TASK_DEFINITION_PROCESSED", "NOT_AUDITED_MISSING_AGENT_OUTPUT", {})


def test_bfcl_false_decision_rejected_by_replay(tmp_path):
    import hashlib, json
    from runtime.candidate.run_framework.predicates import validate_audit_payload
    from runtime.candidate.run_framework.core import FrameworkError
    task, response = fixture()
    source = tmp_path / "case.json"
    source.write_text(json.dumps([{"task_id": task["id"], "task": task, "response": response}]))
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    unit = {"unit_id": "d1", "benchmark_id": "bfcl_v4", "benchmark_version": "V4",
            "unit_subtype": "simple_python", "predicate_profile": "BFCL_STRUCTURAL_V2", "task_id": task["id"],
            "predicate_input": {"path": str(source), "sha256": sha, "task_id": task["id"]}}
    from runtime.candidate.run_framework.predicates import build_audit_payload
    payload = build_audit_payload(unit, audit(task, response))["audit_result"]
    index = {"evidence": {"d1": {(str(source), sha)}}, "roots": [tmp_path]}
    assert len(validate_audit_payload(unit, payload, "AGENT_OUTPUT_AUDITED", "AUDITED", index)["replayed_predicates"]) == 2
    payload["predicate_results"][3]["decision"] = "CONTRADICTED"
    with pytest.raises(FrameworkError, match="NOT_EXACT_RECONSTRUCTION"):
        validate_audit_payload(unit, payload, "AGENT_OUTPUT_AUDITED", "AUDITED", index)
    source.write_text("[]")
    with pytest.raises(FrameworkError):
        validate_audit_payload(unit, payload, "AGENT_OUTPUT_AUDITED", "AUDITED", index)


def test_swe_unbound_root_rejected_before_adapter_reads(tmp_path):
    from runtime.candidate.run_framework.predicates import validate_audit_payload
    from runtime.candidate.run_framework.core import FrameworkError
    unit = {"unit_id": "d1", "benchmark_id": "swebench", "benchmark_version": "multilingual",
            "unit_subtype": "archived_explicit_completion_statement", "predicate_profile": "SWE_ARCHIVED_COMPLETION_V1", "task_id": "axios__axios-5892",
            "predicate_input": {"data_root": str(tmp_path / "unavailable"), "task_id": "axios__axios-5892"}}
    payload = {"schema": "pgop1.predicate-evidence.v1", **definition_disposition("swebench", "multilingual", "archived_explicit_completion_statement")}
    with pytest.raises(FrameworkError, match="UNBOUND_SOURCE"):
        validate_audit_payload(unit, payload, "AGENT_OUTPUT_AUDITED", "AUDITED", {"evidence": {"d1": set()}, "roots": [tmp_path]})


@pytest.mark.parametrize("field,value", [("semantic_audits_completed", 99), ("abstentions", [{"classification": "JUSTIFIED"}]), ("authentic_output_present", True)])
def test_definition_forged_crossfield_claims_rejected(field, value):
    from runtime.candidate.run_framework.predicates import validate_audit_payload, build_audit_payload
    from runtime.candidate.run_framework.core import FrameworkError
    unit = {"unit_id": "d1", "benchmark_id": "bfcl_v4", "benchmark_version": "V4"}
    payload = build_audit_payload(unit)["audit_result"]
    payload[field] = value
    with pytest.raises(FrameworkError, match="NOT_EXACT_RECONSTRUCTION"):
        validate_audit_payload(unit, payload, "TASK_DEFINITION_PROCESSED", "NOT_AUDITED_MISSING_AGENT_OUTPUT", {})
