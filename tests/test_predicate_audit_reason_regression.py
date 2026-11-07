"""Synthetic regression for profile-aware not-evaluated explanations."""
import pytest

from runtime.candidate.bfcl_structured_audit_v2 import CONTRACT
from runtime.candidate.run_framework.predicates import (
    PREDICATES,
    build_audit_payload,
    definition_disposition,
)


@pytest.mark.parametrize(
    "profile,unit,adapted",
    [
        (
            "BFCL_STRUCTURAL_V2",
            {"benchmark_id": "bfcl_v4", "benchmark_version": "V4",
             "unit_subtype": "simple_python", "task_id": "simple_python_1"},
            {"contract": CONTRACT, "status": "STRUCTURAL_PASS",
             "task_id": "simple_python_1",
             "predicates": {"FUNCTION_CALL_FORMAT_VALID": True,
                            "FUNCTION_ARGUMENTS_VALID": True}},
        ),
        (
            "BFCL_ARCHIVED_ROW_PAIR_V1",
            {"benchmark_id": "bfcl_v4", "benchmark_version": "V4",
             "unit_subtype": "simple_python", "task_id": "simple_python_1"},
            {"contract": CONTRACT, "status": "STRUCTURAL_PASS",
             "task_id": "simple_python_1",
             "predicates": {"FUNCTION_CALL_FORMAT_VALID": True,
                            "FUNCTION_ARGUMENTS_VALID": True}},
        ),
        (
            "SWE_ARCHIVED_COMPLETION_V1",
            {"benchmark_id": "swebench", "benchmark_version": "multilingual",
             "unit_subtype": "archived_explicit_completion_statement",
             "task_id": "axios__axios-5892"},
            {"AUDIT_VERDICT": "SUPPORTED"},
        ),
    ],
)
def test_audited_profiles_do_not_report_missing_authentic_output(
    profile, unit, adapted
):
    unit = {**unit, "predicate_profile": profile}
    baseline = definition_disposition(
        unit["benchmark_id"], unit["benchmark_version"], unit["unit_subtype"]
    )
    payload = build_audit_payload(unit, adapted)["audit_result"]

    assert payload["authentic_output_present"] is True
    assert payload["missing_evidence"] == []
    assert {row["predicate_id"]: row["applicability"]
            for row in payload["predicate_results"]} == {
                row["predicate_id"]: row["applicability"]
                for row in baseline["predicate_results"]
            }
    evaluated = ({"FUNCTION_CALL_STRUCTURE", "FUNCTION_ARGUMENT_VALIDITY"}
                 if profile.startswith("BFCL_") else {"CLAIM_EVIDENCE_SUPPORT"})
    for row in payload["predicate_results"]:
        if row["predicate_id"] not in evaluated:
            assert row["decision"] == "NOT_EVALUATED"
            assert row["reason"] == "Selected auditor did not evaluate this predicate"
        else:
            assert row["decision"] == "SUPPORTED"


def test_definition_only_retains_missing_output_reason_and_decisions():
    unit = {"benchmark_id": "bfcl_v4", "benchmark_version": "V4",
            "unit_subtype": "simple_python"}
    payload = build_audit_payload(unit)["audit_result"]
    baseline = definition_disposition("bfcl_v4", "V4", "simple_python")

    assert payload["authentic_output_present"] is False
    assert payload["predicate_results"] == baseline["predicate_results"]
    assert {row["predicate_id"] for row in payload["predicate_results"]
            if row["reason"] == "No authentic output is bound"} == set(PREDICATES)
