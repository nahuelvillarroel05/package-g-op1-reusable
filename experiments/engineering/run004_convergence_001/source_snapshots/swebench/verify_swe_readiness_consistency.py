import hashlib
import json
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(r"D:\PGOP1_DATA\PGOP1_BASELINE_001")
EVIDENCE = ROOT / "Engineering/PGOP1_SIX_FAMILY_EVIDENCE_CLOSURE_001"
REPORT_PATH = EVIDENCE / "SWE_EVIDENCE_ANALYSIS.json"
ROWS_PATH = EVIDENCE / "swebench/SWE_CLASSIFICATION_ROWS_ATTEMPT002.jsonl"
CASE_PATH = EVIDENCE / "swebench/SWE_SOURCE_CASE_REVIEW_ATTEMPT002.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    rows = [json.loads(line) for line in ROWS_PATH.read_text(encoding="utf-8").splitlines() if line]
    expected = report["counts"]
    verdicts = Counter(row["verdict"] for row in rows)
    reason_rows = Counter(code for row in rows for code in set(row.get("reason_codes", [])))
    label_rows = Counter(code for row in rows for code in set(row.get("category_labels", [])))
    values = {
        "report_schema": report["schema"],
        "rows": len(rows),
        "row_sha256": sha256(ROWS_PATH),
        "case_review_sha256": sha256(CASE_PATH),
        "unique_request_indices": len({row["request_index"] for row in rows}),
        "unique_instance_ids": len({row["instance_id"] for row in rows}),
        "verdict_insufficient": verdicts["INSUFFICIENT_EVIDENCE"],
        "verdict_integrity_failure": verdicts["INTEGRITY_FAILURE"],
        "reason_unsupported_patch_shape_rows": reason_rows["UNSUPPORTED_PATCH_SHAPE"],
        "reason_mixed_noncomparable_rows": reason_rows["MIXED_OR_NONCOMPARABLE_CLAIMS"],
        "label_unknown_attribution_rows": label_rows["UNKNOWN_ATTRIBUTION"],
        "label_source_auth_unknown_rows": label_rows["SOURCE_AUTHENTICATION_UNKNOWN"],
        "label_no_matching_predicate_rows": label_rows["NO_MATCHING_PREDICATE"],
        "label_missing_evidence_rows": label_rows["MISSING_EVIDENCE"],
        "agent_statement_events": sum(row.get("agent_statement_count", 0) for row in rows),
        "agent_statement_bearing_rows": sum(row.get("agent_statement_count", 0) > 0 for row in rows),
        "unauthenticated_and_execution_unproven_rows": sum(
            row.get("evaluator_authentication") == "UNAUTHENTICATED"
            and row.get("execution_authentication") == "NOT_PROVEN"
            for row in rows
        ),
    }
    checks = {
        "row_hash_matches_report": values["row_sha256"] == report["row_output"]["sha256"],
        "case_review_hash_matches_report": values["case_review_sha256"] == report["case_review"]["sha256"],
        "request_population_matches": values["rows"] == expected["requests"] == values["unique_request_indices"] == values["unique_instance_ids"],
        "verdict_counts_match": values["verdict_insufficient"] == expected["insufficient_evidence"] and values["verdict_integrity_failure"] == expected["source_binding_failures"],
        "patch_shape_rows_match": values["reason_unsupported_patch_shape_rows"] == expected["NO_MATCHING_PREDICATE_unsupported_patch_shape_rows"],
        "mixed_noncomparable_rows_match": values["reason_mixed_noncomparable_rows"] == expected["AMBIGUOUS_CLAIM_reason_rows"],
        "attribution_rows_match": values["label_unknown_attribution_rows"] == expected["UNKNOWN_ATTRIBUTION_rows"],
        "source_authentication_rows_match": values["label_source_auth_unknown_rows"] == expected["SOURCE_AUTHENTICATION_UNKNOWN_rows"],
        "no_matching_predicate_rows_match": values["label_no_matching_predicate_rows"] == expected["NO_MATCHING_PREDICATE_unsupported_patch_shape_rows"],
        "missing_evidence_rows_match": values["label_missing_evidence_rows"] == expected["MISSING_EVIDENCE_no_bound_evaluator_rows"],
        "statement_counts_match": values["agent_statement_events"] == expected["AMBIGUOUS_CLAIM_agent_statement_events"] and values["agent_statement_bearing_rows"] == expected["agent_statement_bearing_rows"],
        "authentication_boundary_retained": values["unauthenticated_and_execution_unproven_rows"] == values["rows"],
    }
    result = {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks, "observed": values}
    print(json.dumps(result, sort_keys=True))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
