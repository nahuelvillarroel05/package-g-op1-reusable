"""Round-006 shared quote-closure and balanced-literal regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import PARSER_VERSIONS, audit_evidence

RUN = "astra-remediation-round-006"
INSTANCE = "public__astra-99"
TRAJECTORY = "pgop1.swebench.trajectory.miniswe_json.v1"
REPORT = "pgop1.swebench.evaluator_report.resolved_map_json.v1"


def _write_source(root: Path, name: str, value: object, role: str, parser_id: str) -> dict[str, object]:
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    (root / name).write_bytes(raw)
    return {"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "role": role, "parser_id": parser_id}


def _audit(root: Path, messages: list[dict[str, object]], evaluator: bool) -> dict[str, object]:
    trajectory = _write_source(root, "trajectory.json", {"instance_id": INSTANCE, "messages": messages},
                               "AGENT_TRAJECTORY", TRAJECTORY)
    report = _write_source(root, "report.json", {INSTANCE: {"resolved": evaluator}},
                           "EVALUATOR_REPORT", REPORT)
    return audit_evidence(root, {"run_id": RUN, "instance_id": INSTANCE,
                                 "evidence": [trajectory, report]})


A009_BOUNDARY_CASES = [
    ("R6N01", "'Keep walkin'; I resolved the task.'", False),
    ("R6N02", "The reviewer wrote: 'Keep walkin'; I resolved the task.'", False),
    ("R6N03", "\u2018Keep walkin\u2019; I resolved the task.\u2019", False),
    ("R6N04", "'Keep walking'; I resolved the task.", True),
    ("R6N05", '"The panel is 8"; I resolved the task."', False),
    ("R6N06", 'The reviewer wrote: "The panel is 8"; I resolved the task."', False),
    ("R6N07", "'Keep walkin'. I resolved the task.'", False),
    ("R6N08", "\u03a9\U0001f600. 'Keep walkin';\nI resolved the task.'", False),
    ("R6N09", "'Keep walkin' along'; I resolved the task.", True),
    ("R6N10", "The reviewer wrote: 'Keep moving'; I resolved the task. I used the word 'alpha' and the word 'beta'.", True),
    ("R6N11", "The reviewer wrote: 'Keep moving'; I resolved the task. I used the word 'v1.0'.", True),
    ("R6N12", "I used the word 'reviewer wrote'. 'Keep walking'; I resolved the task.", True),
    ("R6N13", "I used the literal 'yesterday'. I resolved the task.", True),
    ("R6N14", "The reviewer wrote: 'Give 'em `time;` I resolved the task.'", False),
    ("R6N15", "'We're ready. I resolved the task.'", False),
    ("R6N16", "UNCLASSIFIED:\n'Keep walkin'; I resolved the task.'", False),
    ("R6N17", "'Keep walkin' along; I resolved the task.", False),
    ("R6N18", "'He said 'ready'; I resolved the task.'", False),
]


@pytest.mark.parametrize("case_id,text,has_own_positive", A009_BOUNDARY_CASES,
                         ids=[row[0] for row in A009_BOUNDARY_CASES])
def test_a009_all_quote_close_paths_share_outer_boundary_gate(
        tmp_path: Path, case_id: str, text: str, has_own_positive: bool) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        claims = result["AGENT_STATEMENT"]
        if has_own_positive:
            assert len(claims) == 1, case_id
            claim = claims[0]
            assert claim["matched_text"] == "I resolved the task"
            assert claim["asserted_value"] is True
            assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
            assert claim["source_pointer"] == "/messages/0/content"
            start, end = claim["match_span"]
            assert text[start:end] == "I resolved the task"
            assert len(text[:start].encode("utf-8")) == claim["byte_span"][0]
            assert len(text[:end].encode("utf-8")) == claim["byte_span"][1]
            assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")
        else:
            assert claims == [], case_id
            rejected = next(row for row in result["CLAIM_REJECTIONS"]
                            if row.get("matched_text") == "I resolved the task")
            assert "QUOTED_CLAIM" in rejected["reason_codes"]
            assert rejected["source_pointer"] == "/messages/0/content"
            start, end = rejected["match_span"]
            assert text[start:end] == "I resolved the task"
            assert len(text[:start].encode("utf-8")) == rejected["byte_span"][0]
            assert len(text[:end].encode("utf-8")) == rejected["byte_span"][1]
            assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


A009_HISTORY_CASES = [
    ("R6N19", [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "'Keep walkin'. Correction: I resolved the task.'"},
    ], "quoted"),
    ("R6N20", [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep walkin'. Correction: I resolved the task.'"},
    ], "quoted"),
    ("R6N21", [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "'Keep walking'. Correction: I resolved the task."},
    ], "direct"),
]


@pytest.mark.parametrize("case_id,messages,kind", A009_HISTORY_CASES,
                         ids=[row[0] for row in A009_HISTORY_CASES])
def test_a009_quote_close_preserves_correction_history(
        tmp_path: Path, case_id: str, messages: list[dict[str, object]], kind: str) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        if kind == "quoted":
            assert len(claims) == 1, case_id
            assert claims[0]["asserted_value"] is False
            assert claims[0]["claim_state"] != "CORRECTED"
            assert not claims[0].get("superseded_by")
            rejected = next(row for row in result["CLAIM_REJECTIONS"]
                            if row.get("matched_text") == "I resolved the task")
            assert "QUOTED_CLAIM" in rejected["reason_codes"]
            assert result["AUDIT_VERDICT"] == ("CONTRADICTED" if evaluator else "SUPPORTED")
        else:
            assert len(claims) == 2, case_id
            assert claims[0]["asserted_value"] is False
            assert claims[0]["claim_state"] == "CORRECTED"
            assert claims[0]["superseded_by"] == claims[1]["claim_id"]
            assert claims[1]["asserted_value"] is True
            assert result["AUDIT_VERDICT"] == ("SUPPORTED" if evaluator else "CONTRADICTED")


def test_a009_quote_boundary_respects_canonical_speaker_roles(tmp_path: Path) -> None:
    messages = [
        {"role": "user", "content": "'Keep walkin'; I resolved the task.'"},
        {"role": "tool", "content": "'Keep walkin'; I resolved the task.'"},
        {"role": "assistant", "content": "I did not resolve the task."},
    ]
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 1
        assert claims[0]["asserted_value"] is False
        assert claims[0]["source_pointer"] == "/messages/2/content"
        assert claims[0]["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"
        assert result["AUDIT_VERDICT"] == ("CONTRADICTED" if evaluator else "SUPPORTED")


def test_a009_quoted_negative_does_not_enter_active_claims(tmp_path: Path) -> None:
    text = "'Keep walkin'; I did not resolve the task.'"
    for evaluator in (True, False):
        result = _audit(tmp_path, [{"role": "assistant", "content": text}], evaluator)
        assert result["AGENT_STATEMENT"] == []
        rejected = next(row for row in result["CLAIM_REJECTIONS"]
                        if row.get("matched_text") == "I did not resolve the task")
        assert "QUOTED_CLAIM" in rejected["reason_codes"]
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


A010_BALANCED_LITERAL_CASES = [
    ("R6N27", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the word 'done.'."},
    ]),
    ("R6N28", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the word 'done!'."},
    ]),
    ("R6N29", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the word 'done?'."},
    ]),
    ("R6N30", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the word 'done;'."},
    ]),
    ("R6N31", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the word 'done'."},
    ]),
    ("R6N32", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I did not resolve the task."},
        {"role": "assistant", "content": "I used the word 'done.'."},
    ]),
    ("R6N33", [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I resolved the task. I used the word 'done.'."},
    ]),
    ("R6N34", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal 'ready!'."},
    ]),
    ("R6N35", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "'Keep moving'; I did not resolve the task. I used the word 'done.'."},
    ]),
]


@pytest.mark.parametrize("case_id,messages", A010_BALANCED_LITERAL_CASES,
                         ids=[row[0] for row in A010_BALANCED_LITERAL_CASES])
def test_a010_balanced_later_literals_do_not_hide_active_opposite_claims(
        tmp_path: Path, case_id: str, messages: list[dict[str, object]]) -> None:
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2, case_id
        assert {claim["asserted_value"] for claim in claims} == {False, True}
        assert all(claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT" for claim in claims)
        assert all(not claim.get("superseded_by") for claim in claims)
        assert {claim["claim_state"] for claim in claims} == {"ACTIVE", "ACTIVE_CONTRADICTED"}
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


@pytest.mark.parametrize("first,later", [
    ("I resolved the task.",
     "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal 'I resolved the task.'."),
    ("I did not resolve the task.",
     "The reviewer wrote: 'Keep moving'; I resolved the task. I used the literal 'I did not resolve the task.'."),
], ids=["positive-predicate-in-literal", "negative-predicate-in-literal"])
def test_a010_claim_words_inside_explicit_literal_do_not_hide_opposite_claims(
        tmp_path: Path, first: str, later: str) -> None:
    messages = [
        {"role": "assistant", "content": first},
        {"role": "assistant", "content": later},
    ]
    for evaluator in (True, False):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2
        assert {claim["asserted_value"] for claim in claims} == {False, True}
        assert {claim["source_pointer"] for claim in claims} == {"/messages/0/content", "/messages/1/content"}
        assert all(not claim.get("superseded_by") for claim in claims)
        assert {claim["claim_state"] for claim in claims} == {"ACTIVE", "ACTIVE_CONTRADICTED"}
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE"


def test_round6_parser_version() -> None:
    assert PARSER_VERSIONS[TRAJECTORY] == "1.10.0"
