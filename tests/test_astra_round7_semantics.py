"""Round-007 typed literal and code span closure regressions."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from runtime.candidate.swebench_claim_audit.generalized import PARSER_VERSIONS, audit_evidence

RUN = "astra-remediation-round-007"
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


def _assert_source_span(claim: dict[str, object], messages: list[dict[str, object]], index: int) -> None:
    content = messages[index]["content"]
    assert isinstance(content, str)
    assert claim["source_pointer"] == f"/messages/{index}/content"
    start, end = claim["match_span"]
    assert content[start:end] == claim["matched_text"]
    byte_start, byte_end = claim["byte_span"]
    encoded = content.encode("utf-8")
    assert encoded[byte_start:byte_end].decode("utf-8") == claim["matched_text"]
    assert claim["attribution"] == "ASSISTANT_ROLE_IN_TRAJECTORY_CONTENT"


LATER_LITERAL_CASES = [
    ("R7N01", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal ' done.'"),
    ("R7N02", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal '\tdone.'"),
    ("R7N03", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal '\ndone.'"),
    ("R7N04", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal 'done.'"),
    ("R7N05", "The reviewer wrote: \u2018Keep moving\u2019; I did not resolve the task. I used the literal \u2018done.\u2019."),
    ("R7N06", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal \u2018done.\u2019."),
    ("R7N07", "The reviewer wrote: \u2018Keep moving\u2019; I did not resolve the task. I used the literal 'done.'"),
    ("R7N08", "The reviewer wrote: \u201cKeep moving\u201d; I did not resolve the task. I used the literal \u201cdone.\u201d."),
    ("R7N09", 'The reviewer wrote: "Keep moving"; I did not resolve the task. I used the literal " done.".'),
    ("R7N10", "The reviewer wrote: 'Keep moving'; I did not resolve the task. `value'; token`"),
    ("R7N11", "The reviewer wrote: 'Keep moving'; I did not resolve the task.\n```text\nvalue'; token\n```"),
    ("R7N12", "The reviewer wrote: 'Keep moving'; I did not resolve the task. `value; token`"),
    ("R7N13", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal ' '."),
    ("R7N14", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal ''."),
    ("R7N15", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal ' I resolved the task.'"),
    ("R7N16", "The reviewer wrote: 'Keep moving'; I did not resolve the task. I used the literal '\u00a0done.'"),
]


@pytest.mark.parametrize("case_id,text", LATER_LITERAL_CASES,
                         ids=[row[0] for row in LATER_LITERAL_CASES])
def test_a010_balanced_later_objects_preserve_prior_opposite_claims(
        tmp_path: Path, case_id: str, text: str) -> None:
    messages = [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": text},
    ]
    for evaluator in (False, True):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2, case_id
        assert [claim["asserted_value"] for claim in claims] == [True, False], case_id
        assert all(claim["claim_state"] != "CORRECTED" for claim in claims), case_id
        assert result["CLAIM_AGGREGATION"]["active_contradicted_claim_ids"], case_id
        assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE", case_id
        _assert_source_span(claims[0], messages, 0)
        _assert_source_span(claims[1], messages, 1)


HISTORY_CASES = [
    ("R7N17", [
        {"role": "assistant", "content": "I did not resolve the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; I resolved the task. I used the literal ' done.'."},
    ], "opposite"),
    ("R7N18", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; Correction: I did not resolve the task. I used the literal ' done.'."},
    ], "correction"),
    ("R7N19", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": "The reviewer wrote: 'Keep moving'; Correction: I did not resolve the task. I used the literal 'done.'."},
    ], "correction"),
]


@pytest.mark.parametrize("case_id,messages,kind", HISTORY_CASES,
                         ids=[row[0] for row in HISTORY_CASES])
def test_a010_later_literal_does_not_change_opposite_or_correction_history(
        tmp_path: Path, case_id: str, messages: list[dict[str, object]], kind: str) -> None:
    for evaluator in (False, True):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2, case_id
        if kind == "opposite":
            assert [claim["asserted_value"] for claim in claims] == [False, True], case_id
            assert all(claim["claim_state"] != "CORRECTED" for claim in claims), case_id
            assert result["AUDIT_VERDICT"] == "INSUFFICIENT_EVIDENCE", case_id
        else:
            assert [claim["asserted_value"] for claim in claims] == [True, False], case_id
            assert claims[0]["claim_state"] == "CORRECTED", case_id
            assert claims[0]["superseded_by"] == claims[1]["claim_id"], case_id
            assert claims[1]["claim_state"] != "CORRECTED", case_id
            assert result["AUDIT_VERDICT"] == ("SUPPORTED" if not evaluator else "CONTRADICTED"), case_id
        _assert_source_span(claims[0], messages, 0)
        _assert_source_span(claims[1], messages, 1)


TYPED_LITERAL_CORRECTION_CASES = [
    ("R3N37", [
        {"role": "assistant", "content": "Yesterday, I did not resolve the task."},
        {"role": "assistant", "content": 'The literal "today" appears. Actually, yesterday, I resolved the task.'},
    ], [False, True]),
    ("R7N25", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": 'The literal "today" appears. Correction: I did not resolve the task.'},
    ], [True, False]),
    ("R7N26", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": 'The literal "today." appears. Correction: I did not resolve the task.'},
    ], [True, False]),
    ("R7N27", [
        {"role": "assistant", "content": "I resolved the task."},
        {"role": "assistant", "content": 'The literal "today" appears.'},
        {"role": "assistant", "content": "Correction: I did not resolve the task."},
    ], [True, False]),
]


@pytest.mark.parametrize("case_id,messages,values", TYPED_LITERAL_CORRECTION_CASES,
                         ids=[row[0] for row in TYPED_LITERAL_CORRECTION_CASES])
def test_typed_literal_ends_before_following_sentence_and_correction(
        tmp_path: Path, case_id: str, messages: list[dict[str, object]], values: list[bool]) -> None:
    for evaluator in (False, True):
        result = _audit(tmp_path, messages, evaluator)
        claims = result["AGENT_STATEMENT"]
        assert len(claims) == 2, case_id
        assert [claim["asserted_value"] for claim in claims] == values, case_id
        assert claims[0]["claim_state"] == "CORRECTED", case_id
        assert claims[0]["superseded_by"] == claims[1]["claim_id"], case_id
        assert claims[1]["claim_state"] != "CORRECTED", case_id
        assert result["AUDIT_VERDICT"] == ("SUPPORTED" if claims[1]["asserted_value"] == evaluator else "CONTRADICTED"), case_id
        _assert_source_span(claims[0], messages, 0)
        last_claim_message = int(claims[1]["source_pointer"].split("/")[2])
        _assert_source_span(claims[1], messages, last_claim_message)


def test_round7_uses_explicit_prospective_parser_version() -> None:
    assert PARSER_VERSIONS[TRAJECTORY] == "1.11.0"
