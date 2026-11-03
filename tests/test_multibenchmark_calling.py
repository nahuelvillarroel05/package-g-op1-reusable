import json
import stat
from types import SimpleNamespace

import pytest

from runtime.candidate.multibenchmark.calling import (
    UNKNOWN,
    CallingFormatError,
    parse_bfcl,
    parse_tau,
)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _bfcl_question(content="text"):
    return [[{"role": "user", "content": content}]]


def test_parse_bfcl_jsonl_records_line_selectors_and_unknown_revision(tmp_path):
    path = _write(
        tmp_path / "BFCL_v4_web_search.json",
        '\n{"id":"web_search_0","question":[[{"role":"user","content":"find"}]],"function":null}\n'
        '{"id":"web_search_1","question":[[{"role":"user","content":"search"}]],"function":null}\n',
    )

    rows = parse_bfcl(path)

    assert [row["task_id"] for row in rows] == ["web_search_0", "web_search_1"]
    assert rows[0]["source_family_id"] == "bfcl_v4:web_search"
    assert rows[0]["metadata"]["source_format"] == "jsonl"
    assert rows[0]["metadata"]["source_line_number"] == 2
    assert rows[0]["source_pointer"] == UNKNOWN
    assert rows[0]["source_revision"] == UNKNOWN
    assert rows[0]["reference_type"] == "task_definition_only"
    assert rows[0]["evaluator_type"] == "official_bfcl_v4_evaluator_not_acquired"


def test_parse_bfcl_json_array_uses_json_pointer(tmp_path):
    path = tmp_path / "BFCL_v4_simple_python.json"
    path.write_text(json.dumps([
        {"id": "simple_python_0", "question": _bfcl_question("add"), "function": [{"name": "add", "description": "Add values", "parameters": {"type": "dict", "properties": {}}}]},
        {"id": "simple_python_1", "question": _bfcl_question("sum"), "function": []},
    ]), encoding="utf-8")

    rows = parse_bfcl(path)

    assert rows[1]["source_pointer"] == "/1"
    assert rows[0]["metadata"]["function_schema_count"] == 1
    assert "structured_function_arguments" in rows[0]["capabilities"]


@pytest.mark.parametrize(
    "text",
    [
        '{"id":"simple_python_0","id":"simple_python_1","question":"x"}',
        '{"id":"simple_python_0","question":NaN}',
    ],
)
def test_parse_bfcl_rejects_duplicate_keys_and_nonfinite_values(tmp_path, text):
    path = _write(tmp_path / "BFCL_v4_simple_python.json", text)

    with pytest.raises(CallingFormatError):
        parse_bfcl(path)


def test_parse_bfcl_rejects_duplicate_or_mixed_category_ids(tmp_path):
    duplicate = _write(
        tmp_path / "BFCL_v4_simple_python.json",
        "\n".join([
            json.dumps({"id": "simple_python_0", "question": _bfcl_question("x")}),
            json.dumps({"id": "simple_python_0", "question": _bfcl_question("y")}),
        ]),
    )
    with pytest.raises(CallingFormatError, match="duplicate BFCL task id"):
        parse_bfcl(duplicate)

    mixed = _write(
        tmp_path / "BFCL_v4_simple_python.json",
        json.dumps([{"id": "multi_turn_base_0", "question": _bfcl_question("x")}]),
    )
    with pytest.raises(CallingFormatError, match="does not match source category"):
        parse_bfcl(mixed)


def _tau_task(task_id="10", *, domain="airline", actions=None, assertions=None):
    return {
        "id": task_id,
        "user_scenario": {"instructions": {"domain": domain, "reason_for_call": "check a reservation"}},
        "evaluation_criteria": {
            "actions": actions if actions is not None else [{"action_id": "10_0", "name": "get_reservation_details"}],
            "reward_basis": ["DB", "COMMUNICATE"],
            "nl_assertions": assertions,
        },
        "initial_state": None,
    }


def test_parse_tau_keeps_reference_trajectory_distinct_from_observed_calls(tmp_path):
    path = tmp_path / "airline" / "tasks.json"
    path.parent.mkdir()
    path.write_text(json.dumps([_tau_task()]), encoding="utf-8")

    row = parse_tau(path)[0]

    assert row["task_id"] == "tau2:airline:10"
    assert row["source_family_id"] == "tau2_v2_text_v1:airline"
    assert row["metadata"]["source_pointer"] == "/0"
    assert row["metadata"]["reference_action_count"] == 1
    assert row["reference_type"] == "reference_trajectory_and_task_criteria"
    assert row["evaluator_type"] == "tau2_declared_reward_basis_not_executed"
    assert row["source_revision"] == UNKNOWN
    assert "reference_action_trajectory" in row["capabilities"]


def test_parse_tau_accepts_null_assertions_but_rejects_domain_mismatch(tmp_path):
    path = tmp_path / "retail" / "tasks.json"
    path.parent.mkdir()
    path.write_text(json.dumps([_tau_task("6", domain="retail", assertions=None)]), encoding="utf-8")
    assert parse_tau(path)[0]["metadata"]["nl_assertion_count"] == 0

    path.write_text(json.dumps([_tau_task("6", domain="airline")]), encoding="utf-8")
    with pytest.raises(CallingFormatError, match="domain mismatch"):
        parse_tau(path)


def test_parse_tau_rejects_duplicate_task_ids_and_incompatible_format(tmp_path):
    path = tmp_path / "telecom" / "tasks.json"
    path.parent.mkdir()
    task = _tau_task("same", domain="telecom")
    path.write_text(json.dumps([task, task]), encoding="utf-8")
    with pytest.raises(CallingFormatError, match="duplicate tau task id"):
        parse_tau(path)

    path.write_text('{"id":"same"}', encoding="utf-8")
    with pytest.raises(CallingFormatError, match="JSON array"):
        parse_tau(path)


def test_parse_tau_requires_supported_domain_task_path(tmp_path):
    path = _write(tmp_path / "other" / "tasks.json", json.dumps([_tau_task()]))
    with pytest.raises(CallingFormatError, match="supported domain"):
        parse_tau(path)


@pytest.mark.parametrize(
    "question",
    ["", [None], [[]], [[None]], [[{"role": "user", "content": "  "}]], [[{"role": "", "content": "text"}]]],
)
def test_parse_bfcl_rejects_empty_or_malformed_text_turns(tmp_path, question):
    path = _write(
        tmp_path / "BFCL_v4_simple_python.json",
        json.dumps([{"id": "simple_python_0", "question": question, "function": []}]),
    )
    with pytest.raises(CallingFormatError):
        parse_bfcl(path)


def test_parse_bfcl_rejects_malformed_function_schema_and_none_member(tmp_path):
    base = {"id": "simple_python_0", "question": _bfcl_question()}
    for functions in ([None], [{}], [{"name": "  ", "description": "desc", "parameters": {"type": "dict", "properties": {}}}],
                      [{"name": "f", "description": "desc", "parameters": {"type": "dict"}}]):
        path = _write(tmp_path / "BFCL_v4_simple_python.json", json.dumps([{**base, "function": functions}]))
        with pytest.raises(CallingFormatError):
            parse_bfcl(path)


@pytest.mark.parametrize("task_id", ["", "   "])
def test_parse_tau_rejects_empty_or_whitespace_task_ids(tmp_path, task_id):
    path = tmp_path / "airline" / "tasks.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps([_tau_task(task_id)]), encoding="utf-8")
    with pytest.raises(CallingFormatError, match="empty tau task id"):
        parse_tau(path)


@pytest.mark.parametrize(
    "action",
    [None, {}, {"action_id": " ", "name": "tool"}, {"action_id": "a1", "name": "  "}],
)
def test_parse_tau_rejects_malformed_reference_actions(tmp_path, action):
    path = tmp_path / "airline" / "tasks.json"
    path.parent.mkdir(parents=True)
    task = _tau_task()
    task["evaluation_criteria"]["actions"] = [action]
    path.write_text(json.dumps([task]), encoding="utf-8")
    with pytest.raises(CallingFormatError):
        parse_tau(path)


@pytest.mark.parametrize("assertions", [{"claim": "x"}, 7, ["  "]])
def test_parse_tau_rejects_incompatible_assertion_shapes(tmp_path, assertions):
    path = tmp_path / "retail" / "tasks.json"
    path.parent.mkdir(parents=True)
    task = _tau_task("6", domain="retail")
    task["evaluation_criteria"]["nl_assertions"] = assertions
    path.write_text(json.dumps([task]), encoding="utf-8")
    with pytest.raises(CallingFormatError, match="nl_assertions"):
        parse_tau(path)


def test_parser_rejects_reparse_ancestor_before_resolve_or_read(tmp_path, monkeypatch):
    source = tmp_path / "junction" / "BFCL_v4_simple_python.json"
    original_lstat = type(source).lstat
    reparse_ancestor = tmp_path / "junction"

    def fake_lstat(path):
        if path == reparse_ancestor:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_file_attributes=0x400)
        return original_lstat(path)

    def forbidden(*args, **kwargs):
        raise AssertionError("resolve/read must not occur before reparse rejection")

    monkeypatch.setattr(type(source), "lstat", fake_lstat)
    monkeypatch.setattr(type(source), "resolve", forbidden)
    monkeypatch.setattr(type(source), "read_text", forbidden)
    with pytest.raises(CallingFormatError, match="reparse source rejected"):
        parse_bfcl(source)
