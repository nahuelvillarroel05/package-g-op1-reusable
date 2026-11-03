import copy
import json

import pytest

from runtime.candidate.bfcl_structured_audit_v2 import audit

TASK = {'id': 'simple_python_999999', 'function': [{'name': 'f', 'parameters': {
    'type': 'dict', 'properties': {'x': {'type': 'array', 'items': {'type': 'integer'}},
                                 'mode': {'type': 'string', 'enum': ['a', 'b']}}, 'required': ['x']}}]}


def response(args):
    return {'id': TASK['id'], 'result': [{'f': args}]}


def test_native_and_json_string_arguments():
    for args in ({'x': [1, 2]}, '{"x":[1,2]}'):
        result = audit(TASK, response(args))
        assert result['status'] == 'STRUCTURAL_PASS'
        assert result['predicates']['OFFICIAL_EVALUATOR_ACCEPTANCE'] is None
        assert result['predicates']['FUNCTION_SELECTION_MATCHES_REFERENCE'] is None
        assert result['semantic_verdict'] == 'NOT_COMPARABLE'


@pytest.mark.parametrize('args', [ {'x': [True]}, {'x': ['1']}, {'x': [1], 'mode': 'c'},
                                 {'x': [1], 'extra': 1}, {}, {'x': [float('nan')]},
                                 '{"x":[1],"x":[2]}', '{"x":[NaN]}', '{"x":[1e999]}'])
def test_strict_invalid_arguments(args):
    assert audit(TASK, response(args))['status'] == 'STRUCTURAL_REJECT'


def test_unknown_optional_restriction_abstains():
    changed = copy.deepcopy(TASK)
    changed['function'][0]['parameters']['properties']['mode']['pattern'] = 'a'
    assert audit(changed, response({'x': [1]}))['status'] == 'ABSTAIN_UNSUPPORTED_SCHEMA'


def test_unsupported_schema_on_unchosen_function_abstains():
    changed = copy.deepcopy(TASK); changed['id'] = 'multiple_999999'
    changed['function'].append({'name': 'g', 'parameters': {'type': 'dict', 'properties': {'q': {'type': 'any'}}}})
    assert audit(changed, {**response({'x': [1]}), 'id': changed['id']})['status'] == 'ABSTAIN_UNSUPPORTED_SCHEMA'


@pytest.mark.parametrize('changed_id', ['parallel_1', 'simple_java_1', 'multi_turn_base_1', 'simple_python_1:other', 'simple_python_\u0661'])
def test_unsupported_categories_no_alias(changed_id):
    changed = {**TASK, 'id': changed_id}
    assert audit(changed, {**response({'x': [1]}), 'id': changed_id})['status'] == 'ABSTAIN_UNSUPPORTED_CATEGORY'


@pytest.mark.parametrize('category', ['live_simple', 'live_multiple'])
def test_authentic_live_id_grammar_keeps_exact_identity(category):
    changed = {**TASK, 'id': category+'_999999-2-3'}
    raw = {**response({'x': [1]}), 'id': changed['id']}
    assert audit(changed, raw)['status'] == 'STRUCTURAL_PASS'
    assert audit(changed, {**raw, 'id': category+'_999999-2-4'})['status'] == 'INCOMPATIBLE_ID'
    for suffix in ('999999', '999999-2', '999999-2-3-4', '999999-2-\u0663'):
        bad={**changed, 'id': category+'_'+suffix}
        assert audit(bad, {**raw, 'id': bad['id']})['status'] == 'ABSTAIN_UNSUPPORTED_CATEGORY'


def test_empty_extra_and_unknown_calls_reject():
    for raw in ([], [{'f': {'x': [1]}}, {'f': {'x': [2]}}], [{'g': {'x': [1]}}]):
        assert audit(TASK, {**response({}), 'result': raw})['status'] == 'STRUCTURAL_REJECT'
    empty = audit(TASK, {**response({}), 'result': []})['predicates']
    assert empty['FUNCTION_COUNT_VALID'] is False
    assert empty['FUNCTION_NAME_VALID'] is None
    assert empty['FUNCTION_ARGUMENTS_VALID'] is None


def test_duplicate_outer_keys_reject_and_python_text_is_inert():
    raw = '<tool_call>{"name":"f","name":"g","arguments":{"x":[1]}}</tool_call>'
    assert audit(TASK, {**response({}), 'result': raw})['status'] == 'STRUCTURAL_REJECT'
    assert audit(TASK, {**response({}), 'result': '[f(x=[1])]'})['status'] == 'ABSTAIN_UNSUPPORTED_REPRESENTATION'
    assert audit(TASK, response("{'x':[1]}"))['status'] == 'ABSTAIN_UNSUPPORTED_REPRESENTATION'
    assert audit(TASK, {**response({}), 'result': '<tool_call>{bad json}</tool_call>'})['status'] == 'STRUCTURAL_REJECT'


def test_mixed_native_unsupported_dialect_keeps_parser_prerequisite():
    raw = {**response({}), 'result': [{'f': {'x': [1]}}, {'f': "{'x':[2]}"}]}
    result = audit(TASK, raw)
    assert result['status'] == 'ABSTAIN_UNSUPPORTED_REPRESENTATION'
    assert result['calls'] is None
    for key in ('FUNCTION_CALL_FORMAT_VALID', 'FUNCTION_NAME_VALID', 'FUNCTION_ARGUMENTS_VALID', 'FUNCTION_COUNT_VALID'):
        assert result['predicates'][key] is None


def test_identity_and_official_score_cannot_supply_decision():
    raw = response({'x': [1]})
    assert audit(TASK, {**raw, 'id': 'simple_python_1'})['status'] == 'INCOMPATIBLE_ID'
    assert audit(TASK, raw) == audit(TASK, {**raw, 'official_result': {'valid': False}})


def test_nested_object_required_fields_and_unknown_keys():
    task = copy.deepcopy(TASK)
    task['function'][0]['parameters']['properties']['x'] = {'type': 'dict', 'properties': {'a': {'type': 'integer'}}, 'required': ['a']}
    assert audit(task, response({'x': {'a': 2}}))['status'] == 'STRUCTURAL_PASS'
    assert audit(task, response({'x': {}}))['status'] == 'STRUCTURAL_REJECT'
    assert audit(task, response({'x': {'a': 2, 'b': 3}}))['status'] == 'STRUCTURAL_REJECT'


def test_nested_enum_never_equates_boolean_with_number():
    task = copy.deepcopy(TASK)
    task['function'][0]['parameters']['properties']['x'] = {
        'type': 'array', 'items': {'type': 'integer'}, 'enum': [[1]]}
    assert audit(task, response({'x': [1]}))['status'] == 'STRUCTURAL_PASS'
    assert audit(task, response({'x': [True]}))['status'] == 'STRUCTURAL_REJECT'
