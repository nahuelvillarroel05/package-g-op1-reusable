import json

import pytest

from runtime.candidate.multibenchmark.calling import CallingFormatError, parse_bfcl


def row():
    return {'id': 'multi_turn_miss_func_0',
            'question': [[{'role': 'user', 'content': 'inert initial request'}], [],
                         [{'role': 'user', 'content': 'inert next request'}]],
            'missed_function': {'1': ['unavailable_function']}}


def test_schema_declared_missing_function_turn_is_structural_task_metadata(tmp_path):
    path = tmp_path / 'BFCL_v4_multi_turn_miss_func.json'
    path.write_text(json.dumps([row()]), encoding='utf-8')
    task = parse_bfcl(path)[0]
    assert task['metadata']['missing_function_turn_indices'] == [1]
    assert task['metadata']['question_turn_count'] == 3
    assert task['reference_type'] == 'task_definition_only'


@pytest.mark.parametrize('mutation', ['missing', 'wrong_index', 'extra_index', 'empty_names', 'blank_name', 'first_turn', 'other_category'])
def test_arbitrary_empty_turns_are_not_relaxed(tmp_path, mutation):
    task = row()
    category = 'multi_turn_miss_func'
    if mutation == 'missing': task.pop('missed_function')
    if mutation == 'wrong_index': task['missed_function'] = {'2': ['unavailable_function']}
    if mutation == 'extra_index': task['missed_function']['2'] = ['unavailable_function']
    if mutation == 'empty_names': task['missed_function'] = {'1': []}
    if mutation == 'blank_name': task['missed_function'] = {'1': ['  ']}
    if mutation == 'first_turn': task['question'][0] = []; task['missed_function']['0'] = ['unavailable_function']
    if mutation == 'other_category': category = 'multi_turn_base'; task['id'] = category + '_0'
    path = tmp_path / ('BFCL_v4_' + category + '.json')
    path.write_text(json.dumps([task]), encoding='utf-8')
    with pytest.raises(CallingFormatError):
        parse_bfcl(path)
