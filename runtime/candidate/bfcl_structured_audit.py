"""Restricted JSON tool-call audit. Never executes calls or reads official scores.

Contract v1 supports simple Python BFCL JSON calls and primitive argument types.
Unsupported schemas abstain. Reference selection is a separate second stage.
"""
import json
import math
import re
from collections import Counter

CONTRACT = 'pgop1.bfcl.structured-tool-call-audit.v1'

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result

def _finite(raw):
    value = float(raw)
    if not math.isfinite(value): raise ValueError('nonfinite number')
    return value

def audit(task, response):
    try:
        return _audit(task, response)
    except (TypeError, KeyError, AttributeError, ValueError):
        return {'contract':CONTRACT, 'task_id':task.get('id') if isinstance(task,dict) else None,
                'predicates':{k:None for k in ('FUNCTION_CALL_FORMAT_VALID','FUNCTION_NAME_VALID',
                    'FUNCTION_ARGUMENTS_VALID','FUNCTION_COUNT_VALID')}, 'calls':None,
                'status':'ABSTAIN_INVALID_TASK'}

def _audit(task, response):
    """Only task definitions and original response are permitted in this stage."""
    predicates = {k: None for k in ('FUNCTION_CALL_FORMAT_VALID', 'FUNCTION_NAME_VALID',
        'FUNCTION_ARGUMENTS_VALID', 'FUNCTION_COUNT_VALID')}
    out = {'contract': CONTRACT, 'task_id': task['id'], 'predicates': predicates,
           'calls': None, 'scope': 'structural task-relative; no execution or independent semantic truth'}
    if response.get('id') != task['id']:
        out['status'] = 'INCOMPATIBLE_ID'; return out
    try:
        raw = response['result']
        if (raw.count('<tool_call>') != 1 or raw.count('</tool_call>') != 1 or
                not re.fullmatch(r'\s*<tool_call>.*</tool_call>\s*', raw, flags=re.S)):
            raise ValueError('one JSON tool-call envelope required')
        payload = raw.split('<tool_call>')[1].split('</tool_call>')[0].strip()
        calls = json.loads(payload, object_pairs_hook=_pairs, parse_float=_finite,
                           parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
        if isinstance(calls, dict): calls = [calls]
        if not isinstance(calls, list) or not calls or any(
            not isinstance(c, dict) or set(c) != {'name', 'arguments'} or
            not isinstance(c['name'], str) or not isinstance(c['arguments'], dict) for c in calls):
            raise ValueError('invalid call structure')
    except (ValueError, KeyError, TypeError, AttributeError):
        predicates['FUNCTION_CALL_FORMAT_VALID'] = False
        out['status'] = 'STRUCTURAL_REJECT'; return out
    out['calls'] = calls
    predicates['FUNCTION_CALL_FORMAT_VALID'] = True
    # This revision supports only single-call simple_python tasks.
    if not task['id'].startswith('simple_python_'):
        out['status'] = 'ABSTAIN_UNSUPPORTED_CATEGORY'; return out
    predicates['FUNCTION_COUNT_VALID'] = len(calls) == 1
    definitions = {f['name']: f for f in task['function']}
    if len(definitions) != len(task['function']):
        out['status'] = 'ABSTAIN_INVALID_TASK'; return out
    predicates['FUNCTION_NAME_VALID'] = all(c['name'] in definitions for c in calls)
    types = {'integer': lambda v: type(v) is int, 'float': lambda v: type(v) in (int, float),
             'number': lambda v: type(v) in (int, float), 'string': lambda v: type(v) is str,
             'boolean': lambda v: type(v) is bool}
    valid = True; unsupported = False
    # Unsupported restrictions anywhere in the declared schema cannot become
    # an implied PASS merely because the constrained optional field is absent.
    for definition in definitions.values():
        schema = definition.get('parameters', {})
        required = schema.get('required', [])
        if (not isinstance(required,list) or any(not isinstance(x,str) for x in required)
                or len(required) != len(set(required)) or not set(required).issubset(schema.get('properties', {}))):
            out['status'] = 'ABSTAIN_INVALID_TASK'; return out
        if schema.get('type') not in ('dict', 'object') or set(schema) - {'type','properties','required','description'}:
            unsupported = True
        for prop in schema.get('properties', {}).values():
            if prop.get('type') not in types or set(prop) - {'type','description','default'}:
                unsupported = True
    for c in calls:
        if c['name'] not in definitions:
            valid = False; continue
        schema = definitions[c['name']]['parameters']; props = schema.get('properties', {})
        args = c['arguments']
        if not set(schema.get('required', [])).issubset(args) or not set(args).issubset(props):
            valid = False
        for key, value in args.items():
            if key not in props: continue
            kind = props[key].get('type')
            if kind not in types: unsupported = True
            elif not types[kind](value): valid = False
    predicates['FUNCTION_ARGUMENTS_VALID'] = False if not valid else None if unsupported else True
    out['status'] = ('STRUCTURAL_REJECT' if False in predicates.values() else
                     'ABSTAIN_UNSUPPORTED_SCHEMA' if None in predicates.values() else 'STRUCTURAL_PASS')
    return out

def compare_reference(decision, reference):
    """Run only after serializing audit(); never receives an official verdict."""
    if reference.get('id') != decision['task_id']:
        return {'FUNCTION_SELECTION_MATCHES_REFERENCE': None, 'status': 'INCOMPATIBLE_ID'}
    calls = decision['calls']
    truth = reference.get('ground_truth')
    if calls is None or not isinstance(truth, list) or any(not isinstance(x, dict) for x in truth):
        return {'FUNCTION_SELECTION_MATCHES_REFERENCE': None, 'status': 'NOT_COMPARABLE'}
    expected = [name for entry in truth for name in entry]
    return {'FUNCTION_SELECTION_MATCHES_REFERENCE': Counter(c['name'] for c in calls) == Counter(expected),
            'status': 'REFERENCE_RELATIVE_FUNCTION_SELECTION_ONLY'}
