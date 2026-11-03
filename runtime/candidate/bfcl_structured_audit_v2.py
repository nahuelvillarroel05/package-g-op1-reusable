"""Prospective bounded structural audit; v1 and archived decisions stay immutable.

No evaluation of source text, function execution, official score or oracle access.
Exact response ID is necessary but does not establish producer/revision provenance.
"""
import json
import math
import re

from .bfcl_structured_audit import _finite, _pairs

CONTRACT = 'pgop1.bfcl.structured-tool-call-audit.v2'
CATEGORIES = ('simple_python', 'live_simple', 'multiple', 'live_multiple')
PREDICATES = ('FUNCTION_CALL_FORMAT_VALID', 'FUNCTION_NAME_VALID',
              'FUNCTION_ARGUMENTS_VALID', 'FUNCTION_COUNT_VALID',
              'FUNCTION_SELECTION_MATCHES_REFERENCE', 'MULTI_TURN_CONSISTENCY',
              'CATEGORY_COMPATIBILITY', 'OFFICIAL_EVALUATOR_ACCEPTANCE')


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs, parse_float=_finite,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))


def _json_value(value, depth=0):
    if depth > 32:
        return False
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is list:
        return all(_json_value(v, depth+1) for v in value)
    if type(value) is dict:
        return all(type(k) is str and _json_value(v, depth+1) for k, v in value.items())
    return False


def _schema_supported(schema, depth=0):
    """Unknown restrictions anywhere abstain, including absent optional fields."""
    if depth > 32 or not isinstance(schema, dict):
        return False
    kind = schema.get('type')
    if not isinstance(kind, str):
        return False
    allowed = {'type', 'description', 'default', 'enum'}
    if kind in ('dict', 'object'):
        allowed |= {'properties', 'required'}
        props = schema.get('properties')
        required = schema.get('required', [])
        if (not isinstance(props, dict) or not isinstance(required, list)
                or any(type(k) is not str for k in required)
                or len(required) != len(set(required)) or not set(required) <= props.keys()
                or any(type(k) is not str or not _schema_supported(v, depth+1)
                       for k, v in props.items())):
            return False
    elif kind == 'array':
        allowed.add('items')
        if not _schema_supported(schema.get('items'), depth+1):
            return False
    elif kind not in ('integer', 'float', 'number', 'string', 'boolean'):
        return False
    if set(schema) - allowed:
        return False
    if 'enum' in schema:
        enum = schema['enum']
        if (not isinstance(enum, list) or not enum
                or any(not _json_value(v) or not _matches(v, {k: v2 for k, v2 in schema.items() if k != 'enum'})
                       for v in enum)):
            return False
    return True


def _matches(value, schema):
    kind = schema['type']
    if kind in ('dict', 'object'):
        props = schema['properties']
        valid = (type(value) is dict and set(schema.get('required', [])) <= value.keys()
                 and value.keys() <= props.keys()
                 and all(_matches(v, props[k]) for k, v in value.items()))
    elif kind == 'array':
        valid = type(value) is list and all(_matches(v, schema['items']) for v in value)
    elif kind == 'integer':
        valid = type(value) is int
    elif kind in ('number', 'float'):
        valid = type(value) in (int, float)
    elif kind == 'string':
        valid = type(value) is str
    else:
        valid = type(value) is bool
    # JSON numeric equality is allowed; bool is always a distinct type.
    if valid and 'enum' in schema:
        valid = any(_same_json(value, choice) for choice in schema['enum'])
    return valid


def _same_json(left, right):
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(_same_json(v, right[k]) for k, v in left.items())
    if isinstance(left, list):
        return len(left) == len(right) and all(_same_json(a, b) for a, b in zip(left, right))
    return left == right


def _calls(raw):
    if isinstance(raw, str):
        if '<tool_call>' not in raw and '</tool_call>' not in raw:
            return None
        if (raw.count('<tool_call>') != 1 or raw.count('</tool_call>') != 1
                or not re.fullmatch(r'\s*<tool_call>.*</tool_call>\s*', raw, re.S)):
            raise ValueError('invalid envelope')
        payload = _json(raw.split('<tool_call>')[1].split('</tool_call>')[0].strip())
        calls = [payload] if isinstance(payload, dict) else payload
        if not isinstance(calls, list) or any(
                not isinstance(c, dict) or set(c) != {'name', 'arguments'} for c in calls):
            raise ValueError('invalid envelope call schema')
    elif isinstance(raw, list):
        calls = []
        for entry in raw:
            if not isinstance(entry, dict) or len(entry) != 1:
                raise ValueError('native call requires exactly one function key')
            name, args = next(iter(entry.items()))
            calls.append({'name': name, 'arguments': _json(args) if isinstance(args, str) else args})
    else:
        return None
    if any(type(c['name']) is not str or type(c['arguments']) is not dict
           or not _json_value(c['arguments']) for c in calls):
        raise ValueError('invalid name or arguments')
    return calls


def audit(task, response):
    predicates = dict.fromkeys(PREDICATES)
    out = {'contract': CONTRACT, 'task_id': task.get('id') if isinstance(task, dict) else None,
           'predicates': predicates, 'calls': None,
           'scope': 'structural task-relative; no independent semantic verdict',
           'source_binding': 'NOT_ESTABLISHED_BY_THIS_API', 'semantic_verdict': 'NOT_COMPARABLE'}
    if not isinstance(task, dict) or not isinstance(task.get('id'), str) or not isinstance(response, dict):
        out['status'] = 'ABSTAIN_INVALID_TASK'; return out
    if response.get('id') != task['id']:
        out['status'] = 'INCOMPATIBLE_ID'; return out
    category = next((c for c in CATEGORIES if re.fullmatch(re.escape(c)+r'_[0-9]+', task['id'])), None)
    predicates['CATEGORY_COMPATIBILITY'] = category is not None
    if category is None:
        out['status'] = 'ABSTAIN_UNSUPPORTED_CATEGORY'; return out
    out['category'] = category
    definitions = task.get('function')
    if (not isinstance(definitions, list) or not definitions
            or any(not isinstance(f, dict) or type(f.get('name')) is not str
                   or not isinstance(f.get('parameters'), dict) for f in definitions)
            or len({f['name'] for f in definitions}) != len(definitions)
            or category in ('simple_python', 'live_simple') and len(definitions) != 1):
        out['status'] = 'ABSTAIN_INVALID_TASK'; return out
    try:
        calls = _calls(response.get('result'))
    except (ValueError, TypeError, RecursionError):
        predicates['FUNCTION_CALL_FORMAT_VALID'] = False
        out['status'] = 'STRUCTURAL_REJECT'; return out
    if calls is None:
        out['status'] = 'ABSTAIN_UNSUPPORTED_REPRESENTATION'; return out
    out['calls'] = calls
    predicates['FUNCTION_CALL_FORMAT_VALID'] = True
    predicates['FUNCTION_COUNT_VALID'] = len(calls) == 1
    definitions = {f['name']: f for f in definitions}
    predicates['FUNCTION_NAME_VALID'] = all(c['name'] in definitions for c in calls) if calls else None
    if calls and all(_schema_supported(f['parameters']) for f in definitions.values()):
        predicates['FUNCTION_ARGUMENTS_VALID'] = all(
            c['name'] in definitions and _matches(c['arguments'], definitions[c['name']]['parameters']) for c in calls)
    core = [predicates[k] for k in PREDICATES[:4]]
    out['status'] = ('STRUCTURAL_REJECT' if False in core else
                     'ABSTAIN_UNSUPPORTED_SCHEMA' if None in core else 'STRUCTURAL_PASS')
    return out
