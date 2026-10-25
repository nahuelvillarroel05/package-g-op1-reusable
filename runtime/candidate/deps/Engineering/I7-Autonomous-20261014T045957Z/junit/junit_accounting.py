"""Data-only JUnit accounting; no producer or runtime inference."""
import argparse
import collections
import copy
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
from xml.parsers import expat

POLICIES = ('ROOT_SUITES', 'ALL_SUITES', 'LEAF_SUITES', 'UNKNOWN')
FIELDS = ('tests', 'failures', 'errors', 'skipped')
MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 128
MAX_ELEMENTS = 100000
ACCOUNTING_TAGS = ('testsuites', 'testsuite', 'testcase', 'failure', 'error', 'skipped')

def _safe_xml(data):
    if not isinstance(data, bytes):
        raise TypeError('XML input must be bytes')
    if len(data) > MAX_BYTES:
        raise ValueError('XML exceeds bounded input size')
    parser = expat.ParserCreate()
    depth = 0
    elements = 0
    def start(name, attributes):
        nonlocal depth, elements
        depth += 1
        elements += 1
        if depth > MAX_DEPTH:
            raise ValueError('XML exceeds bounded depth')
        if elements > MAX_ELEMENTS:
            raise ValueError('XML exceeds bounded element count')
    def end(name):
        nonlocal depth
        depth -= 1
    def reject(*args):
        raise ValueError('DTD and entity declarations are forbidden')
    parser.StartDoctypeDeclHandler = reject
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.Parse(data, True)
    root = ET.fromstring(data)
    if root.tag not in ('testsuites', 'testsuite'):
        raise ValueError('Expected unnamespaced testsuites or testsuite root')
    parents = {id(child): parent for parent in root.iter() for child in parent}
    allowed_parents = {'testsuites': ('testsuites',),
                       'testsuite': ('testsuites', 'testsuite'),
                       'testcase': ('testsuite',),
                       'failure': ('testcase',), 'error': ('testcase',), 'skipped': ('testcase',)}
    for element in root.iter():
        if any(element.tag.endswith('}' + tag) for tag in ACCOUNTING_TAGS):
            raise ValueError('Namespaced accounting nodes are unsupported')
        if element is not root and element.tag in allowed_parents:
            parent = parents[id(element)]
            if parent.tag not in allowed_parents[element.tag]:
                raise ValueError('Misplaced accounting node: ' + element.tag)
    return root

def _declarations(element):
    values, invalid = {}, {}
    for field in FIELDS:
        raw = element.get(field)
        if raw is None:
            values[field] = None
        elif raw.isascii() and raw.isdecimal():
            values[field] = int(raw)
        else:
            values[field] = None
            invalid[field] = raw
    return values, invalid

def _counts(cases):
    return {'tests': len(cases),
            'failures': sum(any(c.tag == 'failure' for c in t) for t in cases),
            'errors': sum(any(c.tag == 'error' for c in t) for t in cases),
            'skipped': sum(any(c.tag == 'skipped' for c in t) for t in cases)}

def analyze_junit(data, policy='UNKNOWN'):
    """Caller supplies admission authority. Policies select suite declarations.
    
    Each selected declaration is compared to its serialized subtree. ALL_SUITES
    explicitly counts nested nodes repeatedly; physical coverage is separate.
    """
    if policy not in POLICIES:
        raise ValueError('Unknown aggregation policy')
    root = _safe_xml(data)
    suites = list(root.iter('testsuite'))
    all_cases = list(root.iter('testcase'))
    indices = {id(s): i for i, s in enumerate(suites)}
    parents = {id(c): e for e in root.iter() for c in e}
    rows = []
    for i, suite in enumerate(suites):
        direct = [c for c in suite if c.tag == 'testcase']
        subtree = list(suite.iter('testcase'))
        declared, invalid = _declarations(suite)
        ancestor = parents.get(id(suite))
        while ancestor is not None and ancestor.tag != 'testsuite':
            ancestor = parents.get(id(ancestor))
        counts = _counts(subtree)
        rows.append({
            'index': i, 'name': suite.get('name'),
            'parent_suite_index': indices.get(id(ancestor)),
            'declared': declared, 'invalid_declarations': invalid,
            'direct_serialized': _counts(direct), 'subtree_serialized': counts,
            'count_mismatch': any(declared[f] is not None and declared[f] != counts[f] for f in FIELDS),
            'declared_minus_subtree': {
                f: None if declared[f] is None else declared[f] - counts[f] for f in FIELDS},
            'descendant_suite_indices': [
                indices[id(s)] for s in suite.iter('testsuite') if s is not suite]})
    if policy == 'ROOT_SUITES':
        selected = [r['index'] for r in rows if r['parent_suite_index'] is None]
    elif policy == 'ALL_SUITES':
        selected = list(range(len(suites)))
    elif policy == 'LEAF_SUITES':
        selected = [r['index'] for r in rows if not r['descendant_suite_indices']]
    else:
        selected = None
    identities = collections.defaultdict(list)
    records = collections.defaultdict(list)
    missing, case_rows = [], []
    for i, case in enumerate(all_cases):
        classname, name = case.get('classname'), case.get('name')
        identity = [classname, name] if classname and name else None
        if identity is None:
            missing.append(i)
        else:
            identities[(classname, name)].append(i)
        record = copy.copy(case)
        record.tail = None
        canonical = ET.canonicalize(ET.tostring(record, encoding='unicode'))
        digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        records[digest].append(i)
        case_rows.append({'index': i, 'identity': identity, 'record_sha256': digest})
    root_declared, root_invalid = _declarations(root)
    invalid = bool(root_invalid) or any(r['invalid_declarations'] for r in rows)
    aggregate = None
    if selected is not None:
        weighted = [c for i in selected for c in suites[i].iter('testcase')]
        unique = {id(c): c for c in weighted}
        serialized = _counts(weighted)
        declared = {
            f: sum(rows[i]['declared'][f] for i in selected)
            if selected and all(rows[i]['declared'][f] is not None for i in selected)
            else None for f in FIELDS}
        delta = {f: None if declared[f] is None else declared[f] - serialized[f] for f in FIELDS}
        mismatch = any(v not in (None, 0) for v in delta.values()) or any(rows[i]['count_mismatch'] for i in selected)
        unknown = any(v is None for v in declared.values()) or not selected
        accounting_status = 'FAIL' if invalid or mismatch else 'UNKNOWN' if unknown else 'PASS'
        aggregate = {
            'selected_suite_indices': selected, 'declared': declared,
            'policy_weighted_serialized': serialized,
            'unique_physical_serialized': _counts(list(unique.values())),
            'repeated_physical_records_by_policy': len(weighted) - len(unique),
            'uncovered_physical_testcase_nodes': len(all_cases) - len(unique),
            'declared_minus_policy_serialized': delta,
            'unaccounted_test_delta': delta['tests'], 'accounting_status': accounting_status}
    else:
        accounting_status = 'FAIL' if invalid else 'UNKNOWN'
    duplicates = [{'identity': list(k), 'indices': v} for k, v in identities.items() if len(v) > 1]
    exact_duplicates = [{'record_sha256': k, 'indices': v} for k, v in records.items() if len(v) > 1]
    overall = accounting_status
    if overall == 'PASS' and (missing or duplicates or aggregate['uncovered_physical_testcase_nodes']):
        overall = 'PARTIAL'
    return {
        'schema': 'I7_JUNIT_ACCOUNTING_V1', 'input_sha256': hashlib.sha256(data).hexdigest(),
        'input_bytes': len(data), 'policy': policy, 'status': overall,
        'accounting_status': accounting_status, 'serialized_physical': _counts(all_cases),
        'root_tag': root.tag, 'root_declared': root_declared,
        'root_invalid_declarations': root_invalid,
        'root_declared_role': 'Container metadata only; aggregation selects testsuite declarations',
        'suites': rows, 'aggregate': aggregate, 'testcase_records': case_rows,
        'identity_status': 'UNKNOWN' if missing else 'VERIFIED_SERIALIZED_IDENTITIES',
        'missing_identity_indices': missing, 'unique_classname_name_identities': len(identities),
        'duplicate_identities': duplicates, 'exact_duplicate_records': exact_duplicates,
        'retry_interpretation': 'UNKNOWN; duplicate records do not prove retries',
        'serialized_status_elements': {
            f: sum(1 for e in root.iter(tag))
            for f, tag in (('failures', 'failure'), ('errors', 'error'), ('skipped', 'skipped'))},
        'operational_provenance': {
            'producer': 'UNKNOWN', 'ancestry': 'UNKNOWN', 'executor_process_tool': 'UNKNOWN',
            'native_qualification_credit': 0}}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('xml', type=Path)
    parser.add_argument('--policy', choices=POLICIES, default='UNKNOWN')
    args = parser.parse_args(argv)
    try:
        with args.xml.open('rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        report = analyze_junit(data, args.policy)
    except (ValueError, TypeError, ET.ParseError, expat.ExpatError, OSError) as error:
        print(json.dumps({'schema': 'I7_JUNIT_ACCOUNTING_V1', 'status': 'REJECTED', 'error': str(error)}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report['accounting_status'] == 'FAIL' else 0

if __name__ == '__main__':
    sys.exit(main())
