"""Prospective, read-only corroboration of corpus archive output ledgers.

This verifies a completed engineering catalog, not benchmark execution or truth.
Reserved BFCL IDs are identified mechanically and never passed to the auditor.
The producer and its historical receipts are never modified.
"""
import argparse
import collections
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verify(attempt, repo):
    attempt, repo = Path(attempt).resolve(), Path(repo).resolve()
    sys.path.insert(0, str(repo))
    from runtime.candidate.context_engine import Engine, canonical_json, strict_json_loads
    auditor = importlib.import_module('runtime.candidate.bfcl_structured_audit')

    def load(path):
        return strict_json_loads(Path(path).read_bytes())

    def original_rows(raw):
        try:
            value = strict_json_loads(raw)
        except json.JSONDecodeError:
            return [(i, strict_json_loads(line)) for i, line in enumerate(raw.splitlines()) if line.strip()]
        require(isinstance(value, (list, dict)), 'UNSUPPORTED_ARCHIVE_ROOT')
        return list(enumerate(value)) if isinstance(value, list) else [(None, value)]

    start = load(attempt / 'START_RECEIPT.json')
    result = load(attempt / 'RESULTS.json')
    plan_raw = (attempt / 'PLAN.json').read_bytes()
    plan = strict_json_loads(plan_raw)
    require(start == result['attempt'], 'START_RECEIPT_MISMATCH')
    require(start['PLAN_TYPE'] == 'ARCHIVED_FILES', 'WRONG_PLAN_TYPE')
    require(result['status'] == 'PASS' and not result['errors'], 'INCOMPLETE_PRODUCER')
    require(sha(plan_raw) == start['INPUT_MANIFEST_SHA256'], 'PLAN_HASH_MISMATCH')
    require(sha(canonical_json(plan['configuration'])) == start['CONFIGURATION_SHA256'], 'CONFIGURATION_HASH_MISMATCH')
    producer_commit = start['CODE_COMMIT']
    require(len(producer_commit) == 40 and all(c in '0123456789abcdef' for c in producer_commit), 'INVALID_PRODUCER_COMMIT')
    producer_tree = subprocess.check_output(['git', '-c', 'safe.directory=' + repo.as_posix(), '-C', str(repo), 'rev-parse', producer_commit + '^{tree}'], text=True).strip()
    require(start['CODE_TREE'] == producer_tree, 'CODE_TREE_DIFFERS_FROM_PRODUCER_COMMIT')
    bindings = {}
    for field, relative in [('SCRIPT_SHA256', 'experiments/engineering/corpus_001/full_corpus_pipeline.py'),
                            ('ARCHIVE_SCRIPT_SHA256', 'experiments/engineering/corpus_001/archive_catalog.py')]:
        blob = subprocess.check_output(['git', '-c', 'safe.directory=' + repo.as_posix(), '-C', str(repo), 'show', producer_commit + ':' + relative])
        require(sha(blob) == start[field], field + '_DIFFERS_FROM_PRODUCER_COMMIT')
        bindings[relative] = sha(blob)
    relative = 'runtime/candidate/bfcl_structured_audit.py'
    blob = subprocess.check_output(['git', '-c', 'safe.directory=' + repo.as_posix(), '-C', str(repo), 'show', producer_commit + ':' + relative])
    require(Path(auditor.__file__).resolve() == (repo / relative).resolve(), 'AUDITOR_IMPORT_ROOT_MISMATCH')
    require(sha(Path(auditor.__file__).read_bytes()) == sha(blob), 'RECOMPUTATION_AUDITOR_DIFFERS_FROM_PRODUCER')
    bindings[relative] = sha(blob)
    sources = {s['path']: s for s in plan['sources']}
    auxiliary = {s['path']: s for s in plan['auxiliary_sources']}
    require(len(sources) == len(plan['sources']) and len(auxiliary) == len(plan['auxiliary_sources']), 'DUPLICATE_PLANNED_SOURCE')
    require(not set(sources).intersection(auxiliary), 'AMBIGUOUS_SOURCE_ROLE')
    require(result['shards'] and result['record_count'] > 0, 'EMPTY_PRODUCER_POPULATION')
    require(len({s['store'] for s in result['shards']}) == len(result['shards']), 'DUPLICATE_SHARD')
    tasks = {}
    task_source_hashes = {}
    seen_sources = set()
    seen_responses = set()
    units, statuses = collections.Counter(), collections.Counter()
    count = audits = reserved = 0
    paths = ['ARTIFACT_CATALOG.jsonl', 'STRUCTURAL_AUDIT_RESULTS.jsonl']
    streams = [(attempt / name).open('rb') for name in paths]
    ledger_hashers = [hashlib.sha256(), hashlib.sha256()]

    def next_ledger(index, expected):
        line = streams[index].readline()
        require(bool(line.strip()), paths[index] + '_MISSING_ROW')
        ledger_hashers[index].update(line)
        require(strict_json_loads(line) == expected, paths[index] + '_ROW_MISMATCH')

    try:
        for shard in result['shards']:
            engine = Engine(shard['store'])
            engine.verify()
            require(engine._manifest == shard['manifest'], 'ENGINE_HEAD_MISMATCH')
            raw = engine.read_source(shard['index_source_id'])
            require(sha(raw) == shard['index_sha256'], 'ENGINE_INDEX_HASH_MISMATCH')
            document = strict_json_loads(raw)
            require(document['sources'] == shard['source_objects'], 'SOURCE_RECEIPT_MISMATCH')
            rows = document['records']
            require(len(rows) == shard['record_count'] == len(shard['records']), 'SHARD_COUNT_MISMATCH')
            local_aux = {s['path']: s for s in document['sources'] if s.get('role') == 'AUDIT_TASK_DEFINITION'}
            require(set(local_aux) == set(auxiliary), 'AUXILIARY_SOURCE_POPULATION_MISMATCH')
            for path, source in local_aux.items():
                require(source['sha256'] == auxiliary[path]['sha256'], 'AUXILIARY_SOURCE_HASH_MISMATCH')
                raw_task = engine.read_source(source['source_id'])
                require(sha(raw_task) == source['sha256'], 'AUXILIARY_OBJECT_HASH_MISMATCH')
                if path not in task_source_hashes:
                    for _, task in original_rows(raw_task):
                        require(task['id'] not in tasks, 'DUPLICATE_TASK_SCHEMA_ID')
                        tasks[task['id']] = task
                    task_source_hashes[path] = source['sha256']
            cursor = 0
            for source in document['sources']:
                if source.get('role') == 'AUDIT_TASK_DEFINITION':
                    continue
                path = source['path']
                require(path in sources and path not in seen_sources, 'UNPLANNED_OR_DUPLICATE_ARCHIVE_SOURCE')
                planned = sources[path]
                require(source['sha256'] == planned['sha256'], 'ARCHIVE_SOURCE_HASH_MISMATCH')
                raw_source = engine.read_source(source['source_id'])
                require(sha(raw_source) == planned['sha256'], 'ARCHIVE_OBJECT_HASH_MISMATCH')
                seen_sources.add(path)
                duplicate_ids = set()
                for pos, original in original_rows(raw_source):
                    require(isinstance(original, dict), 'NONOBJECT_ARCHIVE_ROW')
                    tid = original.get('id')
                    identity = tid if isinstance(tid, str) else 'UNKNOWN'
                    matched = identity in tasks
                    is_reserved = identity in {f'simple_python_{i}' for i in range(20, 40)}
                    role = 'AGGREGATE_SCORE_ONLY' if tid is None else planned['role']
                    duplicate = identity in duplicate_ids and identity != 'UNKNOWN'
                    duplicate_ids.add(identity)
                    response_id = sha(canonical_json({'source_path': path, 'source_sha256': planned['sha256'], 'row_index': pos,
                        'source_revision': planned['revision'], 'model_id': planned['model_id'], 'role': role}))
                    require(response_id not in seen_responses, 'DUPLICATE_RESPONSE_ID')
                    seen_responses.add(response_id)
                    expected = {'kind': 'BENCHMARK_ARCHIVED_ARTIFACT', 'task_key': planned['family'] + ':V4:' + identity,
                        'benchmark_id': planned['family'], 'version': 'V4', 'task_id': identity, 'category': planned['category'], 'model_id': planned['model_id'],
                        'response_id': response_id, 'response_id_kind': 'SOURCE_INSTANCE_ROW_ID_NOT_PRODUCER_REQUEST_ID', 'reference_id': 'UNKNOWN',
                        'task_schema_reference_id': identity if matched else 'UNKNOWN', 'source_revision': planned['revision'], 'source_path': path,
                        'source_sha256': planned['sha256'], 'source_row_index': pos, 'row_canonical_sha256': sha(canonical_json(original)),
                        'role': role, 'task_binding': 'EXACT_TASK_ID_ONLY_PRODUCER_TASK_REVISION_UNKNOWN' if matched else 'UNRESOLVED_TASK_ID_OR_AGGREGATE',
                        'duplicate_id_in_source': duplicate, 'producer_identity': 'PRODUCER_DECLARED_NOT_AUTHENTICATED', 'audit_verdict': 'NOT_COMPARABLE',
                        'official_result_is_pgop1_verdict': False, 'reserved_no_scoring': is_reserved}
                    if role == 'MODEL_RESPONSE':
                        decision = None
                        if is_reserved:
                            status = 'RESERVED_EXCLUDED_NO_SCORING'
                            reserved += 1
                        elif not matched:
                            status = 'NOT_COMPARABLE_UNRESOLVED_TASK_ID'
                        elif not identity.startswith('simple_python_'):
                            status = 'ABSTAIN_UNSUPPORTED_CATEGORY'
                        elif not isinstance(original.get('result'), str) or '<tool_call>' not in original['result']:
                            status = 'ABSTAIN_UNSUPPORTED_RESPONSE_REPRESENTATION'
                        else:
                            decision = auditor.audit(tasks[identity], original)
                            status = decision['status']
                        expected['structural_status'] = status
                        audit_row = {'response_id': response_id, 'task_id': identity, 'model_id': planned['model_id'], 'source_sha256': planned['sha256'],
                            'status': status, 'predicates': decision['predicates'] if decision is not None and status in ['STRUCTURAL_REJECT', 'STRUCTURAL_PASS', 'ABSTAIN_UNSUPPORTED_SCHEMA', 'ABSTAIN_INVALID_TASK'] else None,
                            'contract': 'pgop1.bfcl.structured-tool-call-audit.v1', 'semantic_verdict': 'NOT_COMPARABLE'}
                        next_ledger(1, audit_row)
                        statuses[status] += 1
                        audits += 1
                    require(cursor < len(rows) and rows[cursor] == expected, 'DERIVED_ROW_DIFFERS_FROM_ORIGINAL_ARCHIVE')
                    receipt = shard['records'][cursor]
                    require(receipt['row_sha256'] == sha(canonical_json(expected)), 'ROW_RECEIPT_HASH_MISMATCH')
                    require(receipt['observation_id'] == 'corpus:' + receipt['row_sha256'] and receipt['task_key'] == expected['task_key'], 'OBSERVATION_IDENTITY_MISMATCH')
                    next_ledger(0, expected)
                    cursor += 1
                    count += 1
                    units[role] += 1
                del raw_source
            require(cursor == len(rows), 'UNBOUND_EXTRA_DERIVED_ROWS')
        for index, stream in enumerate(streams):
            require(stream.read() == b'', paths[index] + '_EXTRA_ROWS_OR_BYTES')
    finally:
        for stream in streams:
            stream.close()
    require(seen_sources == set(sources), 'ARCHIVE_SOURCE_POPULATION_MISMATCH')
    require(count == result['record_count'] == sum(s['record_count'] for s in result['shards']), 'RECORD_COUNT_MISMATCH')
    require(len(seen_sources) == result['source_file_count'], 'SOURCE_FILE_COUNT_MISMATCH')
    require(dict(units) == result['units'], 'UNIT_DENOMINATORS_MISMATCH')
    require(dict(statuses) == result['structural_audit_statuses'], 'AUDIT_DENOMINATORS_MISMATCH')
    require(result['semantic_audits'] == 0 and result['semantic_verdict'] == 'NOT_COMPARABLE', 'SEMANTIC_SCOPE_PROMOTION')
    return {'schema': 'pgop1.archive-ledger-corroboration.v1', 'status': 'PASS', 'attempt_id': start['ATTEMPT_ID'],
        'producer_commit': producer_commit, 'producer_tree': producer_tree, 'producer_script_bindings': bindings, 'validator_sha256': sha(Path(__file__).read_bytes()),
        'record_count': count, 'source_file_count': len(seen_sources), 'units': dict(units), 'structural_audit_statuses': dict(statuses),
        'audit_ledger_rows': audits, 'reserved_response_rows_excluded_without_audit': reserved,
        'ledger_sha256': {name: hasher.hexdigest() for name, hasher in zip(paths, ledger_hashers)},
        'input_receipt_sha256': {name: sha((attempt / name).read_bytes()) for name in ['START_RECEIPT.json', 'PLAN.json', 'RESULTS.json']},
        'scope': 'ORIGINAL_ENGINE_BYTES_AND_ORDERED_LEDGER_CORROBORATION_ONLY', 'semantic_audits': 0, 'benchmark_executions': 0,
        'official_evaluator_executions': 0, 'reserved_auditor_calls': 0, 'formal_gate11_independence': 'NOT_CLAIMED'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('attempt')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    report = verify(args.attempt, args.repo)
    with Path(args.output).open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'status': report['status'], 'records': report['record_count'], 'source_files': report['source_file_count']}))


if __name__ == '__main__':
    main()
