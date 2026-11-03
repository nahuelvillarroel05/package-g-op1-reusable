"""Bounded authentic ingestion runner; selection must predate execution.

python -B -m runtime.candidate.multibenchmark.pipeline selection.json output-dir
python -B -m runtime.candidate.multibenchmark.pipeline --recover output-dir
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from runtime.candidate.context_engine import Engine, strict_json_loads
from .core import EvidenceError, checked_path, checked_source, ingest, normalize, parser_for, recover


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n', encoding='utf-8')


def run(selection_path, output):
    selection_path, output = Path(selection_path), Path(output)
    selection = strict_json_loads(selection_path.read_bytes())
    if selection.get('schema') != 'pgop1.multibenchmark-authentic-selection.v1':
        raise EvidenceError('unsupported selection contract')
    if output.exists():
        raise EvidenceError('fresh output required; preserve prior attempts')
    planned = []
    identities = set()
    for group in selection['groups']:
        family, version = group['benchmark_id'], group['version']
        for task_id in group['task_ids']:
            identity = (family, version, task_id)
            if identity in identities:
                raise EvidenceError('duplicate selected identity')
            identities.add(identity)
        input_path = checked_path(group['input_path'], selection['allowed_roots'])
        # Commitments and roots are checked before any parser reads task content.
        if input_path.is_file() and str(input_path) not in group['source_commitments']:
            raise EvidenceError('input file not committed')
        for source_path, digest in group['source_commitments'].items():
            checked_source(source_path, selection['allowed_roots'], digest)
        # Parse once for selection; normalization independently reparses each source.
        parsed = parser_for(family)(group['input_path'])
        tasks = {task['task_id']: task for task in parsed}
        if len(tasks) != len(parsed):
            raise EvidenceError('duplicate parser identity')
        for task_id in group['task_ids']:
            if task_id not in tasks:
                raise EvidenceError('selected authentic task absent: ' + task_id)
            planned.append((group, tasks[task_id]))
    output.mkdir(parents=True)
    (output / 'selection.json').write_bytes(selection_path.read_bytes())
    engine = Engine(output / 'context')
    results = []
    for group, task in planned:
        source_path = str(Path(task['source_path']).resolve(strict=True))
        if source_path not in group['source_commitments']:
            raise EvidenceError('primary source not preregistered')
        digest = group['source_commitments'][source_path]
        envelope = normalize(task, benchmark_id=group['benchmark_id'], version=group['version'],
                             revision=group['revision'], source_sha256=digest,
                             allowed_roots=selection['allowed_roots'], source_commitments=group['source_commitments'])
        receipt = ingest(engine, envelope, allowed_roots=selection['allowed_roots'],
                         source_commitments=group['source_commitments'], expected_identity={
                             'benchmark_id': group['benchmark_id'], 'benchmark_version': group['version'],
                             'task_id': task['task_id'], 'source_revision': group['revision'], 'source_sha256': digest})
        if recover(engine, receipt) != envelope:
            raise EvidenceError('same-process recovery differs')
        results.append({'benchmark_id': group['benchmark_id'], 'task_id': task['task_id'],
                        'source_path': source_path, 'source_sha256': digest,
                        'receipt': receipt, 'DATA_DOWNLOADED': 'REUSED' if group.get('reused') else True,
                        'DATA_INTEGRITY_VERIFIED': True, 'FORMAT_PARSED': True,
                        'EVIDENCE_NORMALIZED': True, 'CONTEXT_ENGINE_INGESTED': True,
                        'EVIDENCE_RECOVERED': 'SAME_PROCESS_ONLY', 'EVALUATOR_EXECUTED': False,
                        'SEMANTIC_REFERENCE_AVAILABLE': 'NOT_ESTABLISHED', 'GATE11_ELIGIBLE': False})
        write(output / 'results.json', {'status': 'INGESTION_IN_PROGRESS', 'records': results})
    result = {'schema': 'pgop1.multibenchmark-authentic-results.v1', 'status': 'INGESTED',
              'selection_sha256': hashlib.sha256(selection_path.read_bytes()).hexdigest(),
              'record_count': len(results), 'engine_verification': engine.verify(),
              'engine_manifest': engine.latest(), 'records': results}
    write(output / 'results.json', result)
    return result


def recover_run(output):
    output = Path(output)
    results = strict_json_loads((output / 'results.json').read_bytes())
    selection_bytes = (output / 'selection.json').read_bytes()
    selection = strict_json_loads(selection_bytes)
    if (results.get('schema') != 'pgop1.multibenchmark-authentic-results.v1' or results.get('status') != 'INGESTED'
            or results.get('record_count') != len(results.get('records', []))
            or hashlib.sha256(selection_bytes).hexdigest() != results.get('selection_sha256')):
        raise EvidenceError('results/selection commitment differs')
    planned = {}
    for group in selection['groups']:
        for task_id in group['task_ids']:
            key = group['benchmark_id'] + ':' + group['version'] + ':' + task_id
            if key in planned:
                raise EvidenceError('duplicate planned task')
            planned[key] = group
    keys = [record['receipt']['task_key'] for record in results['records']]
    if len(set(keys)) != len(keys) or set(keys) != set(planned):
        raise EvidenceError('result membership differs from selection')
    engine = Engine(output / 'context')
    if engine.latest() != results.get('engine_manifest'):
        raise EvidenceError('result Engine snapshot differs')
    if len(engine._graph['observations']) != 2 * len(planned):
        raise EvidenceError('Engine task population differs')
    checked = []
    for record in results['records']:
        envelope = recover(engine, record['receipt'])
        group = planned[record['receipt']['task_key']]
        if (envelope['task_id'] != record['task_id'] or envelope['benchmark_id'] != record['benchmark_id']
                or envelope['source_sha256'] != record['source_sha256'] or envelope['source']['path'] != record['source_path']
                or envelope['benchmark_version'] != group['version'] or envelope['source_revision'] != group['revision']
                or group['source_commitments'].get(record['source_path']) != record['source_sha256']):
            raise EvidenceError('recovered family/task differs')
        observation = record['receipt']['observation_id']
        edges = [edge for edge in engine._graph['edges'] if edge['from'] == observation]
        if len(edges) != 1 or edges[0]['to'] != observation + ':source' or edges[0]['relationship'] != 'DERIVED_ASSOCIATION':
            raise EvidenceError('source association differs')
        checked.append({'benchmark_id': record['benchmark_id'], 'task_id': record['task_id'],
                        'source_sha256': record['source_sha256'], 'EVIDENCE_RECOVERED': True,
                        'relation_verified': 'DERIVED_ASSOCIATION_ONLY'})
    report = {'status': 'PASS', 'records': checked, 'record_count': len(checked),
              'engine_verification': engine.verify(), 'process_id': __import__('os').getpid()}
    write(output / 'fresh-process-recovery.json', report)
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--recover', action='store_true')
    ap.add_argument('selection_or_output')
    ap.add_argument('output', nargs='?')
    args = ap.parse_args()
    result = recover_run(args.selection_or_output) if args.recover else run(args.selection_or_output, args.output)
    print(json.dumps({'status': result['status'], 'record_count': result['record_count']}))


if __name__ == '__main__':
    main()
