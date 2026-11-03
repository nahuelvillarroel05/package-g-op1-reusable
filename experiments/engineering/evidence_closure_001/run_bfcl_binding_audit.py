"""Bounded BFCL binding reconciliation. Reads only prior nonreserve row outcomes."""
from __future__ import annotations
import collections, hashlib, json, pathlib, re, sys

ROOT = pathlib.Path(r'D:\PGOP1_DATA\PGOP1_BASELINE_001')
OLD = ROOT / 'Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/bfcl'
OUT = ROOT / 'Engineering/PGOP1_SIX_FAMILY_EVIDENCE_CLOSURE_001/bfcl'
REPO = ROOT / 'Engineering/Active_Candidate/repo'
TASK_ROOT = ROOT / 'baseline/BENCHMARK_CORPUS_001/calling/gorilla/berkeley-function-call-leaderboard/bfcl_eval/data'
PLAN = json.loads((OLD / 'PROCESSING_PLAN_002.json').read_text(encoding='utf8'))
SUM = json.loads((OLD / 'attempt-002/TASK_BINDING_SUMMARY.json').read_text(encoding='utf8'))
RESERVED = {f'simple_python_{i}' for i in range(20,40)}
sys.path.insert(0, str(REPO / 'experiments/engineering/evidence_closure_001'))
from bfcl_identity_resolver import TaskRef, resolve_identity


def sha(b): return hashlib.sha256(b).hexdigest()

def read_rows(path):
    raw = path.read_bytes()
    try:
        obj = json.loads(raw)
        if isinstance(obj, list): return raw, iter(obj)
        return raw, iter([obj])
    except json.JSONDecodeError:
        return raw, (json.loads(line) for line in raw.splitlines() if line.strip())


def build_task_index():
    index = collections.defaultdict(list)
    task_source_hashes = {}
    for raw_path, expected in SUM['task_definition_sources'].items():
        path = pathlib.Path(raw_path)
        category = path.stem.removeprefix('BFCL_v4_')
        if category not in {'multi_turn_base', 'multi_turn_long_context', 'multi_turn_miss_func', 'multi_turn_miss_param'}:
            continue
        raw, rows = read_rows(path)
        actual = sha(raw)
        if actual != expected: raise ValueError(f'task source hash mismatch: {path}')
        task_source_hashes[str(path)] = actual
        for pos, row in enumerate(rows):
            if not isinstance(row, dict) or not isinstance(row.get('id'), str): continue
            task_id = row['id']
            if task_id in RESERVED:
                # Do not touch any other field in a reserved task row.
                continue
            raw_row = json.dumps(row, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf8')
            ref = TaskRef(category, task_id, str(path), actual, pos, sha(raw_row), "function" in row)
            index[task_id].append(ref)
    return index, task_source_hashes


def main():
    index, task_source_hashes = build_task_index()
    allowlist = {}
    allowlist_path, allowlist_hash = None, None
    resolver_hash = sha((REPO / 'experiments/engineering/evidence_closure_001/bfcl_identity_resolver.py').read_bytes())
    input_path = OLD / 'row_audit_results.jsonl'
    cause_counts = collections.Counter()
    per_category = collections.defaultdict(collections.Counter)
    per_source = collections.defaultdict(collections.Counter)
    associations = OUT / 'BFCL_EXACT_TASK_ASSOCIATIONS.jsonl'
    association_groups = {}
    unresolved_total = exact_total = row_count = 0
    with input_path.open('rb') as rows:
        input_hash = hashlib.sha256()
        for line in rows:
            input_hash.update(line)
            row = json.loads(line)
            row_count += 1
            if row['source_binding_status'] != 'SOURCE_BINDING_NOT_PROVEN': continue
            unresolved_total += 1
            category, task_id = row['category'], row['task_id']
            # The pinned code snapshot does not contain its format-config enumerator;
            # pass no config allowlist so no transformed format ID can be promoted.
            result = resolve_identity(task_id, category, index, allowlist, RESERVED, None)
            status = result['identity_status']
            source_path, source_hash = row['source_path'], row['source_sha256']
            cause_counts[status] += 1
            per_category[category][status] += 1
            per_source[(source_path, source_hash)][status] += 1
            if status == 'EXACT_PROMPT_IDENTITY':
                ref = result.pop('task_ref')
                key = (category, task_id, result['identity_kind'], ref.source_path, ref.source_row_index)
                if key not in association_groups:
                    association_groups[key] = {
                        'task_id': task_id,
                        'response_category': category,
                        'identity_kind': result['identity_kind'],
                        'task_source_path': ref.source_path,
                        'task_source_sha256': ref.source_sha256,
                        'task_source_row_index': ref.source_row_index,
                        'task_source_row_sha256': ref.source_row_sha256,
                        'structural_schema_status': result['structural_schema_status'],
                        'response_occurrences': 0,
                    }
                association_groups[key]['response_occurrences'] += 1
                exact_total += 1
    with associations.open('x', encoding='utf8', newline='\n') as assoc:
        for key in sorted(association_groups):
            assoc.write(json.dumps(association_groups[key], sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n')
    prior_results = json.loads((OLD / 'BFCL_FULL_SCALE_RESULTS.json').read_text(encoding='utf8'))
    if input_hash.hexdigest() != prior_results['row_results_sha256']:
        raise ValueError('row audit results hash differs from prior manifest')
    source_rows = []
    for (path, h), counts in sorted(per_source.items()):
        source_rows.append({'response_source_path': path, 'response_source_sha256': h,
                            'counts_by_identity_status': dict(counts), 'total_unresolved_rows': sum(counts.values())})
    category_rows = [{'category': cat, 'counts_by_identity_status': dict(counts), 'total_unresolved_rows': sum(counts.values())}
                     for cat, counts in sorted(per_category.items())]
    result = {
        'schema': 'pgop1.bfcl.binding-results.v1',
        'status': 'PARTIAL_EXACT_IDENTITY_RECOVERY_WITH_EXACT_LIMITATIONS',
        'input_row_results_path': str(input_path),
        'input_row_results_sha256': input_hash.hexdigest(),
        'input_population_rows': row_count,
        'prior_unresolved_rows': unresolved_total,
        'new_exact_prompt_identity_rows': exact_total,
        'remaining_unresolved_rows': unresolved_total - exact_total,
        'reserves': {'ids_inspected': 0, 'task_rows_used': 0, 'policy': 'simple_python_20..39 blocked before source-row fields are read'},
        'identity_resolution_counts': dict(cause_counts),
        'category_counts': category_rows,
        'original_response_source_hash_index': source_rows,
        'pinned_task_source_hashes': task_source_hashes,
        'format_sensitivity_allowlist': {'status': 'NOT_READ_TO_PRESERVE_RESERVE_BOUNDARY'},
        'format_config_allowlist': {'status': 'UNAVAILABLE_IN_PINNED_CODE_SNAPSHOT', 'exact_rows_promoted': 0},
        'resolver_path': str(REPO / 'experiments/engineering/evidence_closure_001/bfcl_identity_resolver.py'),
        'resolver_sha256': resolver_hash,
        'exact_associations_path': str(associations),
        'scope': 'identity only; task_id/category occurrences are joined to pinned source rows. No response body, label, possible answer, model score, tool/model execution, or official evaluator execution.',
    }
    outpath = OUT / 'BFCL_BINDING_RESULTS.json'
    with outpath.open('x', encoding='utf8', newline='\n') as f: json.dump(result, f, indent=2, ensure_ascii=False); f.write('\n')
    print(json.dumps({'unresolved': unresolved_total, 'exact': exact_total, 'remaining': unresolved_total-exact_total,
                      'counts': dict(cause_counts), 'associations': str(associations), 'result': str(outpath)}, indent=2))

if __name__ == '__main__': main()

