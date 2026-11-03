"""Frozen bounded authentic pilot; no reserved rows, label access or dispatch.

Run from any directory: python -B bfcl_qualify.py WORKSPACE ATTEMPT_ID
Requires the preserved previous corpus workspace and a clean committed checkout.
"""
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[3]
ROOT = REPO.parents[2]
OLD = ROOT/'Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001'
OWNED_ATTEMPT = None
sys.path.insert(0, str(REPO))
from runtime.candidate.bfcl_structured_audit import audit as old_audit
from runtime.candidate.bfcl_structured_audit_v2 import audit, _json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write(path, value):
    with path.open('x', encoding='utf-8') as f:
        json.dump(value, f, indent=2, sort_keys=True, allow_nan=False)


def git(*args):
    return subprocess.check_output(['git', '-c', 'safe.directory='+REPO.as_posix(), '-C', str(REPO), *args], text=True).strip()


def source_key(path):
    return os.path.normcase(os.path.normpath(str(path)))


def source_maps(plan):
    """Frozen PLAN is authoritative for source attribution, not derived metadata."""
    responses={}; tasks={}
    for entries, target in ((plan['sources'],responses),(plan['auxiliary_sources'],tasks)):
        for entry in entries:
            key=source_key(entry['path'])
            if key in target or key in responses and target is tasks:
                raise ValueError('duplicate/conflicting PLAN source path')
            target[key]=entry
    if any(s.get('role')!='AUDIT_TASK_DEFINITION' for s in tasks.values()):
        raise ValueError('invalid PLAN task source role')
    return responses,tasks


def check_sample(sample, response_sources):
    if sample['task_id'] in {f'simple_python_{i}' for i in range(20,40)}:
        raise ValueError('reserve pointer rejected before source read')
    source=response_sources.get(source_key(sample['source_path']))
    if source is None or source['role']!='MODEL_RESPONSE' or sample.get('role')!='MODEL_RESPONSE':
        raise ValueError('sample is not a PLAN model response')
    if any(sample[field]!=source[declared] for field,declared in (
            ('source_sha256','sha256'),('model_id','model_id'),('category','category'),('source_revision','revision'))):
        raise ValueError('sample attribution differs from frozen PLAN')


def check_task_sources(actual, declared):
    seen=set()
    for entry in actual:
        key=source_key(entry['path'])
        if key in seen:raise ValueError('duplicate baseline task source')
        seen.add(key)
        source=declared.get(key)
        if source is None or set(source)!=set(entry) or any(
                entry[k]!=source[k] for k in source if k!='path'):
            raise ValueError('baseline task source differs from frozen PLAN')
    if seen!=declared.keys():raise ValueError('baseline task source set differs from frozen PLAN')


def row_at(path, pos):
    # Sources are original JSONL, not reparsed model text. Never load reserve labels.
    with path.open(encoding='utf-8') as f:
        for i, line in enumerate(f):
            if i == pos:
                return _json(line)
    raise ValueError('missing source row')


def main():
    global OWNED_ATTEMPT
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}', sys.argv[2]):
        raise ValueError('unsafe ATTEMPT_ID')
    workspace=Path(sys.argv[1]).resolve(); attempt=workspace/'attempts'/sys.argv[2]
    if git('status', '--porcelain'):
        raise ValueError('clean committed checkout required')
    attempt.mkdir(parents=True, exist_ok=False)
    OWNED_ATTEMPT = attempt
    baseline_path=workspace/'BFCL_BASELINE_FROZEN.json'
    baseline=json.loads(baseline_path.read_text())
    planpath=OLD/'attempts/attempt-0004/PLAN.json'
    assert digest(planpath)==baseline['plan_sha256']
    oldplan=json.loads(planpath.read_text())
    response_sources,task_sources=source_maps(oldplan)
    check_task_sources(baseline['task_sources'],task_sources)
    gateway=REPO/'experiments/engineering/corpus_001/archive_catalog.py'
    baseline_gateway=subprocess.check_output(['git','-c','safe.directory='+REPO.as_posix(),'-C',str(REPO),
        'show',baseline['baseline_code_commit']+':experiments/engineering/corpus_001/archive_catalog.py'])
    assert hashlib.sha256(baseline_gateway).hexdigest()==digest(gateway)
    baseline_v1=subprocess.check_output(['git','-c','safe.directory='+REPO.as_posix(),'-C',str(REPO),
        'show',baseline['baseline_code_commit']+':runtime/candidate/bfcl_structured_audit.py'])
    assert hashlib.sha256(baseline_v1).hexdigest()==digest(REPO/'runtime/candidate/bfcl_structured_audit.py')
    samples={(r['source_path'], r['source_row_index']):r for r in baseline['sample_pointers']
             if r['structural_status']!='NOT_COMPARABLE_UNRESOLVED_TASK_ID'}
    if len(samples)!=sum(r['structural_status']!='NOT_COMPARABLE_UNRESOLVED_TASK_ID' for r in baseline['sample_pointers']):
        raise ValueError('duplicate baseline sample identity')
    for sample in samples.values():check_sample(sample,response_sources)
    # Explicit representation strata in the four newly supported categories;
    # one first development task per category/representation stratum, not tuned for PASS.
    seen=set()
    for s in oldplan['sources']:
        if s['role']!='MODEL_RESPONSE' or s['category'] not in ('simple_python','live_simple','multiple','live_multiple'):
            continue
        row=row_at(Path(s['path']),0)
        raw=row.get('result')
        shape=('native_json_arguments' if isinstance(raw,list) and raw and isinstance(raw[0],dict)
               and isinstance(next(iter(raw[0].values()),None),str) else
               'native_object_arguments' if isinstance(raw,list) else
               'envelope' if isinstance(raw,str) and '<tool_call>' in raw else 'other_text')
        key=(s['category'],shape)
        if key in seen:continue
        seen.add(key)
        tid=row.get('id')
        if tid in {f'simple_python_{i}' for i in range(20,40)}:raise ValueError('reserve selected')
        samples.setdefault((s['path'],0),{'source_path':s['path'],'source_sha256':s['sha256'],
            'role':'MODEL_RESPONSE',
            'source_row_index':0,'task_id':tid,'model_id':s['model_id'],'category':s['category'],
            'source_revision':s['revision'],'row_canonical_sha256':hashlib.sha256(canonical(row)).hexdigest(),
            'selection_basis':'first task in category/representation stratum; no score selection'})
    tasks={}; taskbindings={}; verified={}
    for source in baseline['task_sources']:
        p=Path(source['path']);assert digest(p)==source['sha256'];verified[str(p)]=source['sha256']
        for line in p.open(encoding='utf-8'):
            row=_json(line)
            if row['id'] in {f'simple_python_{i}' for i in range(20,40)}:continue
            if row['id'] in tasks:raise ValueError('duplicate/conflicting task identity')
            tasks[row['id']]=row;taskbindings[row['id']]=source
    inputs=[]
    for s in samples.values():
        check_sample(s,response_sources)
        p=Path(s['source_path'])
        if str(p) not in verified:
            assert digest(p)==s['source_sha256'];verified[str(p)]=s['source_sha256']
        row=row_at(p,s['source_row_index'])
        assert hashlib.sha256(canonical(row)).hexdigest()==s['row_canonical_sha256']
        assert row['id']==s['task_id']
        assert s['task_id'] in tasks
        inputs.append({**s,'task_source':taskbindings[s['task_id']],
                       'task_canonical_sha256':hashlib.sha256(canonical(tasks[s['task_id']])).hexdigest()})
    plan={'INPUT_MANIFEST':inputs,'verified_source_files':verified,'baseline_metadata_sha256':digest(baseline_path),
          'selection':'bounded development strata, no reserve, no label/reference use',
          'EVALUATION_SCOPE':'authentic archived responses, structural task-relative only; no official evaluator',
          'script_sha256':digest(Path(__file__)),
          'historical_gateway_sha256':digest(gateway),
          'before_result_kind':'RECOMPUTED_V1_ARCHIVE_GATEWAY_ON_IDENTICAL_INPUTS',
          'runtime_sha256':{n:digest(REPO/'runtime/candidate'/n) for n in ('bfcl_structured_audit.py','bfcl_structured_audit_v2.py')}}
    write(attempt/'INPUT_MANIFEST.json',plan)
    start={'ATTEMPT_ID':attempt.name,'BASELINE_COMMIT':baseline['baseline_code_commit'],'CANDIDATE_COMMIT':git('rev-parse','HEAD'),
           'CODE_TREE':git('rev-parse','HEAD^{tree}'),'INPUT_MANIFEST':'INPUT_MANIFEST.json','INPUT_SHA256':digest(attempt/'INPUT_MANIFEST.json'),
           'EVALUATION_SCOPE':plan['EVALUATION_SCOPE'],'EXECUTED_COMMANDS':[sys.executable,'-B',str(Path(__file__)),*sys.argv[1:]],
           'RESULTS':'PENDING_TERMINAL_RECEIPT','ERRORS':'PENDING_TERMINAL_RECEIPT','REGRESSION_STATUS':'PENDING_ROOT_FULL_REGRESSION',
           'AUDIT_STATUS':'PENDING_FINAL_AUDITS','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    write(attempt/'START_RECEIPT.json',start)
    before=collections.Counter();after=collections.Counter();transitions=collections.Counter();results=[]
    for s in inputs:
        row=row_at(Path(s['source_path']),s['source_row_index']);task=tasks[s['task_id']]
        if hashlib.sha256(canonical(row)).hexdigest()!=s['row_canonical_sha256']:
            raise ValueError('response row changed after frozen input manifest')
        if hashlib.sha256(canonical(task)).hexdigest()!=s['task_canonical_sha256']:
            raise ValueError('task changed after frozen input manifest')
        # Same historical archive gateway on identical original inputs.
        raw=row.get('result')
        historical=('ABSTAIN_UNSUPPORTED_CATEGORY' if not task['id'].startswith('simple_python_') else
                    'ABSTAIN_UNSUPPORTED_RESPONSE_REPRESENTATION' if not isinstance(raw,str) or '<tool_call>' not in raw else old_audit(task,row)['status'])
        if 'structural_status' in s and s['structural_status']!=historical:
            raise ValueError('frozen historical status differs from gateway replay')
        decision=audit(task,row)
        before[historical]+=1;after[decision['status']]+=1;transitions[historical+' -> '+decision['status']]+=1
        results.append({'task_id':s['task_id'],'model_id':s['model_id'],'category':s['category'],
            'input':s,'before_status':historical,'after_status':decision['status'],'predicates':decision['predicates'],
            'decision_canonical_sha256':hashlib.sha256(canonical(decision)).hexdigest(),
            'calls_canonical_sha256':hashlib.sha256(canonical(decision['calls'])).hexdigest(),
            'semantic_verdict':decision['semantic_verdict'],'source_binding':'EXACT_ARCHIVE_MODEL_SOURCE_ROW; PRODUCER_TASK_REVISION_UNKNOWN'})
    for source, expected in verified.items():
        if digest(Path(source))!=expected:
            raise ValueError('source changed during evaluation: '+source)
    if git('status','--porcelain') or git('rev-parse','HEAD')!=start['CANDIDATE_COMMIT']:
        raise ValueError('code identity changed during evaluation')
    report={'attempt':start,'INPUT_SHA256':start['INPUT_SHA256'],'unit':'authentic archived model response row',
        'denominator':len(inputs),'BEFORE_RESULTS':before,'AFTER_RESULTS':after,'transitions':transitions,'results':results,
        'IDENTICAL_INPUT_SET':True,'BEFORE_CODE_COMMIT':baseline['baseline_code_commit'],'AFTER_CODE_COMMIT':start['CANDIDATE_COMMIT'],
        'BEFORE_RESULT_KIND':plan['before_result_kind'],'historical_gateway_sha256':plan['historical_gateway_sha256'],
        'NEW_SUPPORTED':0,'NEW_CONTRADICTED':0,'NEW_ERRORS':0,'semantic_decisive_verdicts':0,
        'official_evaluator_executions':0,'official_comparison':'NOT_EXECUTED_UNQUALIFIED_PRODUCER_TASK_REVISION',
        'comparison_circularity':'no official results/references consumed; structural task-relative only',
        'reserved_excluded_historical_rows':2180,'reserve_eligibility':'UNKNOWN_PENDING_ACCESS_REVIEW',
        'errors':[],'source_integrity_after_evaluation':'PASS',
        'REGRESSION_STATUS':'PENDING_ROOT_FULL_REGRESSION','AUDIT_STATUS':'PENDING_FINAL_AUDITS',
        'RESULTS':'COMPLETED_BOUNDED_STRUCTURAL_EVALUATION','completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    write(attempt/'RESULTS.json',report)
    print(json.dumps({'attempt':attempt.name,'rows':len(inputs),'before':before,'after':after}))


if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        if OWNED_ATTEMPT is not None:
            attempt=OWNED_ATTEMPT
            if attempt.is_dir():
                terminal={'ATTEMPT_ID':attempt.name,'RESULTS':'FAILED_WITH_PRESERVED_ERROR',
                          'ERRORS':[{'type':type(exc).__name__,'message':str(exc)}],
                          'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                          'START_STATUS':'STARTED' if (attempt/'START_RECEIPT.json').exists() else 'NOT_STARTED',
                          'REGRESSION_STATUS':'NOT_RUN','AUDIT_STATUS':'PENDING'}
                if not (attempt/'ERROR_RECEIPT.json').exists():write(attempt/'ERROR_RECEIPT.json',terminal)
        raise
