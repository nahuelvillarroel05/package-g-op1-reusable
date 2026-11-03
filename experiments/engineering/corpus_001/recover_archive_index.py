"""Full archive recovery through existing Engine and its read-only derived index.

The Engine's bounded query API remains unchanged. A complete index scan checks
every stored observation against the verified authoritative graph. Original raw
sources, ledgers and counters are corroborated separately, without redispatch.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import datetime
from contextlib import closing
import sys

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO))
from runtime.candidate.context_engine import Engine,canonical_json,strict_json_loads
from verify_archive_ledgers import verify as corroborate

def require(value,message):
    if not value:raise ValueError(message)
def sha(raw):return hashlib.sha256(raw).hexdigest()

def resolve_store(raw,attempt,workspace):
    path=Path(raw)
    require('..' not in path.parts,'UNSAFE_RELATIVE_STORE')
    candidate=path if path.is_absolute() else workspace/path
    for component in (candidate,*candidate.parents):
        require(not component.is_symlink() and not getattr(component,'is_junction',lambda:False)(),'STORE_REPARSE_POINT')
    resolved=candidate.resolve(strict=True)
    require(resolved.parent==(attempt/'context').resolve(strict=True),'STORE_OUTSIDE_EXACT_ATTEMPT_CONTEXT')
    return resolved

def index_fingerprint(root):
    """Capture all indexed columns before any auto-recovery-capable Engine call."""
    root=Path(root).resolve(strict=True);count=0;digest=hashlib.sha256()
    uri=(root/'index.sqlite').as_uri()+'?mode=ro'
    with closing(sqlite3.connect(uri,uri=True)) as db:
        columns=[row[1] for row in db.execute('PRAGMA table_info(observations)')]
        require(columns==['id','task_id','kind','finding_id','event_id','artifact_id','dependency_id','active','body'],'INDEX_SCHEMA_DIFFERS')
        previous=None
        for row in db.execute('SELECT * FROM observations ORDER BY id'):
            require(previous is None or previous<row[0],'DUPLICATE_OR_UNORDERED_INDEX_ID')
            previous=row[0];digest.update(canonical_json(list(row))+b'\n');count+=1
    return {'rows':count,'all_column_sha256':digest.hexdigest(),'file_sha256':sha((root/'index.sqlite').read_bytes())}

def expected_fingerprint(engine):
    rows=sorted(engine._index_rows());digest=hashlib.sha256()
    for row in rows:digest.update(canonical_json(list(row))+b'\n')
    return {'rows':len(rows),'all_column_sha256':digest.hexdigest()}

def verify_complete_index(engine):
    """Audit every existing indexed field against the verified Engine graph."""
    actual=index_fingerprint(engine.root);expected=expected_fingerprint(engine)
    require(all(actual[k]==v for k,v in expected.items()),'INDEX_COLUMNS_OR_POPULATION_DIFFER_FROM_AUTHORITATIVE_GRAPH')
    return actual['rows']

def recover(attempt,repo,output):
    attempt,repo,output=Path(attempt).resolve(),Path(repo).resolve(),Path(output).resolve()
    require(not output.exists(),'FRESH_RECOVERY_OUTPUT_REQUIRED')
    git=lambda *args:subprocess.check_output(['git','-c','safe.directory='+repo.as_posix(),'-C',str(repo),*args])
    recovery_commit=git('rev-parse','HEAD').decode().strip()
    recovery_tree=git('rev-parse','HEAD^{tree}').decode().strip()
    bindings={}
    for relative in ['experiments/engineering/corpus_001/recover_archive_index.py',
                     'experiments/engineering/corpus_001/verify_archive_ledgers.py',
                     'runtime/candidate/context_engine.py','runtime/candidate/bfcl_structured_audit.py']:
        digest=sha(git('show',recovery_commit+':'+relative))
        require(sha((repo/relative).read_bytes())==digest,'UNCOMMITTED_RECOVERY_IMPLEMENTATION:'+relative)
        bindings[relative]=digest
    require(Path(__file__).resolve()==(repo/'experiments/engineering/corpus_001/recover_archive_index.py').resolve(),'RECOVERY_SCRIPT_ROOT_DIFFERS')
    load=lambda p:strict_json_loads(Path(p).read_bytes())
    start=load(attempt/'START_RECEIPT.json');result=load(attempt/'RESULTS.json')
    require(os.getpid()!=start['process_id'],'FRESH_PROCESS_REQUIRED')
    workspace=repo.parents[2];invocation_cwd=Path.cwd().resolve()
    require(attempt.is_relative_to(workspace),'ATTEMPT_OUTSIDE_BOUND_WORKSPACE')
    stores={s['store']:resolve_store(s['store'],attempt,workspace) for s in result['shards']}
    start_path=output.with_name(output.name+'.START.json')
    with start_path.open('x',encoding='utf-8') as f:
        json.dump({'status':'STARTED','process_id':os.getpid(),'code_commit':recovery_commit,'code_tree':recovery_tree,
            'script_bindings':bindings,'producer_workspace_root':str(workspace),'invocation_cwd':str(invocation_cwd),
            'plan_sha256':sha((attempt/'PLAN.json').read_bytes()),'result_sha256':sha((attempt/'RESULTS.json').read_bytes()),
            'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()},f,indent=2)
    # Snapshot all existing index columns before corroboration constructs an
    # Engine (which is allowed to repair a derived index during initialization).
    before_indexes={raw:index_fingerprint(path) for raw,path in stores.items()}
    # The frozen producer recorded workspace-relative store paths. Bind that
    # known root explicitly for the unchanged corroborator, then restore cwd.
    try:
        os.chdir(workspace);proof=corroborate(attempt,repo)
    finally:os.chdir(invocation_cwd)
    require(proof['status']=='PASS','ARCHIVE_CORROBORATION_FAILED')
    checked=[];total=0;all_ids=set()
    for shard in result['shards']:
        engine=Engine(stores[shard['store']]);engine.verify()
        expected=expected_fingerprint(engine)
        require(all(before_indexes[shard['store']][k]==v for k,v in expected.items()),'PREEXISTING_INDEX_COLUMNS_OR_POPULATION_DIFFER')
        require(engine._manifest==shard['manifest'],'RECORDED_ENGINE_HEAD_DIFFERS')
        document=strict_json_loads(engine.read_source(shard['index_source_id']))
        require(sha(canonical_json(document))==shard['index_sha256'],'DERIVED_INDEX_OBJECT_DIFFERS')
        nodes={r['id']:r for r in engine._graph['observations']}
        links={e['from']:[] for e in engine._graph['edges']}
        for edge in engine._graph['edges']:links[edge['from']].append(edge)
        for row,receipt in zip(document['records'],shard['records']):
            oid=receipt['observation_id'];require(oid not in all_ids,'DUPLICATE_RECOVERED_OBSERVATION');all_ids.add(oid)
            require(oid in nodes and nodes[oid]['value']==row and nodes[oid]['task_id']==receipt['task_key'],'RECOVERED_ROW_IDENTITY_DIFFERS')
            require(sha(canonical_json(row))==receipt['row_sha256'],'RECOVERED_ROW_HASH_DIFFERS')
            edge=links.get(oid,[])
            require(len(edge)==1 and edge[0]['to']==oid+':source' and edge[0]['relationship']=='DERIVED_ASSOCIATION','RECOVERED_ASSOCIATION_DIFFERS')
        expected=2*shard['record_count'];require(len(nodes)==expected,'GRAPH_POPULATION_DIFFERS')
        before=verify_complete_index(engine);require(before==expected,'INDEX_COUNT_DIFFERS')
        engine.rebuild_index();after=verify_complete_index(engine);require(after==before,'REBUILT_INDEX_DIFFERS')
        # Retrieval API controls stay within its documented bound. Complete
        # recovery above is verified for every index and graph observation.
        for receipt in (shard['records'][0],shard['records'][-1]):
            queried=[r for r in engine.query(identifier=receipt['observation_id'],limit=1) if r['id']==receipt['observation_id']]
            require(len(queried)==1 and queried[0]==nodes[receipt['observation_id']],'BOUNDED_API_RETRIEVAL_DIFFERS')
        total+=shard['record_count']
        checked.append({'store':shard['store'],'resolved_store':str(stores[shard['store']]),'records':shard['record_count'],'observations':expected,'index_scan':'PASS','index_rebuild':'PASS',
            'all_associations':'PASS','bounded_api_queries':2,'query_limit_raised':False,'pre_constructor_index_fingerprint':before_indexes[shard['store']]})
        print(json.dumps({'recovered_shards':len(checked),'shards':len(result['shards']),'records':total}),flush=True)
    require(total==proof['record_count']==result['record_count'] and len(all_ids)==total,'FINAL_RECOVERY_POPULATION_DIFFERS')
    report={'schema':'pgop1.full-archive-fresh-recovery.v1','status':'PASS','record_count':total,'source_file_count':proof['source_file_count'],
        'shards':checked,'process_id':os.getpid(),'producer_process_id':start['process_id'],'different_process':True,
        'recovery_scope':'COMPLETE_PLANNED_POPULATION_AND_ALL_EXTERNAL_LEDGERS','method':'EXISTING_ENGINE_ORIGINAL_OBJECTS_AND_COMPLETE_READ_ONLY_DERIVED_INDEX_SCAN',
        'producer_commit':start['CODE_COMMIT'],'producer_tree':start['CODE_TREE'],'recovery_code_commit':recovery_commit,'recovery_code_tree':recovery_tree,
        'recovery_committed_script_bindings':bindings,'previous_recovery_attempts':['RECOVERY_ATTEMPT_001_ERROR.json','RECOVERY_ATTEMPT_002_ERROR.json'],
        'producer_workspace_root':str(workspace),'invocation_cwd':str(invocation_cwd),'cwd_binding_basis':'Owner workspace and recorded workspace-relative Engineering store paths; original producer did not receipt cwd',
        'recovery_script_sha256':sha(Path(__file__).read_bytes()),'corroboration':proof,'redispatches':0,'sources_reacquired':0,
        'new_storage_engines':0,'query_cap_changes':0,'semantic_audits':0}
    with output.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
    print(json.dumps({'status':'PASS','recovered':total,'source_files':proof['source_file_count']}));return report

def main():
    ap=argparse.ArgumentParser();ap.add_argument('attempt');ap.add_argument('--repo',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
    recover(a.attempt,a.repo,a.output)
if __name__=='__main__':main()
