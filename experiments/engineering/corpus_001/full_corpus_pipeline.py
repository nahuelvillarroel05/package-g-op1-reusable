"""Batched engineering composition of existing adapters and Context Engine.

No benchmark code is executed. Original source objects and compact, parsed
descriptors remain distinct. A task definition is never an agent execution.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import datetime

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO))
from runtime.candidate.context_engine import Engine, canonical_json, strict_json_loads
from runtime.candidate.multibenchmark.core import VerifiedSourceSession, checked_source

def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:f.write(canonical_json(data))
def load(path):return strict_json_loads(Path(path).read_bytes())
def git(*args):return subprocess.check_output(['git','-c','safe.directory='+REPO.as_posix(),'-C',str(REPO),*args],text=True).strip()

def admit_batch(store,records,sources,roots):
    """Original raw objects plus derived JSON index, using existing Engine only."""
    grants=[{'path':s['path'],'sha256':s['sha256'],'scope':'AUTHORIZED_METADATA'} for s in sources]
    engine=Engine(store,grants=grants)
    source_rows=[]
    for source in sources:
        checked_source(source['path'],roots,source['sha256'])
        sid='corpus-source:'+source['sha256']
        admitted=engine.admit_source(source['path'],source['sha256'],'AUTHORIZED_METADATA',source_id=sid)
        source_rows.append({'source_id':sid,'path':source['path'],'sha256':source['sha256'],'bytes':admitted['byte_length'],'role':source.get('role','PRIMARY')})
    document={'schema':'pgop1.full-corpus-derived-index.v1','records':records,'sources':source_rows,
              'boundary':'ENGINEERING_METADATA_AND_SOURCE_BYTES; NOT_EXECUTION_ATTESTATION'}
    path=store/'engineering-inputs/index.json';write(path,document)
    index=engine.admit_source(path,sha(path.read_bytes()),'ENGINEERING_RESULT')
    observations=[];edges=[]
    for i,row in enumerate(records):
        oid='corpus:'+sha(canonical_json(row))
        observations.append({'id':oid,'task_id':row['task_key'],'kind':row['kind'],
            'source_id':index['source_id'],'evidence_pointer':f'/records/{i}','value':row})
        sid=oid+':source'
        observations.append({'id':sid,'task_id':row['task_key'],'kind':'CORPUS_SOURCE_BINDING',
            'source_id':index['source_id'],'evidence_pointer':f'/records/{i}/source_sha256','value':row['source_sha256']})
        edges.append({'id':oid+':association','from':oid,'to':sid,'relationship':'DERIVED_ASSOCIATION',
            'evidence_bindings':[{'source_id':index['source_id'],'pointer':f'/records/{i}'}]})
        row_identity={'observation_id':oid,'task_key':row['task_key'],'row_sha256':sha(canonical_json(row))}
        records[i]={**row,'_receipt':row_identity}
    manifest=engine.ingest(observations,edges)
    verification=engine.verify()
    receipt={'store':str(store),'record_count':len(records),'source_objects':source_rows,
             'index_source_id':index['source_id'],'index_sha256':sha(path.read_bytes()),'manifest':manifest,
             'verification':verification,'records':[r['_receipt'] for r in records]}
    return receipt

def run_tasks(plan_path,out):
    plan=load(plan_path);out=Path(out);out.mkdir(exist_ok=False,parents=True)
    if git('status','--porcelain'):raise ValueError('clean committed execution code required')
    for group in plan['groups']:
        if len(group['task_ids'])!=group['expected_task_count'] or len(set(group['task_ids']))!=len(group['task_ids']):raise ValueError('explicit unique planned IDs required')
    with (out/'PLAN.json').open('xb') as f:f.write(Path(plan_path).read_bytes())
    start={'ATTEMPT_ID':out.name,'CODE_COMMIT':git('rev-parse','HEAD'),'CODE_TREE':git('rev-parse','HEAD^{tree}'),
           'INPUT_MANIFEST_SHA256':sha(Path(plan_path).read_bytes()),'CONFIGURATION_SHA256':sha(canonical_json(plan['configuration'])),
           'START_STATUS':'STARTED','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
           'RUN004_EXECUTION':'NOT_EXECUTED','process_id':os.getpid(),'SCRIPT_SHA256':sha(Path(__file__).read_bytes()),'PLAN_TYPE':'TASK_DEFINITIONS'}
    write(out/'START_RECEIPT.json',start)
    results=[];errors=[];shards=[];counter=0
    with (out/'TASK_RESULTS.jsonl').open('x',encoding='utf-8') as log:
        for gi,group in enumerate(plan['groups']):
            commitments=group['source_commitments'];primary=group['input_path'];local=[];local_shards=[]
            try:
                with VerifiedSourceSession(primary,benchmark_id=group['benchmark_id'],version=group['version'],revision=group['revision'],source_sha256=commitments[primary],allowed_roots=plan['allowed_roots'],source_commitments=commitments) as session:
                    tasks=session.tasks
                    if 'task_ids' in group:
                        wanted=set(group['task_ids']);tasks=[t for t in tasks if t['task_id'] in wanted]
                        if len(tasks)!=len(wanted):raise ValueError('selected task IDs absent or duplicate')
                    if len(tasks)!=group['expected_task_count']:raise ValueError('parsed population differs from census')
                    for offset in range(0,len(tasks),plan['configuration']['task_batch_size']):
                        batch=tasks[offset:offset+plan['configuration']['task_batch_size']]
                        rows=[]
                        for task in batch:
                            tid=task['task_id'];source=task['source_path']
                            if source!=primary:raise ValueError('parser primary differs from planned source')
                            key=':'.join((group['benchmark_id'],group['version'],group.get('split',''),tid))
                            rows.append({'kind':'BENCHMARK_TASK_DEFINITION','task_key':key,'benchmark_id':group['benchmark_id'],'version':group['version'],
                                'split':group.get('split',''),'task_id':tid,'source_revision':group['revision'],'source_path':source,
                                'source_sha256':commitments[source],'adapter_task':task,'evidence_comparability':'TASK_DEFINITION_ONLY',
                                'audit_verdict':'NOT_EVALUATED','evaluator_executed':False,'gate11_eligible':False})
                        sources=[{'path':p,'sha256':d} for p,d in commitments.items()]
                        store=out/'context'/f'shard-{counter:06d}';counter+=1
                        receipt=admit_batch(store,rows,sources,plan['allowed_roots']);local_shards.append(receipt)
                        for row in rows:
                            local.append({'benchmark_id':group['benchmark_id'],'version':group['version'],'split':group.get('split',''),'task_id':row['task_id'],
                                'task_key':row['task_key'],'source_sha256':row['source_sha256'],'source_path':source,'status':'INGESTED_PENDING_SESSION_EXIT',
                                'store':str(store),'observation_id':row['_receipt']['observation_id']})
                assert session.verified_on_exit
                for row in local:row['status']='INGESTED_SOURCE_SESSION_VERIFIED';log.write(json.dumps(row)+'\n')
                results.extend(local);shards.extend(local_shards);log.flush()
                print(json.dumps({'group':gi+1,'groups':len(plan['groups']),'processed':len(results),'errors':len(errors)}),flush=True)
            except Exception as exc:
                error={'group':gi,'input_path':primary,'benchmark_id':group['benchmark_id'],'task_count':group['expected_task_count'],
                    'status':'PROCESSING_FAILURE','error_type':type(exc).__name__,'error':str(exc),'retained_partial_records':local,'retained_shards':local_shards}
                errors.append(error);write(out/'errors'/f'group-{gi:06d}.json',error)
                print(json.dumps({'group':gi,'error_type':type(exc).__name__,'error':str(exc)}),flush=True)
    result={'status':'PASS' if not errors else 'PARTIAL_WITH_EXACT_ERRORS','attempt':start,'record_count':len(results),
        'expected_task_memberships':sum(g['expected_task_count'] for g in plan['groups']),'errors':errors,'shards':shards,
        'per_family':{family:sum(r['benchmark_id']==family for r in results) for family in sorted({g['benchmark_id'] for g in plan['groups']})},
        'RECOVERY_STATUS':'PENDING_FRESH_PROCESS','INTEGRITY_STATUS':'SOURCE_SESSION_AND_ENGINE_VERIFIED','ended_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    write(out/'RESULTS.json',result);return result

def recover_attempt(out):
    out=Path(out);result=load(out/'RESULTS.json');checked=[]
    start=load(out/'START_RECEIPT.json');assert result['attempt']==start,'start receipt differs'
    assert start['SCRIPT_SHA256']==sha(Path(__file__).read_bytes()),'recovery implementation differs'
    plan=load(out/'PLAN.json');assert sha((out/'PLAN.json').read_bytes())==start['INPUT_MANIFEST_SHA256'],'plan hash differs'
    assert sha(canonical_json(plan['configuration']))==start['CONFIGURATION_SHA256'],'configuration hash differs'
    assert os.getpid()!=start['process_id'],'fresh process required'
    assert result['record_count']>0 and result['shards'],'nonempty completed population required'
    assert sum(s['record_count'] for s in result['shards'])==result['record_count'],'truncated shard population'
    assert len({s['store'] for s in result['shards']})==len(result['shards']),'duplicate shards'
    allowed={};expected_tasks={}
    if start['PLAN_TYPE']=='TASK_DEFINITIONS':
        for group in plan['groups']:
            assert len(group['task_ids'])==group['expected_task_count'],'planned IDs/count differ'
            for tid in group['task_ids']:
                key=':'.join((group['benchmark_id'],group['version'],group.get('split',''),tid))
                assert key not in expected_tasks,'duplicate planned task identity'
                expected_tasks[key]=(group['input_path'],group['source_commitments'][group['input_path']],group['revision'])
            for path,digest in group['source_commitments'].items():
                if path in allowed:assert allowed[path]==digest,'conflicting planned source'
                allowed[path]=digest
        expected=sum(g['expected_task_count'] for g in plan['groups'])
        assert result['expected_task_memberships']==expected
        if result['status']=='PASS':assert result['record_count']==expected,'population differs from plan'
    else:
        allowed={s['path']:s['sha256'] for s in plan['sources']}
        allowed.update({s['path']:s['sha256'] for s in plan.get('auxiliary_sources',[])})
    all_observations=set();recovered_sources=set();recovered_tasks=set()
    for shard in result['shards']:
        engine=Engine(shard['store']);verification=engine.verify()
        assert engine._manifest==shard['manifest'],'recorded Engine head differs'
        index=load(Path(shard['store'])/'engineering-inputs/index.json')
        assert sha(engine.read_source(shard['index_source_id']))==shard['index_sha256']
        assert index['sources']==shard['source_objects'],'source descriptor list differs'
        for source in shard['source_objects']:
            assert allowed.get(source['path'])==source['sha256'],'source not in frozen plan'
            assert sha(engine.read_source(source['source_id']))==source['sha256']
            recovered_sources.add(source['path'])
        receipts=shard['records'];assert len(index['records'])==len(receipts)
        if start['PLAN_TYPE']=='ARCHIVED_FILES':
            from archive_catalog import iter_rows
            for source in shard['source_objects']:
                if source.get('role')=='AUDIT_TASK_DEFINITION':continue
                original=iter_rows(engine.read_source(source['source_id']))
                expected_rows=[(pos,sha(canonical_json(value))) for pos,value in original]
                actual_rows=[(row['source_row_index'],row['row_canonical_sha256']) for row in index['records'] if row['source_path']==source['path']]
                assert actual_rows==expected_rows,'archive row population/content differs from original source'
        for row,receipt in zip(index['records'],receipts):
            assert row['source_path'] in {s['path'] for s in shard['source_objects']},'unadmitted row source'
            assert allowed[row['source_path']]==row['source_sha256'],'row source hash differs from plan'
            assert receipt['observation_id'] not in all_observations,'duplicate observation receipt'
            all_observations.add(receipt['observation_id'])
            if start['PLAN_TYPE']=='TASK_DEFINITIONS':
                assert row['task_key'] not in recovered_tasks,'duplicate recovered task'
                recovered_tasks.add(row['task_key'])
                assert expected_tasks.get(row['task_key'])==(row['source_path'],row['source_sha256'],row['source_revision']),'task identity differs from plan'
            assert sha(canonical_json(row))==receipt['row_sha256']
            nodes=engine.query(identifier=receipt['observation_id'])
            nodes=[n for n in nodes if n['id']==receipt['observation_id']]
            assert len(nodes)==1 and nodes[0]['task_id']==receipt['task_key'] and nodes[0]['value']==row
            links=[e for e in engine._graph['edges'] if e['from']==receipt['observation_id']]
            assert len(links)==1 and links[0]['to']==receipt['observation_id']+':source' and links[0]['relationship']=='DERIVED_ASSOCIATION'
        engine.rebuild_index()
        assert len(engine.query(limit=2*len(receipts)+1))==2*len(receipts)
        checked.append({'store':shard['store'],'records':len(receipts),'source_objects':len(shard['source_objects']),'verification':verification,'index_rebuild':'PASS','associations':'PASS'})
    if start['PLAN_TYPE']=='ARCHIVED_FILES' and result['status']=='PASS':assert recovered_sources==set(allowed),'truncated archived source population'
    if start['PLAN_TYPE']=='TASK_DEFINITIONS':
        ledger=[strict_json_loads(line) for line in (out/'TASK_RESULTS.jsonl').read_bytes().splitlines() if line]
        assert len(ledger)==result['record_count'] and {r['task_key'] for r in ledger}==recovered_tasks,'task ledger population differs'
        if result['status']=='PASS':assert recovered_tasks==set(expected_tasks),'planned task population missing'
    report={'status':'PASS','record_count':sum(r['records'] for r in checked),'shards':checked,'process_id':os.getpid(),
        'producer_process_id':result['attempt']['process_id'],'different_process':os.getpid()!=result['attempt']['process_id'],
        'redispatches':0,'sources_reacquired':0,'integrity':'PASS','recovery':'PASS'}
    report['original_processing_status']=result['status']
    report['recovery_scope']='COMPLETE_PLANNED_POPULATION' if result['status']=='PASS' else 'VALID_RECORDS_ONLY_ORIGINAL_PROCESSING_PARTIAL'
    write(out/'FRESH_PROCESS_RECOVERY.json',report);print(json.dumps({'status':report['status'],'recovered':report['record_count']}));return report

def main():
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['tasks','recover']);ap.add_argument('path');ap.add_argument('out',nargs='?');a=ap.parse_args()
    if a.mode=='tasks':run_tasks(a.path,a.out)
    else:recover_attempt(a.path)
if __name__=='__main__':main()
