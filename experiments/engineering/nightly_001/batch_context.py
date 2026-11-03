"""Sharded authored descriptor integration through the existing Context Engine.

Original benchmark bodies stay at their hash-bound corpus locators. This stores
every descriptor, not a summary. Caller supplies exact expected file populations
before ingest. Recovery never dispatches benchmark producers or evaluators.
"""
import argparse,copy,datetime,hashlib,json,os,shutil,subprocess,sys,uuid
from pathlib import Path
if sys.flags.optimize:
    raise RuntimeError('Optimized Python is unsupported: invariant checks must remain enabled')
EXECUTED_DRIVER_RAW=Path(__file__).read_bytes()
EXECUTED_DRIVER_SHA256=hashlib.sha256(EXECUTED_DRIVER_RAW).hexdigest()
CODE_DIR=Path(__file__).resolve().parent
if CODE_DIR.name=='nightly_001':
    REPO=CODE_DIR.parents[2]
    ROOT=REPO.parents[2]
    HERE=ROOT/'Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/context_engine'
else:
    HERE=CODE_DIR
    ROOT=HERE.parents[2]
    REPO=ROOT/'Engineering/Active_Candidate/repo'
sys.path.insert(0,str(REPO))
from runtime.candidate.context_engine import Engine,EngineError,canonical_json,strict_json_loads
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def write(p,v):
    with p.open('xb') as f:f.write(canonical_json(v))
def rows(p):
    with p.open(encoding='utf-8') as f:
        for i,line in enumerate(f):
            if not line.strip():raise ValueError('blank descriptor row')
            row=strict_json_loads(line)
            if not isinstance(row,dict):raise ValueError('descriptor must be object')
            yield i,row
def checkpoint(work,v):
    with (work/'CHECKPOINTS.jsonl').open('ab') as f:f.write(canonical_json(v)+b'\n');f.flush();os.fsync(f.fileno())
def verify_population(expected,observed):
    if observed!=expected['shards'] or sum(s['count'] for s in observed)!=expected['expected_count']:
        raise ValueError('external expected shard membership or population differs')
def verify_external_plan(work,start,plan):
    path=start.get('external_plan_path')
    if path:
        external=Path(path)
    else:
        candidates=[p for p in HERE.glob('*PLAN.json') if sha(p)==start['plan_sha256']]
        if len(candidates)!=1:raise ValueError('original external plan locator unavailable or ambiguous; BLOCK recovery')
        external=candidates[0]
    if sha(external)!=start['plan_sha256'] or external.read_bytes()!=(work/'PLAN.json').read_bytes():
        raise ValueError('external frozen population plan differs; BLOCK recovery')
    total=sum(s['expected_count'] for s in plan['sources'])
    if plan.get('expected_total',total)!=total:raise ValueError('external expected_total arithmetic differs')
    return external
def build(plan_path,resume_work=None):
    plan=json.loads(plan_path.read_text());assert plan['batch_size']<=1000
    assert type(plan['batch_size']) is int and plan['batch_size']>0
    assert len({str(Path(s['path']).resolve()).casefold() for s in plan['sources']})==len(plan['sources']),'duplicate input source'
    assert all(type(s['expected_count']) is int and s['expected_count']>=0 for s in plan['sources'])
    if plan.get('expected_total',sum(s['expected_count'] for s in plan['sources']))!=sum(s['expected_count'] for s in plan['sources']):
        raise ValueError('expected_total differs from source populations')
    if resume_work:
        attempt=resume_work
        start=json.loads((attempt/'START.json').read_text())
        assert start['driver_sha256']==sha(Path(__file__)) and start['engine_sha256']==sha(REPO/'runtime/candidate/context_engine.py'),'identity changed; BLOCK recovery'
        assert start['plan_sha256']==sha(plan_path) and json.loads((attempt/'PLAN.json').read_text())==plan
        assert not (attempt/'BUILD_COMPLETE.json').exists(),'terminal attempt cannot resume'
        allshards=[json.loads(p.read_text()) for p in sorted(attempt.glob('RECEIPT-*.json'))]
        assert {str(p) for p in attempt.glob('shard-*')}=={s['store'] for s in allshards},'orphan partial store; BLOCK recovery'
        for s in allshards:
            e=Engine(s['store']);assert e.latest()==s['manifest']
            assert hashlib.sha256(e.read_source(s['source_id'])).hexdigest()==s['source_sha256']
        checkpoint(attempt,{'recovery':'VERIFIED_CHECKPOINT_RESUME_PENDING_UNITS_ONLY','completed_shards':len(allshards),'dispatches':0})
    else:
        attempt=HERE/('CONTEXT-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);attempt.mkdir()
        with (attempt/'PLAN.json').open('xb') as f:f.write(plan_path.read_bytes())
        with (attempt/'EXECUTED_DRIVER.py').open('xb') as f:f.write(EXECUTED_DRIVER_RAW)
        write(attempt/'START.json',{'plan_sha256':sha(plan_path),'external_plan_path':str(plan_path.resolve()),'pid':os.getpid(),'engine_sha256':sha(REPO/'runtime/candidate/context_engine.py'),'driver_sha256':EXECUTED_DRIVER_SHA256,'dispatches':0})
        allshards=[]
    total=sum(s['count'] for s in allshards)
    for source in plan['sources']:
        p=Path(source['path']);assert sha(p)==source['sha256']
        seen=0;batch=[]
        completed=[s for s in allshards if s.get('input_path')==str(p)]
        next_row=0
        for s in completed:
            assert s['input_sha256']==source['sha256'] and s['input_start']==next_row
            next_row=s['input_end']+1
        def flush():
            nonlocal total,batch
            if not batch:return
            number=len(allshards);store=attempt/f'shard-{number:06d}'
            engine=Engine(store)
            values=[{'family':source['family'],'input_path':str(p),'input_sha256':source['sha256'],'input_row':i,'descriptor':r} for i,r in batch]
            index=store/'descriptors.json';write(index,values)
            sid=engine.admit_source(index,sha(index),'ENGINEERING_RESULT',source_id=f'nightly:{number:06d}')['source_id']
            observations=[{'id':f'nightly:{number:06d}:{j:04d}','task_id':str(v['descriptor'].get('task_id',v['descriptor'].get('TASK_ID',v['descriptor'].get('instance_id',v['input_row'])))),'kind':'NIGHTLY_DESCRIPTOR','source_id':sid,'evidence_pointer':f'/{j}','value':v} for j,v in enumerate(values)]
            manifest=engine.ingest(observations)
            assert len(engine.query(kind='NIGHTLY_DESCRIPTOR',limit=1000))==len(batch)
            entry={'store':str(store),'count':len(batch),'family':source['family'],'input_path':str(p),'input_sha256':source['sha256'],'input_start':batch[0][0],'input_end':batch[-1][0],'source_id':sid,'source_sha256':sha(index),'values_sha256':hashlib.sha256(canonical_json(values)).hexdigest(),'manifest':manifest}
            allshards.append(entry);total+=len(batch)
            write(attempt/f'RECEIPT-{number:06d}.json',entry)
            checkpoint(attempt,{'completed_shards':len(allshards),'completed_units':total,'last_receipt_sha256':sha(attempt/f'RECEIPT-{number:06d}.json'),'next_input_row':batch[-1][0]+1,'dispatches':0})
            if number%20==0:print(json.dumps({'context_shards':len(allshards),'descriptors':total}),flush=True)
            batch=[]
        for i,row in rows(p):
            seen+=1
            if i<next_row:continue
            batch.append((i,row))
            if len(batch)==plan['batch_size']:flush()
        flush()
        assert seen==source['expected_count'],(p,seen,source['expected_count'])
        assert sha(p)==source['sha256'],'source changed during ingestion'
    assert total==sum(s['expected_count'] for s in plan['sources'])
    expected={'plan_sha256':sha(plan_path),'shards':allshards,'expected_count':total,'producer_pid':os.getpid(),'dispatches':0}
    write(attempt/'EXPECTED.json',expected)
    write(attempt/'BUILD_COMPLETE.json',{'expected_sha256':sha(attempt/'EXPECTED.json'),'count':total,'shards':len(allshards)})
    print(json.dumps({'attempt':str(attempt),'count':total,'shards':len(allshards)}))
def recover(work,rebuild):
    snapshot=work/('RECOVERY_DRIVER-'+EXECUTED_DRIVER_SHA256+'.py')
    if snapshot.exists():
        if sha(snapshot)!=EXECUTED_DRIVER_SHA256:raise ValueError('recovery driver snapshot conflict')
    else:
        with snapshot.open('xb') as f:f.write(EXECUTED_DRIVER_RAW)
    expected=json.loads((work/'EXPECTED.json').read_text());assert os.getpid()!=expected['producer_pid']
    assert sha(work/'EXPECTED.json')==json.loads((work/'BUILD_COMPLETE.json').read_text())['expected_sha256']
    plan=json.loads((work/'PLAN.json').read_text())
    start=json.loads((work/'START.json').read_text())
    external=verify_external_plan(work,start,plan)
    if sha(REPO/'runtime/candidate/context_engine.py')!=start['engine_sha256']:
        raise ValueError('Context Engine identity changed; BLOCK recovery')
    if sha(work/'EXECUTED_DRIVER.py')!=start['driver_sha256']:
        raise ValueError('Executed ingestion driver snapshot differs; BLOCK recovery')
    assert sha(work/'PLAN.json')==start['plan_sha256']
    assert sum(s['expected_count'] for s in plan['sources'])==expected['expected_count']
    streams={}
    for s in plan['sources']:
        p=Path(s['path']);assert sha(p)==s['sha256'],'external descriptor input changed'
        streams[str(p)]=iter(rows(p))
    actual=[json.loads(p.read_text()) for p in sorted(work.glob('RECEIPT-*.json'))]
    verify_population(expected,actual)
    count=0
    for n,s in enumerate(expected['shards']):
        engine=Engine(s['store'])
        if rebuild:engine.rebuild_index()
        assert engine.latest()==s['manifest']
        raw=engine.read_source(s['source_id']);assert hashlib.sha256(raw).hexdigest()==s['source_sha256']
        values=json.loads(raw)
        results=engine.query(kind='NIGHTLY_DESCRIPTOR',limit=1000)
        assert len(results)==s['count']
        actual=[r['value'] for r in results]
        assert hashlib.sha256(canonical_json(actual)).hexdigest()==s['values_sha256']
        assert actual==values
        for value in actual:
            i,original=next(streams[value['input_path']])
            assert value['input_row']==i and value['descriptor']==original,'recovered descriptor differs from external committed input'
        count+=len(results)
        if n%50==0:print(json.dumps({'recovered_shards':n+1,'count':count,'rebuild':rebuild}),flush=True)
    assert count==expected['expected_count']
    for stream in streams.values():
        try:next(stream)
        except StopIteration:pass
        else:raise ValueError('external input has unprocessed rows')
    receipt=work/('RECOVERY_REBUILT.json' if rebuild else 'RECOVERY_FRESH.json')
    if receipt.exists():receipt=receipt.with_name(receipt.stem+'-'+uuid.uuid4().hex[:8]+'.json')
    write(receipt,{'status':'PASS','count':count,'shards':len(expected['shards']),'pid':os.getpid(),'different_process':True,'expected_sha256':sha(work/'EXPECTED.json'),'external_plan_path':str(external),'external_plan_sha256':sha(external),'rebuild_all_indices':rebuild,'redispatches':0,'engine_sha256':start['engine_sha256'],'ingestion_driver_sha256':start['driver_sha256'],'recovery_driver_sha256':EXECUTED_DRIVER_SHA256,'recovery_driver_snapshot':str(snapshot),'driver_relation':'Read-only recovery may use prospectively repaired verification code; ingestion bytes preserved and verified separately'})
def controls(work):
    exp=json.loads((work/'EXPECTED.json').read_text());first=exp['shards'][0]
    e=Engine(first['store']);obs=e.query(kind='NIGHTLY_DESCRIPTOR',limit=1000)[0]
    results=[]
    def reject(name,fn):
        try:fn()
        except (EngineError,AssertionError,ValueError) as exc:results.append({'control':name,'status':'REJECTED','error':str(exc)[:240]})
        else:raise AssertionError('unexpected accept: '+name)
    changed=copy.deepcopy(obs);changed['id']='substitution';changed['value']['input_row']=-1
    # query returns normalized evidence_binding; use an explicit ingest envelope.
    def envelope(o):return {'id':o['id'],'task_id':o['task_id'],'kind':o['kind'],'source_id':o['evidence_binding']['source_id'],'evidence_pointer':o['evidence_binding']['pointer'],'value':o['value']}
    reject('substituted_result',lambda:e.ingest([envelope(changed)]))
    changed=copy.deepcopy(obs);changed['task_id']='FALSE_TASK'
    reject('identity_rebinding',lambda:e.ingest([envelope(changed)]))
    reject('wrong_source_hash',lambda:e.admit_source(Path(first['store'])/'descriptors.json','0'*64,'ENGINEERING_RESULT'))
    new=copy.deepcopy(obs);new['id']='new-fabricated-process-control'
    reject('fabricated_execution_identity',lambda:e.ingest([envelope(new)],provenance={'process_identity':'authenticated'}))
    # External expected membership exposes a self-consistent omission.
    receipts=[json.loads(p.read_text()) for p in sorted(work.glob('RECEIPT-*.json'))]
    reject('missing_receipt_against_frozen_expected_membership',lambda:verify_population(exp,receipts[:-1]))
    reject('duplicate_shard',lambda:verify_population(exp,receipts+[receipts[0]]))
    omission=work/'self-consistent-plan-omission-control';omission.mkdir()
    original=json.loads((work/'PLAN.json').read_text());altered=copy.deepcopy(original)
    altered['sources']=altered['sources'][:-1]
    altered['expected_total']=sum(s['expected_count'] for s in altered['sources'])
    write(omission/'PLAN.json',altered)
    start=json.loads((work/'START.json').read_text())
    external=verify_external_plan(work,start,original)
    start.update(plan_sha256=sha(omission/'PLAN.json'),external_plan_path=str(external))
    write(omission/'START.json',start)
    reject('self_consistent_plan_omission_vs_external_anchor',lambda:verify_external_plan(omission,start,altered))
    clone=work/'tampered-disposable-clone';shutil.copytree(first['store'],clone)
    (clone/'objects'/first['source_sha256']).write_bytes(b'ALTERED')
    reject('authoritative_source_tamper',lambda:Engine(clone))
    # Corruption is confined to a disposable derivative index, evidence retained.
    corrupt=work/'corrupt-index-disposable-clone';shutil.copytree(first['store'],corrupt)
    (corrupt/'index.sqlite').write_bytes(b'NIGHTLY_CORRUPT_INDEX')
    rebuilt=Engine(corrupt)
    assert rebuilt.latest()==first['manifest'] and len(rebuilt.query(kind='NIGHTLY_DESCRIPTOR',limit=1000))==first['count']
    quarantines=list(corrupt.glob('index.sqlite.corrupt-*'));assert len(quarantines)==1 and quarantines[0].read_bytes()==b'NIGHTLY_CORRUPT_INDEX'
    results.append({'control':'corrupt_derived_index','status':'REBUILT_WITH_ORIGINAL_CORRUPTION_PRESERVED'})
    write(work/'ADVERSARIAL_CONTROLS.json',{'controls':results,'redispatches':0,'semantic_authority':'NOT_ESTABLISHED','full_population_anchor':sha(work/'EXPECTED.json')})
    print(json.dumps({'controls':len(results)}))
def main():
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['build','resume','recover','rebuild','controls']);ap.add_argument('path',type=Path);a=ap.parse_args()
    if a.mode=='build':build(a.path)
    elif a.mode=='resume':build(a.path/'PLAN.json',a.path)
    elif a.mode=='controls':controls(a.path)
    else:recover(a.path,a.mode=='rebuild')
if __name__=='__main__':main()
