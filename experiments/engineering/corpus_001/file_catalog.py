"""Ingest source-bound archive catalogs into existing Engine, without scoring."""
import argparse,datetime,json,os
from pathlib import Path
import full_corpus_pipeline as pipeline
from full_corpus_pipeline import Engine,admit_batch,canonical_json,git,load,sha,write

def run(plan_path,out):
    plan=load(plan_path);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    assert not git('status','--porcelain'),'clean committed code required'
    with (out/'PLAN.json').open('xb') as f:f.write(Path(plan_path).read_bytes())
    source_map={s['path']:s for s in plan['sources']}
    assert len(source_map)==len(plan['sources']) and plan['records'],'unique sources/nonempty catalog required'
    hashes=[sha(canonical_json(r)) for r in plan['records']];assert len(set(hashes))==len(hashes),'duplicate catalog observations'
    for r in plan['records']:assert source_map[r['source_path']]['sha256']==r['source_sha256']
    start={'ATTEMPT_ID':out.name,'CODE_COMMIT':git('rev-parse','HEAD'),'CODE_TREE':git('rev-parse','HEAD^{tree}'),
        'INPUT_MANIFEST_SHA256':sha(Path(plan_path).read_bytes()),'CONFIGURATION_SHA256':sha(canonical_json(plan['configuration'])),
        'SCRIPT_SHA256':sha(Path(__file__).read_bytes()),'DEPENDENCY_SHA256':sha(Path(pipeline.__file__).read_bytes()),
        'START_STATUS':'STARTED','process_id':os.getpid(),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'RUN004_EXECUTION':'NOT_EXECUTED'}
    write(out/'START_RECEIPT.json',start);shards=[];errors=[];count=0
    batch_size=plan['configuration']['batch_size']
    for i in range(0,len(plan['records']),batch_size):
        rows=plan['records'][i:i+batch_size]
        sources=[source_map[p] for p in sorted({r['source_path'] for r in rows})]
        try:
            receipt=admit_batch(out/'context'/f'shard-{i//batch_size:06d}',rows,sources,plan['allowed_roots'])
            shards.append(receipt);count+=len(rows)
            print(json.dumps({'processed':count,'planned':len(plan['records']),'errors':len(errors)}),flush=True)
        except Exception as exc:
            error={'batch_offset':i,'records':len(rows),'status':'PROCESSING_FAILURE','error_type':type(exc).__name__,'error':str(exc)}
            errors.append(error);write(out/'errors'/f'batch-{i:06d}.json',error)
    result={'status':'PASS' if not errors else 'PARTIAL_WITH_EXACT_ERRORS','attempt':start,'record_count':count,'expected_record_count':len(plan['records']),
        'source_file_count':len(source_map),'shards':shards,'errors':errors,'audit_verdict':'NOT_EVALUATED','RECOVERY_STATUS':'PENDING_FRESH_PROCESS','INTEGRITY_STATUS':'ENGINE_VERIFIED'}
    write(out/'RESULTS.json',result)

def recover(out):
    out=Path(out);start=load(out/'START_RECEIPT.json');result=load(out/'RESULTS.json');plan=load(out/'PLAN.json')
    assert start==result['attempt'] and os.getpid()!=start['process_id']
    assert sha((out/'PLAN.json').read_bytes())==start['INPUT_MANIFEST_SHA256']
    assert sha(canonical_json(plan['configuration']))==start['CONFIGURATION_SHA256']
    assert sha(Path(__file__).read_bytes())==start['SCRIPT_SHA256'] and sha(Path(pipeline.__file__).read_bytes())==start['DEPENDENCY_SHA256']
    assert result['record_count']>0 and sum(s['record_count'] for s in result['shards'])==result['record_count']
    assert len({s['store'] for s in result['shards']})==len(result['shards'])
    expected={sha(canonical_json(r)) for r in plan['records']};source_map={s['path']:s['sha256'] for s in plan['sources']}
    seen=set();sources_seen=set();shards=[]
    for s in result['shards']:
        engine=Engine(s['store']);engine.verify();assert engine._manifest==s['manifest']
        raw=engine.read_source(s['index_source_id']);assert sha(raw)==s['index_sha256'];doc=__import__('json').loads(raw)
        assert doc['sources']==s['source_objects'] and len(doc['records'])==s['record_count']
        for source in s['source_objects']:
            assert source_map[source['path']]==source['sha256'] and sha(engine.read_source(source['source_id']))==source['sha256']
            sources_seen.add(source['path'])
        for row,receipt in zip(doc['records'],s['records']):
            h=sha(canonical_json(row));assert h in expected and h not in seen and h==receipt['row_sha256'];seen.add(h)
            assert source_map[row['source_path']]==row['source_sha256']
            query=[r for r in engine.query(identifier=receipt['observation_id']) if r['id']==receipt['observation_id']]
            assert len(query)==1 and query[0]['value']==row and query[0]['task_id']==receipt['task_key']
            edges=[e for e in engine._graph['edges'] if e['from']==receipt['observation_id']]
            assert len(edges)==1 and edges[0]['relationship']=='DERIVED_ASSOCIATION' and edges[0]['to']==receipt['observation_id']+':source'
        engine.rebuild_index();assert len(engine.query(limit=2*s['record_count']+1))==2*s['record_count']
        shards.append({'store':s['store'],'records':s['record_count'],'source_objects':len(s['source_objects']),'integrity':'PASS','associations':'PASS','index_rebuild':'PASS'})
    assert len(seen)==result['record_count']
    if result['status']=='PASS':assert seen==expected and sources_seen==set(source_map)
    report={'status':'PASS','record_count':len(seen),'source_file_count':len(sources_seen),'shards':shards,'different_process':True,'process_id':os.getpid(),
        'redispatches':0,'source_reacquisitions':0,'recovery_scope':'COMPLETE_PLANNED_POPULATION' if result['status']=='PASS' else 'VALID_PARTIAL_RECORDS_ONLY'}
    write(out/'FRESH_PROCESS_RECOVERY.json',report);print(json.dumps({'status':'PASS','recovered':len(seen)}))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['run','recover']);ap.add_argument('path');ap.add_argument('out',nargs='?');a=ap.parse_args()
    if a.mode=='run':run(a.path,a.out)
    else:recover(a.path)
if __name__=='__main__':main()
