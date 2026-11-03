"""Catalog original public archives as inert evidence; never copy scores as verdicts."""
import argparse,collections,datetime,hashlib,json,os
from pathlib import Path
import sys
import full_corpus_pipeline
from full_corpus_pipeline import admit_batch,canonical_json,git,load,sha,write,strict_json_loads,checked_source

def iter_rows(raw):
    try:
        value=strict_json_loads(raw)
        if isinstance(value,list):return list(enumerate(value))
        if isinstance(value,dict):return [(None,value)]
        raise ValueError('unsupported JSON root')
    except json.JSONDecodeError:
        return [(i,strict_json_loads(line)) for i,line in enumerate(raw.splitlines()) if line.strip()]

def calling(manifest,inventory):
    taskmap={x['TASK_ID']:x for x in load(inventory)}
    for source in load(manifest)['files']:
        if source['family']!='bfcl-results' or source['status']!='SOURCE_HASH_VERIFIED':continue
        parts=Path(source['relative_path']).parts;role='MODEL_RESPONSE' if parts[1]=='result' else 'PUBLISHER_EVALUATOR_REPORT'
        model=parts[2];category=Path(parts[-1]).stem.removeprefix('BFCL_v4_').removesuffix('_result').removesuffix('_score')
        yield {'family':'bfcl_v4','version':'V4','model_id':model,'role':role,'path':source['path'],'sha256':source['sha256'],
               'revision':source['revision'],'category':category,'source_url':source['url'],'taskmap':taskmap}

def run_calling(manifest,inventory,out,roots):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    if git('status','--porcelain'):raise ValueError('clean committed execution code required')
    planned=list(calling(manifest,inventory))
    task_sources={r['SOURCE_PATH']:r['SOURCE_SHA256'] for r in load(inventory)}
    auxiliary=[{'path':p,'sha256':d,'role':'AUDIT_TASK_DEFINITION'} for p,d in task_sources.items()]
    configuration={'source_files_per_shard':20,'auditor':'RESTRICTED_V1_SIMPLE_PYTHON_EXPLICIT_ENVELOPE_ONLY','reserved_bfcl':'NO_SCORING'}
    plan={'schema':'pgop1.archived-files-plan.v1','configuration':configuration,'sources':[{k:s[k] for k in ['path','sha256','role','family','version','revision','model_id','category']} for s in planned],
          'source_manifest_sha256':sha(Path(manifest).read_bytes()),'task_inventory_sha256':sha(Path(inventory).read_bytes()),'auxiliary_sources':auxiliary}
    write(out/'PLAN.json',plan)
    start={'ATTEMPT_ID':out.name,'CODE_COMMIT':git('rev-parse','HEAD'),'CODE_TREE':git('rev-parse','HEAD^{tree}'),
        'INPUT_MANIFEST_SHA256':sha((out/'PLAN.json').read_bytes()),'CONFIGURATION_SHA256':sha(canonical_json(configuration)),
        'SCRIPT_SHA256':sha(Path(full_corpus_pipeline.__file__).read_bytes()),'ARCHIVE_SCRIPT_SHA256':sha(Path(__file__).read_bytes()),'PLAN_TYPE':'ARCHIVED_FILES',
        'START_STATUS':'STARTED','process_id':os.getpid(),'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'RUN004_EXECUTION':'NOT_EXECUTED'}
    write(out/'START_RECEIPT.json',start)
    counts=collections.Counter();audits=collections.Counter();errors=[];shards=[];batch=[];sources=[];source_count=0
    from runtime.candidate.bfcl_structured_audit import audit
    taskrows={}
    for s,digest in task_sources.items():
        _,raw=checked_source(s,roots,digest)
        for _,r in iter_rows(raw):taskrows[r['id']]=r
    def flush():
        nonlocal batch,sources
        if not batch:return
        receipt=admit_batch(out/'context'/f'shard-{len(shards):06d}',batch,sources+auxiliary,roots);shards.append(receipt)
        batch=[];sources=[]
        print(json.dumps({'source_files':source_count,'records':sum(counts.values()),'shards':len(shards),'errors':len(errors)}),flush=True)
    with (out/'ARTIFACT_CATALOG.jsonl').open('x',encoding='utf-8') as log,(out/'STRUCTURAL_AUDIT_RESULTS.jsonl').open('x',encoding='utf-8') as auditlog:
        for s in planned:
            try:
                raw=Path(s['path']).read_bytes();assert sha(raw)==s['sha256'],'source hash mismatch'
                original_rows=iter_rows(raw);seen=set();file_records=[];file_audits=[];file_audit_counts=collections.Counter()
                for pos,row in original_rows:
                    if not isinstance(row,dict):raise ValueError('non-object archive row')
                    tid=row.get('id');identity=tid if isinstance(tid,str) else 'UNKNOWN'
                    matched=identity in s['taskmap'];reserved=identity in {f'simple_python_{i}' for i in range(20,40)}
                    is_summary=tid is None
                    role='AGGREGATE_SCORE_ONLY' if is_summary else s['role']
                    duplicate=identity in seen and identity!='UNKNOWN';seen.add(identity)
                    rid=sha(canonical_json({'source_path':s['path'],'source_sha256':s['sha256'],'row_index':pos,
                        'source_revision':s['revision'],'model_id':s['model_id'],'role':role}))
                    record={'kind':'BENCHMARK_ARCHIVED_ARTIFACT','task_key':s['family']+':V4:'+identity,
                        'benchmark_id':s['family'],'version':'V4','task_id':identity,'category':s['category'],'model_id':s['model_id'],
                        'response_id':rid,'response_id_kind':'SOURCE_INSTANCE_ROW_ID_NOT_PRODUCER_REQUEST_ID','reference_id':'UNKNOWN',
                        'task_schema_reference_id':identity if matched else 'UNKNOWN','source_revision':s['revision'],'source_path':s['path'],
                        'source_sha256':s['sha256'],'source_row_index':pos,'row_canonical_sha256':sha(canonical_json(row)),
                        'role':role,'task_binding':'EXACT_TASK_ID_ONLY_PRODUCER_TASK_REVISION_UNKNOWN' if matched else 'UNRESOLVED_TASK_ID_OR_AGGREGATE',
                        'duplicate_id_in_source':duplicate,'producer_identity':'PRODUCER_DECLARED_NOT_AUTHENTICATED','audit_verdict':'NOT_COMPARABLE',
                        'official_result_is_pgop1_verdict':False,'reserved_no_scoring':reserved}
                    file_records.append(record)
                    if role=='MODEL_RESPONSE':
                        result=row.get('result')
                        if reserved:status='RESERVED_EXCLUDED_NO_SCORING'
                        elif not matched:status='NOT_COMPARABLE_UNRESOLVED_TASK_ID'
                        elif not identity.startswith('simple_python_'):status='ABSTAIN_UNSUPPORTED_CATEGORY'
                        elif not isinstance(result,str) or '<tool_call>' not in result:status='ABSTAIN_UNSUPPORTED_RESPONSE_REPRESENTATION'
                        else:
                            decision=audit(taskrows[identity],row);status=decision['status']
                        record['structural_status']=status
                        file_audits.append({'response_id':rid,'task_id':identity,'model_id':s['model_id'],'source_sha256':s['sha256'],
                                'status':status,'predicates':decision['predicates'] if status in ['STRUCTURAL_REJECT','STRUCTURAL_PASS','ABSTAIN_UNSUPPORTED_SCHEMA','ABSTAIN_INVALID_TASK'] else None,
                                'contract':'pgop1.bfcl.structured-tool-call-audit.v1','semantic_verdict':'NOT_COMPARABLE'})
                        file_audit_counts[status]+=1
                for record in file_records:
                    batch.append(record);log.write(json.dumps(record)+'\n');counts[record['role']]+=1
                for record in file_audits:auditlog.write(json.dumps(record)+'\n')
                audits.update(file_audit_counts)
                sources.append({'path':s['path'],'sha256':s['sha256'],'role':'ARCHIVE'});source_count+=1
                if len(sources)>=20:flush();log.flush();auditlog.flush()
            except Exception as exc:
                error={'source_path':s['path'],'source_sha256':s['sha256'],'error_type':type(exc).__name__,'error':str(exc),'status':'PROCESSING_FAILURE'}
                errors.append(error);write(out/'errors'/f'file-{len(errors):06d}.json',error)
        flush()
    result={'status':'PASS' if not errors else 'PARTIAL_WITH_EXACT_ERRORS','attempt':start,'record_count':sum(counts.values()),'source_file_count':source_count,
        'units':dict(counts),'structural_audit_statuses':dict(audits),'semantic_audits':0,'semantic_verdict':'NOT_COMPARABLE','errors':errors,'shards':shards,
        'RECOVERY_STATUS':'PENDING_FRESH_PROCESS','INTEGRITY_STATUS':'ORIGINAL_SOURCES_AND_DERIVED_INDEX_VERIFIED'}
    write(out/'RESULTS.json',result);print(json.dumps({'status':result['status'],'counts':dict(counts),'audits':dict(audits),'errors':len(errors)}))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('manifest');ap.add_argument('inventory');ap.add_argument('out');ap.add_argument('allowed_root');a=ap.parse_args()
    run_calling(a.manifest,a.inventory,a.out,[a.allowed_root])
if __name__=='__main__':main()
