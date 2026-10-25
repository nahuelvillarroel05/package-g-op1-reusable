"""Reusable local Engineering orchestration. No operational-original dispatcher."""
import sys,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from runtime import *
def append_registry(row):
 with (ROOT/'ATTEMPT_REGISTRY.jsonl').open('ab') as f:
  f.write(canonical(row)+b'\n');f.flush();os.fsync(f.fileno())
def source_commitments():
 paths=list(ROOT.glob('*.py'))+[ROOT/'CONFIG.json']
 return {str(p):sha(p.read_bytes()) for p in paths}|CONFIG['baseline_pins']
def register(case,kind,schema):
 return {'CASE_ID':case,'RELATIONSHIP_ID':uid('REL'),'CLASSIFICATION':'ENGINEERING_LIVE',
 'PROVIDER_ID':uid('PROVIDER'),'PROVIDER_SOURCE':str(ROOT/('provider_'+kind+'.py')),'PROVIDER_SHA256':sha((ROOT/('provider_'+kind+'.py')).read_bytes()),
 'CONSUMER_ID':uid('CONSUMER'),'CONSUMER_SOURCE':str(ROOT/('consumer_'+kind+'.py')),'CONSUMER_SHA256':sha((ROOT/('consumer_'+kind+'.py')).read_bytes()),
 'OUTPUT_ID':uid('OUTPUT'),'OUTPUT_SCHEMA':schema,'INPUT_CONTRACT':schema,
 'NEGATIVE_MODE':{'structured':'OUTPUT_TAMPER','stream':'PROCESS_FAILURE','tests':'TEST_FAILURE','inventory':'INVENTORY_BINDING','events':'REVOCATION'}[kind],
 'SOURCE_ID':uid('SOURCE'),'EXECUTION_METHOD':'ISOLATED_PYTHON_PINNED_WORKER_DIRECT_POPEN',
 'AUTHORITY_SCOPE':CONFIG['authority_scope'],'VERIFICATION_METHOD':'ACTUAL_CONSUMER_RECOMPUTATION_AND_FRESH_PROCESS_RECOVERY'}
def build_request(relation,attempt,parent,variant):
 offset=int(uuid.uuid4().hex[:6],16);values=[offset+11,offset+23,offset+37,offset+41,offset+53]
 r={'CAMPAIGN_ID':CONFIG['CAMPAIGN_ID'],'CASE_ID':relation['CASE_ID'],'ATTEMPT_ID':attempt,'PARENT_ATTEMPT_ID':parent,
 'START_TIMESTAMP':now(),'SOURCE_SHA256':source_commitments(),'PROVIDER_ID':relation['PROVIDER_ID'],'CONSUMER_ID':relation['CONSUMER_ID'],
 'REQUEST_ID':uid('REQ'),'ACTOR_ID':uid('ACTOR'),'ACTOR_DESCRIPTION':'Current Codex authorized local Engineering campaign worker',
 'TOOL_ID':uid('TOOL'),'TOOL_DESCRIPTION':'CPython isolated worker launched without shell or elevation',
 'AUTHORITY_SCOPE':CONFIG['authority_scope'],'EXPECTED_OUTPUTS':[relation['OUTPUT_ID']],'relationship':relation,
 'RUN_ID':uid('RUN'),'variant':variant,'nonce':uuid.uuid4().hex,'values':values,'expected_sum':sum(values),
 'data_event_ids':[uid('DATAEVT') for v in values],'journal':str(ROOT/'journal.jsonl'),
 'inventory_sources':{str(ROOT/name):sha((ROOT/name).read_bytes()) for name in ('runtime.py','worker.py')}}
 if variant=='NEGATIVE':
  if relation['NEGATIVE_MODE']=='PROCESS_FAILURE':r['force_failure']=True
  if relation['NEGATIVE_MODE']=='TEST_FAILURE':r['expected_sum']+=1
  if relation['NEGATIVE_MODE']=='INVENTORY_BINDING':
   r['inventory_sources'][str(ROOT/'worker.py')]='0'*64
 return r
def recover(d,request_hash,result_hash):
 d=Path(d);r=read(d/'request.json');result=read(d/'result.json')
 if sha((d/'request.json').read_bytes())!=request_hash or sha((d/'result.json').read_bytes())!=result_hash:raise ValueError('trusted request/result anchor mismatch')
 for p,digest in r['SOURCE_SHA256'].items():
  source=Path(p);source=(ROOT/source).resolve() if not source.is_absolute() else source
  if sha(source.read_bytes())!=digest:raise ValueError('recovery source commitment mismatch')
 validate_relationship(r['relationship'])
 for name,digest in result['artifact_commitments'].items():
  if sha((d/name).read_bytes())!=digest:raise ValueError('recovery artifact tamper: '+name)
 for label in ('provider','consumer'):
  proc=read(d/(label+'.process.json'))
  receipt_api.validate_receipt(proc['receipt'],outputs(d,label))
  expected=[sys.executable,'-I','-B',str(ROOT/'worker.py'),label,result['consumer_directory'] if label=='consumer' else str(d)]
  if proc['command']!=expected or not proc['terminal_observed'] or proc['timed_out']:raise ValueError('process lifecycle/command mismatch')
 module=load_pinned(r['relationship']['CONSUMER_SOURCE'],r['relationship']['CONSUMER_SHA256'])
 if r['variant']=='NEGATIVE':
  try:module.consume(r,result['consumer_directory'])
  except (ValueError,KeyError,TypeError):pass
  else:raise ValueError('negative behavior no longer rejected')
  if result['FINAL_STATUS']!='CONTROLLED_NEGATIVE_DETECTED' or result['CONSUMER_RESULT_VERIFIED']:raise ValueError('unsupported negative success claim')
 else:
  recomputed=module.consume(r,result['consumer_directory'])
  if recomputed!=result['CONSUMER_RESULT'] or recomputed['processed_sha256']!=result['OUTPUT_HASHES']['stdout']:raise ValueError('consumer reconstruction mismatch')
  if result['END_TO_END_VERIFICATION']!='PASS':raise ValueError('clean result not accepted')
 registry=DurableRegistry(r['journal']);snapshot=registry.snapshot()
 receipt=read(d/'provider.process.json')['receipt'];before=Path(r['journal']).read_bytes()
 try:registry.admit(receipt,outputs(d))
 except ValueError as error:replay_reason=str(error)
 else:raise ValueError('replay unexpectedly accepted')
 if Path(r['journal']).read_bytes()!=before:raise ValueError('replay mutated journal')
 if r['relationship']['NEGATIVE_MODE']=='REVOCATION' and r['variant']=='NEGATIVE' and r['RUN_ID'] not in snapshot['revoked_runs']:raise ValueError('revocation lost')
 return {'AUDIT_ID':uid('AUDIT'),'ATTEMPT_ID':r['ATTEMPT_ID'],'RUN_ID':r['RUN_ID'],'request_sha256':request_hash,'result_sha256':result_hash,
 'fresh_process_pid':os.getpid(),'recovery_timestamp':now(),'status':'PASS','replay_rejected':True,'replay_reason':replay_reason,
 'source_commitments_verified':True,'output_commitments_verified':True,'original_identities_preserved':True,'independent_custody':'NOT_PROVEN'}
def execute(relation,variant,parent=None):
 validate_relationship(relation)
 attempt='ATT-'+now().replace(':','').replace('.','')+'-'+uuid.uuid4().hex
 d=ROOT/'cases'/relation['CASE_ID']/'attempts'/attempt;d.mkdir(parents=True,exist_ok=False)
 r=build_request(relation,attempt,parent,variant);write(d/'request.json',r)
 start={k:r[k] for k in ['CAMPAIGN_ID','CASE_ID','ATTEMPT_ID','PARENT_ATTEMPT_ID','START_TIMESTAMP','SOURCE_SHA256','PROVIDER_ID','CONSUMER_ID','REQUEST_ID','ACTOR_ID','TOOL_ID','AUTHORITY_SCOPE','EXPECTED_OUTPUTS']}
 start.update(record_type='BEFORE_EXECUTION',request_sha256=sha((d/'request.json').read_bytes()),directory=str(d));write(d/'attempt.start.json',start);append_registry(start)
 provider,out,err=spawn_capture([sys.executable,'-I','-B',str(ROOT/'worker.py'),'provider',str(d)],d,'provider',r['ACTOR_ID'],r['RUN_ID'])
 registry=DurableRegistry(r['journal']);registry.admit(provider['receipt'],outputs(d))
 effective=d
 if variant=='NEGATIVE' and relation['NEGATIVE_MODE']=='OUTPUT_TAMPER':
  effective=d/'controlled-tamper';effective.mkdir()
  for name in ('request.json','provider.process.json','provider.stderr'):
   with (effective/name).open('xb') as f:f.write((d/name).read_bytes())
  with (effective/'provider.stdout').open('xb') as f:f.write(out+b'CONTROLLED_TAMPER')
 if variant=='NEGATIVE' and relation['NEGATIVE_MODE']=='REVOCATION':registry.revoke_run(r['RUN_ID'])
 consumer,c_out,c_err=spawn_capture([sys.executable,'-I','-B',str(ROOT/'worker.py'),'consumer',str(effective)],d,'consumer',r['ACTOR_ID'],uid('RUN'))
 consumer_result=json.loads(c_out) if consumer['exit_code']==0 else {'error':c_err.decode('utf8',errors='replace')}
 clean=provider['exit_code']==0 and not provider['timed_out'] and consumer['exit_code']==0 and not consumer['timed_out'] and consumer_result.get('processed_sha256')==sha(out)
 negative=variant=='NEGATIVE' and consumer['exit_code']!=0 and not consumer['timed_out'] and bool(c_err)
 result={'CAMPAIGN_ID':CONFIG['CAMPAIGN_ID'],'CASE_ID':relation['CASE_ID'],'ATTEMPT_ID':attempt,'PARENT_ATTEMPT_ID':parent,'END_TIMESTAMP':now(),
 'RUN_ID':r['RUN_ID'],'EVENT_IDS':[e['id'] for p in (provider,consumer) for e in p['receipt']['events']]+(r['data_event_ids'] if relation['OUTPUT_SCHEMA']=='engineering.events.v1' else []),
 'PROCESS_IDENTITY':{'provider':provider['PROCESS_ID'],'consumer':consumer['PROCESS_ID']},'EXIT_CODE':{'provider':provider['exit_code'],'consumer':consumer['exit_code']},
 'OUTPUT_HASHES':provider['output_hashes'],'CONSUMER_RESULT':consumer_result,'consumer_directory':str(effective),
 'PROVIDER_EXECUTED':True,'OUTPUT_GENERATED':bool(out),'OUTPUT_IDENTITY_VERIFIED':True,'CONSUMER_EXECUTED':True,'CONSUMER_RESULT_VERIFIED':clean,
 'END_TO_END_VERIFICATION':'PASS' if clean and variant!='NEGATIVE' else 'FAIL',
 'VERIFICATION_RESULT':'PENDING_FRESH_PROCESS','AUDIT_STATUS':'PENDING_INDEPENDENT_REVIEW',
 'FINAL_STATUS':'CONTROLLED_NEGATIVE_DETECTED' if negative else 'CLEAN_EXECUTION_PASS' if clean and variant!='NEGATIVE' else 'UNEXPECTED_FAILURE',
 'artifact_commitments':{}}
 for p in d.rglob('*'):
  if p.is_file():result['artifact_commitments'][str(p.relative_to(d))]=sha(p.read_bytes())
 write(d/'result.json',result);append_registry(dict(record_type='AFTER_EXECUTION',**result))
 recovery,rec_out,rec_err=spawn_capture([sys.executable,'-I','-B',str(ROOT/'engine.py'),'recover',str(d),sha((d/'request.json').read_bytes()),sha((d/'result.json').read_bytes())],d,'recovery',r['ACTOR_ID'],uid('RUN'))
 recovered=json.loads(rec_out) if recovery['exit_code']==0 else {'status':'FAIL','error':rec_err.decode(errors='replace')}
 write(d/'recovery.json',recovered)
 final={'record_type':'FINAL_VERIFICATION','ATTEMPT_ID':attempt,'CASE_ID':relation['CASE_ID'],'RUN_ID':r['RUN_ID'],
 'FINAL_STATUS':result['FINAL_STATUS'],'VERIFICATION_RESULT':recovered['status'],'directory':str(d),'result_sha256':sha((d/'result.json').read_bytes()),'request_sha256':sha((d/'request.json').read_bytes()),'recovery_sha256':sha((d/'recovery.json').read_bytes())}
 append_registry(final);print(canonical(final).decode(),flush=True)
 return final
def campaign():
 if (ROOT/'RELATIONSHIP_REGISTRY.json').exists():raise ValueError('campaign already initialized; no silent restart')
 relationships=[register('CASE-%03d'%i,kind,schema) for i,kind,schema in [(1,'structured','engineering.totals.v1'),(2,'stream','engineering.cubes.csv.v1'),(3,'tests','junit.xml.actual.v1'),(4,'inventory','engineering.inventory.v1'),(5,'events','engineering.events.v1')]]
 for r in relationships:validate_relationship(r)
 write(ROOT/'RELATIONSHIP_REGISTRY.json',{'CAMPAIGN_ID':CONFIG['CAMPAIGN_ID'],'relationships':relationships,
 'discovery':'Accepted dispatch supports fixed synthetic probe only; five new authorized Engineering-owned programs selected; no historical operational relationship inferred'})
 DurableRegistry.create(ROOT/'journal.jsonl')
 all_results=[]
 for relation in relationships:
  a=execute(relation,'CLEAN_A');b=execute(relation,'CLEAN_B',a['ATTEMPT_ID']);c=execute(relation,'NEGATIVE',b['ATTEMPT_ID']);all_results.extend([a,b,c])
 write(ROOT/'EXECUTION_SUMMARY.json',{'results':all_results})
if __name__=='__main__':
 if sys.argv[1]=='campaign':campaign()
 elif sys.argv[1]=='recover':print(canonical(recover(*sys.argv[2:])).decode())
 else:raise ValueError('unsupported command')
