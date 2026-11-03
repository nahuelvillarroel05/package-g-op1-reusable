import json, hashlib, pathlib, re, collections
BASE=pathlib.Path(r'D:\PGOP1_DATA\PGOP1_BASELINE_001')
CORPUS=BASE/'Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/families/operations/acquisition_002'
CAT=CORPUS/'NORMALIZED_OUTPUT_CATALOG.json'
STRUCT=BASE/'Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/mcpmark/attempts/MCP-STRUCT-20261103-003/structural_rows.jsonl'
OUT=BASE/'Engineering/PGOP1_SIX_FAMILY_EVIDENCE_CLOSURE_001/mcpmark/MCP_ORIGINAL_SOURCE_REVIEW.json'
if OUT.exists():
 raise FileExistsError('Preserve existing evidence; select a fresh output path before another attempt: '+str(OUT))
cat=json.loads(CAT.read_text(encoding='utf-8'))
records=cat['artifact_records']
amb=json.loads((BASE/'Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/mcpmark/MCPMARK_FULL_SCALE_RESULTS.json').read_text(encoding='utf-8'))['summary']['ambiguous_kimi_task_ids']
missing=json.loads((BASE/'Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/mcpmark/MCPMARK_FULL_SCALE_RESULTS.json').read_text(encoding='utf-8'))['summary']['missing_trajectory_details']
ids=[(t,None,None) for t in amb]+[(x['task_id'],x['model_id'],x['published_run_label']) for x in missing]
# Match exact target task family only. For ambiguity rows retain only Kimi trajectory identities.
def sha(p):
 h=hashlib.sha256();
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def summarize(path):
 raw=json.loads(path.read_text(encoding='utf-8'))
 msgs=raw if isinstance(raw,list) else raw.get('messages',raw.get('trajectory',[]))
 if isinstance(msgs,dict): msgs=msgs.get('messages',[])
 if not isinstance(msgs,list): return {'json_shape':type(raw).__name__,'message_count':None}
 types=collections.Counter(); roles=collections.Counter(); calls=[]; outs=[]; assistants=[]
 for m in msgs:
  if not isinstance(m,dict): continue
  typ=m.get('type') or m.get('message_type') or 'type_absent'; types[str(typ)]+=1
  roles[str(m.get('role'))]+=1
  if typ=='function_call' or 'function_call' in m:
   c=m.get('function_call',m); calls.append({'name':c.get('name'),'call_id':c.get('call_id',c.get('id'))})
  if typ=='function_call_output' or 'function_call_output' in m:
   o=m.get('function_call_output',m); outs.append({'call_id':o.get('call_id',o.get('id'))})
  if m.get('role')=='assistant' or typ=='message':
   content=m.get('content')
   if isinstance(content,list): content=' '.join(str(z.get('text','')) for z in content if isinstance(z,dict))
   if isinstance(content,str):
    txt=content.lower(); assistants.append({'final_candidate':m is msgs[-1], 'text_bytes':len(content.encode()),'claim_markers':{k:(k in txt) for k in ['success','completed','done','failed','cannot','unable','created','updated']}})
 ids_calls=[c['call_id'] for c in calls if c['call_id'] is not None]
 ids_out=[o['call_id'] for o in outs if o['call_id'] is not None]
 return {'json_shape': 'list' if isinstance(raw,list) else 'object','message_count':len(msgs),'message_types':dict(types),'roles':dict(roles),'tool_call_count':len(calls),'tool_output_count':len(outs),'tool_call_names':dict(collections.Counter(c['name'] for c in calls)),'call_ids_present':len(ids_calls),'output_ids_present':len(ids_out),'matched_ids':sum(i in ids_out for i in ids_calls),'orphan_output_ids':sum(i not in ids_calls for i in ids_out),'assistant_text_message_count':len(assistants),'assistant_text_markers':assistants,'verifier_execution_receipt_found':False}
rows=[]
for task,required_model,run in ids:
 cand=[r for r in records if r.get('TASK_ID')==task and r.get('ROLE')=='trajectory' and 'kimi' in str(r.get('MODEL_ID','')).lower()]
 if required_model: cand=[r for r in cand if r.get('MODEL_ID')==required_model]
 rr=[]
 for r in cand:
  p=pathlib.Path(r['PATH']); exists=p.is_file(); actual=sha(p) if exists else None
  rr.append({'model_id':r.get('MODEL_ID'),'source_revision':r.get('SOURCE_REVISION'),'source_sha256_catalog':r.get('SOURCE_SHA256'),'source_path':r.get('PATH'),'upstream_path':r.get('UPSTREAM_PATH'),'upstream_url':r.get('UPSTREAM_URL'),'upstream_git_blob_sha1':r.get('UPSTREAM_GIT_BLOB_SHA1'),'artifact_exists':exists,'sha256_verified':actual==r.get('SOURCE_SHA256') if exists else False,'actual_sha256':actual,'structure':summarize(p) if exists else None})
 # pair with model result identities, but do not export payloads
 result=[{'model_id':r.get('MODEL_ID'),'source_revision':r.get('SOURCE_REVISION'),'source_sha256':r.get('SOURCE_SHA256'),'source_path':r.get('PATH'),'published_run_label':r.get('RESPONSE_ID')} for r in records if r.get('TASK_ID')==task and r.get('ROLE')=='model_result' and 'kimi' in str(r.get('MODEL_ID','')).lower() and (not required_model or r.get('MODEL_ID')==required_model)]
 rows.append({'task_id':task,'required_model':required_model,'published_run_label':run,'kind':'missing_trajectory' if required_model else 'ambiguous_kimi_filesystem','trajectory_artifacts':rr,'kimi_result_artifacts':result,'claim_or_final_state':'trajectory text summarized as marker counts only; no verifier receipt or bound evaluation evidence identified','binding_conclusion':'UNRESOLVED' if required_model or len(rr)>0 else 'NO_KIMI_TRAJECTORY_CATALOG_ROW'})
report={'schema':'pgop1.mcpmark.original-source-review.v1','scope':{'ambiguous_kimi_tasks':len(amb),'missing_trajectory_identities':len(missing),'records_reviewed':len(rows),'trajectory_bodies_read':sum(len(x['trajectory_artifacts']) for x in rows if x['kind']=='ambiguous_kimi_filesystem'),'execution_performed':False},'source_revision':{'catalog_path':str(CAT),'catalog_sha256':sha(CAT),'catalog_row_source_revisions':sorted(set(r.get('SOURCE_REVISION') for r in records if r.get('ROLE')=='trajectory' and 'kimi' in str(r.get('MODEL_ID','')).lower()))},'per_record':rows}
with OUT.open('x',encoding='utf-8') as output:
 output.write(json.dumps(report,indent=2)+'\n')
print(json.dumps({'records':len(rows),'ambiguous_with_trajectory':sum(bool(x['trajectory_artifacts']) for x in rows if x['kind']=='ambiguous_kimi_filesystem'),'missing_trajectories_found':sum(bool(x['trajectory_artifacts']) for x in rows if x['kind']=='missing_trajectory'),'report_sha256':sha(OUT)},indent=2))
