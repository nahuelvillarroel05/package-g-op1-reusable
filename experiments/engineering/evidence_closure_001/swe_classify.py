from __future__ import annotations
import collections, hashlib, json
from pathlib import Path
BASE = Path(r'D:\PGOP1_DATA\PGOP1_BASELINE_001')
ATTEMPT = BASE/'Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/attempts/attempt-0003'
FRESH = BASE/'Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001/swebench/attempts/SWE-AUDIT-20261103-001/fresh_claim_audit_rows.jsonl'
OUT = BASE/'Engineering/PGOP1_SIX_FAMILY_EVIDENCE_CLOSURE_001/swebench'
TARGET = OUT/'SWE_CLASSIFICATION_ROWS_ATTEMPT002.jsonl'
if TARGET.exists():
 raise FileExistsError('Preserve existing evidence; select a fresh output path before another attempt: '+str(TARGET))
def sha(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()
history=json.loads((ATTEMPT/'SWE_PROCESSING_RESULTS.json').read_text(encoding='utf-8'))['audit_decisions']
fresh=[json.loads(line) for line in FRESH.read_text(encoding='utf-8').splitlines()]
assert len(history)==len(fresh)==266
reason_to_category={'NO_ATTRIBUTABLE_CLAIM':'UNKNOWN_ATTRIBUTION','UNSUPPORTED_PATCH_SHAPE':'NO_MATCHING_PREDICATE','MIXED_OR_NONCOMPARABLE_CLAIMS':'AMBIGUOUS_CLAIM','NO_BOUND_EVALUATOR_RESULT':'MISSING_EVIDENCE','WRONG_INSTANCE_BINDING':'SOURCE_BINDING_FAILURE'}
counts=collections.Counter(); classified=[]
for h,f in zip(history,fresh):
 assert h['request_index']==f['request_index'] and h['instance_id']==f['instance_id']
 labels=[]
 for reason,category in reason_to_category.items():
  if reason in h.get('reason_codes',[]): labels.append(category); counts[category+'_ROWS']+=1
 if h.get('agent_statement_count',0): counts['AGENT_STATEMENT_EVENTS']+=h['agent_statement_count']; labels.append('AMBIGUOUS_CLAIM')
 if h.get('audit_verdict')=='INSUFFICIENT_EVIDENCE': labels.append('SOURCE_AUTHENTICATION_UNKNOWN'); counts['SOURCE_AUTHENTICATION_UNKNOWN_ROWS']+=1
 classified.append({'request_index':h['request_index'],'instance_id':h['instance_id'],'verdict':h['audit_verdict'],'reason_codes':h.get('reason_codes',[]),'category_labels':sorted(set(labels)),'agent_statement_count':h.get('agent_statement_count',0),'claim_rejection_count':h.get('claim_rejection_count',0),'source_refs':[{'role':e.get('role'),'path':e.get('path'),'sha256':e.get('sha256'),'bytes':e.get('bytes')} for e in h.get('evidence',[])],'evaluator_authentication':h.get('source_provenance',{}).get('evaluator_authentication'),'execution_authentication':h.get('source_provenance',{}).get('upstream_run_authentication')})
out=TARGET
with out.open('x',encoding='utf-8') as output:
 output.write(''.join(json.dumps(r,separators=(',',':'))+'\n' for r in classified))
print(json.dumps({'rows':len(classified),'categories':dict(counts),'output_sha256':sha(out)},indent=2))
