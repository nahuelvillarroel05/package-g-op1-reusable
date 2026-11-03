"""Check existing descriptor stores incrementally; never build a new store."""
import argparse, hashlib, json, os, subprocess, sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
ROOT=REPO.parents[2]
PRIOR=ROOT/'Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001'
WORK=ROOT/'Engineering/PGOP1_SIX_FAMILY_EVIDENCE_CLOSURE_001'
sys.path.insert(0,str(REPO))
from runtime.candidate.context_engine import Engine, canonical_json
def sha(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def load(p):return json.loads(Path(p).read_text(encoding='utf-8-sig'))
def binding(p):return {'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size}
def sample(entry):
    root=Path(entry['store'])
    if not root.is_relative_to(ROOT) or any(getattr(p.lstat(),'st_file_attributes',0)&1024 for p in [root,*root.parents] if p.exists()):
        raise ValueError('out-of-scope/reparse store')
    # Constructor must find an already existing complete store. No ingestion.
    if not (root/'index.sqlite').is_file():raise ValueError('existing index absent; do not silently construct')
    before=sha(root/'index.sqlite')
    engine=Engine(root)
    if engine.metrics['RECONSTRUCTION_REQUIRED']:raise ValueError('unexpected reconstruction; stop and preserve evidence')
    if engine.latest()!=entry['manifest']:raise ValueError('manifest differs')
    values=json.loads(engine.read_source(entry['source_id']))
    if sha(root/'descriptors.json')!=entry['source_sha256']:raise ValueError('descriptor source differs')
    recovered=engine.query(kind='NIGHTLY_DESCRIPTOR',limit=1000)
    actual=[r['value'] for r in recovered]
    if actual!=values or len(actual)!=entry['count']:raise ValueError('recovered values/count differ')
    if hashlib.sha256(canonical_json(actual)).hexdigest()!=entry['values_sha256']:raise ValueError('value commitment differs')
    if sha(root/'index.sqlite')!=before:raise ValueError('index unexpectedly changed')
    return {'family':entry['family'],'store':str(root),'count':len(actual),'manifest':entry['manifest'],'values_sha256':entry['values_sha256'],'index_unchanged':True,'pid':os.getpid(),'producer_dispatches':0,'redispatches':0}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--sample-entry',type=Path);a=ap.parse_args()
    if a.sample_entry:
        print(json.dumps(sample(load(a.sample_entry))));return
    reference=load(PRIOR/'CONTEXT_ENGINE_RECOVERY.json')
    if sha(REPO/'runtime/candidate/context_engine.py')!=reference['engine_sha256']:raise ValueError('Engine identity changed')
    records=[];selected={};total=0
    for group in reference['groups']:
        expected_path=Path(group['expected_manifest']['path']);plan_path=Path(group['external_plan']['path'])
        if sha(expected_path)!=group['expected_manifest']['sha256'] or sha(plan_path)!=group['external_plan']['sha256']:raise ValueError('external commitment differs')
        expected=load(expected_path);plan=load(plan_path);work=expected_path.parent
        if sum(x['expected_count'] for x in plan['sources'])!=expected['expected_count']:raise ValueError('external population mismatch')
        observed=[load(p) for p in sorted(work.glob('RECEIPT-*.json'))]
        if observed!=expected['shards'] or sum(x['count'] for x in observed)!=expected['expected_count']:raise ValueError('shard membership differs')
        if {str(p) for p in work.glob('shard-*')}!={x['store'] for x in observed}:raise ValueError('orphan/missing shard')
        if load(work/'PLAN.json')!=plan:raise ValueError('external/internal plan mismatch')
        records.append({'group':group['group'],'manifest':binding(expected_path),'external_plan':binding(plan_path),'receipt_shards':len(observed),'expected_count':expected['expected_count'],'membership':'PASS','object_scope':'Only selected sample shards read; full historical recovery not repeated'})
        total+=len(observed)
        for entry in observed:selected.setdefault(entry['family'],entry)
    out=WORK/'context_engine';out.mkdir(exist_ok=True)
    samples=[]
    for family,entry in selected.items():
        p=out/(family+'-sample-entry.json')
        with p.open('x',encoding='utf-8') as f:json.dump(entry,f)
        child=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--sample-entry',str(p)],capture_output=True,text=True)
        if child.returncode:raise RuntimeError(child.stderr)
        samples.append(json.loads(child.stdout))
    result={'schema':'pgop1.context-engine-incremental.v1','status':'PASS_WITH_EXACT_INCREMENTAL_SCOPE','engine':binding(REPO/'runtime/candidate/context_engine.py'),'driver':binding(Path(__file__).resolve()),'receipt_membership_shards_checked':total,'groups':records,'fresh_process_samples':samples,'sample_descriptors':sum(s['count'] for s in samples),'new_stores':0,'new_ingestions':0,'producer_dispatches':0,'redispatches':0,'full_796805_descriptor_recovery':'NOT_REPEATED','source_body_recovery':'NOT_REPEATED; original source must be hash-verified before retrieval','authentication_limit':'Integrity of authored descriptors does not authenticate execution labels or semantic truth','negative_controls_and_index_rebuild':'Separate focused existing regression receipt; authoritative source stores are not mutated'}
    with (WORK/'CONTEXT_ENGINE_RESULTS.json').open('x',encoding='utf-8') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'status':result['status'],'receipt_shards':total,'families':len(samples),'sample_descriptors':result['sample_descriptors']}))
if __name__=='__main__':main()
