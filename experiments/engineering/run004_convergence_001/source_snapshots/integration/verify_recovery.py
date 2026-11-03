"""Fresh read-only recovery of two existing shards; no ingestion or redispatch."""
import datetime,hashlib,json,subprocess,sys
from pathlib import Path
W=Path(__file__).resolve().parents[1];ROOT=W.parents[1];R=ROOT/'Engineering/Active_Candidate/repo'
PRIOR=ROOT/'Engineering/PGOP1_SIX_FAMILY_EVIDENCE_CLOSURE_001'
def bind(p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
def main():
    driver=R/'experiments/engineering/evidence_closure_001/verify_incremental_context.py'
    rows=[]
    for family in ['bfcl','mcpmark']:
        entry=PRIOR/'context_engine'/(family+'-sample-entry.json')
        argv=[sys.executable,'-I','-B',str(driver),'--sample-entry',str(entry)]
        start=datetime.datetime.now(datetime.timezone.utc).isoformat()
        p=subprocess.run(argv,capture_output=True,text=True,cwd=ROOT)
        for suffix,value in [('stdout',p.stdout),('stderr',p.stderr)]:
            (W/'execution_receipts'/('recovery-'+family+'-'+suffix+'.txt')).write_text(value,encoding='utf-8')
        rows.append({'family':family,'argv':argv,'started_utc':start,'exit_code':p.returncode,'entry':bind(entry),'stdout':bind(W/'execution_receipts'/('recovery-'+family+'-stdout.txt')),'stderr':bind(W/'execution_receipts'/('recovery-'+family+'-stderr.txt')),'result':json.loads(p.stdout) if p.returncode==0 else None})
        if p.returncode:break # inaccessible optional accelerator: attempt once, no ACL workaround
    out={'status':'PASS_WITH_EXACT_TWO_SHARD_SCOPE' if len(rows)==2 and all(r['exit_code']==0 for r in rows) else 'DEFERRED_ACCESS_OR_RECOVERY_FAILURE','driver':bind(driver),'engine':bind(R/'runtime/candidate/context_engine.py'),'samples':rows,'full_corpus_reprocessing':'NOT_PERFORMED','new_stores':0,'new_ingestions':0,'redispatches':0,'limitation':'Selected existing authored descriptors only; does not recover all original bodies or prove producer authenticity. Previous 806-membership check remains historical.'}
    with (W/'CONTEXT_ENGINE_RECOVERY.json').open('x',encoding='utf-8') as f:json.dump(out,f,indent=2)
    print(json.dumps({'status':out['status'],'samples':len(rows),'descriptors':sum(r['result']['count'] for r in rows if r['result'])}))
if __name__=='__main__':main()
