"""Verify final private continuity without changing runtime or campaign state."""
import hashlib,json,subprocess,zipfile
from pathlib import Path
W=Path(__file__).resolve().parent;ROOT=W.parents[1];R=ROOT/'Engineering/Active_Candidate/repo'
def load(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def bind(p):return {'path':str(p),'sha256':sha(p),'bytes':p.stat().st_size}
def git(*a):return subprocess.check_output(['git','-c','safe.directory='+R.as_posix(),'-C',str(R),*a],text=True).strip()
def main():
    doc=load(W/'DOCUMENTATION_VERIFICATION_RECEIPT.json');z=load(W/'ZIP_INTEGRITY_REPORT.json');code=load(W/'CODE_REFERENCE.json')
    assert doc['status']=='PASS' and doc['exit_code']==0 and not doc['summary']['errors']
    assert sha(ROOT/'docs/DOCUMENTATION_INTEGRITY_MANIFEST.json')==doc['document_manifest_sha256']
    for k in ['stdout','stderr']:assert sha(Path(doc[k]['path']))==doc[k]['sha256']
    assert git('rev-parse','HEAD')==code['metadata_delivery_commit'] and git('rev-parse','HEAD^{tree}')==code['metadata_delivery_tree']
    assert git('branch','--show-current')=='experimental/pgop1-runs' and not git('status','--porcelain')
    assert not git('diff','--name-only',code['baseline_commit'],'HEAD','--','runtime/','src/package_g/','runs/')
    ready=load(W/'RUN004_READINESS_MATRIX.json');assert len(ready['families'])==6 and all(x['FULL_CAMPAIGN_READY']=='BLOCKED' for x in ready['families'])
    for row in ready['families']:
        ref=row['CURRENT_REPORT'];assert sha(Path(ref['path']))==ref['sha256'] and Path(ref['path']).stat().st_size==ref['bytes']
    for key,val in [('RUN004_CONTRACT','NOT_APPROVED'),('RUN004_FINAL_FREEZE','NOT_ISSUED'),('RUN004_EXECUTION','NOT_EXECUTED')]:assert ready[key]==val
    before=load(W/'preimages/Engineering/Active_Candidate/repo/experiments/RUN_REGISTRY.json');now=load(R/'experiments/RUN_REGISTRY.json')
    assert before['runs'][:3]==now['runs'][:3] and before['pilots']==now['pilots']
    evals=load(W/'AUTHENTIC_EVALUATION_RECEIPTS.json');assert evals['official_per_case_results']==21 and evals['fresh_original_task_executions']==0 and evals['official_full_cli_completions']==0
    assert sha(Path(z['archive']))==z['sha256']
    assert all(z[k]=='PASS' for k in ['SHA256','CRC','MEMBERSHIP','FRESH_EXTRACTION']) and z['DUPLICATES']==z['UNSAFE_PATHS']==0
    members=load(W/'FINAL_INTEGRITY_MANIFEST.json')['members'];fresh=Path(z['fresh_extraction'])
    with zipfile.ZipFile(z['archive']) as archive:
        assert archive.testzip() is None
        assert not any('.test_output.' in n or any(p.startswith('official-') for p in Path(n).parts[:-1]) for n in archive.namelist())
    for row in members:assert sha(fresh/row['path'])==row['sha256'] and (fresh/row['path']).stat().st_size==row['bytes']
    # Confirm core current delivery inside ZIP is identical to the handed-off originals.
    for name in ['FINAL_HANDOFF.md','CODE_REFERENCE.json','AUTHENTIC_EVALUATION_RECEIPTS.json','RUN004_READINESS_MATRIX.json','SOL_XHIGH_AUDIT.md','ASTRA_INDEPENDENT_AUDIT.md']:assert sha(fresh/name)==sha(W/name)
    out={'status':'PASS_FOR_PARTIAL_ENGINEERING_DELIVERY','result':'PGOP1_RUN004_CONTRACT_AND_EVALUATOR_PARTIAL_WITH_EXACT_LIMITATIONS','code':code,'documentation':bind(W/'DOCUMENTATION_VERIFICATION_RECEIPT.json'),'zip':bind(W/'ZIP_INTEGRITY_REPORT.json'),'manifest':bind(W/'FINAL_INTEGRITY_MANIFEST.json'),'fresh_members_rehashed':len(members),'official_per_case_results':21,'successful_official_component_processes':2,'failed_evaluator_processes':1,'preflight_failures':5,'full_official_cli_completions':0,'fresh_original_task_executions':0,'full_ready_families':0,'RUN004_CONTRACT':'NOT_APPROVED','RUN004_FINAL_FREEZE':'NOT_ISSUED','RUN004_EXECUTION':'NOT_EXECUTED','historical_runs_preserved':True,'runtime_src_unchanged':True,'original_test_log_exported':False,'stop':'VERIFIED_PRIVATE_CONTINUITY_DELIVERED; NO_CAMPAIGN_AUTHORITY'}
    with (W/'FINAL_DELIVERY_VALIDATION.json').open('x',encoding='utf-8',newline='\n') as f:json.dump(out,f,indent=2)
    print(json.dumps({'status':out['status'],'fresh_members_rehashed':len(members),'official_results':21,'run004':'NOT_EXECUTED'}))
if __name__=='__main__':main()
