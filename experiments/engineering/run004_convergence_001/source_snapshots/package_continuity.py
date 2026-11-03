"""Source-free local continuity ZIP with detached verification; no campaign."""
import argparse,hashlib,json,shutil,subprocess,zipfile
from pathlib import Path,PurePosixPath
W=Path(__file__).resolve().parent;ROOT=W.parents[1];R=ROOT/'Engineering/Active_Candidate/repo'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def put(p,v):
    with p.open('x',encoding='utf-8',newline='\n') as f:json.dump(v,f,indent=2);f.write('\n')
def safe(n):
    p=PurePosixPath(n)
    if not n or p.is_absolute() or '..' in p.parts or ':' in n or '\\' in n:raise ValueError(n)
def nolink(p):
    if not p.resolve().is_relative_to(ROOT):raise ValueError('outside root')
    if any(getattr(q.lstat(),'st_file_attributes',0)&1024 for q in [p,*p.parents] if q.exists()):raise ValueError('reparse point')
def git(*a):return subprocess.check_output(['git','-c','safe.directory='+R.as_posix(),'-C',str(R),*a])
def validate_selection_row(row):
    n=row['path'];safe(n);p=W/n;nolink(p)
    if '.test_output.' in n or any(x.startswith('official-') for x in PurePosixPath(n).parts[:-1]):raise ValueError('original source body prohibited')
    if not p.is_file() or sha(p)!=row['sha256'] or p.stat().st_size!=row['bytes']:raise ValueError('selection identity mismatch')
    return n,p
def main():
    assert not git('status','--porcelain').strip()
    stage=W/'continuity-export-002';stage.mkdir()
    selected={}
    # Freeze and review exact membership before packaging; discovery is never export authority.
    selection=json.loads((W/'CONTINUITY_SELECTION.json').read_text(encoding='utf-8'))
    assert selection['review_status']=='REVIEWED_SOURCE_FREE_LOCAL_EXPORT'
    excluded=selection['external_exclusions']
    for row in selection['members']:
        n,p=validate_selection_row(row)
        if n.casefold() in {k.casefold() for k in selected}:raise ValueError('duplicate')
        selected[n]=p
    for rel in ['CURRENT_STATE.md','docs/NEXT_STEP.md','docs/WORKSPACE_STATE.json','docs/DOCUMENTATION_INTEGRITY_MANIFEST.json']:
        selected['workspace/'+rel]=ROOT/rel
    for rel in ['INVOCATION.json','RESULT.json','pytest-output.log']:
        selected['receipts/regression/'+rel]=ROOT/'Temp/pytest/run004-prep-regression-20261103-001'/rel
    for n,p in selected.items():
        safe(n);nolink(p);dst=stage/n;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dst)
    # Increment contains only owned prospective plans and continuity metadata.
    bundle=stage/'EXPERIMENTAL_INCREMENT.bundle';git('bundle','create',str(bundle),'experimental/pgop1-runs','^9a798fee36b15d04e989d5ca2b3a938cab1e27a3')
    p=subprocess.run(['git','-c','safe.directory='+R.as_posix(),'-C',str(R),'bundle','verify',str(bundle)],capture_output=True,text=True);assert p.returncode==0
    put(stage/'BUNDLE_VERIFICATION.json',{'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'sha256':sha(bundle),'prerequisite':'9a798fee36b15d04e989d5ca2b3a938cab1e27a3'})
    (stage/'CONTINUITY_INDEX.md').write_text('# Local continuity\n\nRead FINAL_HANDOFF.md, CODE_REFERENCE.json, RUN004_CONTRACT_REV003.md, SIX_FAMILY_EVALUATOR_READINESS.json, AUTHENTIC_EVALUATION_RECEIPTS.json, audits and NEXT_STEP.md. Verify FINAL_INTEGRITY_MANIFEST.json. Original datasets, outputs, evaluator source and Engine stores remain external at bound paths. The Git bundle requires baseline 9a798fee36b15d04e989d5ca2b3a938cab1e27a3. No RUN004 approval or execution. Detached ZIP_INTEGRITY_REPORT.json and FINAL_DELIVERY_VALIDATION.json beside the archive verify final gates.\n',encoding='utf-8',newline='\n')
    put(W/'EXPORT_ALLOWLIST.json',{'selected':[{'member':n,'source':str(p),'sha256':sha(p)} for n,p in selected.items()],'generated':['EXPERIMENTAL_INCREMENT.bundle','BUNDLE_VERIFICATION.json','CONTINUITY_INDEX.md'],'excluded':excluded,'policy':'Local continuity only; no original task/output/evaluator source bodies, datasets, credentials or stores.'})
    shutil.copyfile(W/'EXPORT_ALLOWLIST.json',stage/'EXPORT_ALLOWLIST.json')
    rows=[{'path':p.relative_to(stage).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(stage.rglob('*')) if p.is_file()]
    manifest={'schema':'pgop1.run004.convergence.integrity.v1','members':rows,'scope':'Exact source-free local export; excludes original corpus and downloaded evaluator sources','self_hash':'DETACHED_ZIP_INTEGRITY_REPORT'}
    put(W/'FINAL_INTEGRITY_MANIFEST.json',manifest);shutil.copyfile(W/'FINAL_INTEGRITY_MANIFEST.json',stage/'FINAL_INTEGRITY_MANIFEST.json')
    print(json.dumps({'status':'STAGED_NOT_YET_ZIPPED','members':len(rows)+1}))
def archive():
    doc=json.loads((W/'DOCUMENTATION_VERIFICATION_RECEIPT.json').read_text(encoding='utf-8-sig'));assert doc['status']=='PASS'
    assert not git('status','--porcelain').strip()
    stage=W/'continuity-export-002'
    rows=json.loads((W/'FINAL_INTEGRITY_MANIFEST.json').read_text(encoding='utf-8-sig'))['members']
    archive=W/(W.name+'_CONTINUITY.zip');expected={x['path'] for x in rows}|{'FINAL_INTEGRITY_MANIFEST.json'}
    assert {p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file()}==expected
    for row in rows:assert sha(stage/row['path'])==row['sha256'] and (stage/row['path']).stat().st_size==row['bytes']
    with zipfile.ZipFile(archive,'x',zipfile.ZIP_DEFLATED) as z:
        for n in sorted(expected):safe(n);z.write(stage/n,n)
    fresh=W/'fresh-extraction-002';fresh.mkdir()
    with zipfile.ZipFile(archive) as z:
        names=z.namelist();assert len(names)==len({n.casefold() for n in names});assert set(names)==expected
        for n in names:safe(n)
        assert z.testzip() is None;z.extractall(fresh)
    for row in rows:assert sha(fresh/row['path'])==row['sha256'] and (fresh/row['path']).stat().st_size==row['bytes']
    assert sha(fresh/'FINAL_INTEGRITY_MANIFEST.json')==sha(W/'FINAL_INTEGRITY_MANIFEST.json')
    result={'SHA256':'PASS','sha256':sha(archive),'bytes':archive.stat().st_size,'CRC':'PASS','MEMBERSHIP':'PASS','DUPLICATES':0,'UNSAFE_PATHS':0,'FRESH_EXTRACTION':'PASS','members':len(names),'archive':str(archive),'fresh_extraction':str(fresh),'final_integrity_manifest_sha256':sha(W/'FINAL_INTEGRITY_MANIFEST.json')}
    put(W/'ZIP_INTEGRITY_REPORT.json',result);print(json.dumps(result))
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['stage','zip']);a=ap.parse_args();main() if a.mode=='stage' else archive()
