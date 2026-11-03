"""Durable receipt of the mandatory full documentary check, without skip options."""
import datetime,hashlib,json,subprocess,sys
from pathlib import Path
W=Path(__file__).resolve().parent;ROOT=W.parents[1]
def bind(p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
def main():
    argv=[sys.executable,'-B',str(ROOT/'docs/verify_documentation.py')];start=datetime.datetime.now(datetime.timezone.utc).isoformat()
    out=W/'DOCUMENTATION_VERIFIER_STDOUT.json';err=W/'DOCUMENTATION_VERIFIER_STDERR.txt'
    with out.open('xb') as o,err.open('xb') as e:p=subprocess.run(argv,cwd=ROOT,stdout=o,stderr=e)
    summary=json.loads(out.read_text(encoding='utf-8-sig'))
    status='PASS' if p.returncode==0 and summary['status']=='PASS' and not summary['errors'] else 'FAIL'
    receipt={'status':status,'argv':argv,'cwd':str(ROOT),'started_utc':start,'ended_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':p.returncode,'stdout':bind(out),'stderr':bind(err),'summary':summary,'document_manifest_sha256':bind(ROOT/'docs/DOCUMENTATION_INTEGRITY_MANIFEST.json')['sha256'],'scope':'Full documentary verifier, no skip-integrity; not runtime qualification'}
    with (W/'DOCUMENTATION_VERIFICATION_RECEIPT.json').open('x',encoding='utf-8',newline='\n') as f:json.dump(receipt,f,indent=2)
    print(json.dumps({'status':status,'exit_code':p.returncode,'summary':summary}));sys.exit(0 if status=='PASS' else 1)
if __name__=='__main__':main()
