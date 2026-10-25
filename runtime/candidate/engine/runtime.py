"""Engineering-only adapters around accepted immutable validators."""
import hashlib,json,sys,uuid,os,time,subprocess,types
from pathlib import Path
ROOT=Path(__file__).resolve().parent
CONFIG=json.loads((ROOT/'CONFIG.json').read_bytes())
BASE=Path(CONFIG['integration_root']); BASE=(ROOT/BASE).resolve() if not BASE.is_absolute() else BASE
for name,digest in CONFIG['baseline_pins'].items():
 pin=Path(name); pin=(ROOT/pin).resolve() if not pin.is_absolute() else pin
 if hashlib.sha256(pin.read_bytes()).hexdigest()!=digest: raise ValueError('baseline drift: '+name)
sys.path.insert(0,str(BASE))
from loader import MODULES
from durable_registry import DurableRegistry
from integration import canonical,sha
receipt_api=MODULES['mechanical.process_receipts']
junit_api=MODULES['junit.junit_accounting']
def uid(prefix): return prefix+'-'+uuid.uuid4().hex
def now():
 from datetime import datetime,timezone
 return datetime.now(timezone.utc).isoformat()
def write(p,value):
 with Path(p).open('xb') as f:
  f.write(canonical(value)); f.flush(); os.fsync(f.fileno())
def read(p): return json.loads(Path(p).read_bytes())
def load_pinned(p,digest):
 body=Path(p).read_bytes()
 if sha(body)!=digest: raise ValueError('source binding mismatch: '+str(p))
 module=types.ModuleType(uid('module'));module.__file__=str(p)
 exec(compile(body,str(p),'exec'),module.__dict__)
 return module
def validate_relationship(r):
 if r['CLASSIFICATION']!='ENGINEERING_LIVE' or r['AUTHORITY_SCOPE']!=CONFIG['authority_scope']: raise ValueError('unauthorized relationship')
 if r['OUTPUT_SCHEMA']!=r['INPUT_CONTRACT']: raise ValueError('schema mismatch')
 for role in ('PROVIDER','CONSUMER'):
  p=Path(r[role+'_SOURCE']).resolve()
  if p.parent!=ROOT or p.is_symlink(): raise ValueError('source outside campaign')
  if sha(p.read_bytes())!=r[role+'_SHA256']: raise ValueError('source binding mismatch')
 return True
def spawn_capture(argv,directory,label,actor,run):
 start=now(); tick=time.monotonic(); process_id=uid('PROC'); invocation_id=uid('INV')
 child=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
 pid=child.pid;timed_out=False
 try: out,err=child.communicate(timeout=15)
 except subprocess.TimeoutExpired:
  timed_out=True; child.kill();out,err=child.communicate(timeout=5)
 end=now()
 for suffix,body in [('stdout',out),('stderr',err)]:
  with Path(directory,label+'.'+suffix).open('xb') as f:f.write(body)
 instance={'pid':pid,'start_id':process_id}
 command=json.dumps(argv,ensure_ascii=True,separators=(',',':'))
 invocation={'id':invocation_id,'command':command,'command_sha256':sha(command.encode()),'actor_id':actor,'actor_role':'WORKER','process_instance':instance}
 events=[]
 for kind,extra in [('START',{}),('OUTPUT',{'output_id':'stdout','sha256':sha(out)}),('OUTPUT',{'output_id':'stderr','sha256':sha(err)}),('EXIT',{'exit_code':child.returncode})]:
  events.append(dict(id=uid('EVT'),sequence=len(events)+1,kind=kind,invocation_id=invocation_id,actor_id=actor,process_instance=instance,**extra))
 receipt={'schema':'MECHANICAL034_SYNTHETIC_RECEIPT_V1','scope':'SYNTHETIC_ENGINEERING','run_id':run,'invocations':[invocation],'events':events}
 lifecycle={'PROCESS_ID':process_id,'RECEIPT_ID':uid('RCP'),'parent_pid':os.getpid(),'pid':pid,'start':start,'end':end,'elapsed_seconds':time.monotonic()-tick,'exit_code':child.returncode,'timed_out':timed_out,'terminal_observed':child.poll() is not None,'command':argv,'receipt':receipt,'output_hashes':{'stdout':sha(out),'stderr':sha(err)},'runner_sha256':sha(Path(sys.executable).read_bytes())}
 write(Path(directory,label+'.process.json'),lifecycle)
 return lifecycle,out,err
def outputs(directory,label='provider'):
 return {k:Path(directory,label+'.'+k).read_bytes() for k in ('stdout','stderr')}
def verify_receipt(directory):
 proc=read(Path(directory,'provider.process.json'))
 result=receipt_api.validate_receipt(proc['receipt'],outputs(directory))
 if proc['timed_out'] or not proc['terminal_observed'] or not result['execution_success']:raise ValueError('producer process failure')
 return result


