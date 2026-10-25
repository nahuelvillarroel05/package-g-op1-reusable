import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from runtime import *
mode,d=sys.argv[1:3];d=Path(d);r=read(d/'request.json');relation=r['relationship'];validate_relationship(relation)
module=load_pinned(relation[mode.upper()+'_SOURCE'],relation[mode.upper()+'_SHA256'])
if mode=='provider':module.produce(r)
elif mode=='consumer':print(canonical(module.consume(r,d)).decode())
else:raise ValueError('unknown worker mode')
