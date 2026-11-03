"""Regression for material original-log export finding; no archive mutation."""
import hashlib,importlib.util,json
from pathlib import Path
W=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('package_continuity',W/'package_continuity.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def row(p):return {'path':p.relative_to(W).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
log=W/'execution_receipts/swebench/SWE_OFFICIAL_REGRADE_001/apache__druid-15402.test_output.txt'
assert log.is_file()
# Reproducer of the exact old selector condition documented in the initial audit.
old_selected=log.suffix in ['.md','.json','.py','.txt','.log','.jsonl'] and log.stat().st_size<=2_000_000 and not any(x.lower() in ['raw','downloads','blobs','fetched','official','official_sources'] or x.startswith('official-') for x in log.relative_to(W).parts)
assert old_selected
results=[]
for name,r in [('raw_original_log',row(log)),('path_traversal',{'path':'../outside.json','sha256':'0'*64,'bytes':0}),('official_source',{'path':'evaluator_dependencies/bfcl/official-pin/a.py','sha256':'0'*64,'bytes':0}),('tampered_hash',{**row(W/'RUN004_CONTRACT_REV003.md'),'sha256':'0'*64})]:
    try:m.validate_selection_row(r)
    except ValueError:results.append({'case':name,'result':'REJECTED_AS_REQUIRED'})
    else:raise AssertionError(name)
assert m.validate_selection_row(row(W/'RUN004_CONTRACT_REV003.md'))[1].is_file()
out={'status':'PASS','defect':'ZIP_ORIGINAL_BODY_SELECTION_001','before':'Old selector includes exact original decompressed log (static condition reproduced)','after':results,'positive_control':'Authored contract with exact hash accepted','scope':'Export-membership control, not PGOP1 runtime quality; actual ZIP membership checked separately'}
with (W/'fixes/ZIP_SELECTION_REGRESSION.json').open('x',encoding='utf-8') as f:json.dump(out,f,indent=2)
print(json.dumps(out))
