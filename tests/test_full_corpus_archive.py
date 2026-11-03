"""Synthetic controls for archived source identity and recovery populations."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

SCRIPTS=Path(__file__).resolve().parents[1]/'experiments/engineering/corpus_001'
sys.path.insert(0,str(SCRIPTS))
import archive_catalog
from runtime.candidate.context_engine import EngineError

def test_identical_archives_keep_distinct_response_identity_and_recover(tmp_path,monkeypatch):
    task={'id':'simple_python_0','function':[{'name':'f','parameters':{'type':'object','properties':{'x':{'type':'integer'}},'required':['x']}}]}
    taskfile=tmp_path/'tasks.json';taskfile.write_text(json.dumps([task]))
    inventory=tmp_path/'inventory.json';inventory.write_text(json.dumps([{'TASK_ID':task['id'],'SOURCE_PATH':str(taskfile),'SOURCE_SHA256':hashlib.sha256(taskfile.read_bytes()).hexdigest()}]))
    response={'id':task['id'],'result':'<tool_call>{"name":"f","arguments":{"x":1}}</tool_call>'}
    files=[]
    for model in ('model-a','model-b'):
        path=tmp_path/(model+'.json');path.write_text(json.dumps([response]))
        files.append({'family':'bfcl-results','status':'SOURCE_HASH_VERIFIED','path':str(path),
            'relative_path':f'2025-12-16/result/{model}/non_live/BFCL_v4_simple_python_result.json',
            'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'revision':'a'*40,'url':'https://example.invalid/synthetic'})
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps({'files':files}))
    monkeypatch.setattr(archive_catalog,'git',lambda *a:'' if a[0]=='status' else 'b'*40)
    out=tmp_path/'attempt';archive_catalog.run_calling(manifest,inventory,out,[str(tmp_path)])
    rows=[json.loads(line) for line in (out/'ARTIFACT_CATALOG.jsonl').read_text().splitlines()]
    assert len(rows)==2 and len({r['response_id'] for r in rows})==2
    assert len({r['source_sha256'] for r in rows})==1
    assert all(r['reference_id']=='UNKNOWN' and r['audit_verdict']=='NOT_COMPARABLE' for r in rows)
    subprocess.run([sys.executable,'-B',str(SCRIPTS/'full_corpus_pipeline.py'),'recover',str(out)],check=True,capture_output=True)
    recovery=json.loads((out/'FRESH_PROCESS_RECOVERY.json').read_text())
    assert recovery['different_process'] and recovery['record_count']==2
    result=json.loads((out/'RESULTS.json').read_text());result['shards']=[]
    (out/'RESULTS.json').write_text(json.dumps(result))
    truncated=subprocess.run([sys.executable,'-B',str(SCRIPTS/'full_corpus_pipeline.py'),'recover',str(out)],capture_output=True)
    assert truncated.returncode!=0

def test_duplicate_json_keys_never_become_last_wins_archive_rows():
    with pytest.raises(EngineError,match='duplicate JSON key'):
        archive_catalog.iter_rows(b'{"id":"a","id":"b"}')
