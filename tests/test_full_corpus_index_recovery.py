"""Scale and negative controls for the existing Engine's derived index audit."""
import hashlib,json
from pathlib import Path
import sqlite3
import subprocess
import sys
import pytest

REPO=Path(__file__).resolve().parents[1]
SCRIPTS=REPO/'experiments/engineering/corpus_001';sys.path.insert(0,str(SCRIPTS))
from recover_archive_index import index_fingerprint,verify_complete_index
from runtime.candidate.context_engine import Engine,EngineError

@pytest.fixture
def indexed_engine(tmp_path):
    engine=Engine(tmp_path/'context')
    source=engine.root/'input.json';source.write_text(json.dumps({'rows':list(range(1001))}))
    admitted=engine.admit_source(source,hashlib.sha256(source.read_bytes()).hexdigest(),'SYNTHETIC')
    engine.ingest([{'id':f'row:{i:05d}','task_id':f'task:{i}','kind':'SYNTHETIC_INDEX_CONTROL','source_id':admitted['source_id'],
                    'evidence_pointer':f'/rows/{i}','value':i} for i in range(1001)])
    return engine

def test_complete_fresh_index_scan_exceeds_query_page_without_raising_cap(indexed_engine):
    engine=indexed_engine
    with pytest.raises(EngineError,match='query limit'):engine.query(limit=1001)
    assert verify_complete_index(engine)==1001
    code='import sys;sys.path.insert(0,sys.argv[1]);from recover_archive_index import Engine,verify_complete_index;print(verify_complete_index(Engine(sys.argv[2])))'
    result=subprocess.run([sys.executable,'-B','-c',code,str(SCRIPTS),str(engine.root)],capture_output=True,text=True,check=True)
    assert result.stdout.strip()=='1001'

@pytest.mark.parametrize('mutation',["UPDATE observations SET active=0 WHERE id='row:00000'", "DELETE FROM observations WHERE id='row:00000'"])
def test_pre_rebuild_scan_rejects_indexed_column_tamper_and_omission(indexed_engine,mutation):
    engine=indexed_engine;original=index_fingerprint(engine.root)
    with sqlite3.connect(engine.root/'index.sqlite') as db:db.execute(mutation)
    changed=index_fingerprint(engine.root)
    assert changed['all_column_sha256']!=original['all_column_sha256']
    with pytest.raises(ValueError,match='INDEX_COLUMNS_OR_POPULATION'):verify_complete_index(engine)

def test_full_archive_recovery_resolves_producer_relative_paths_from_another_cwd(tmp_path,monkeypatch):
    import archive_catalog
    workspace=REPO.parents[2]
    # Controlled pytest temp is explicitly inside this authorized workspace.
    relative=tmp_path.relative_to(workspace)/'relative-attempt'
    taskfile=tmp_path/'tasks.json'
    tasks=[{'id':f'simple_python_{3000+i}','function':[{'name':'f','parameters':{'type':'object','properties':{},'required':[]}}]} for i in range(600)]
    taskfile.write_text(json.dumps(tasks))
    inventory=tmp_path/'inventory.json';inventory.write_text(json.dumps([{'TASK_ID':r['id'],'SOURCE_PATH':str(taskfile),'SOURCE_SHA256':hashlib.sha256(taskfile.read_bytes()).hexdigest()} for r in tasks]))
    response=tmp_path/'response.json';response.write_text(json.dumps([{'id':r['id'],'result':'<tool_call>{"name":"f","arguments":{}}</tool_call>'} for r in tasks]))
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps({'files':[{'family':'bfcl-results','status':'SOURCE_HASH_VERIFIED','path':str(response),
        'relative_path':'2025-12-16/result/synthetic/non_live/BFCL_v4_simple_python_result.json','sha256':hashlib.sha256(response.read_bytes()).hexdigest(),
        'revision':'a'*40,'url':'https://example.invalid/synthetic'}]}))
    def git(*args):
        if args[0]=='status':return ''
        return subprocess.check_output(['git','-c','safe.directory='+REPO.as_posix(),'-C',str(REPO),*args],text=True).strip()
    monkeypatch.setattr(archive_catalog,'git',git);monkeypatch.chdir(workspace)
    archive_catalog.run_calling(manifest,inventory,relative,[str(tmp_path)])
    attempt=workspace/relative;output=tmp_path/'recovery.json'
    proc=subprocess.run([sys.executable,'-B',str(SCRIPTS/'recover_archive_index.py'),str(attempt),'--repo',str(REPO),'--output',str(output)],
        cwd=tmp_path,capture_output=True,text=True)
    assert proc.returncode==0,proc.stderr
    report=json.loads(output.read_text());assert report['record_count']==600 and report['different_process']
    assert report['query_cap_changes']==0 and report['shards'][0]['observations']==1200
    assert report['producer_workspace_root']==str(workspace) and report['invocation_cwd']==str(tmp_path)
