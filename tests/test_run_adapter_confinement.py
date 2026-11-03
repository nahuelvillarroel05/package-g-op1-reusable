"""SWE Pro parser read-boundary probe with authored disposable bytes only."""
import hashlib
import sys
from pathlib import Path
from runtime.candidate.context_engine import Engine
from runtime.candidate.run_adapter_bridge import process_authored_unit

def test_pro_parser_must_not_read_parent_manifest_outside_allowed_roots(tmp_path,monkeypatch):
    allowed=tmp_path/'allowed';allowed.mkdir()
    task=allowed/'instance_synthetic';task.mkdir()
    source=task/'instruction.md';source.write_text('Authored synthetic task.',encoding='utf-8')
    (task/'task.toml').write_text('schema_version = "1.0"\n[task]\nname = "swebench-pro/instance_synthetic"\n',encoding='utf-8')
    outside=tmp_path/'SOURCE_MANIFEST.json';outside.write_text('{}',encoding='utf-8')
    commitments={str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in task.iterdir()}
    original=Path.open; observed=[]
    def traced_open(path,*args,**kwargs):
        if path.absolute()==outside.absolute():observed.append(str(path))
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',traced_open)
    process_authored_unit(Engine(tmp_path/'engine'),family='swebench_pro_v2',version='V2',revision='a'*40,source_path=source,task_id='instance_synthetic',source_sha256=commitments[str(source.resolve())],allowed_roots=[allowed],source_commitments=commitments)
    assert observed==[], 'Pro parser read synthetic SOURCE_MANIFEST.json outside caller allowlist'

"""Read boundary counterexamples over authored fixtures only."""
import hashlib
import sys
from pathlib import Path
import pytest
from runtime.candidate.context_engine import Engine
from runtime.candidate.run_adapter_bridge import process_authored_unit

@pytest.mark.parametrize('scenario',['terminal_parent','pro_uncommitted'])
def test_rejects_uncommitted_or_outside_ancillary_before_read(tmp_path,monkeypatch,scenario):
    task=tmp_path/'synthetic-task';task.mkdir()
    if scenario=='terminal_parent':
        tests=task/'tests';tests.mkdir()
        source=tests/'test.sh';source.write_text('# inert synthetic\n',encoding='utf-8')
        (tests/'test_a.py').write_text('# inert synthetic\n',encoding='utf-8')
        forbidden=task/'task.toml';forbidden.write_text('schema_version = "1.0"\n[task]\nname = "terminal-bench/synthetic-task"\n[metadata]\ncategory = "synthetic"\n',encoding='utf-8')
        (task/'instruction.md').write_text('synthetic',encoding='utf-8')
        family,version,task_id,allowed='terminal_bench_2','2.0','synthetic-task',[tests]
        commitments={str(source.resolve()):hashlib.sha256(source.read_bytes()).hexdigest()}
    else:
        source=task/'instruction.md';source.write_text('synthetic',encoding='utf-8')
        config=task/'task.toml';config.write_text('schema_version = "1.0"\n[task]\nname = "swebench-pro/instance_synthetic"\n',encoding='utf-8')
        forbidden=task/'uncommitted.txt';forbidden.write_text('authored bytes excluded by caller commitments',encoding='utf-8')
        family,version,task_id,allowed='swebench_pro_v2','V2','instance_synthetic',[task]
        commitments={str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,config]}
    original=Path.open;observed=[]
    def trace(path,*args,**kwargs):
        if path.absolute()==forbidden.absolute():observed.append(str(path))
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',trace)
    try:
        process_authored_unit(Engine(tmp_path/'engine'),family=family,version=version,revision='a'*40,source_path=source,task_id=task_id,source_sha256=commitments[str(source.resolve())],allowed_roots=allowed,source_commitments=commitments)
    except ValueError:
        pass
    assert observed==[], 'ancillary bytes were read before allowlist/commitment rejection'

"""Two independently bound authored manifests must not share stale contents."""
import hashlib
import json
import sys
from pathlib import Path
import pytest
from runtime.candidate.context_engine import Engine
from runtime.candidate.multibenchmark.core import EvidenceError
from runtime.candidate.run_adapter_bridge import process_authored_unit

def test_new_manifest_commitment_cannot_reuse_previous_cached_revision(tmp_path):
    task=tmp_path/'instance_synthetic';task.mkdir()
    source=task/'instruction.md';source.write_text('synthetic',encoding='utf-8')
    config=task/'task.toml';config.write_text('schema_version = "1.0"\n[task]\nname = "swebench-pro/instance_synthetic"\n',encoding='utf-8')
    h=hashlib.sha256(source.read_bytes()).hexdigest()
    manifest=tmp_path/'SOURCE_MANIFEST.json'
    contents={'schema':'pgop1.multibenchmark.software-acquisition.v1','corpus_root':str(tmp_path),'source_revision':'a'*40,'files':[{'path':source.relative_to(tmp_path).as_posix(),'bytes':source.stat().st_size,'sha256':h}]}
    manifest.write_text(json.dumps(contents),encoding='utf-8')
    def run(engine):
        commitments={str(p.resolve()):hashlib.sha256(p.read_bytes()).hexdigest() for p in [source,config,manifest]}
        return process_authored_unit(engine,family='swebench_pro_v2',version='V2',revision='a'*40,source_path=source,task_id='instance_synthetic',source_sha256=h,allowed_roots=[tmp_path],source_commitments=commitments)
    run(Engine(tmp_path/'first-engine'))
    contents['source_revision']='b'*40
    manifest.write_text(json.dumps(contents),encoding='utf-8')
    with pytest.raises(EvidenceError):run(Engine(tmp_path/'second-engine'))
