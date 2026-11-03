"""Task-name schema controls; downloaded task/verifier code is never executed."""
from pathlib import Path
import pytest
from runtime.candidate.multibenchmark.operations import parse_terminal_bench

def fixture(root,task_id):
    directory=root/task_id
    (directory/'tests').mkdir(parents=True)
    (directory/'task.toml').write_text('schema_version="1.1"\n[task]\nname="terminal-bench/'+task_id+'"\nkeywords=[]\n[metadata]\ncategory="debugging"\n')
    (directory/'instruction.md').write_text('Synthetic task definition only.\n')
    (directory/'tests/test.sh').write_text('# inert source\n')
    (directory/'tests/test_outputs.py').write_text('# inert source\n')
    return directory

@pytest.mark.parametrize('task_id',['unit-task','install-windows-3.11','python3.12-tests'])
def test_versioned_terminal_task_names_are_source_identities(tmp_path,task_id):
    directory=fixture(tmp_path,task_id)
    records=parse_terminal_bench(directory/'task.toml')
    assert len(records)==1 and records[0]['task_id']==task_id
    assert records[0]['source_path']==str((directory/'task.toml').resolve())

@pytest.mark.parametrize('task_id',['.hidden','task.','task..name','../escape','task/name','task\\name','unit_task','TASK'])
def test_terminal_name_extension_preserves_safe_single_component(tmp_path,task_id):
    directory=fixture(tmp_path,'actual-task')
    config=directory/'task.toml'
    # Escape TOML literal characters without ever constructing an unsafe path.
    import json
    config.write_text('schema_version="1.1"\n[task]\nname='+json.dumps('terminal-bench/'+task_id)+'\nkeywords=[]\n[metadata]\ncategory="debugging"\n')
    with pytest.raises(ValueError):parse_terminal_bench(config)
