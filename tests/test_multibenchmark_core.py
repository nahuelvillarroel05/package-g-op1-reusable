import base64
import copy
import hashlib
import json
import subprocess
import sys
import stat
import zipfile
from pathlib import Path

import pytest

from runtime.candidate.context_engine import Engine, EngineError
from runtime.candidate.multibenchmark import core


def fixture(tmp_path, monkeypatch):
    source = tmp_path / 'tasks.json'
    source.write_text('[{"id":"task-a","instruction":"create artifact"}]', encoding='utf-8')
    task = {'task_id': 'task-a', 'source_path': str(source), 'source_family_id': 'fixture',
            'source_revision': 'a' * 40, 'source_pointer': '/0'}
    monkeypatch.setattr(core, 'parser_for', lambda family: lambda path: [task])
    args = dict(benchmark_id='bfcl_v4', version='V4', revision='a' * 40,
                source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(), allowed_roots=[tmp_path])
    return source, task, args


def admit(engine, envelope):
    commitments = {envelope['source']['path']: envelope['source_sha256']}
    commitments.update({item['path']: item['sha256'] for item in envelope.get('source_artifacts', [])})
    return core.ingest(engine, envelope, allowed_roots=[engine.root.parent], source_commitments=commitments,
                       expected_identity={key: envelope[key] for key in
                                          ('benchmark_id', 'benchmark_version', 'task_id', 'source_revision', 'source_sha256')})


def test_original_bytes_and_fresh_process_recovery(tmp_path, monkeypatch):
    source, task, args = fixture(tmp_path, monkeypatch)
    envelope = core.normalize(task, **args)
    engine = Engine(tmp_path / 'engine')
    receipt = admit(engine, envelope)
    assert core.recover(engine, receipt) == envelope
    assert admit(engine, envelope) == receipt
    assert engine.latest()['version'] == 1
    source.unlink()  # recovery must use Engine bytes, not mutable original/index paths
    code = ('import json,sys; from runtime.candidate.context_engine import Engine; '
            'from runtime.candidate.multibenchmark.core import recover; '
            'print(json.dumps(recover(Engine(sys.argv[1]),json.loads(sys.argv[2]))))')
    done = subprocess.run([sys.executable, '-B', '-c', code, str(engine.root), json.dumps(receipt)],
                          cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == envelope
    assert len(engine._graph['edges']) == 1
    assert engine._graph['edges'][0]['relationship'] == 'DERIVED_ASSOCIATION'


@pytest.mark.parametrize('mutation', ['task_id', 'mixed_family', 'revision', 'version', 'hash', 'missing', 'outside'])
def test_normalize_rejects_substitution(tmp_path, monkeypatch, mutation):
    source, task, args = fixture(tmp_path, monkeypatch)
    task = copy.deepcopy(task)
    if mutation == 'task_id': task['task_id'] = 'other-task'
    if mutation == 'mixed_family': task['benchmark_id'] = 'swebench'
    if mutation == 'revision': task['source_revision'] = 'b' * 40
    if mutation == 'version': args['version'] = 'V3'
    if mutation == 'hash': args['source_sha256'] = '0' * 64
    if mutation == 'missing': source.unlink()
    if mutation == 'outside': args['allowed_roots'] = [tmp_path / 'engine'] ; (tmp_path / 'engine').mkdir()
    with pytest.raises((ValueError, FileNotFoundError)):
        core.normalize(task, **args)


@pytest.mark.parametrize('field,value', [('agent_statement', 'I succeeded'), ('evaluator_result', {'passed': True}),
                                      ('claim_predicate', 'TASK_RESOLVED'), ('audit_verdict', 'SUPPORTED'),
                                      ('evaluator_executed', True), ('gate11_eligible', True)])
def test_no_claim_or_result_promotion(tmp_path, monkeypatch, field, value):
    _, task, args = fixture(tmp_path, monkeypatch)
    envelope = core.normalize(task, **args)
    envelope[field] = value
    with pytest.raises(core.EvidenceError): admit(Engine(tmp_path / 'engine'), envelope)


def test_embedded_bytes_and_exact_retrieval_identity(tmp_path, monkeypatch):
    _, task, args = fixture(tmp_path, monkeypatch)
    envelope = core.normalize(task, **args)
    engine = Engine(tmp_path / 'engine')
    receipt = admit(engine, envelope)
    bad = copy.deepcopy(envelope)
    bad['source']['bytes_base64'] = base64.b64encode(b'other bytes').decode()
    with pytest.raises(core.EvidenceError): admit(engine, bad)
    bad_receipt = dict(receipt, task_key='bfcl_v4:V4:other-task')
    with pytest.raises(core.EvidenceError): core.recover(engine, bad_receipt)
    bad_receipt = dict(receipt, envelope_sha256='0' * 64)
    with pytest.raises(core.EvidenceError): core.recover(engine, bad_receipt)
    obj = next((engine.root / 'objects').iterdir())
    obj.write_bytes(b'{}')
    with pytest.raises(EngineError): core.recover(Engine(engine.root), receipt)


@pytest.mark.parametrize('path', ['../x', '/x', 'C:/x', 'a\\b', 'a/../b', 'a//b', './x'])
def test_unsafe_archive_member(path):
    with pytest.raises(core.EvidenceError): core.safe_relative(path)


def test_malformed_duplicate_json_rejected():
    with pytest.raises(EngineError): core.strict_json_loads('{"id":"a","id":"b"}')


@pytest.mark.parametrize('attack', ['traversal', 'duplicate', 'symlink', 'expansion', 'reserved'])
def test_dangerous_archive_preflight(tmp_path, attack):
    path = tmp_path / 'source.zip'
    with zipfile.ZipFile(path, 'w') as archive:
        if attack == 'traversal': archive.writestr('../escape', b'bad')
        if attack == 'duplicate':
            archive.writestr('FILE', b'a')
            archive.writestr('file', b'b')
        if attack == 'symlink':
            member = zipfile.ZipInfo('link')
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, b'/outside')
        if attack == 'expansion': archive.writestr('large', b'x' * 2048)
        if attack == 'reserved': archive.writestr('CON.txt', b'bad')
    with pytest.raises(core.EvidenceError): core.validate_zip_members(path, max_bytes=1024)


def test_ancillary_contract_and_original_bytes_recover(tmp_path, monkeypatch):
    _, task, args = fixture(tmp_path, monkeypatch)
    verifier = tmp_path / 'verify.py'
    verifier.write_bytes(b'raise RuntimeError("inert source; never execute")\n')
    digest = hashlib.sha256(verifier.read_bytes()).hexdigest()
    task['metadata'] = {'ancillary_artifacts': [{'path': str(verifier), 'role': 'verifier_source', 'sha256': digest}]}
    with pytest.raises(core.EvidenceError): core.normalize(task, **args, source_commitments={})
    envelope = core.normalize(task, **args, source_commitments={str(verifier): digest})
    engine = Engine(tmp_path / 'engine')
    receipt = admit(engine, envelope)
    verifier.unlink()
    recovered = core.recover(Engine(engine.root), receipt)
    assert recovered == envelope
    assert base64.b64decode(recovered['source_artifacts'][0]['bytes_base64']).startswith(b'raise RuntimeError')
    recovered['source_artifacts'] = []
    with pytest.raises(core.EvidenceError): admit(engine, recovered)
