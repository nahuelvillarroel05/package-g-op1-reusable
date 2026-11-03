import copy
import hashlib
import json

import pytest

from runtime.candidate.context_engine import Engine
from runtime.candidate.multibenchmark import core


def source_fixture(tmp_path):
    source = tmp_path / 'BFCL_v4_simple_python.json'
    source.write_text(json.dumps([
        {'id': f'simple_python_{i}', 'question': [[{'role': 'user', 'content': 'inert task'}]], 'function': []}
        for i in range(3)]), encoding='utf-8')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    args = dict(benchmark_id='bfcl_v4', version='V4', revision='a' * 40,
                source_sha256=digest, allowed_roots=[tmp_path], source_commitments={str(source): digest})
    return source, args


def admission(engine, envelope, args, session=None):
    return core.ingest(engine, envelope, allowed_roots=args['allowed_roots'],
                       source_commitments=args['source_commitments'], source_session=session,
                       expected_identity={key: envelope[key] for key in
                                          ('benchmark_id', 'benchmark_version', 'task_id', 'source_revision', 'source_sha256')})


def test_source_session_parses_once_and_preserves_default_envelopes(tmp_path, monkeypatch):
    source, args = source_fixture(tmp_path)
    parser = core.parser_for('bfcl_v4')
    tasks = parser(source)
    calls = []

    def counted(path):
        calls.append(str(path))
        return parser(path)

    monkeypatch.setattr(core, 'parser_for', lambda family: counted)
    expected = [core.normalize(task, **args) for task in tasks]
    default_engine = Engine(tmp_path / 'default')
    default_receipts = [admission(default_engine, envelope, args) for envelope in expected]
    assert len(calls) == 2 * len(tasks)  # demonstrated per-task reparse defect
    calls.clear()
    engine = Engine(tmp_path / 'session')
    with core.VerifiedSourceSession(source, **args) as session:
        actual = [core.normalize(task, **args, source_session=session) for task in session.tasks]
        receipts = [admission(engine, envelope, args, session) for envelope in actual]
        assert actual == expected
        assert receipts == default_receipts
        assert [core.recover(engine, receipt) for receipt in receipts] == actual
        assert len(calls) == 1
    assert session.verified_on_exit is True
    assert [core.recover(Engine(engine.root), receipt) for receipt in receipts] == expected


@pytest.mark.parametrize('mutation', ['task', 'metadata', 'commitments', 'revision', 'roots'])
def test_session_never_bypasses_task_or_admission_binding(tmp_path, mutation):
    source, args = source_fixture(tmp_path)
    with core.VerifiedSourceSession(source, **args) as session:
        task = session.tasks[0]
        changed = copy.deepcopy(args)
        if mutation == 'task': task['task_id'] = 'absent'
        if mutation == 'metadata': task['metadata']['invented'] = True
        if mutation == 'commitments': changed['source_commitments'] = {}
        if mutation == 'revision': changed['revision'] = 'b' * 40
        if mutation == 'roots': changed['allowed_roots'] = [tmp_path.parent]
        with pytest.raises(core.EvidenceError):
            core.normalize(task, **changed, source_session=session)
        # The public task list cannot mutate the stored parser snapshot.
        assert 'invented' not in session.tasks[0]['metadata']


def test_session_checks_commitments_before_parser(tmp_path, monkeypatch):
    source, args = source_fixture(tmp_path)
    args['source_commitments'][str(source)] = '0' * 64
    monkeypatch.setattr(core, 'parser_for', lambda family: pytest.fail('parser called before hash check'))
    with pytest.raises(core.EvidenceError):
        with core.VerifiedSourceSession(source, **args):
            pytest.fail('entered invalid session')


def test_session_rejects_mid_parse_change(tmp_path, monkeypatch):
    source, args = source_fixture(tmp_path)
    parser = core.parser_for('bfcl_v4')

    def mutate(path):
        tasks = parser(path)
        source.write_bytes(b'changed during parse')
        return tasks

    monkeypatch.setattr(core, 'parser_for', lambda family: mutate)
    with pytest.raises(core.EvidenceError, match='hash differs'):
        with core.VerifiedSourceSession(source, **args):
            pytest.fail('entered changed session')


def test_session_uses_committed_snapshot_then_fails_exit_if_live_source_changes(tmp_path):
    source, args = source_fixture(tmp_path)
    with pytest.raises(core.EvidenceError, match='hash differs'):
        with core.VerifiedSourceSession(source, **args) as session:
            task = session.tasks[0]
            before = core.normalize(task, **args, source_session=session)
            source.write_bytes(b'changed while batch runs')
            assert core.normalize(task, **args, source_session=session) == before
            receipt = admission(Engine(tmp_path / 'failed-batch'), before, args, session)
    assert session.verified_on_exit is False
    assert core.recover(Engine(tmp_path / 'failed-batch'), receipt) == before
    with pytest.raises(core.EvidenceError, match='not active'):
        _ = session.tasks
    with pytest.raises(core.EvidenceError, match='cannot be reopened'):
        session.__enter__()
    with pytest.raises(core.EvidenceError):
        core.normalize(task, **args, source_session=session)


def test_session_ancillary_commitments_rechecked_on_exit(tmp_path, monkeypatch):
    source, args = source_fixture(tmp_path)
    artifact = tmp_path / 'verify.py'
    artifact.write_bytes(b'raise RuntimeError("inert; never execute")')
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    args['source_commitments'][str(artifact)] = digest
    parser = core.parser_for('bfcl_v4')

    def with_artifact(path):
        tasks = parser(path)
        for task in tasks:
            task['metadata']['ancillary_artifacts'] = [{'path': str(artifact), 'role': 'verifier_source', 'sha256': digest}]
        return tasks

    monkeypatch.setattr(core, 'parser_for', lambda family: with_artifact)
    with pytest.raises(core.EvidenceError, match='hash differs'):
        with core.VerifiedSourceSession(source, **args) as session:
            envelope = core.normalize(session.tasks[0], **args, source_session=session)
            assert envelope['source_artifacts'][0]['sha256'] == digest
            artifact.write_bytes(b'changed')


def test_session_failure_does_not_claim_verified_exit(tmp_path):
    source, args = source_fixture(tmp_path)
    with pytest.raises(RuntimeError):
        with core.VerifiedSourceSession(source, **args) as session:
            raise RuntimeError('batch failed')
    assert session.verified_on_exit is False
