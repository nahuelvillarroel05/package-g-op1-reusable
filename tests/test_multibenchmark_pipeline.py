import copy
import hashlib
import json

import pytest

from runtime.candidate.context_engine import Engine
from runtime.candidate.multibenchmark.core import EvidenceError, ingest, normalize, parser_for
from runtime.candidate.multibenchmark.pipeline import run, recover_run


def inputs(tmp_path):
    source = tmp_path / 'BFCL_v4_simple_python.json'
    source.write_text(json.dumps([{'id': 'simple_python_0', 'question': [[{'role': 'user', 'content': 'call f'}]],
                                   'function': [{'name': 'f', 'description': 'A valid text fixture function',
                                                 'parameters': {'type': 'object', 'properties': {}}}]}]), encoding='utf-8')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    group = {'benchmark_id': 'bfcl_v4', 'version': 'V4', 'revision': 'a' * 40,
             'input_path': str(source), 'task_ids': ['simple_python_0'], 'source_commitments': {str(source): digest}}
    selection = {'schema': 'pgop1.multibenchmark-authentic-selection.v1', 'allowed_roots': [str(tmp_path)], 'groups': [group]}
    selection_path = tmp_path / 'selection.json'
    selection_path.write_text(json.dumps(selection, separators=(',', ':')), encoding='utf-8')
    return source, group, selection, selection_path


def test_compact_selection_is_preserved_and_recovered(tmp_path):
    source, _, _, selection = inputs(tmp_path)
    result = run(selection, tmp_path / 'run')
    assert result['record_count'] == 1
    assert (tmp_path / 'run/selection.json').read_bytes() == selection.read_bytes()
    source.unlink()
    assert recover_run(tmp_path / 'run')['record_count'] == 1


@pytest.mark.parametrize('mutation', ['hash', 'path', 'empty', 'count', 'task', 'selection'])
def test_recovery_rejects_report_substitution(tmp_path, mutation):
    _, _, _, selection = inputs(tmp_path)
    output = tmp_path / 'run'
    run(selection, output)
    results = json.loads((output / 'results.json').read_text())
    if mutation == 'hash': results['records'][0]['source_sha256'] = '0' * 64
    if mutation == 'path': results['records'][0]['source_path'] += '.other'
    if mutation == 'empty': results['records'] = [] ; results['record_count'] = 0
    if mutation == 'count': results['record_count'] = 200
    if mutation == 'task': results['records'][0]['task_id'] = 'simple_python_1'
    if mutation == 'selection': (output / 'selection.json').write_bytes(b'{}')
    (output / 'results.json').write_text(json.dumps(results), encoding='utf-8')
    with pytest.raises(EvidenceError): recover_run(output)


@pytest.mark.parametrize('mutation', ['task', 'metadata', 'pointer', 'family', 'source_family', 'artifact_refs'])
def test_public_ingestion_rebinds_source_not_only_internal_labels(tmp_path, mutation):
    source, group, selection, _ = inputs(tmp_path)
    task = parser_for('bfcl_v4')(source)[0]
    envelope = normalize(task, benchmark_id='bfcl_v4', version='V4', revision=group['revision'],
                         source_sha256=group['source_commitments'][str(source)], allowed_roots=selection['allowed_roots'])
    identity = {key: envelope[key] for key in ('benchmark_id', 'benchmark_version', 'task_id', 'source_revision', 'source_sha256')}
    forged = copy.deepcopy(envelope)
    if mutation == 'task': forged['task_id'] = forged['task_definition']['task_id'] = 'nonexistent'
    if mutation == 'metadata': forged['task_definition']['metadata']['agent_claim'] = 'SUCCESS'
    if mutation == 'pointer': forged['source']['pointer'] = '/nonexistent'
    if mutation == 'family': forged['benchmark_id'] = 'swebench'; forged['benchmark_version'] = 'full'
    if mutation == 'source_family': forged['source_family_id'] = 'invented'
    if mutation == 'artifact_refs': forged['artifact_references'] = [{'claim': 'contaminated'}]
    with pytest.raises(EvidenceError):
        ingest(Engine(tmp_path / 'engine'), forged, allowed_roots=selection['allowed_roots'],
               source_commitments=group['source_commitments'], expected_identity=identity)


def test_ingestion_requires_explicit_admission_grants(tmp_path):
    source, group, selection, _ = inputs(tmp_path)
    envelope = normalize(parser_for('bfcl_v4')(source)[0], benchmark_id='bfcl_v4', version='V4', revision=group['revision'],
                         source_sha256=group['source_commitments'][str(source)], allowed_roots=selection['allowed_roots'])
    with pytest.raises(EvidenceError, match='explicit admission'):
        ingest(Engine(tmp_path / 'engine'), envelope)
