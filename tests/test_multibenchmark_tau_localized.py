import hashlib
import json

import pytest

from runtime.candidate.multibenchmark.calling import CallingFormatError, parse_tau
from runtime.candidate.multibenchmark.core import normalize


def fixture(tmp_path, language, domain, *, bundled=True):
    root = tmp_path / 'multilingual' / language
    path = root / 'regional' / (domain + '.json') if bundled else root / f'{domain}_tasks_{language}.json'
    path.parent.mkdir(parents=True)
    task = {'id': '0_identity', 'user_scenario': {'instructions': {'domain': domain, 'reason_for_call': 'inert text'}},
            'evaluation_criteria': {'actions': [], 'nl_assertions': [], 'reward_basis': []}}
    data = {'domain': domain, 'tasks': [task], 'database': {'inert': True}, 'policies': {}} if bundled else [task]
    path.write_text(json.dumps(data), encoding='utf-8')
    return path, data


@pytest.mark.parametrize('language', ['en', 'es', 'hi', 'ko', 'pt', 'zh'])
@pytest.mark.parametrize('domain', ['airline', 'retail', 'telecom'])
def test_text_v1_cells_have_language_bound_identity_and_exact_source_pointer(tmp_path, language, domain):
    path, _ = fixture(tmp_path, language, domain)
    task = parse_tau(path)[0]
    assert task['task_id'] == f'tau2:{language}:{domain}:0_identity'
    assert task['source_pointer'] == '/tasks/0'
    assert task['metadata']['language'] == language
    assert task['metadata']['source_task_id'] == '0_identity'
    assert task['metadata']['canonical_task_alias'] == 'UNKNOWN'
    assert task['reference_type'] == 'task_criteria_without_reference_actions'
    envelope = normalize(task, benchmark_id='tau_bench', version='2.0.0:text-v1', revision='a' * 40,
                         source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), allowed_roots=[tmp_path])
    assert envelope['evaluator_executed'] is False
    assert envelope['agent_statement'] == 'UNKNOWN'
    assert envelope['tool_call'] == 'UNKNOWN'


def test_localized_array_and_regional_bundle_never_conflate_with_canonical_identity(tmp_path):
    path, _ = fixture(tmp_path, 'en', 'retail', bundled=False)
    task = parse_tau(path)[0]
    assert task['task_id'] == 'tau2:en:retail:0_identity'
    assert task['source_pointer'] == '/0'
    assert task['metadata']['source_layout'] == 'localized_task_array'


@pytest.mark.parametrize('mutation', ['domain', 'tasks_type', 'duplicate', 'instructions_domain', 'language', 'parent', 'suffix'])
def test_localized_sources_reject_incompatible_layout_or_schema(tmp_path, mutation):
    path, data = fixture(tmp_path, 'es', 'airline')
    if mutation == 'domain': data['domain'] = 'retail'
    if mutation == 'tasks_type': data['tasks'] = {}
    if mutation == 'duplicate': data['tasks'] *= 2
    if mutation == 'instructions_domain': data['tasks'][0]['user_scenario']['instructions']['domain'] = 'retail'
    if mutation in {'language', 'parent', 'suffix'}:
        if mutation == 'language': new_path = tmp_path / 'multilingual/fr/regional/airline.json'
        if mutation == 'parent': new_path = tmp_path / 'unbound/es/regional/airline.json'
        if mutation == 'suffix': new_path = path.with_suffix('.jsonl')
        new_path.parent.mkdir(parents=True, exist_ok=True)
        path = new_path
    path.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(CallingFormatError):
        parse_tau(path)
