"""RUN010 archived-claim measurement; no extractor changes or benchmark execution.

The caller freezes config, selection, and an explicit exact source scope. The
existing SWE adapter owns verdicts; this module only associates them with the
selected claim and persists their unmodified output using Campaign and Engine.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from .core import canonical, digest, load_config, FrameworkError, _write_immutable
from .read_scope import install_read_scope, require_read_scope
from .protection_policy import load_protection_policy
from runtime.candidate.context_engine import Engine, pointer
from runtime.candidate.swebench_claim_audit.adapter import audit_instance


def normalize_claim(original, data_root):
    """Render a frozen structured locator without changing selected content."""
    claim = dict(original)
    loc = claim['source_pointer']
    expected_path = Path(data_root) / 'logs/trajs' / (claim['instance_id'] + '.traj.json')
    if (not isinstance(loc, dict) or loc.get('field') != 'messages[].content'
            or loc.get('role') != 'assistant' or type(loc.get('message_index')) is not int
            or loc['message_index'] < 0 or Path(loc['path']) != expected_path):
        raise FrameworkError('SEMANTIC_E1_INVALID_FROZEN_CLAIM_LOCATOR')
    span = claim['decoded_content_char_span']
    if claim['message_text'][span['start']:span['end_exclusive']] != claim['claim_text']:
        raise FrameworkError('SEMANTIC_E1_INVALID_SELECTED_CLAIM_SPAN')
    if digest(claim['message_text'].encode('utf-8')) != claim['message_content_sha256']:
        raise FrameworkError('SEMANTIC_E1_INVALID_MESSAGE_COMMITMENT')
    claim['original_source_locator'] = loc
    claim['source_pointer'] = f"/messages/{loc['message_index']}/content"
    claim['repository'] = claim['instance_id'].rsplit('-', 1)[0].replace('__', '/')
    claim['predicate_scope'] = ('ONLY_TASK_COMPLETION_PROPOSITION_NOT_OTHER_CLAUSES'
                                if claim['predicate'] == 'TASK_RESOLVED' else 'EXACT_TEST_ASSERTION_UNADJUDICATED')
    return claim


def associate(claim, audit):
    """Never transfer a trajectory-level verdict to a different selected claim."""
    statement = audit.get('AGENT_STATEMENT') or {}
    pointers = statement.get('source_pointers', [statement.get('source_pointer')])
    verdict = audit['AUDIT_VERDICT']
    selected_span = claim.get('decoded_content_char_span', {})
    matched_span = statement.get('match_span', [])
    contained = (len(matched_span) == 2
                 and type(matched_span[0]) is int and type(matched_span[1]) is int
                 and selected_span.get('start', -1) <= matched_span[0] < matched_span[1]
                 <= selected_span.get('end_exclusive', -1)
                 and claim['message_text'][matched_span[0]:matched_span[1]]
                 == statement.get('matched_text'))
    exact = (claim['source_pointer'] in pointers
             and claim['message_text'] == statement.get('text')
             and claim['predicate'] == 'TASK_RESOLVED' and contained)
    if verdict in {'VERIFICATION_ERROR', 'INTEGRITY_FAILURE'}:
        return {'disposition': 'VERIFICATION_ERROR', 'semantic': False,
                'association': 'ADAPTER_ERROR', 'auditor_verdict': verdict}
    if verdict in {'INSUFFICIENT_EVIDENCE', 'ABSTAIN'}:
        if 'NO_EXPLICIT_COMPLETION_CLAIM' in audit.get('reason_codes', []):
            return {'disposition': 'NOT_EVALUABLE', 'semantic': False,
                    'association': 'SELECTED_CLAIM_MISSED_BY_EXTRACTOR',
                    'auditor_verdict': verdict}
        return {'disposition': 'ABSTAIN', 'semantic': False,
                'association': 'NO_DEFINITIVE_ADAPTER_RESULT', 'auditor_verdict': verdict}
    if not exact:
        return {'disposition': 'NOT_EVALUABLE', 'semantic': False,
                'association': 'SELECTED_CLAIM_NOT_EXACTLY_AUDITED', 'auditor_verdict': verdict}
    return {'disposition': verdict, 'semantic': verdict in {'SUPPORTED', 'CONTRADICTED'},
            'association': 'EXACT_MESSAGE_POINTER_CONTAINED_SPAN_TASK_PREDICATE', 'auditor_verdict': verdict}


def _read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def _write(path, value):
    _write_immutable(Path(path), canonical(value))


def validate_runtime_policy(policy):
    if (any(policy['reserved_data'].get(key) != 'NEVER_OPEN'
            for key in ('gold', 'credentials', 'protected_directories'))
            or policy['runtime_limits'].get('equivalent_to_os_sandbox') is not False
            or policy['runtime_limits'].get('child_process_access')
            != 'PROHIBITED_UNLESS_EXPLICITLY_SCOPED'):
        raise FrameworkError('SEMANTIC_E1_PROTECTION_POLICY_INVALID')


def bootstrap(args):
    # Scope is first-party launch metadata, never a reference label/body. Its
    # digest must be supplied out of band by the frozen launch command.
    raw = Path(args.scope).read_bytes()
    if digest(raw) != args.scope_sha256:
        raise FrameworkError('SEMANTIC_E1_SCOPE_COMMITMENT_MISMATCH')
    scope = json.loads(raw)
    policy = load_protection_policy(scope['policy']['path'], scope['policy']['sha256'])
    validate_runtime_policy(policy)
    guard = install_read_scope(scope['protected_roots'], scope['allowed_sources'])
    require_read_scope(scope['protected_roots'], scope['allowed_sources'])
    campaign = load_config(args.config, [args.workspace], args.output,
                           [args.data_root], [args.output_root])
    bound = {r['path']: r['sha256'] for r in campaign.config['input_bindings']}
    if bound.get(str(Path(args.scope))) != args.scope_sha256:
        raise FrameworkError('SEMANTIC_E1_SCOPE_NOT_CONFIG_BOUND')
    if bound.get(scope['policy']['path']) != scope['policy']['sha256']:
        raise FrameworkError('SEMANTIC_E1_POLICY_NOT_CONFIG_BOUND')
    campaign.preflight()
    return scope, guard, campaign


def execute(args):
    scope, guard, campaign = bootstrap(args)
    selection = _read(campaign.config['dataset_manifest_path'])
    claims = selection['claims']
    if [c['claim_id'] for c in claims] != campaign.config['expected_units']:
        raise FrameworkError('SEMANTIC_E1_SELECTION_ORDER_MISMATCH')
    if not 1 <= len(claims) <= 100:
        raise FrameworkError('SEMANTIC_E1_CLAIM_BUDGET')
    launch = _read(args.launch)
    if (launch.get('status') != 'OWNER_AUTHORIZED'
            or launch.get('config_sha256') != campaign.config_sha256
            or launch.get('scope_sha256') != args.scope_sha256
            or launch.get('candidate_commit') != campaign.config['candidate_commit']
            or launch.get('candidate_tree') != campaign.config['candidate_tree']):
        raise FrameworkError('SEMANTIC_E1_BOUND_OWNER_FREEZE_REQUIRED')
    engine_root = Path(args.output).parent.parent.parent / (campaign.config['campaign_attempt_id'] + '-engine')
    if engine_root.exists():
        raise FrameworkError('SEMANTIC_E1_FRESH_ENGINE_REQUIRED')
    engine = Engine(engine_root)
    rows, cache = [], {}
    begun = time.monotonic_ns()
    refs = scope['source_references']
    allowed = set(scope['allowed_sources'])
    if {r['path'] for r in refs} != allowed:
        raise FrameworkError('SEMANTIC_E1_COMPLETE_SOURCE_SCOPE_REQUIRED')
    for offset in range(0, len(claims), 10):
        require_read_scope(scope['protected_roots'], scope['allowed_sources'])
        # Hash every permitted dependency before each deterministic batch.
        for ref in refs:
            raw = Path(ref['path']).read_bytes()
            if digest(raw) != ref['sha256'] or len(raw) != ref['bytes']:
                raise FrameworkError('SEMANTIC_E1_SOURCE_CHANGED_STOP')
        for claim in claims[offset:offset+10]:
            cid = claim['claim_id']
            start = time.monotonic_ns()
            trajectory_path = str(Path(args.data_root) / 'logs' / 'trajs' / (claim['instance_id'] + '.traj.json'))
            if trajectory_path not in allowed:
                raise FrameworkError('SEMANTIC_E1_CLAIM_SOURCE_NOT_ALLOWED')
            trajectory = _read(trajectory_path)
            index = claim['original_source_locator']['message_index']
            if (trajectory.get('instance_id') != claim['instance_id']
                    or trajectory['messages'][index].get('role') != 'assistant'
                    or pointer(trajectory, claim['source_pointer']) != claim['message_text']):
                raise FrameworkError('SEMANTIC_E1_CLAIM_TEXT_NOT_SOURCE_BOUND')
            campaign.begin_unit(cid, {'claim_id': cid, 'instance_id': claim['instance_id']})
            iid = claim['instance_id']
            if iid not in cache:
                cache[iid] = audit_instance(args.data_root, iid)
            audit = cache[iid]
            row = {'claim_id': cid, 'instance_id': iid, **associate(claim, audit),
                   'parser_reason_codes': audit.get('reason_codes', []),
                   'audit': audit, 'selected_claim': claim,
                   'duration_ns': time.monotonic_ns() - start,
                   'cost': 'NOT_OBSERVABLE_LOCAL_NO_PAID_SERVICE',
                   'producer_redispatch': False}
            raw = canonical(row)
            capsule = engine.root / 'capsules' / (cid + '.json')
            _write_immutable(capsule, raw)
            source = engine.admit_source(capsule, digest(raw), 'ENGINEERING_RESULT', source_id=cid)
            nodes = [{'id': cid + ':' + key, 'task_id': cid, 'run_id': 'RUN010',
                      'kind': 'RUN010_' + key.upper(), 'source_id': source['source_id'],
                      'evidence_pointer': '/' + key}
                     for key in ('selected_claim', 'audit', 'disposition')]
            edges = [{'id': cid + ':association', 'from': cid + ':selected_claim',
                      'to': cid + ':audit', 'relationship': 'DERIVED_ASSOCIATION',
                      'evidence_bindings': [{'source_id': cid, 'pointer': ''}]}]
            manifest = engine.ingest(nodes, edges)
            receipt = campaign.complete_unit(cid, row['disposition'], {
                'capsule_path': str(capsule), 'capsule_sha256': digest(raw),
                'engine_manifest': manifest, 'duration_ns': row['duration_ns']})
            rows.append({'claim_id': cid, 'instance_id': iid,
                         'disposition': row['disposition'], 'semantic': row['semantic'],
                         'association': row['association'], 'capsule_path': str(capsule),
                         'capsule_sha256': digest(raw), 'receipt_sha256': receipt['receipt_sha256']})
        _write(Path(args.output) / 'batches' / f'{offset//10+1:03d}.json',
               {'batch': offset//10+1, 'completed': [r['claim_id'] for r in rows],
                'producer_redispatch': False})
        print(json.dumps({'completed_claims': len(rows), 'selected': len(claims)}), flush=True)
    _write(Path(args.output) / 'LEDGER.json', {'rows': rows, 'auditor_invocations': len(cache),
           'engine_root': str(engine_root), 'duration_ns': time.monotonic_ns()-begun,
           'scope_denials': len(guard.denied_events)})


def recover(args):
    _, _, campaign = bootstrap(args)
    state = campaign.recover()
    ledger = _read(Path(args.output) / 'LEDGER.json')
    engine = Engine(ledger['engine_root'])
    verified = engine.verify()
    for row in ledger['rows']:
        raw = Path(row['capsule_path']).read_bytes()
        if digest(raw) != row['capsule_sha256']:
            raise FrameworkError('SEMANTIC_E1_CAPSULE_HASH_MISMATCH')
        expected = json.loads(raw)
        observations = engine.query(task_id=row['claim_id'], limit=10)
        keys = ('selected_claim', 'audit', 'disposition')
        if (len(observations) != 3 or {o['id'] for o in observations} !=
                {row['claim_id'] + ':' + key for key in keys}):
            raise FrameworkError('SEMANTIC_E1_OBSERVATION_MEMBERSHIP')
        for obs in observations:
            binding = obs['evidence_binding']
            key = obs['id'].split(':')[-1]
            if binding != {'source_id': row['claim_id'], 'pointer': '/' + key}:
                raise FrameworkError('SEMANTIC_E1_OBSERVATION_BINDING_MISMATCH')
            value = pointer(json.loads(engine.read_source(binding['source_id'])), binding['pointer'])
            if value != pointer(expected, binding['pointer']) or obs['value'] != value:
                raise FrameworkError('SEMANTIC_E1_RECOVERY_VALUE_MISMATCH')
        terminals = [r for r in state['receipts'] if r['unit_id'] == row['claim_id'] and r['phase'] == 'terminal']
        if len(terminals) != 1 or terminals[0]['sha256'] != row['receipt_sha256']:
            raise FrameworkError('SEMANTIC_E1_RECOVERY_RECEIPT_BINDING')
    if not state['complete'] or set(state['completed']) != {r['claim_id'] for r in ledger['rows']}:
        raise FrameworkError('SEMANTIC_E1_RECOVERY_INCOMPLETE')
    _write(Path(args.workspace) / 'FRESH_RECOVERY.json', {
        'status': 'PASS', 'recovered': len(ledger['rows']), 'engine_verify': verified,
        'framework_receipts': len(state['receipts']), 'framework_checkpoints': len(state['checkpoints']),
        'pending': sorted(state['pending']), 'inflight': sorted(state['inflight']),
        'producer_redispatch': False, 'mode': 'READ_ONLY_NO_RESUME'})


def main():
    parser = argparse.ArgumentParser()
    for name in ('scope', 'scope-sha256', 'config', 'workspace', 'output', 'data-root', 'output-root'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--launch')
    parser.add_argument('--recover', action='store_true')
    parser.add_argument('--preflight-only', action='store_true')
    args = parser.parse_args()
    if args.preflight_only:
        _, _, campaign = bootstrap(args)
        _write(Path(args.workspace) / 'PREFLIGHT.json', {'status': 'PASS',
            'config_sha256': campaign.config_sha256, 'reservation_performed': False,
            'candidate_commit': campaign.config['candidate_commit'],
            'candidate_tree': campaign.config['candidate_tree']})
        print('PREFLIGHT_PASS_NO_RESERVATION')
    else:
        recover(args) if args.recover else execute(args)


if __name__ == '__main__':
    main()
