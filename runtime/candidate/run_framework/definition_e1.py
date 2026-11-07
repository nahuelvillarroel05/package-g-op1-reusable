"""Closed first-party definition composition with process-local source read scope.

Only admitted primary JSON/TOML metadata is parsed. No benchmark commands,
outputs, environments or model callbacks execute. This is not a sandbox for
untrusted Python, nor a guard for separate processes started by another actor.
"""
from __future__ import annotations

import json
from collections import Counter
import os
from pathlib import Path
import time

from .core import FrameworkError, canonical, digest, load_config, _loads
from .provenance import _read_bound_file


def validate_admission(config, admission, units):
    if (config.get('run_id') not in {'RUN008', 'RUN009'}
            or config.get('campaign_id') != f"PGOP1-{config.get('run_id')}-E1"
            or admission.get('schema') != 'pgop1.definition-e1.admission.v1'):
        raise FrameworkError('DEFINITION_E1_IDENTITY_OR_ADMISSION_INVALID')
    if [u['unit_id'] for u in units] != config['expected_units']:
        raise FrameworkError('DEFINITION_E1_SELECTION_ORDER_MISMATCH')
    if (len(units) != 4 or Counter(u['benchmark_id'] for u in units) !=
            {'mcpmark_verified': 2, 'terminal_bench_2': 2}
            or config['resource_budget'].get('max_units') != 4
            or config['resource_budget'].get('max_units_per_shard') != 2
            or config['checkpoint_policy'].get('interval') != 1):
        raise FrameworkError('DEFINITION_E1_FOUR_UNITS_TWO_FAMILIES_REQUIRED')
    rows = admission.get('units', [])
    if len(rows) != len(units) or len({r['unit_id'] for r in rows}) != len(rows):
        raise FrameworkError('DEFINITION_E1_RIGHTS_MEMBERSHIP_MISMATCH')
    by_id = {r['unit_id']: r for r in rows}
    for unit in units:
        row = by_id.get(unit['unit_id'], {})
        expected = {'path': unit['source_path'], 'sha256': unit['source_sha256']}
        if (unit.get('benchmark_id') not in {'mcpmark_verified', 'terminal_bench_2'}
                or unit.get('predicate_profile') != 'DEFINITION_ONLY'
                or unit.get('authentic_output_references') != []
                or unit.get('evidence_references') != [expected]
                or row.get('processing_status') != 'PROCESSING_PERMITTED'
                or row.get('allowed_source_references') != [expected]):
            raise FrameworkError('DEFINITION_E1_SOURCE_OPERATION_NOT_ADMITTED')
    return {'units': len(units), 'authentic_agent_outputs': 0, 'rights_granted_by_runner': False}


def run(args, *, launch_authorization=None, freeze=None):
    from .read_scope import install_read_scope
    from .caller import GenericCaller, validate_configuration
    from .e1 import process_definition
    from .predicates import build_audit_payload
    from .run005 import source_manifest_read_gate, execute_batches, record_engine_result, _serial
    from .resources import ResourceGuard
    from runtime.candidate.context_engine import Engine

    config_raw = Path(args.config).read_bytes()
    config = _loads(config_raw)
    if (not isinstance(launch_authorization, dict) or launch_authorization.get('status') != 'OWNER_AUTHORIZED'
            or launch_authorization.get('config_sha256') != digest(config_raw)
            or launch_authorization.get('campaign_attempt_id') != config.get('campaign_attempt_id')
            or not isinstance(freeze, dict) or freeze.get('status') != 'FROZEN'
            or freeze.get('config_sha256') != digest(config_raw)
            or freeze.get('launch_authorization_sha256') != digest(canonical(launch_authorization))
            or freeze.get('candidate_commit') != config.get('candidate_commit')
            or freeze.get('candidate_tree') != config.get('candidate_tree')
            or freeze.get('campaign_attempt_id') != config.get('campaign_attempt_id')):
        raise FrameworkError('DEFINITION_E1_BOUND_OWNER_LAUNCH_AND_FREEZE_REQUIRED')
    campaign = load_config(args.config, args.config_root, args.output, args.trusted_root, args.output_root)
    cfg = campaign.config
    roots = [Path(r) for r in cfg['allowlisted_roots']]
    bindings = {r['path']: r['sha256'] for r in cfg['input_bindings']}
    admission_path = str(Path(args.admission).resolve(strict=True))
    if admission_path not in bindings:
        raise FrameworkError('DEFINITION_E1_ADMISSION_NOT_FROZEN')
    _, admission_raw = _read_bound_file(admission_path, bindings[admission_path], roots, 'admission metadata')
    admission = _loads(admission_raw)
    _, dataset_raw = _read_bound_file(cfg['dataset_manifest_path'], cfg['input_manifest_sha256'], roots, 'dataset metadata')
    units = _loads(dataset_raw)['units']
    gate = validate_admission(cfg, admission, units)
    protected = admission.get('protected_roots')
    if not isinstance(protected, list) or not protected:
        raise FrameworkError('DEFINITION_E1_PROTECTED_ROOTS_REQUIRED')
    allowed_sources = [u['source_path'] for u in units]
    guard = install_read_scope(protected, allowed_sources)
    body_bindings = [r for r in cfg['input_bindings'] if r['path'] != admission_path]
    permitted = {(r['path'], r['sha256']) for r in admission.get('allowed_read_references', [])}
    if permitted != {(r['path'], r['sha256']) for r in body_bindings}:
        raise FrameworkError('DEFINITION_E1_COMPLETE_READ_SET_MISMATCH')
    source_manifest_read_gate(admission, body_bindings, cfg['audit_policy']['generic_caller'], roots)
    # The hook is active before selected primary bodies can be rehashed.
    campaign.preflight()
    validate_configuration(campaign)
    if args.action == 'recover':
        return {'status': 'RECOVERED_READ_ONLY', 'pid': os.getpid(), 'redispatch': 0,
                'state': _serial(campaign.recover()), 'denied_reads': list(guard.denied_events)}
    if campaign.output.exists():
        raise FrameworkError('DEFINITION_E1_EXISTING_ATTEMPT_NO_REDISPATCH')
    probe = admission['denied_probe_path']
    if str(Path(probe).resolve()) in {str(Path(p).resolve()) for p in allowed_sources}:
        raise FrameworkError('DEFINITION_E1_PROBE_MUST_BE_UNSELECTED')
    controls = []
    for kind in ('path_read', 'os_open', 'read_write'):
        try:
            if kind == 'path_read':
                Path(probe).read_bytes()
            elif kind == 'os_open':
                fd = os.open(probe, os.O_RDONLY)
                os.close(fd)
            else:
                with open(probe, 'r+b'):
                    pass
        except PermissionError:
            controls.append({'kind': kind, 'status': 'DENIED_BEFORE_BODY_READ', 'source_kind': 'UNSELECTED_PATH_DENIAL_CONTROL'})
        else:
            raise FrameworkError('DEFINITION_E1_UNSELECTED_READ_NOT_DENIED')
    if len(guard.denied_events) != 3:
        raise FrameworkError('DEFINITION_E1_DENIAL_EVENT_MISMATCH')
    context = campaign.output.parent / (cfg['campaign_attempt_id'] + '-context')
    if context.exists():
        raise FrameworkError('DEFINITION_E1_EXISTING_ENGINE_NO_REDISPATCH')
    engine = Engine(context)
    engine_guard = ResourceGuard(context, max_bytes=16 * 1024**2)
    events = []
    producer = f"PGOP1-{cfg['run_id']}-E1"

    def auditor(unit, _adapted):
        result = build_audit_payload(unit)
        events.append(record_engine_result(engine, engine_guard, unit, result, cfg['run_id'],
            producer_id=producer, event_kind=cfg['run_id'] + '_DEFINITION_RESULT'))
        return result

    adapters = {(u['adapter_id'], u['adapter_version']): process_definition for u in units}
    caller = GenericCaller(campaign, adapters, auditor, producer_id=producer)
    started = time.monotonic()
    operations, batches = execute_batches(campaign, caller, units)
    state = campaign.recover()
    if len(guard.denied_events) != 3:
        raise FrameworkError('DEFINITION_E1_UNEXPECTED_SOURCE_READ_DENIAL')
    return {'status': 'DEFINITIONS_PROCESSED_WITH_EXACT_LIMITATIONS', 'pid': os.getpid(),
        'admission': gate, 'operations': operations, 'batch_observations': batches, 'state': _serial(state),
        'engine_events': events, 'engine_verify': engine.verify(), 'resources': campaign.resources_report(),
        'duration_seconds': time.monotonic() - started, 'denial_controls': controls,
        'denied_reads': list(guard.denied_events), 'semantic_audits': 0, 'structural_output_audits': 0,
        'guard_scope': 'Current trusted Python process only; not independent sandbox, native isolation or descendant coverage'}
