"""Shared evidence envelope and bridge to the existing I4/I5-NEXT Engine.

Task definitions are never promoted to observed executions or agent statements.
The envelope commits the original primary file bytes, without executing them.
"""
from __future__ import annotations

import base64
import hashlib
import re
import stat
import zipfile
from copy import deepcopy
from pathlib import Path, PurePosixPath

from runtime.candidate.context_engine import Engine, canonical_json, strict_json_loads

SCHEMA = 'pgop1.benchmark-evidence.v1'
FAMILIES = {'swebench', 'swebench_pro_v2', 'terminal_bench_2', 'mcpmark_verified', 'bfcl_v4', 'tau_bench'}
UNKNOWN = 'UNKNOWN'
LEVELS = {'E0': 'NOT_ESTABLISHED', 'E1': 'NOT_ESTABLISHED', 'E2': 'SOURCE_BYTES_VERIFIABLE_ONLY',
          'E3': 'NOT_ESTABLISHED', 'E4': 'NOT_QUALIFIED'}
VERSIONS = {'swebench': {'full', 'lite', 'verified', 'multilingual'}, 'swebench_pro_v2': {'V2'},
            'terminal_bench_2': {'2.0'}, 'bfcl_v4': {'V4'}, 'tau_bench': {'2.0.0:text-v1'}}


class EvidenceError(ValueError):
    pass


def safe_relative(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise EvidenceError('unsafe relative path')
    path = PurePosixPath(name)
    if path.is_absolute() or any(p in {'', '.', '..'} for p in name.split('/')):
        raise EvidenceError('unsafe relative path')
    return name


def validate_zip_members(path, *, max_bytes=200 * 1024 * 1024, max_members=10000):
    """Preflight untrusted ZIPs without extracting or executing any content."""
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > max_members or sum(member.file_size for member in members) > max_bytes:
            raise EvidenceError('archive expansion limit exceeded')
        seen = set()
        for member in members:
            name = safe_relative(member.filename.rstrip('/') if member.is_dir() else member.filename)
            if name.casefold() in seen:
                raise EvidenceError('duplicate archive path')
            seen.add(name.casefold())
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode) or member.flag_bits & 1:
                raise EvidenceError('link/encrypted archive member rejected')
            for component in name.split('/'):
                stem = component.split('.')[0].upper()
                if component.endswith((' ', '.')) or stem in {'CON', 'PRN', 'AUX', 'NUL', *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}:
                    raise EvidenceError('unsafe Windows archive path')
        return [member.filename for member in members]


def checked_path(path, allowed_roots):
    original = Path(path).absolute()
    for part in (original, *original.parents):
        if part.is_symlink() or getattr(part, 'is_junction', lambda: False)():
            raise EvidenceError('reparse source rejected')
    resolved = original.resolve(strict=True)
    if not any(resolved.is_relative_to(Path(root).resolve(strict=True)) for root in allowed_roots):
        raise EvidenceError('source outside explicit roots')
    return resolved


def checked_source(path, allowed_roots, expected_sha256):
    resolved = checked_path(path, allowed_roots)
    if not re.fullmatch('[0-9a-f]{64}', expected_sha256 or ''):
        raise EvidenceError('source commitment missing')
    if not resolved.is_file() or resolved.stat().st_size > 200 * 1024 * 1024:
        raise EvidenceError('source size/type unsupported')
    raw = resolved.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise EvidenceError('source hash differs')
    return resolved, raw


def parser_for(benchmark_id):
    from importlib import import_module
    module, function = {
        'swebench': ('software', 'parse_swebench'), 'swebench_pro_v2': ('software', 'parse_swebench_pro'),
        'terminal_bench_2': ('operations', 'parse_terminal_bench'), 'mcpmark_verified': ('operations', 'parse_mcpmark'),
        'bfcl_v4': ('calling', 'parse_bfcl'), 'tau_bench': ('calling', 'parse_tau'),
    }[benchmark_id]
    return getattr(import_module('.' + module, __package__), function)


def normalize(task, *, benchmark_id, version, revision, source_sha256, allowed_roots, source_commitments=None):
    if benchmark_id not in FAMILIES:
        raise EvidenceError('unsupported benchmark family')
    if not isinstance(version, str) or not version or not isinstance(revision, str) or not revision:
        raise EvidenceError('version/revision required; use UNKNOWN explicitly')
    if benchmark_id in VERSIONS and version not in VERSIONS[benchmark_id]:
        raise EvidenceError('unsupported benchmark version')
    if benchmark_id == 'mcpmark_verified' and version != 'Verified@' + revision[:12]:
        raise EvidenceError('unsupported Verified snapshot identity')
    if not isinstance(task, dict):
        raise EvidenceError('task must be an object')
    task_id = task.get('task_id')
    if not isinstance(task_id, str) or not task_id.strip() or len(task_id) > 256:
        raise EvidenceError('invalid task identity')
    if task.get('benchmark_id', benchmark_id) != benchmark_id:
        raise EvidenceError('mixed benchmark')
    if task.get('source_revision', revision) not in {revision, UNKNOWN}:
        raise EvidenceError('incompatible revision')
    path, raw = checked_source(task['source_path'], allowed_roots, source_sha256)
    matches = [item for item in parser_for(benchmark_id)(path) if item.get('task_id') == task_id]
    if len(matches) != 1 or matches[0] != task:
        raise EvidenceError('task differs from parsed source')
    if path.read_bytes() != raw:
        raise EvidenceError('source changed while parsing')
    if benchmark_id == 'mcpmark_verified' and (task.get('metadata', {}).get('task_suite') != 'standard' or revision == UNKNOWN):
        raise EvidenceError('Verified requires a pinned standard-suite task')
    artifacts = []
    for artifact in task.get('metadata', {}).get('ancillary_artifacts', []):
        artifact_path = str(Path(artifact['path']).absolute())
        if source_commitments is not None and source_commitments.get(artifact_path) != artifact['sha256']:
            raise EvidenceError('ancillary artifact not committed by selection')
        resolved, artifact_bytes = checked_source(artifact_path, allowed_roots, artifact['sha256'])
        artifacts.append({'path': str(resolved), 'role': artifact['role'], 'sha256': artifact['sha256'],
                          'size_bytes': len(artifact_bytes), 'bytes_base64': base64.b64encode(artifact_bytes).decode('ascii')})
    return {
        'schema': SCHEMA, 'benchmark_id': benchmark_id, 'benchmark_version': version,
        'task_id': task_id, 'source_family_id': task.get('source_family_id', UNKNOWN),
        'source_sha256': source_sha256, 'source_revision': revision,
        'source': {'path': str(path), 'size_bytes': len(raw), 'bytes_base64': base64.b64encode(raw).decode('ascii'),
                   'pointer': task.get('source_pointer', UNKNOWN)},
        'task_definition': task,
        'source_artifacts': artifacts,
        'trajectory_id': UNKNOWN, 'agent_statement': UNKNOWN, 'agent_statement_provenance': UNKNOWN,
        'tool_call': UNKNOWN, 'tool_result': UNKNOWN, 'evaluator_result': UNKNOWN,
        'expected_state': UNKNOWN, 'observed_state': UNKNOWN,
        'artifact_references': task.get('artifact_references', []),
        'claim_predicate': UNKNOWN, 'claim_evidence': UNKNOWN,
        'evidence_comparability': 'TASK_DEFINITION_ONLY', 'audit_verdict': 'NOT_EVALUATED',
        'evidence_levels': dict(LEVELS),
        'usage': 'DEVELOPMENT_ONLY', 'evaluator_executed': False, 'gate11_eligible': False,
    }


def validate(envelope):
    if envelope.get('schema') != SCHEMA or envelope.get('benchmark_id') not in FAMILIES:
        raise EvidenceError('unsupported envelope')
    family, version, revision = envelope['benchmark_id'], envelope.get('benchmark_version'), envelope.get('source_revision')
    if family in VERSIONS and version not in VERSIONS[family]:
        raise EvidenceError('unsupported benchmark version')
    if not isinstance(revision, str) or (revision != UNKNOWN and not re.fullmatch('[0-9a-f]{40}', revision)):
        raise EvidenceError('malformed source revision')
    if family == 'mcpmark_verified' and version != 'Verified@' + revision[:12]:
        raise EvidenceError('unsupported Verified snapshot identity')
    source = envelope['source']
    try:
        raw = base64.b64decode(source['bytes_base64'], validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceError('invalid source encoding') from exc
    if len(raw) != source['size_bytes'] or hashlib.sha256(raw).hexdigest() != envelope['source_sha256']:
        raise EvidenceError('embedded source differs')
    for artifact in envelope.get('source_artifacts', []):
        artifact_raw = base64.b64decode(artifact['bytes_base64'], validate=True)
        if len(artifact_raw) != artifact['size_bytes'] or hashlib.sha256(artifact_raw).hexdigest() != artifact['sha256']:
            raise EvidenceError('embedded ancillary artifact differs')
    task = envelope['task_definition']
    if task.get('task_id') != envelope['task_id'] or task.get('source_path') != source['path']:
        raise EvidenceError('task/source association differs')
    if family == 'mcpmark_verified' and (task.get('metadata', {}).get('task_suite') != 'standard' or revision == UNKNOWN):
        raise EvidenceError('Verified requires a pinned standard-suite task')
    expected_artifacts = [(item['path'], item['role'], item['sha256']) for item in task.get('metadata', {}).get('ancillary_artifacts', [])]
    actual_artifacts = [(item['path'], item['role'], item['sha256']) for item in envelope.get('source_artifacts', [])]
    if expected_artifacts != actual_artifacts:
        raise EvidenceError('ancillary task association differs')
    for key in ('trajectory_id', 'agent_statement', 'agent_statement_provenance', 'tool_call', 'tool_result', 'evaluator_result', 'expected_state', 'observed_state', 'claim_predicate', 'claim_evidence'):
        if envelope.get(key) != UNKNOWN:
            raise EvidenceError('task-only contract forbids execution/claim evidence')
    if envelope.get('audit_verdict') != 'NOT_EVALUATED' or envelope.get('evaluator_executed') is not False or envelope.get('gate11_eligible') is not False:
        raise EvidenceError('unsupported evidence promotion')
    if envelope.get('evidence_levels') != LEVELS or envelope.get('usage') != 'DEVELOPMENT_ONLY' or envelope.get('evidence_comparability') != 'TASK_DEFINITION_ONLY':
        raise EvidenceError('unsupported diagnostic evidence level')
    return raw


def ingest(engine: Engine, envelope, *, allowed_roots=None, source_commitments=None, expected_identity=None):
    original_bytes = validate(envelope)
    if not allowed_roots or not isinstance(source_commitments, dict) or not isinstance(expected_identity, dict):
        raise EvidenceError('explicit admission roots, commitments and identity required')
    identity = {key: envelope[key] for key in ('benchmark_id', 'benchmark_version', 'task_id', 'source_revision', 'source_sha256')}
    if identity != expected_identity:
        raise EvidenceError('admission identity differs from selection')
    if source_commitments.get(envelope['source']['path']) != envelope['source_sha256']:
        raise EvidenceError('primary source not committed for admission')
    rebound = normalize(envelope['task_definition'], benchmark_id=identity['benchmark_id'],
                        version=identity['benchmark_version'], revision=identity['source_revision'],
                        source_sha256=identity['source_sha256'], allowed_roots=allowed_roots,
                        source_commitments=source_commitments)
    if canonical_json(rebound) != canonical_json(envelope):
        raise EvidenceError('envelope differs from source-derived normalization')
    raw = canonical_json(envelope)
    digest = hashlib.sha256(raw).hexdigest()
    inputs = engine.root / 'engineering-inputs'
    inputs.mkdir(exist_ok=True)
    original_path = inputs / (envelope['source_sha256'] + '.source')
    Engine._immutable(original_path, original_bytes)
    original_source = engine.admit_source(original_path, envelope['source_sha256'], 'ENGINEERING_RESULT',
                                          source_id='benchmark-source:' + envelope['source_sha256'])
    # Store large original files once in the existing Engine object store, rather
    # than repeating base64 data in every cumulative graph version.
    compact = deepcopy(envelope)
    compact['source'].pop('bytes_base64')
    compact['source']['engine_source_id'] = original_source['source_id']
    for artifact in compact.get('source_artifacts', []):
        artifact_bytes = base64.b64decode(artifact.pop('bytes_base64'), validate=True)
        artifact_path = inputs / (artifact['sha256'] + '.source')
        Engine._immutable(artifact_path, artifact_bytes)
        admitted = engine.admit_source(artifact_path, artifact['sha256'], 'ENGINEERING_RESULT',
                                       source_id='benchmark-source:' + artifact['sha256'])
        artifact['engine_source_id'] = admitted['source_id']
    stored_raw = canonical_json(compact)
    stored_digest = hashlib.sha256(stored_raw).hexdigest()
    path = inputs / (stored_digest + '.json')
    path.parent.mkdir(exist_ok=True)
    Engine._immutable(path, stored_raw)
    source = engine.admit_source(path, stored_digest, 'ENGINEERING_RESULT')
    identity = 'benchmark:' + digest
    task_key = envelope['benchmark_id'] + ':' + envelope['benchmark_version'] + ':' + envelope['task_id']
    observation = {'id': identity, 'task_id': task_key, 'kind': 'BENCHMARK_TASK_DEFINITION',
                   'source_id': source['source_id'], 'evidence_pointer': '', 'value': compact}
    # Association is derived from this envelope; it asserts no causal/execution fact.
    metadata = {'id': identity + ':source', 'task_id': task_key, 'kind': 'BENCHMARK_SOURCE_IDENTITY',
                'source_id': source['source_id'], 'evidence_pointer': '/source_sha256', 'value': envelope['source_sha256']}
    edge = {'id': identity + ':association', 'from': identity, 'to': metadata['id'],
            'relationship': 'DERIVED_ASSOCIATION', 'evidence_bindings': [{'source_id': source['source_id'], 'pointer': ''}]}
    engine.ingest([observation, metadata], [edge])
    return {'observation_id': identity, 'task_key': task_key, 'envelope_sha256': digest}


def recover(engine: Engine, receipt):
    rows = engine.query(identifier=receipt['observation_id'])
    rows = [row for row in rows if row['id'] == receipt['observation_id']]
    if len(rows) != 1 or rows[0]['task_id'] != receipt['task_key']:
        raise EvidenceError('exact task observation missing')
    row = rows[0]
    envelope = strict_json_loads(engine.read_source(row['evidence_binding']['source_id']))
    original_source_id = envelope['source'].pop('engine_source_id')
    if original_source_id != 'benchmark-source:' + envelope['source_sha256']:
        raise EvidenceError('original source identity differs')
    original_bytes = engine.read_source(original_source_id)
    envelope['source']['bytes_base64'] = base64.b64encode(original_bytes).decode('ascii')
    for artifact in envelope.get('source_artifacts', []):
        artifact_id = artifact.pop('engine_source_id')
        if artifact_id != 'benchmark-source:' + artifact['sha256']:
            raise EvidenceError('ancillary source identity differs')
        artifact['bytes_base64'] = base64.b64encode(engine.read_source(artifact_id)).decode('ascii')
    validate(envelope)
    if hashlib.sha256(canonical_json(envelope)).hexdigest() != receipt['envelope_sha256']:
        raise EvidenceError('recovered envelope differs')
    return envelope
