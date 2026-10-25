"""Prospective synthetic Engineering composition. No native admission authority.

Trusted requests and evidence hashes must be retained outside the evidence
directory by the caller. Hashes establish consistency, not independent custody.
"""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import sys
import time

from loader import MODULES, SOURCE_READS, source_pins

probe_module = MODULES['mechanical.synthetic_probe']
binding_module = MODULES['binding.operational_bindings']
ReceiptRegistry = MODULES['security.receipt_registry'].ReceiptRegistry
verify_pipeline = MODULES['synthetic_pipeline'].verify_pipeline
DEFAULT_XML = b'<testsuite name="synthetic" tests="1" failures="0" errors="0" skipped="0"><testcase classname="engineering" name="fixed_probe"/></testsuite>'
_RUNNER_PIN = None

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

def sha(body):
    return hashlib.sha256(body).hexdigest()

def _write(path, value):
    with path.open('xb') as stream:
        stream.write(canonical(value))

def make_request(xml_bytes=None, *, role_count=2, exit_code=0, timeout=5.0):
    """Build an explicitly synthetic ROOT_V2 declaration, including 19-role joins.

    Additional roles are declaration-only synthetic fixtures; they are not
    executed providers and confer no historical all19 closure.
    """
    if type(role_count) is not int or not 2 <= role_count <= 19:
        raise ValueError('role_count requires integer 2..19')
    xml = DEFAULT_XML if xml_bytes is None else xml_bytes
    if type(xml) is not bytes:
        raise ValueError('XML bytes required')
    providers = {'fixed-probe': probe_module._PROBE_CODE.encode('ascii'), 'junit-data': xml}
    roles = []
    for i, (provider, body) in enumerate(providers.items()):
        roles.append({'role': 'runner' if i == 0 else 'data', 'provider_id': provider,
                      'source_id': 'source025', 'sha256': sha(body),
                      'inputs': {'junit': 'synthetic.junit.v1'} if i == 0 else {},
                      'outputs': {'junit': 'synthetic.junit.v1'} if i == 1 else {}})
    links = [{'provider_role': 'data', 'output': 'junit', 'consumer_role': 'runner', 'input': 'junit'}]
    for i in range(2, role_count):
        provider, role = 'fixture-' + str(i), 'fixture-role-' + str(i)
        providers[provider] = ('synthetic declaration fixture ' + str(i)).encode('ascii')
        roles.append({'role': role, 'provider_id': provider, 'source_id': 'source025',
                      'sha256': sha(providers[provider]), 'inputs': {'junit': 'synthetic.junit.v1'}, 'outputs': {}})
        links.append({'provider_role': 'data', 'output': 'junit', 'consumer_role': role, 'input': 'junit'})
    contract = {'schema': 'ROOT_V2', 'roles': roles, 'links': links}
    global _RUNNER_PIN
    if _RUNNER_PIN is None:
        _RUNNER_PIN = {'executable': sys.executable, 'executable_sha256': sha(Path(sys.executable).read_bytes()),
                       'python_version': platform.python_version()}
    return {'schema': 'I7_INTEGRATED_SYNTHETIC_REQUEST_V1', 'contract': contract,
            'observed': {'schema': 'ROOT_V2', 'roles': copy.deepcopy(roles)},
            'providers_hex': {key: value.hex() for key, value in providers.items()},
            'execution_provider_id': 'fixed-probe', 'stdout_provider_id': 'junit-data',
            'stderr_hex': '', 'policy': 'ROOT_SUITES', 'exit_code': exit_code, 'timeout': timeout,
            'runner_pin': dict(_RUNNER_PIN)}

def _decode(mapping):
    if type(mapping) is not dict or any(type(k) is not str or type(v) is not str for k, v in mapping.items()):
        raise ValueError('exact hex byte mapping required')
    result = {key: bytes.fromhex(value) for key, value in mapping.items()}
    if any(result[key].hex() != value for key, value in mapping.items()):
        raise ValueError('canonical lowercase hex required')
    return result

def _request(request):
    fields = {'schema', 'contract', 'observed', 'providers_hex', 'execution_provider_id', 'stdout_provider_id', 'stderr_hex', 'policy', 'exit_code', 'timeout', 'runner_pin'}
    if type(request) is not dict or set(request) != fields or request['schema'] != 'I7_INTEGRATED_SYNTHETIC_REQUEST_V1':
        raise ValueError('exact synthetic request fields required')
    providers = _decode(request['providers_hex'])
    pin = request['runner_pin']
    if type(pin) is not dict or set(pin) != {'executable', 'executable_sha256', 'python_version'} or any(type(v) is not str or not v for v in pin.values()):
        raise ValueError('trusted runner identity required')
    binding_module.validate_provider_bytes(request['contract'], request['observed'], providers)
    if providers.get(request['execution_provider_id']) != probe_module._PROBE_CODE.encode('ascii'):
        raise ValueError('only accepted fixed synthetic probe code authorized')
    if request['stdout_provider_id'] not in providers:
        raise ValueError('stdout provider absent')
    roles = {r['provider_id']: r for r in request['contract']['roles']}
    runner, data = roles[request['execution_provider_id']], roles[request['stdout_provider_id']]
    required = {'provider_role': data['role'], 'output': 'junit', 'consumer_role': runner['role'], 'input': 'junit'}
    if required not in request['contract']['links'] or runner['inputs'].get('junit') != 'synthetic.junit.v1' or data['outputs'].get('junit') != 'synthetic.junit.v1':
        raise ValueError('exact execution/data provider relationship required')
    stdout = providers[request['stdout_provider_id']]
    stderr = _decode({'stderr': request['stderr_hex']})['stderr']
    if any(len(body) > 4096 or not body.isascii() for body in (stdout, stderr)):
        raise ValueError('bounded ASCII synthetic streams required')
    if type(request['exit_code']) is not int or not 0 <= request['exit_code'] <= 255:
        raise ValueError('exit code requires integer 0..255')
    timeout = request['timeout']
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10:
        raise ValueError('bounded finite timeout required')
    if request['policy'] not in MODULES['junit.junit_accounting'].POLICIES:
        raise ValueError('unsupported accounting policy')
    return providers, stdout, stderr

def _reconcile(request, evidence, registry):
    providers, stdout, stderr = _request(request)
    if set(evidence) != {'schema', 'request_sha256', 'sources', 'probe', 'outputs_hex', 'runner'} or evidence['schema'] != 'I7_INTEGRATED_EVIDENCE_V1':
        raise ValueError('exact evidence fields required')
    if evidence['request_sha256'] != sha(canonical(request)) or evidence['sources'] != source_pins():
        raise ValueError('trusted request/source identity mismatch')
    outputs = _decode(evidence['outputs_hex'])
    probe = evidence['probe']
    receipt, observation = probe['receipt'], probe['observations']
    if set(outputs) != {'stdout', 'stderr'} or len(receipt['invocations']) != 1:
        raise ValueError('exact synthetic streams/invocation required')
    invocation = receipt['invocations'][0]
    runner = evidence['runner']
    if {key: runner.get(key) for key in request['runner_pin']} != request['runner_pin']:
        raise ValueError('runner differs from trusted runner pin')
    argv = [runner['executable'], '-I', '-B', '-c', probe_module._PROBE_CODE, stdout.hex(), stderr.hex(), str(request['exit_code'])]
    if invocation['command'] != json.dumps(argv, ensure_ascii=True, separators=(',', ':')):
        raise ValueError('invocation is not bound to exact admitted source bytes')
    if runner['child_pid'] != observation['pid'] or observation['pid'] != invocation['process_instance']['pid'] or runner['relationship'] != 'LOCAL_DIRECT_POPEN_OBSERVATION':
        raise ValueError('local parent/child PID mismatch')
    if type(runner['parent_pid']) is not int or runner['parent_pid'] <= 0 or runner['parent_pid'] == runner['child_pid']:
        raise ValueError('invalid runner parent PID')
    exit_events = [e for e in receipt['events'] if e['kind'] == 'EXIT']
    if len(exit_events) != 1 or type(observation['timed_out']) is not bool or observation['exit_observed'] is not True or observation['exit_code'] != exit_events[0]['exit_code']:
        raise ValueError('termination observation mismatch')
    if type(observation['elapsed_monotonic_seconds']) not in (int,float) or not math.isfinite(observation['elapsed_monotonic_seconds']) or observation['elapsed_monotonic_seconds'] < 0:
        raise ValueError('invalid process timing')
    expected = outputs == {'stdout': stdout, 'stderr': stderr} and observation['exit_code'] == request['exit_code']
    success = expected and not observation['timed_out'] and observation['exit_code'] == 0
    status = 'TIMEOUT' if observation['timed_out'] else 'EXITED_ZERO' if observation['exit_code'] == 0 else 'EXITED_NONZERO'
    if probe['expectations_met'] != expected or probe['probe_success'] != success or probe['execution_success'] != (not observation['timed_out'] and observation['exit_code'] == 0) or probe['probe_status'] != status:
        raise ValueError('probe status inconsistent with measured outputs/termination')
    if probe['validation'] != MODULES['mechanical.process_receipts'].validate_receipt(receipt, outputs):
        raise ValueError('stored receipt validation inconsistent')
    reconciled = verify_pipeline(outputs['stdout'], request['policy'], receipt, outputs, 'stdout', request['contract'], request['observed'], providers, registry)
    accepted = reconciled['execution_contract_pass'] and success
    return {'schema': 'I7_INTEGRATED_RESULT_V1', 'status': 'PASS' if accepted else 'FAIL',
            'accepted': accepted, 'request_sha256': evidence['request_sha256'],
            'evidence_sha256': sha(canonical(evidence)), 'sources': evidence['sources'],
            'pipeline': reconciled, 'probe_success': success, 'scope': 'PROSPECTIVE_SYNTHETIC_ENGINEERING_ONLY',
            'process_ownership': 'NOT_PROVEN', 'independent_custody': 'NOT_PROVEN',
            'formal_i7': False, 'physical_c2': False, 'native_qualification_credit': 0}

def execute_cycle(run_dir, request, registry=None):
    """Execute one fresh local synthetic cycle; never resume/overwrite a run.

    The supplied registry owns replay/revocation continuity. Default registries
    are isolated in-memory scopes; they provide no cross-process persistence.
    """
    directory = Path(run_dir)
    directory.mkdir(parents=False, exist_ok=False)
    started = time.perf_counter()
    try:
        request = json.loads(canonical(request))
        _write(directory / 'request.json', request)
        _write(directory / 'started.json', {'state': 'STARTED_NO_RESUME', 'request_sha256': sha(canonical(request))})
        validate_start = time.perf_counter()
        providers, stdout, stderr = _request(request)
        validation_seconds = time.perf_counter() - validate_start
        parent_pid = os.getpid()
        executable = Path(sys.executable)
        runner = {'parent_pid': parent_pid, 'executable': str(executable), 'executable_sha256': sha(executable.read_bytes()),
                  'python_version': platform.python_version(), 'relationship': 'LOCAL_DIRECT_POPEN_OBSERVATION'}
        if {key: runner[key] for key in request['runner_pin']} != request['runner_pin']:
            raise ValueError('current runner does not match trusted runner pin')
        probe = probe_module.record_synthetic_probe(stdout, stderr, exit_code=request['exit_code'], timeout=request['timeout'])
        outputs = probe.pop('outputs')
        runner['child_pid'] = probe['observations']['pid']
        evidence = {'schema': 'I7_INTEGRATED_EVIDENCE_V1', 'request_sha256': sha(canonical(request)),
                    'sources': source_pins(), 'probe': probe, 'outputs_hex': {k:v.hex() for k,v in outputs.items()}, 'runner': runner}
        evidence_start = time.perf_counter()
        _write(directory / 'evidence.json', evidence)
        evidence_seconds = time.perf_counter() - evidence_start
        reconcile_start = time.perf_counter()
        result = _reconcile(request, evidence, registry if registry is not None else ReceiptRegistry())
        reconcile_seconds = time.perf_counter() - reconcile_start
        _write(directory / 'result.json', result)
        _write(directory / 'metrics.json', {'total_seconds': time.perf_counter()-started,
               'binding_validation_seconds': validation_seconds, 'reconciliation_including_junit_seconds': reconcile_seconds,
               'evidence_generation_seconds': evidence_seconds, 'process_seconds': probe['observations']['elapsed_monotonic_seconds'],
               'baseline_source_reads': len(SOURCE_READS), 'baseline_source_repeated_reads': 0,
               'baseline_source_bytes': sum(row['bytes'] for row in SOURCE_READS),
               'artifact_bytes_before_metrics': sum(p.stat().st_size for p in directory.iterdir()),
               'memory_consumption': 'NOT_MEASURED', 'token_usage': 'NOT_OBSERVABLE'})
        return result
    except BaseException as error:
        _write(directory / 'failure.json', {'state': 'FAILED_NO_RESUME', 'error_type': type(error).__name__, 'error': str(error), 'operational_success': False})
        raise

def verify_evidence(run_dir, trusted_request, trusted_sources, registry=None):
    """Recompute from portable stored bytes; no process is executed.

    External caller must trust request/source pins; a forged entire observation
    set is outside self-consistency verification. Persistent registry continuity
    must likewise be supplied by the caller.
    """
    directory = Path(run_dir)
    if trusted_sources != source_pins():
        raise ValueError('trusted baseline source pins mismatch')
    if (directory / 'failure.json').exists():
        raise ValueError('failed/interrupted operation cannot be accepted')
    request = json.loads((directory / 'request.json').read_bytes())
    if canonical(request) != canonical(trusted_request):
        raise ValueError('stored request differs from trusted request')
    evidence = json.loads((directory / 'evidence.json').read_bytes())
    stored = json.loads((directory / 'result.json').read_bytes())
    result = _reconcile(trusted_request, evidence, ReceiptRegistry())
    if canonical(result) != canonical(stored):
        raise ValueError('stored result differs from recomputed evidence')
    if registry is not None:
        registry.admit(evidence['probe']['receipt'], _decode(evidence['outputs_hex']))
    return result
