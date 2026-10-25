"""Request-bound Engineering preflight. No real-original loader or dispatcher.

Trusted policy is caller-retained synthetic test intent, never native authority.
Real operations are always denied pending a source-authored operational contract.
"""
import json
from pathlib import Path
import sys

BASE = Path(__file__).resolve().parent.parent / 'I7-Integration-20261014T1430Z'

import hashlib
DEPENDENCY_PINS = {
  "durable_registry.py": "da256b77ebd5058f14ff93748edb2641c728dcadb8e920562fb235e1b4cf7dbd",
  "integration.py": "56e44d13a98c4941293a7e0ddfb8edcf94e2b2ecda32180b36f0ffc0788ae9a2",
  "loader.py": "475ff6906b2a3739e6d893618e27e28df0b03dbfb742b36ef1200c8b865e4e1e"
}
for _name, _pin in DEPENDENCY_PINS.items():
    if hashlib.sha256((BASE / _name).read_bytes()).hexdigest() != _pin:
        raise ValueError("accepted integration dependency drift: " + _name)
sys.path.insert(0, str(BASE))
import integration as api
from durable_registry import DurableRegistry


def synthetic_intent(request, run_dir, journal, actor='CURRENT_CODEX', tool='DIRECT_ENGINEERING'):
    """Engineering-only fixture, not an operational grant/claim/dispatch."""
    sources = api.source_pins()
    return {
        'schema': 'I7_SYNTHETIC_ADMISSION_INTENT_V1',
        'mode': 'SYNTHETIC', 'classification': 'PROSPECTIVE_DESIGN',
        'request_sha256': api.sha(api.canonical(request)),
        'actor': actor, 'tool': tool,
        'relationship': {'provider_id': request['stdout_provider_id'],
                         'output_id': 'stdout', 'consumer_id': request['execution_provider_id'],
                         'consumer_input': 'junit', 'output_schema': 'synthetic.junit.v1',
                         'consumer_schema': 'synthetic.junit.v1'},
        'sources': sources,
        'source_classifications': {key: 'AUTHORIZED_SYNTHETIC_ENGINEERING' for key in sources},
        'read_scope': {'actor': actor, 'tool': tool, 'sources': sources,
                       'request_sha256': api.sha(api.canonical(request))},
        'execution_scope': {'actor': actor, 'tool': tool,
                            'request_sha256': api.sha(api.canonical(request)),
                            'runner_pin': request['runner_pin'], 'provider': 'fixed-probe'},
        'run_dir': str(Path(run_dir).resolve()), 'journal': str(Path(journal).resolve()),
        'allowed_outputs': ['request.json', 'started.json', 'evidence.json', 'result.json', 'metrics.json', 'failure.json'],
        'limits': {'timeout_seconds': request['timeout'], 'stream_bytes': 4096,
                   'child_processes': 1, 'network': False, 'native': False},
        'evidence_capture': 'ACCEPTED_SEVEN_COMPONENT_PIPELINE',
        'review': 'SYNTHETIC_ONLY_NO_INDEPENDENT_CUSTODY_CLAIM'}


def assess(request, intent, trusted_intent):
    """Fail closed before fixed-probe execution; never opens original bodies.

    Equality to caller-retained intent is required but conveys no authenticity.
    Existing registry is inspected, never initialized or reset by this gate.
    """
    reasons = []
    try:
        if type(intent) is not dict or intent.get('mode') != 'SYNTHETIC':
            raise ValueError('REAL_OPERATION_NOT_IMPLEMENTED_OR_AUTHORIZED')
        if type(trusted_intent) is not dict or intent != trusted_intent:
            raise ValueError('CALLER_RETAINED_INTENT_MISMATCH')
        if type(intent.get('actor')) is not str or not intent['actor'] or type(intent.get('tool')) is not str or not intent['tool']:
            raise ValueError('EXACT_ACTOR_TOOL_REQUIRED')
        expected = synthetic_intent(request, intent['run_dir'], intent['journal'], intent['actor'], intent['tool'])
        if intent != expected:
            raise ValueError('MISSING_OR_INCONSISTENT_ADMISSION_REQUIREMENT')
        api._request(request)  # accepted ROOT_V2, exact bytes, schema, fixed body and bounds
        directory = Path(intent['run_dir'])
        journal = Path(intent['journal'])
        campaign = Path(__file__).resolve().parent
        if directory.parent.resolve() != campaign or journal.parent.resolve() != campaign:
            raise ValueError('EXACT_CAMPAIGN_DESTINATION_REQUIRED')
        if directory.exists() or directory.is_symlink() or journal.is_symlink():
            raise ValueError('FRESH_NONLINK_DESTINATION_REQUIRED')
        state = DurableRegistry(journal).snapshot()  # fail closed on missing/corrupt/locked history
        if type(state) is not dict:
            raise ValueError('REPLAY_REVOCATION_STATE_UNAVAILABLE')
    except (ValueError, TypeError, KeyError, OSError) as error:
        reasons.append(str(error))
    return {'schema': 'I7_PREFLIGHT_RESULT_V1', 'decision': 'DENY' if reasons else 'ALLOW_FIXED_SYNTHETIC_ONLY',
            'reasons': reasons, 'classification': 'SYNTHETIC_OBSERVATION',
            'real_execution_authorized': False, 'independent_custody': 'NOT_PROVEN',
            'grant_issued': False, 'claim_issued': False, 'dispatch_issued': False}


def execute_synthetic(request, intent, trusted_intent):
    decision = assess(request, intent, trusted_intent)
    if decision['decision'] != 'ALLOW_FIXED_SYNTHETIC_ONLY':
        raise ValueError(json.dumps(decision, sort_keys=True))
    return api.execute_cycle(intent['run_dir'], request, DurableRegistry(intent['journal']))
