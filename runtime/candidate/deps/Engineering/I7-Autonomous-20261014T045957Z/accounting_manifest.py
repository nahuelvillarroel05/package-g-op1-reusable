"""Bind prospective serialized JUnit leaves to exact synthetic receipt output.

Pure data validation; no source discovery, path reads or producer execution.
Receipt consistency never authenticates a producer or historical ancestry.
"""
import hashlib
from junit.junit_accounting import analyze_junit
from mechanical.process_receipts import validate_receipt


def build_manifest(xml_bytes, policy, receipt, outputs, xml_output_id):
    """Return exact physical leaf accounting and declared output binding.

    Count mismatches remain visible evidence. They neither reject the manifest
    nor manufacture leaves. Complete accounting and execution success are
    independent results, with no qualification credit attached to either.
    """
    reconciliation = validate_receipt(receipt, outputs)
    if type(xml_output_id) is not str or xml_output_id not in outputs:
        raise ValueError('XML output ID missing from validated outputs')
    if type(xml_bytes) is not bytes or outputs[xml_output_id] != xml_bytes:
        raise ValueError('XML bytes do not match bound receipt output')
    accounting = analyze_junit(xml_bytes, policy)
    event = next(event for event in receipt['events']
                 if event['kind'] == 'OUTPUT' and event['output_id'] == xml_output_id)
    return {
        'schema': 'I7_PROSPECTIVE_JUNIT_LEAF_MANIFEST_V1',
        'xml_sha256': hashlib.sha256(xml_bytes).hexdigest(),
        'xml_bytes': len(xml_bytes), 'policy': policy,
        'leaf_records': accounting['testcase_records'],
        'physical_counts': accounting['serialized_physical'],
        'accounting': accounting['aggregate'],
        'status': accounting['status'],
        'complete_accounting': accounting['status'] == 'PASS',
        'execution_success': reconciliation['execution_success'],
        'output_binding': {
            'run_id': receipt['run_id'], 'output_id': xml_output_id,
            'event_id': event['id'], 'invocation_id': event['invocation_id'],
            'declared_actor_id': event['actor_id'],
            'declared_process_instance': dict(event['process_instance'])},
        'binding_evidence': 'DECLARED_SYNTHETIC_RECEIPT_CONSISTENCY',
        'ownership': 'NOT_PROVEN', 'independent_custody': 'NOT_PROVEN',
        'historical_producer': 'UNKNOWN', 'historical_ancestry': 'UNKNOWN',
        'historical_causation': 'UNKNOWN', 'native_qualification': False}
