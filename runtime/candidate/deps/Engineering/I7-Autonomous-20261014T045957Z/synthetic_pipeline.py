"""Compose exact byte bindings, JUnit accounting and local replay protection.

Pure validation of supplied synthetic evidence; it executes or reads nothing.
Contract consistency is local Engineering evidence, never native admission.
"""
from accounting_manifest import build_manifest
from binding.operational_bindings import validate_provider_bytes


def verify_pipeline(xml_bytes, policy, receipt, outputs, output_id,
                    contract, observed, provider_bytes, registry):
    """Check dependencies before recording the validated receipt once.

    Invalid bindings or malformed XML consume no registry identifiers. Count
    mismatches and failed executions are still retained as valid receipt
    evidence, with execution_contract_pass false. The registry is caller-owned.
    """
    binding = validate_provider_bytes(contract, observed, provider_bytes)
    manifest = build_manifest(xml_bytes, policy, receipt, outputs, output_id)
    registered = registry.admit(receipt, outputs)
    return {
        'schema': 'I7_SYNTHETIC_PIPELINE_RECONCILIATION_V1',
        'binding': binding, 'manifest': manifest, 'registry_entry': registered,
        'execution_contract_pass': manifest['complete_accounting'] and manifest['execution_success'],
        'scope': 'PROSPECTIVE_SYNTHETIC_ENGINEERING_ONLY',
        'process_ownership': 'NOT_PROVEN', 'independent_custody': 'NOT_PROVEN',
        'historical_producer': 'UNKNOWN', 'historical_ancestry': 'UNKNOWN',
        'native_qualification_credit': 0, 'formal_i7': False, 'physical_c2': False}
