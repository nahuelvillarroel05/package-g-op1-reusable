# SPDX-License-Identifier: Apache-2.0
"""Reproduce the existing API's synthetic public pipeline in a fresh workspace."""
from pathlib import Path
import json
import sys
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from candidate import i7_api

workspace = ROOT / 'runtime' / 'campaigns' / ('api-example-' + uuid4().hex)
i7_api.initialize_workspace(workspace_dir=str(workspace))
registry = i7_api.inspect(workspace_dir=str(workspace))
selection = workspace / 'runs' / 'public-selection.json'
i7_api.prepare_document_selection(
    workspace_dir=str(workspace), policy_id='package-fixtures',
    relative_paths=['sample.md', 'sample.json'], selection_id='public-synthetic',
    output_path=str(selection))
i7_api.validate_document_selection(workspace_dir=str(workspace), selection_manifest=str(selection))
result = i7_api.run_pipeline(workspace_dir=str(workspace), selection_manifest=str(selection),
                             data_digest=True, causal_data=True, provenance=True,
                             provenance_mode='prospective')
run = result['stage_b']['run_dir']
checks = {
    'verify': i7_api.verify(workspace_dir=str(workspace), from_run=run),
    'query': i7_api.query(workspace_dir=str(workspace), from_run=run, kind='i4_semantic_graph_identity'),
    'graph': i7_api.get_graph(workspace_dir=str(workspace), from_run=run),
    'provenance': i7_api.get_provenance(workspace_dir=str(workspace), from_run=run),
    'recover': i7_api.recover(workspace_dir=str(workspace), from_run=run),
}
assert checks['verify']['status'] == 'PASS', checks['verify']
assert checks['query']['status'] == 'PASS', checks['query']
assert checks['recover']['status'] == 'PASS', checks['recover']
print(json.dumps({'status': 'PASS', 'workspace': str(workspace), 'run_dir': run,
                  'checks': sorted(checks), 'I7_STATUS': 'INCOMPLETE'}, sort_keys=True))
