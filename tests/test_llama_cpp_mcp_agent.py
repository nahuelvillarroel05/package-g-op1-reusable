# SPDX-License-Identifier: Apache-2.0
"""Import and CLI checks for the relocated client; no model/server is started."""
import importlib.util
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'agent_clients' / 'llama_cpp_mcp_agent.py'


def test_client_import_and_endpoint_root():
    spec = importlib.util.spec_from_file_location('llama_cpp_mcp_agent', CLIENT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._api_root('http://127.0.0.1:8080/v1') == 'http://127.0.0.1:8080'


def test_client_help_without_model():
    result = subprocess.run([sys.executable, '-B', str(CLIENT), '--help'],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert '--endpoint' in result.stdout
    assert '--model' in result.stdout
    assert '--workspace-id' in result.stdout
