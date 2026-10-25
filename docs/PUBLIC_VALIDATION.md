# Public validation scope

The [Windows Python 3.14 workflow](../.github/workflows/public-ci.yml) runs from a clean GitHub checkout with only public pinned dependencies. It has `contents: read`, does not persist checkout credentials, uses action commit pins, and requests no repository secrets. Pull requests use `pull_request`, never `pull_request_target`. Fork code receives no write token or deployment credential. No models or private sources are installed.

Use a fresh disposable checkout and isolated environment as described in [the demo](PUBLIC_DEMO.md). Exact checks, from its root with the venv activated:

| Command | Observable check |
| --- | --- |
| `python -m pip check` | Installed dependency compatibility |
| `python -B tools/verify_public_tree.py` | Exact Git-tracked membership, sizes and SHA-256 |
| `python -B -c "import pg_i7_mcp.server; from runtime.candidate import i7_api; from agent_clients import llama_cpp_mcp_agent; print('IMPORTS_OK')"` | Public runtime/MCP/client imports |
| `python -B runtime/candidate/pg_i7.py --help` | CLI entry point |
| `python -B -m pytest -p no:cacheprovider -q tests/test_llama_cpp_mcp_agent.py tests/test_public_tree_verifier.py` | Relocated client import/CLI and rejection of changed bytes, missing members, extra tracked members and duplicate manifest entries |
| `python -B runtime/candidate/pg_i7.py demo --workspace-dir demo-001 --data-digest --causal-data --provenance --provenance-mode prospective --json` | Existing synthetic CLI path, fresh workspace only |
| `python -B examples/api_synthetic_pipeline.py` | API pipeline, verify, query, graph, prospective provenance and recovery |
| `python -B tests/smoke_stdio.py` | Real MCP transport, public demo, recovery invariants and negative inputs |
| `python -B tests/test_run_ref_boundaries.py` | Identifier lengths and path scope |
| `python -B tests/test_public_boundaries.py` | Private-policy refusal and unavailable original fixture provenance refusal |

Run the selected core in a separate process, with a short fresh temporary path:

```powershell
$env:PYTHONPATH = 'src'
python -B -m pytest -p no:cacheprovider --basetemp C:\pg-tests-unique -q tests/unit
Remove-Item Env:PYTHONPATH
```

`src` must not remain on the MCP process's `PYTHONPATH`: the runtime has a separate pinned I4/I5 dependency closure. Use a fresh basetemp; pytest may clear a pre-existing basetemp. Keep it short because inherited storage contracts enforce a 239 UTF-16-unit path bound. CI uses a unique short path for the core tests. The tests redirect synthetic home fixtures to that location. NTFS/reparse tests use disposable files; they do not run the original protected I3 runtime.

The original [publication results](../manifests/PUBLIC_SOURCE_TEST_RESULTS.json) remain historical and unchanged. New results must be tied to the tested commit and actual [GitHub Actions run](https://github.com/nahuelvillarroel05/package-g-op1-reusable/actions). A badge, workflow file or historical PASS is not evidence that a new commit passed. Failed CI attempts remain visible.

Manifest updates are derivative maintenance: stage only reviewed public files, run `python -B tools/verify_public_tree.py --write`, then review the resulting diff and verify without `--write`. The original baseline identity remains recorded; no update replaces the original commit or tag. The tree manifest excludes itself, and the outer Git commit binds it.

Original native campaigns, private corpus, independent operational custody, original model benchmarks, OD05, E30 and Formal I7 remain outside these tests. Read [the original validation scope](VALIDATION_EVIDENCE.md), [limitations](LIMITATIONS.md) and [roadmap](ROADMAP.md). I7_STATUS=INCOMPLETE.
