# Package-G OP1 Reusable

Package-G OP1 Reusable is an ongoing open-source engineering project.

**I7 INCOMPLETE — FORMAL QUALIFICATION PENDING.**

I7 is incomplete and has not passed formal operational qualification.

This repository publishes implemented components and verified engineering results. It does not represent a completed or production-qualified system.

```text
PROJECT_STATUS=WORK_IN_PROGRESS
I7_STATUS=INCOMPLETE
I7_ENGINEERING_COMPONENTS=PARTIALLY_VALIDATED
I7_FORMAL_QUALIFICATION=NOT_COMPLETED
FORMAL_I7=NOT_COMPLETED
OPERATIONAL_QUALIFICATION=NOT_ACHIEVED
I1_OPERATIONAL_CUSTODY=NOT_PROVEN
MCP_CROSS_AGENT_INTEROPERABILITY=ENGINEERING_DEMONSTRATED
ORNITH_REQUIRED_AGENT_QUALITY=FAIL
ORNITH_V6_FINAL_VALIDATION=PENDING
ORIGINAL_MCP_CAMPAIGN_GLOBAL_TARGET=NOT_ACHIEVED
```

Package-G is experimental infrastructure for controlled execution, verifiable evidence, causality, provenance and AI-agent consumption. OP1 Reusable is its reusable implementation track. It addresses a practical agent workflow problem: how to retain source-bound run evidence, inspect what happened, and recover recorded work without silently dispatching it again.

MCP (Model Context Protocol) lets an agent client discover and call the published tools over stdio. The server binds those calls to one workspace; MCP provides the interface, while the existing engine performs the bounded synthetic work and evidence checks. No language model is needed for the public demonstration.

This engineering snapshot includes real source for the selected reusable core, a lightweight local I7 runtime, fixed provider registry, Python API and CLI, Evidence Engine, Context Engine v0.1, I4-NEXT/I5-NEXT adapters, a ten-tool stdio MCP server, an independent MCP client for local models served by llama.cpp, and synthetic tests/fixtures. Exact included files are listed in `manifests/PUBLIC_TREE_MANIFEST.json`. Original Windows operational helpers and protected evidence stay private; see the selected-core manifest and limitations.

## Public demonstration and CI

Follow the [step-by-step MCP demo](docs/PUBLIC_DEMO.md) to enumerate tools, run a synthetic operation, inspect generated evidence, verify/query it, and recover without redispatch. [Public validation](docs/PUBLIC_VALIDATION.md) lists exact commands and boundaries. The [GitHub Actions runs](https://github.com/nahuelvillarroel05/package-g-op1-reusable/actions/workflows/public-ci.yml) show actual results for each tested commit; historical PASS records are not new CI results.

The original commit `7cab0ed7213712e8b41c4bf0ddb9d669511d8137` and tag `engineering-snapshot-20261025` remain the frozen engineering baseline. Maintenance commits are derivatives, not replacement freezes.

## Run the public synthetic path

Use Python 3.14 (publication checks used 3.14.4) on Windows. The runtime includes Windows-specific path/handle checks. Create an isolated environment from this repository root:

```powershell
py -3.14 -m venv .venv
.venv\Scripts\python.exe -m pip install -r mcp/INSTALL_FREEZE.txt -r tests/requirements.txt
.venv\Scripts\python.exe -I -c "import site; from pathlib import Path; Path(site.getusersitepackages()).mkdir(parents=True, exist_ok=True)"
.venv\Scripts\python.exe -B runtime/candidate/pg_i7.py --help
.venv\Scripts\python.exe -B runtime/candidate/pg_i7.py demo --workspace-dir demo-001 --data-digest --causal-data --provenance --provenance-mode prospective --json
```

The user-site directory preparation above is an inherited environment prerequisite, including in an isolated venv; it creates the Python-derived directory if missing and installs nothing there. CI additionally checks that JSON Schema loads from the venv. See the [full setup](docs/PUBLIC_DEMO.md).

The demo creates a new bound workspace beneath `runtime/campaigns`. A relative `--workspace-dir` is resolved beneath that directory; supply an ID such as `demo-001`, without repeating `campaigns/`. Some inherited CLI-help examples describe the original private distribution; use the tested commands here for this public selection. Producer workspaces are single-use; use fresh IDs. Use the exact `run_dir` returned by a run for verify/query/recover, in the same workspace. Do not retry a producer after an ambiguous response; recover its existing evidence.

The complete synthetic documentary pipeline, Python API example and result checks are exercised by:

```powershell
.venv\Scripts\python.exe -B examples/api_synthetic_pipeline.py
.venv\Scripts\python.exe -B tests/smoke_stdio.py
.venv\Scripts\python.exe -B tests/test_run_ref_boundaries.py
.venv\Scripts\python.exe -B tests/test_public_boundaries.py
```

Run smoke tests in a disposable fresh checkout; they create local evidence and preserve existing outputs. To launch MCP stdio:

```powershell
.venv\Scripts\python.exe -B -m pg_i7_mcp.server --workspace-id public-mcp-001 --initialize-workspace
```

Attach to an existing workspace by omitting initialization. A client must perform the MCP handshake; standard input/output carries the protocol. No GGUF or model server is required for Package-G's basic functions. The independent client is available at `agent_clients/llama_cpp_mcp_agent.py`. Inspect its options with:

```powershell
.venv\Scripts\python.exe -B agent_clients/llama_cpp_mcp_agent.py --help
```

It uses llama.cpp's OpenAI-compatible chat API and context/tokenization endpoints. Supply `--model` with your server's model identifier. The historical default `ornith15-35b-local` is retained for behavior compatibility; the client is not exclusive to Ornith. No model download, server startup or model inference is needed for `--help` or the synthetic tests. Historical Ornith results and FAIL records remain unchanged.

## Evidence and remaining work

Formal I0–I6 history, local I7 validation, multiprovider/API/CLI/Context/NEXT results and MCP/Codex/Ornith interoperability have separate evidence scopes. See [history](docs/DEVELOPMENT_HISTORY.md), [validation](docs/VALIDATION_EVIDENCE.md), [status matrix](docs/I0_I7_STATUS.md) and [architecture](docs/ARCHITECTURE.md).

This repository does not establish operational qualification, independent custody, OD05 completion, E30 completion, formal I7 acceptance, certified security or universal agent compatibility. Source025 closures, OD05 0/3 and the original formal gates remain pending. Expanded OD03 remains deferred by the Owner; Physical C2 is deferred, not waived. See [limitations](docs/LIMITATIONS.md) and the [roadmap](docs/ROADMAP.md).

## Contribute

See [CONTRIBUTING](CONTRIBUTING.md) for a clean-checkout test workflow, evidence rules and PR expectations. [The roadmap](docs/ROADMAP.md) records unresolved obligations; a public CI pass does not close original gates. Public maintenance does not claim external adoption or production readiness.

## License

Owner-authorized Package-G source is distributed under Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). External dependencies retain their original licenses and are installed separately. SPDX-License-Identifier: Apache-2.0.
