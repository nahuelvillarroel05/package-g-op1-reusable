"""Real MCP SDK client smoke/security check for the fixed-workspace server."""
from __future__ import annotations

import anyio
import json
import hashlib
import sys
import tempfile
from uuid import uuid4
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def main() -> None:
    server_stderr = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
    args = ["-m", "pg_i7_mcp.server", "--workspace-id", "mcp-smoke-" + uuid4().hex,
            "--initialize-workspace"]
    params = StdioServerParameters(command=sys.executable, args=args, cwd=ROOT)
    async with stdio_client(params, errlog=server_stderr) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init = await session.initialize()
            print("HANDSHAKE_OK", flush=True)
            tools = await session.list_tools()
            print("LIST_OK", flush=True)
            names = {item.name for item in tools.tools}
            expected = {"inspect", "inspect_document_selection", "prepare_document_selection",
                        "validate_document_selection", "run_pipeline", "verify", "query",
                        "get_graph", "get_provenance", "recover"}
            assert expected == names, (expected - names, names - expected)
            print(json.dumps({"step": "tools_available", "tools": sorted(names)}), flush=True)
            inspect_result = await session.call_tool("inspect", {"data_digest": False, "causal_data": False, "provenance": False})
            print("INSPECT_OK", flush=True)
            assert not inspect_result.is_error, inspect_result
            assert inspect_result.structured_content is not None
            policy = await session.call_tool("inspect_document_selection", {"policy_id": "package-fixtures"})
            print("POLICY_OK", flush=True)
            assert not policy.is_error, policy
            prepared = await session.call_tool("prepare_document_selection", {
                "policy_id": "package-fixtures", "relative_paths": ["sample.md", "sample.json"],
                "selection_id": "smoke-fixture-001"})
            print("PREPARE_DONE", flush=True)
            assert not prepared.is_error, prepared
            selection_ref = prepared.structured_content["mcp_selection_ref"]
            validated = await session.call_tool("validate_document_selection", {"selection_manifest": selection_ref})
            print("VALIDATE_DONE", flush=True)
            assert not validated.is_error, validated
            pipeline = await session.call_tool("run_pipeline", {
                "selection_manifest": selection_ref, "output_name": "agent-a-document-totals"})
            print("PIPELINE_DONE", flush=True)
            assert not pipeline.is_error, pipeline
            run_ref = pipeline.structured_content["mcp_run_ref"]
            run_dir = Path(pipeline.structured_content["stage_b"]["run_dir"])
            workspace = run_dir.parent.parent
            evidence_files = sorted(p.relative_to(run_dir).as_posix() for p in run_dir.rglob("*") if p.is_file())
            assert evidence_files
            print(json.dumps({"step": "synthetic_operation", "run_ref": run_ref,
                              "run_dir": str(run_dir), "evidence_files": evidence_files}), flush=True)
            verified = await session.call_tool("verify", {"from_run": run_ref})
            assert not verified.is_error, verified
            assert verified.structured_content["status"] == "PASS", verified
            print(json.dumps({"step": "verify", "status": verified.structured_content["status"]}), flush=True)
            queried = await session.call_tool("query", {"from_run": run_ref, "kind": "i4_semantic_graph_identity"})
            assert not queried.is_error, queried
            assert queried.structured_content["status"] == "PASS", queried
            print(json.dumps({"step": "query", "result": queried.structured_content}), flush=True)
            graph = await session.call_tool("get_graph", {"from_run": run_ref})
            assert not graph.is_error, graph
            provenance = await session.call_tool("get_provenance", {"from_run": run_ref})
            assert not provenance.is_error, provenance
            def snapshot():
                return {p.relative_to(workspace).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in workspace.rglob("*") if p.is_file()}
            before_recovery = snapshot()
            recovered = await session.call_tool("recover", {"from_run": run_ref})
            assert not recovered.is_error, recovered
            assert recovered.structured_content["status"] == "PASS", recovered
            assert recovered.structured_content["recovery"]["replay_rejected"] is True, recovered
            attempt_ref = Path(pipeline.structured_content["pipeline_attempt_dir"]).name
            attempt_recovered = await session.call_tool("recover", {"from_run": attempt_ref})
            assert not attempt_recovered.is_error, attempt_recovered
            recovery = attempt_recovered.structured_content
            assert recovery["status"] == "PASS", recovery
            assert recovery["dispatch"] == "NOT_PERFORMED", recovery
            assert recovery["redispatch"] == "PROHIBITED", recovery
            assert recovery["read_only"] is True, recovery
            assert before_recovery == snapshot(), "recovery modified workspace evidence"
            print(json.dumps({"step": "recovery", "status": recovery["status"],
                              "dispatch": recovery["dispatch"], "redispatch": recovery["redispatch"],
                              "workspace_file_hashes": "UNCHANGED", "replay_rejected": True}), flush=True)
            # The server rejects traversal before any runtime API call.
            rejected = await session.call_tool("verify", {"from_run": "..\\outside"})
            assert rejected.is_error, rejected
            # The server accepts only known run identifiers; API returns a structured error for an absent run.
            absent = await session.call_tool("verify", {"from_run": "not-a-real-run"})
            assert absent.is_error, absent
            assert absent.structured_content["code"] == "PATH_NOT_FOUND", absent
            coercion = await session.call_tool("inspect", {"data_digest": "true"})
            assert coercion.is_error, coercion
            extra = await session.call_tool("inspect", {"unexpected": "ignored"})
            assert extra.is_error, extra
            list_coercion = await session.call_tool("prepare_document_selection", {
                "policy_id": "package-fixtures", "relative_paths": "[\\\"sample.md\\\"]",
                "selection_id": "bad-coercion"})
            assert list_coercion.is_error, list_coercion
    timing_events = []
    server_stderr.seek(0)
    for line in server_stderr.read().splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event") == "package_g_api_timing":
            timing_events.append(event)
    required_apis = {"initialize_workspace", "inspect", "inspect_document_selection",
                     "prepare_document_selection", "validate_document_selection", "run_pipeline",
                     "verify", "query", "get_graph", "get_provenance", "recover"}
    assert required_apis <= {event["api"] for event in timing_events}, timing_events
    assert any(event["api"] == "verify" and event["success"] is False for event in timing_events), timing_events
    assert all(isinstance(event["started_unix"], (int, float)) and event["duration_seconds"] >= 0 for event in timing_events)
    timing_path = ROOT / "MCP_API_TIMINGS_V3.jsonl"
    if timing_path.exists():
        raise FileExistsError(f"preserve existing timing evidence: {timing_path}")
    timing_path.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in timing_events), encoding="utf-8")
    server_stderr.close()
    print({"protocol": str(init.protocol_version), "tools": sorted(names),
                   "pipeline_evidence_query_graph_provenance_recovery": "PASS",
                   "path_traversal_absent_run_coercion_extra_argument_rejections": "PASS",
                   "package_g_api_timing_events": len(timing_events),
                   "timing_apis": sorted({event["api"] for event in timing_events}),
                   "I7_STATUS": "INCOMPLETE"})


if __name__ == "__main__":
    anyio.run(main)
