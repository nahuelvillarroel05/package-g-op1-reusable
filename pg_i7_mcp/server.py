"""Fixed-workspace stdio MCP facade with V4 generic contract metadata."""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Annotated, Literal

from mcp.server.mcpserver import MCPServer
from mcp_types import CallToolResult, TextContent
from pydantic import Field

CAMPAIGN = Path(__file__).resolve().parents[1]
RUNTIME = CAMPAIGN / "runtime"
RUNTIME_CAMPAIGNS = RUNTIME / "campaigns"
sys.path.insert(0, str(RUNTIME))
from candidate import i7_api  # noqa: E402

server = MCPServer("package-g-i7-local")
_workspace: Path | None = None
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SELECTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
OpaqueId = Annotated[str, Field(pattern=_ID.pattern, description="Opaque identifier; 1-80 ASCII letters, digits, period, underscore, or hyphen; begins with letter or digit.")]
SelectionId = Annotated[str, Field(pattern=_SELECTION_ID.pattern, description="Selection identifier; 1-64 ASCII letters, digits, period, underscore, or hyphen; begins with letter or digit.")]
RunRef = Annotated[str, Field(pattern=_RUN_ID.pattern, description="Single directory basename returned as mcp_run_ref; 1-128 safe characters; resolved only beneath this workspace's runs/ directory.")]
SelectionRef = Annotated[str, Field(pattern=r"^runs/[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.json$", description="Exact mcp_selection_ref returned by prepare_document_selection; resolved only beneath this workspace's runs/ directory.")]
PolicyId = Literal["engineering", "package-fixtures"]


def _bound() -> str:
    if _workspace is None:
        raise ValueError("workspace is not bound")
    return str(_workspace)


def _api_call(function: Any, **kwargs: Any) -> Any:
    started_unix = time.time()
    started_counter = time.perf_counter()
    success = False
    try:
        result = function(**kwargs)
        success = True
        return result
    finally:
        event = {"event": "package_g_api_timing", "api": function.__name__,
                 "started_unix": started_unix,
                 "duration_seconds": time.perf_counter() - started_counter,
                 "success": success}
        sys.stderr.write(json.dumps(event, separators=(",", ":")) + "\n")
        sys.stderr.flush()


def _run_path(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("from_run must be a single safe run directory name (1-128 characters)")
    candidate = (_workspace / "runs" / run_id).resolve(strict=False)
    if candidate.parent != (_workspace / "runs").resolve(strict=False):
        raise ValueError("from_run escapes the bound runs directory")
    return str(candidate)


def _selection_path(name: str) -> str:
    if not isinstance(name, str):
        raise ValueError("selection_manifest must be a relative workspace path")
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or not path.parts or len(path.parts) != 2 or path.parts[0] != "runs":
        raise ValueError("selection_manifest must use the runs/<filename> reference returned by prepare_document_selection")
    candidate = (_workspace / path).resolve(strict=False)
    if candidate.parent != (_workspace / "runs").resolve():
        raise ValueError("selection_manifest escapes the workspace")
    return str(candidate)


@server.tool(description="Inspect the fixed workspace and optionally its available evidence capabilities.")
def inspect(data_digest: bool = False, causal_data: bool = False, provenance: bool = False) -> dict[str, Any]:
    if any(type(v) is not bool for v in (data_digest, causal_data, provenance)):
        raise ValueError("inspect flags must be booleans")
    return _api_call(i7_api.inspect, workspace_dir=_bound(), data_digest=data_digest, causal_data=causal_data, provenance=provenance)


@server.tool(description="Inspect one allowlisted document selection policy. policy_id is one of the exact policy IDs advertised by this schema.")
def inspect_document_selection(policy_id: PolicyId) -> dict[str, Any]:
    return _api_call(i7_api.inspect_document_selection, workspace_dir=_bound(), policy_id=policy_id)


@server.tool(description="Prepare a new explicit selection commitment. Return includes mcp_selection_ref; pass that exact reference to validate_document_selection or run_pipeline. policy_id is one of the exact policy IDs advertised by this schema.")
def prepare_document_selection(policy_id: PolicyId, relative_paths: list[str], selection_id: SelectionId) -> dict[str, Any]:
    if not _SELECTION_ID.fullmatch(selection_id):
        raise ValueError("selection_id must be a simple identifier")
    if not isinstance(policy_id, str) or not isinstance(relative_paths, list) or any(not isinstance(p, str) for p in relative_paths):
        raise ValueError("policy_id and relative_paths must be strings and a string list")
    output = str(_workspace / "runs" / f"selection-{selection_id}.json")
    result = _api_call(i7_api.prepare_document_selection, workspace_dir=_bound(), policy_id=policy_id,
        relative_paths=relative_paths, selection_id=selection_id, output_path=output)
    return {**result, "mcp_selection_ref": f"runs/selection-{selection_id}.json"}


@server.tool(description="Validate a committed selection manifest. Pass the exact runs/<filename> mcp_selection_ref returned by prepare_document_selection.")
def validate_document_selection(selection_manifest: SelectionRef) -> dict[str, Any]:
    return _api_call(i7_api.validate_document_selection, workspace_dir=_bound(), selection_manifest=_selection_path(selection_manifest))


@server.tool(description="Run the bounded document-to-totals pipeline once. Pass the exact mcp_selection_ref. output_name accepts any fresh safe opaque identifier; the adapter adds the runtime-required pipeline- storage prefix when needed. Result includes mcp_run_ref for subsequent read tools.")
def run_pipeline(selection_manifest: SelectionRef, output_name: OpaqueId) -> dict[str, Any]:
    if not _ID.fullmatch(output_name):
        raise ValueError("output_name must be a fresh safe opaque identifier")
    runtime_output_name = output_name if output_name.startswith("pipeline-") else "pipeline-" + output_name
    result = _api_call(i7_api.run_pipeline, workspace_dir=_bound(), selection_manifest=_selection_path(selection_manifest), output_dir=runtime_output_name,
                               data_digest=True, causal_data=True, provenance=True, provenance_mode="prospective")
    run_dir = result.get("stage_b", {}).get("run_dir")
    if isinstance(run_dir, str):
        result["mcp_run_ref"] = Path(run_dir).name
    result["mcp_selection_ref"] = selection_manifest
    return result


@server.tool(description="Verify an immutable run. Pass the basename from mcp_run_ref; paths are resolved only beneath this workspace's runs/ directory.")
def verify(from_run: RunRef, expected_operation_id: str | None = None) -> dict[str, Any]:
    return _api_call(i7_api.verify, workspace_dir=_bound(), from_run=_run_path(from_run), expected_operation_id=expected_operation_id)


@server.tool(description="Query verified committed records; pass the basename from mcp_run_ref. Use kind=i4_semantic_graph_identity for the I4-NEXT semantic graph identity or kind=original_document_content to receive the explicit NOT_CAPTURED response. Other filters may return NO_MATCHING_COMMITTED_RECORDS; records are never inferred or reconstructed.")
def query(from_run: RunRef, task_id: str | None = None, kind: str | None = None, identifier: str | None = None,
          limit: Annotated[int, Field(ge=1, le=1000, description="Maximum records, 1-1000.")] = 50,
          include_superseded: bool = False, expected_operation_id: str | None = None) -> dict[str, Any]:
    return _api_call(i7_api.query, workspace_dir=_bound(), from_run=_run_path(from_run), task_id=task_id,
        kind=kind, identifier=identifier, limit=limit, include_superseded=include_superseded,
        expected_operation_id=expected_operation_id)


@server.tool(description="Read the verified I4-NEXT semantic causal graph for an immutable run. Pass the basename from mcp_run_ref; select json or dot format. Edge source_id and target_id refer to declared graph node IDs. caused_by_ids point from the referencing record back to its cited cause according to the frozen I4 schema. Artifact corpus paths or pointers are references only; they do not create graph nodes.")
def get_graph(from_run: RunRef, graph_format: Annotated[str, Field(pattern="^(json|dot)$", description="Output format: json or dot.")] = "json", expected_operation_id: str | None = None) -> dict[str, Any]:
    return _api_call(i7_api.get_graph, workspace_dir=_bound(), from_run=_run_path(from_run), graph_format=graph_format,
                            expected_operation_id=expected_operation_id)


@server.tool(description="Read verified I5-NEXT prospective Engineering provenance for an immutable run. Pass the basename from mcp_run_ref. UNKNOWN is scoped to the field or record where it is returned; preserve separately supplied known IDs and values as given. This prospective record is not Formal I5 binding or authority.")
def get_provenance(from_run: RunRef, expected_operation_id: str | None = None) -> dict[str, Any]:
    return _api_call(i7_api.get_provenance, workspace_dir=_bound(), from_run=_run_path(from_run),
                                 expected_operation_id=expected_operation_id)


@server.tool(description="Recover/read an existing attempt or run; recovery never redispatches work. Pass the basename from mcp_run_ref.")
def recover(from_run: RunRef, expected_operation_id: str | None = None) -> dict[str, Any]:
    return _api_call(i7_api.recover, workspace_dir=_bound(), from_run=_run_path(from_run), expected_operation_id=expected_operation_id)


def _enforce_wire_arguments() -> None:
    """MCP SDK 2.3 defaults to coercion/extra-ignore; keep tool wire inputs exact."""
    metadata_type = type(server._tool_manager.list_tools()[0].fn_metadata)
    metadata_type.pre_parse_json = lambda self, data: data
    for tool in server._tool_manager.list_tools():  # pinned mcp==2.3.0 contract
        metadata = tool.fn_metadata
        metadata.arg_model.model_config["strict"] = True
        metadata.arg_model.model_config["extra"] = "forbid"
        metadata.arg_model.model_rebuild(force=True)
        # Tool.parameters is cached during registration; refresh it so advertised
        # JSON Schema matches the same strict model used to validate raw calls.
        tool.parameters = metadata.arg_model.model_json_schema(by_alias=True)
        original = tool.fn

        def structured_errors(*args: Any, __original: Any = original, **kwargs: Any) -> Any:
            try:
                return __original(*args, **kwargs)
            except Exception as exc:
                code = getattr(exc, "code", None) or "MCP_TOOL_OPERATION_ERROR"
                payload = {"schema": "i7_mcp.tool-error.v1", "status": "ERROR",
                           "code": code, "message": str(exc), "authority_effect": "NONE"}
                return CallToolResult(content=[TextContent(text=json.dumps(payload, ensure_ascii=False))],
                                      structuredContent=payload, isError=True)

        tool.fn = structured_errors


_enforce_wire_arguments()


def main() -> None:
    global _workspace
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace-id", required=True, help="Opaque workspace id; stored beneath this campaign's workspaces directory")
    parser.add_argument("--initialize-workspace", action="store_true", help="Create/bind a fresh producer workspace; omit for read-only attachment to an existing workspace")
    args = parser.parse_args()
    if not _ID.fullmatch(args.workspace_id):
        parser.error("workspace-id must be a simple identifier")
    root = RUNTIME_CAMPAIGNS.resolve()
    _workspace = (root / args.workspace_id).resolve()
    if _workspace.parent != root:
        parser.error("workspace-id escapes campaign workspace root")
    if args.initialize_workspace:
        root.mkdir(parents=True, exist_ok=True)
        _api_call(i7_api.initialize_workspace, workspace_dir=str(_workspace))
    elif not root.is_dir() or not (_workspace / "FOCUSED_WORKSPACE_BINDING.json").is_file():
        parser.error("existing workspace binding is required unless --initialize-workspace is supplied")
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
