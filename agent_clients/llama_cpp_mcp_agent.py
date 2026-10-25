"""Local OpenAI-compatible model agent backed by a real MCP stdio client.

No planner or tool selection is implemented here: the model response determines
the requested MCP tool. Transcript JSONL records actual wire payloads and timing.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import re
import socket
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from jsonschema import Draft202012Validator

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


_COMPACTION_SYSTEM = (
    "You are the same local model performing bounded conversation-memory compaction. "
    "Summarize only public observations in the supplied resolved conversation or MCP tool results. Do not invent, "
    "repair, infer, or answer the task. Preserve exact identifiers, paths, statuses, hashes, "
    "query facts, recovery state, authority limits, UNKNOWN and NOT_PROVEN values, and every "
    "fact needed to continue the stated task. Clearly preserve uncertainty. The transcript "
    "Preserve completed and pending actions. Never choose or dispatch a tool call. The transcript "
    "contains the full unmodified MCP exchanges; this summary is model-authored memory, not "
    "an API response or independent evidence. Return concise plain text."
)


_SYSTEM_BASE = (
    "You are a local tool-using agent. Use MCP tools only when needed. Never claim an action succeeded without its tool result. "
    "Respect all tool errors. Do not repeat a tool call. A tool result may include delivery_metadata with omitted_paths and a raw transcript reference; "
    "this is transport-only, not API evidence or an API status. Do not infer omitted facts."
)
_SYSTEM_POLICY_V3 = (
    "Preserve tool results exactly, including success/error states, duplicate-call decisions, and transport metadata. "
    "Prior-turn data may be reused when it remains bound to the same workspace and run; do not mix identities across scopes. "
    "Use query filters exactly as supplied by the user or returned by the applicable contract; do not guess, normalize, or paraphrase identifiers. "
    "Interpret graph fields by object and schema: only declared endpoint fields join nodes by exact identifiers from that graph. "
    "Field labels, evidence references, bindings, filenames, and pointers locate source information; they do not create vertices or endpoints. "
    "Keep raw graph data intact and unresolved references unresolved. Keep run, operation, attempt, and audit-record identities in their own scopes. "
    "For successful committed-run recovery, the returned audit identifier is fresh and labels that recovery record, while the original run and attempt identities remain separate. "
    "Preserve other recovery states and missing fields without inventing IDs. Separate request deadlines, MCP-call outcomes, and whole-run stops. "
    "One timeout does not establish infrastructure failure. Do not insert expected entities, values, relationships, or answers."
)
_COMPACTED_SYSTEM_SUFFIX = (
    " Compacted state is model-authored memory, not a tool response; verify further facts with MCP tools."
)


def _api_root(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    return f"{parsed.scheme}://{parsed.netloc}"


def _rendered_token_count(endpoint: str, messages: list[dict[str, Any]],
                          tools: list[dict[str, Any]] | None, timeout: float) -> tuple[int, int, float]:
    root = _api_root(endpoint)
    apply_payload: dict[str, Any] = {"messages": messages, "add_generation_prompt": True}
    if tools:
        apply_payload["tools"] = tools
    rendered, apply_seconds, _ = _post_json(root + "/apply-template", apply_payload, timeout)
    prompt = rendered.get("prompt")
    if not isinstance(prompt, str):
        raise RuntimeError("context_preflight_missing_rendered_prompt")
    tokenized, tokenize_seconds, _ = _post_json(root + "/tokenize", {"content": prompt, "add_special": False}, timeout)
    tokens = tokenized.get("tokens")
    if not isinstance(tokens, list):
        raise RuntimeError("context_preflight_missing_tokens")
    return len(tokens), len(prompt.encode("utf-8")), apply_seconds + tokenize_seconds


def _model_context_size(endpoint: str, timeout: float) -> tuple[int, dict[str, Any]]:
    props, _, _ = _get_json(_api_root(endpoint) + "/props", timeout)
    generation = props.get("default_generation_settings", {})
    params = generation.get("params", {}) if isinstance(generation, dict) else {}
    context = generation.get("n_ctx") if isinstance(generation, dict) else None
    if context is None:
        context = params.get("n_ctx") if isinstance(params, dict) else None
    if not isinstance(context, int) or context <= 0:
        raise RuntimeError("context_preflight_missing_server_n_ctx")
    return context, props


def _compaction_output_budget(context_size: int, prompt_tokens: int, margin_tokens: int,
                              maximum: int = 2048, minimum: int = 1024) -> int | None:
    available = context_size - prompt_tokens - margin_tokens
    return min(maximum, available) if available >= minimum else None


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "__dict__"):
        return value.__dict__
    return str(value)


def _post_json(url: str, payload: dict[str, Any], timeout: float) -> tuple[dict[str, Any], float, int]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"model_http_error:{type(exc).__name__}:{exc}") from exc
    elapsed = time.perf_counter() - started
    return json.loads(raw.decode("utf-8")), elapsed, len(raw)


def _get_json(url: str, timeout: float) -> tuple[dict[str, Any], float, int]:
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            raw = response.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"model_http_error:{type(exc).__name__}:{exc}") from exc
    return json.loads(raw.decode("utf-8")), time.perf_counter() - started, len(raw)


def _post_stream(url: str, payload: dict[str, Any], timeout: float, max_bytes: int) -> tuple[dict[str, Any], dict[str, Any], float, float | None, int, bool]:
    payload = {**payload, "stream": True}
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, body, {"Content-Type": "application/json"})
    started = time.perf_counter()
    first = None
    size = 0
    content: list[str] = []
    tool_calls: dict[int, dict[str, Any]] = {}
    usage: dict[str, Any] | None = None
    finish_reason = None
    raw_events: list[dict[str, Any]] = []
    saw_done = False
    byte_limit_hit = False
    response_deadline_hit = False
    deadline = time.monotonic() + timeout
    try:
        response_context = urllib.request.urlopen(request, timeout=timeout)
    except (TimeoutError, socket.timeout):
        response_context = None
        response_deadline_hit = True
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            response_context = None
            response_deadline_hit = True
        else:
            raise
    if response_context is not None:
        with response_context as response:
            sock = getattr(getattr(response.fp, "raw", None), "_sock", None)
            if sock is None:
                raise RuntimeError("cannot enforce absolute model response deadline on stream socket")
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    response_deadline_hit = True
                    break
                sock.settimeout(remaining)
                try:
                    raw_line = response.readline(max_bytes - size + 1)
                except (TimeoutError, socket.timeout):
                    response_deadline_hit = True
                    break
                if not raw_line:
                    break
                size += len(raw_line)
                if size > max_bytes:
                    byte_limit_hit = True
                    break
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    response_deadline_hit = time.monotonic() > deadline
                    saw_done = True
                    break
                try:
                    event = json.loads(data)
                except ValueError:
                    continue
                safe_event = json.loads(json.dumps(event))
                for choice_event in safe_event.get("choices", []):
                    if isinstance(choice_event.get("delta"), dict):
                        choice_event["delta"].pop("reasoning_content", None)
                raw_events.append(safe_event)
                if event.get("usage"):
                    usage = event["usage"]
                for choice in event.get("choices", []):
                    delta = choice.get("delta", {})
                    if first is None and (delta.get("content") or delta.get("reasoning_content") or delta.get("tool_calls")):
                        first = time.perf_counter() - started
                    if delta.get("content"):
                        content.append(delta["content"])
                    for tc in delta.get("tool_calls", []):
                        slot = tool_calls.setdefault(tc.get("index", 0), {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                        slot["id"] += tc.get("id", "")
                        if tc.get("function", {}).get("name"):
                            slot["function"]["name"] += tc["function"]["name"]
                        slot["function"]["arguments"] += tc.get("function", {}).get("arguments", "")
                    if choice.get("finish_reason"):
                        finish_reason = choice["finish_reason"]
    elapsed = time.perf_counter() - started
    result = {"choices": [{"message": {"content": "".join(content), "tool_calls": list(tool_calls.values()) or None},
                           "finish_reason": finish_reason}], "usage": usage}
    return result, {"sse_events": raw_events, "done_marker_received": saw_done,
                    "response_byte_limit_hit": byte_limit_hit,
                    "response_deadline_hit": response_deadline_hit}, elapsed, first, size, saw_done and not byte_limit_hit and not response_deadline_hit


def _tool_schema(tool: Any) -> dict[str, Any]:
    return {"type": "function", "function": {
        "name": tool.name,
        "description": tool.description or "",
        "parameters": _jsonable(tool.input_schema),
    }}


def _mechanical_graph_endpoint_view(result_data: Any, is_error: bool) -> dict[str, Any]:
    """Copy original same-response graph fields and uniquely matched endpoints."""
    def not_enriched(diagnostic: str) -> dict[str, Any]:
        return {"status": "NOT_ENRICHED", "mechanical_diagnostic": diagnostic,
                "raw_result_json_pointer_root": ""}

    if is_error:
        return not_enriched("TOOL_RESULT_IS_ERROR")
    if not isinstance(result_data, dict) or result_data.get("format") != "json":
        return not_enriched("RESULT_NOT_JSON_OBJECT")
    graph = result_data.get("graph")
    if not isinstance(graph, dict):
        return not_enriched("GRAPH_OBJECT_MISSING")
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return not_enriched("NODE_OR_EDGE_ARRAY_MISSING")

    node_index: dict[str, int] = {}
    for index, node in enumerate(nodes):
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
            return not_enriched("NODE_ID_MISSING_OR_NOT_STRING")
        if node["id"] in node_index:
            return not_enriched("DUPLICATE_NODE_ID")
        node_index[node["id"]] = index

    endpoint_joins: list[dict[str, Any]] = []
    for edge_index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            return not_enriched("EDGE_RECORD_NOT_OBJECT")
        source_id, target_id = edge.get("source_id"), edge.get("target_id")
        if not isinstance(source_id, str) or not source_id or not isinstance(target_id, str) or not target_id:
            return not_enriched("EDGE_ENDPOINT_ID_MISSING_OR_NOT_STRING")
        source_index, target_index = node_index.get(source_id), node_index.get(target_id)
        if source_index is None or target_index is None:
            return not_enriched("UNRESOLVED_EDGE_ENDPOINT")
        endpoint_joins.append({
            "edge_json_pointer": f"/graph/edges/{edge_index}",
            "source_node_json_pointer": f"/graph/nodes/{source_index}",
            "target_node_json_pointer": f"/graph/nodes/{target_index}",
            "edge": copy.deepcopy(edge),
            "source_node": copy.deepcopy(nodes[source_index]),
            "target_node": copy.deepcopy(nodes[target_index]),
        })

    remaining_graph_fields = copy.deepcopy({
        key: value for key, value in graph.items() if key not in {"nodes", "edges"}
    })
    remaining_result_fields = copy.deepcopy({
        key: value for key, value in result_data.items() if key != "graph"
    })
    return {"status": "PROJECTED", "mechanical_only": True,
            "raw_result_json_pointer_root": "", "graph_json_pointer_root": "/graph",
            "remaining_result_fields": remaining_result_fields,
            "remaining_graph_fields": remaining_graph_fields,
            "endpoint_joins": endpoint_joins}


def _project_model_tool_result(tool_name: str, result: Any, raw_transcript_event: str) -> dict[str, Any]:
    """Reduce only verified repetitive metadata in the model view; retain raw result elsewhere."""
    if result.structured_content is not None:
        model_result = {"is_error": bool(result.is_error), "result": _jsonable(result.structured_content)}
    else:
        model_result = {"is_error": bool(result.is_error), "content": _jsonable(result.content)}
    model_result = json.loads(json.dumps(model_result, ensure_ascii=False))
    omitted: list[dict[str, Any]] = []
    if tool_name == "inspect":
        data = model_result.get("result")
        components = data.get("components") if isinstance(data, dict) else None
        expected = {"path", "role", "sha256", "source_path", "source_sha256"}
        if isinstance(components, list) and components and all(
            isinstance(item, dict) and set(item) == expected for item in components
        ):
            del data["components"]
            omitted.append({"path": "/result/components", "record_count": len(components),
                            "omitted_fields": sorted(expected),
                            "reason": "repetitive implementation and source commitment inventory omitted from model delivery"})

    def remove_source_commitments(node: Any, pointer: str = "") -> Any:
        if isinstance(node, dict):
            projected = {}
            for key, value in node.items():
                child_pointer = pointer + "/" + key.replace("~", "~0").replace("/", "~1")
                if (key == "source_commitments" and isinstance(value, dict) and value
                        and all(isinstance(item, str) and re.fullmatch(r"[0-9a-fA-F]{64}", item) for item in value.values())):
                    omitted.append({"path": child_pointer, "entry_count": len(value),
                                    "reason": "source_commitments contains only fixed-length SHA-256 values omitted from model delivery"})
                    continue
                projected[key] = remove_source_commitments(value, child_pointer)
            return projected
        if isinstance(node, list):
            return [remove_source_commitments(item, f"{pointer}/{index}") for index, item in enumerate(node)]
        return node

    graph_endpoint_view = None
    if tool_name == "get_graph":
        graph_endpoint_view = _mechanical_graph_endpoint_view(model_result.get("result"), result.is_error)

    model_result = remove_source_commitments(model_result)
    if graph_endpoint_view is not None:
        model_result.setdefault("delivery_metadata", {})[
            "mechanical_graph_endpoint_view"] = graph_endpoint_view
    if omitted:
        model_result.setdefault("delivery_metadata", {}).update({
            "omitted_paths": omitted,
            "raw_transcript_event": raw_transcript_event,
            "meaning": "transport-only notice; omitted fields are not evidence and must not be inferred"})
    return model_result


def _error_summary(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_error_summary(child) for child in exc.exceptions)
    cause = f" caused_by={type(exc.__cause__).__name__}:{exc.__cause__}" if exc.__cause__ else ""
    return f"{type(exc).__name__}:{exc}{cause}"


def _local_environment() -> tuple[dict[str, str], list[str]]:
    env = dict(os.environ)
    removed = sorted(key for key in env if key.upper().startswith(("OPENAI_", "CODEX_")))
    for key in removed:
        env.pop(key, None)
    return env, removed


def _validate_endpoint(endpoint: str) -> None:
    parsed = urlsplit(endpoint)
    try:
        valid_port = parsed.port is not None and 1 <= parsed.port <= 65535
    except ValueError:
        valid_port = False
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or not valid_port or parsed.path != "/v1" or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        raise ValueError("model endpoint must be http loopback at an explicit valid port with path /v1")


def _fallback_directive(tools: list[Any]) -> str:
    names = [t.name for t in tools]
    return ("Return exactly one JSON object and no prose: {\"tool\": string, \"arguments\": object}. "
            "Choose the single MCP tool that best fulfills the user request; do not invent tools. "
            f"Available tool names: {json.dumps(names)}")


async def run(args: argparse.Namespace) -> int:
    output = Path(args.transcript)
    deadline = time.monotonic() + args.wall_seconds
    transcript: list[dict[str, Any]] = []
    def record(event: str, **fields: Any) -> None:
        frozen = json.loads(json.dumps(fields, ensure_ascii=False))
        row = {"event": event, "observed_unix": time.time(), "client_pid": os.getpid(),
               "elapsed_seconds": round(time.perf_counter() - began, 6), **frozen}
        transcript.append(row)
        with output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")

    began = time.perf_counter()
    _validate_endpoint(args.endpoint)
    context_size, server_props = _model_context_size(args.endpoint, min(args.request_timeout, args.wall_seconds))
    record("model_context", n_ctx=context_size, model_alias=server_props.get("model_alias"),
           build_info=server_props.get("build_info"), measurement="local_server_props")
    clean_env, removed_env_names = _local_environment()
    record("environment_boundary", removed_variable_names=removed_env_names,
           endpoint_policy="http_loopback_only")
    server_args = ["-m", args.server_module, "--workspace-id", args.workspace_id]
    if not args.attach:
        server_args.append("--initialize-workspace")
    server = StdioServerParameters(command=args.python, args=server_args, env=clean_env)
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_start = time.perf_counter()
            await session.initialize()
            record("mcp_initialize", wall_seconds=time.perf_counter() - init_start)
            listed = await session.list_tools()
            tools = list(listed.tools)
            if not tools:
                raise RuntimeError("mcp_server_returned_no_tools")
            allowed = {t.name for t in tools}
            schemas = [_tool_schema(t) for t in tools]
            validators = {}
            for schema in schemas:
                params = schema["function"]["parameters"]
                Draft202012Validator.check_schema(params)
                validators[schema["function"]["name"]] = Draft202012Validator(params)
            record("mcp_tools_list", tools=[{"name": t.name, "inputSchema": _jsonable(t.input_schema)} for t in tools])

            messages: list[dict[str, Any]] = [
                {"role": "system", "content": _SYSTEM_BASE + "\n\n" + _SYSTEM_POLICY_V3},
                {"role": "user", "content": args.task},
            ]
            total_model_seconds = 0.0
            calls_used = 0
            model_calls_used = 0
            compactions_used = 0
            last_compaction_unavailable_reason: str | None = None
            producer_attempted = False
            seen_calls: set[str] = set()

            async def compact_state(source_messages: list[dict[str, Any]], latest_results: list[dict[str, Any]],
                                    kind: str) -> str | None:
                nonlocal total_model_seconds, model_calls_used, compactions_used, last_compaction_unavailable_reason
                if compactions_used >= args.max_compactions:
                    raise RuntimeError("context_compaction_limit")
                if model_calls_used >= args.max_model_calls:
                    raise RuntimeError("total_model_call_limit")
                state = {
                    "task": args.task,
                    "resolved_conversation": source_messages,
                    "latest_mcp_results": latest_results,
                    "source_rule": "MCP results below are exact model-delivery payloads with transcript references; never infer omitted facts.",
                }
                compaction_messages = [
                    {"role": "system", "content": _COMPACTION_SYSTEM},
                    {"role": "user", "content": json.dumps(state, ensure_ascii=False, separators=(",", ":"))},
                ]
                remain = deadline - time.monotonic()
                if remain <= 0:
                    raise RuntimeError("wall_limit_before_context_compaction")
                preflight_start = time.perf_counter()
                prompt_tokens, prompt_bytes, preflight_seconds = await asyncio.to_thread(
                    _rendered_token_count, args.endpoint, compaction_messages, None,
                    min(args.request_timeout, remain))
                compaction_payload_bytes = len(json.dumps(compaction_messages, ensure_ascii=False).encode("utf-8"))
                compaction_output_tokens = _compaction_output_budget(
                    context_size, prompt_tokens, args.context_margin_tokens,
                    maximum=args.compaction_max_tokens, minimum=args.compaction_min_tokens)
                compaction_reserve = ((compaction_output_tokens or 0) + args.context_margin_tokens)
                record("compaction_preflight", prompt_tokens=prompt_tokens, prompt_bytes=prompt_bytes,
                       reserved_tokens=compaction_reserve, n_ctx=context_size,
                       wall_seconds=time.perf_counter() - preflight_start, http_seconds=preflight_seconds,
                       compaction_kind=kind, payload_bytes=compaction_payload_bytes,
                       payload_byte_limit=args.max_context_bytes,
                       compaction_output_tokens=compaction_output_tokens)
                if compaction_payload_bytes > args.max_context_bytes:
                    last_compaction_unavailable_reason = "compaction_payload_byte_limit"
                    record("context_compaction_incomplete", compaction_kind=kind,
                           reason="compaction_payload_byte_limit", payload_bytes=compaction_payload_bytes,
                           byte_limit=args.max_context_bytes)
                    return None
                if compaction_output_tokens is None:
                    last_compaction_unavailable_reason = "compaction_output_budget_unavailable"
                    return None
                remain = deadline - time.monotonic()
                if remain <= 0:
                    raise RuntimeError("wall_limit_before_context_compaction")
                payload = {"model": args.model, "messages": compaction_messages,
                           "temperature": args.compaction_temperature, "max_tokens": compaction_output_tokens,
                           "tool_choice": "none",
                           "stream": True}
                record("compaction_model_request", mode="local_model_state_summary", compaction_kind=kind,
                       payload=payload, prompt_tokens=prompt_tokens, max_tokens=compaction_output_tokens,
                       temperature=args.compaction_temperature)
                response, raw_response, model_seconds, ttft, response_bytes, complete = await asyncio.to_thread(
                    _post_stream, args.endpoint.rstrip("/") + "/chat/completions", payload,
                    min(args.request_timeout, remain), args.max_model_response_bytes)
                total_model_seconds += model_seconds
                model_calls_used += 1
                compactions_used += 1
                choice = response.get("choices", [{}])[0]
                message = choice.get("message", {})
                record("compaction_model_response", mode="local_model_state_summary", payload=raw_response,
                       assembled_message=message, wall_seconds=model_seconds, ttft_seconds=ttft,
                       response_bytes=response_bytes, finish_reason=choice.get("finish_reason"),
                       usage=response.get("usage"), prompt_tokens=prompt_tokens)
                summary = message.get("content")
                if choice.get("finish_reason") == "length":
                    last_compaction_unavailable_reason = "summary_output_token_limit"
                    record("context_compaction_incomplete", compaction_kind=kind,
                           reason="summary_output_token_limit", transcript_retains_raw_history=True)
                    return None
                if (not complete or not isinstance(summary, str) or not summary.strip()):
                    raise RuntimeError("context_compaction_incomplete_model_response")
                record("context_compaction_complete", summary_chars=len(summary),
                       source_result_count=len(latest_results), compaction_kind=kind,
                       transcript_retains_raw_history=True, summary_is_authority=False)
                return summary.strip()

            for index in range(args.max_calls + 1):
                if time.monotonic() >= deadline:
                    record("stop", reason="wall_limit")
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record("stop", reason="wall_limit")
                    break
                request_payload = {"model": args.model, "messages": messages, "tools": schemas,
                                   "tool_choice": "auto", "temperature": args.temperature,
                                   "max_tokens": args.max_tokens, "stream": True}
                remain = deadline - time.monotonic()
                preflight_start = time.perf_counter()
                prompt_tokens, prompt_bytes, preflight_seconds = await asyncio.to_thread(
                    _rendered_token_count, args.endpoint, messages, schemas,
                    min(args.request_timeout, max(0.1, remain)))
                required_tokens = prompt_tokens + args.max_tokens + args.context_margin_tokens
                record("model_context_preflight", attempt=index + 1, prompt_tokens=prompt_tokens,
                       prompt_bytes=prompt_bytes, max_tokens=args.max_tokens,
                       context_margin_tokens=args.context_margin_tokens, required_tokens=required_tokens,
                       n_ctx=context_size, wall_seconds=time.perf_counter() - preflight_start,
                       http_seconds=preflight_seconds)
                if required_tokens > context_size:
                    record("stop", reason="context_limit_after_compaction", prompt_tokens=prompt_tokens,
                           required_tokens=required_tokens, n_ctx=context_size)
                    break
                context_bytes = len(json.dumps({"messages": messages, "tools": schemas},
                                                ensure_ascii=False).encode("utf-8"))
                if context_bytes > args.max_context_bytes:
                    record("stop", reason="context_byte_limit", context_bytes=context_bytes,
                           context_byte_limit=args.max_context_bytes)
                    break
                if model_calls_used >= args.max_model_calls:
                    record("stop", reason="total_model_call_limit")
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record("stop", reason="wall_limit_after_context_preflight")
                    break
                record("model_request", attempt=index + 1, payload=request_payload)
                response, raw_response, model_seconds, ttft, response_bytes, complete = await asyncio.to_thread(
                    _post_stream, args.endpoint.rstrip("/") + "/chat/completions", request_payload,
                    min(args.request_timeout, remaining), args.max_model_response_bytes)
                total_model_seconds += model_seconds
                model_calls_used += 1
                choice = response.get("choices", [{}])[0]
                message = choice.get("message", {})
                record("model_response", attempt=index + 1, payload=raw_response,
                       assembled_message=response["choices"][0]["message"], wall_seconds=model_seconds,
                       response_bytes=response_bytes, usage=response.get("usage"), finish_reason=choice.get("finish_reason"),
                       ttft_seconds=ttft)
                if not complete or choice.get("finish_reason") == "length":
                    reason = "incomplete_request_deadline" if raw_response.get("response_deadline_hit") else "incomplete_or_token_limited_model_stream"
                    record("stop", reason=reason, finish_reason=choice.get("finish_reason"))
                    break
                calls = message.get("tool_calls") or []
                if not calls and index == 0 and args.json_fallback:
                    fallback_remaining = deadline - time.monotonic()
                    if fallback_remaining <= 0:
                        record("stop", reason="wall_limit_before_fallback")
                        break
                    messages.extend([{"role": "assistant", "content": message.get("content")},
                                     {"role": "user", "content": _fallback_directive(tools)}])
                    fb_payload = {"model": args.model, "messages": messages, "temperature": args.temperature,
                                  "max_tokens": min(args.max_tokens, 512), "stream": True,
                                  "tool_choice": "none", "response_format": {"type": "json_object"}}
                    fb_tokens, fb_prompt_bytes, fb_measure_seconds = await asyncio.to_thread(
                        _rendered_token_count, args.endpoint, messages, None,
                        min(args.request_timeout, max(0.1, fallback_remaining)))
                    fb_required = fb_tokens + min(args.max_tokens, 512) + args.context_margin_tokens
                    record("fallback_context_preflight", prompt_tokens=fb_tokens,
                           prompt_bytes=fb_prompt_bytes, max_tokens=min(args.max_tokens, 512),
                           context_margin_tokens=args.context_margin_tokens, required_tokens=fb_required,
                           n_ctx=context_size, http_seconds=fb_measure_seconds)
                    if fb_required > context_size:
                        record("stop", reason="fallback_context_limit", required_tokens=fb_required,
                               n_ctx=context_size)
                        break
                    if model_calls_used >= args.max_model_calls:
                        record("stop", reason="total_model_call_limit_before_fallback")
                        break
                    fallback_remaining = deadline - time.monotonic()
                    if fallback_remaining <= 0:
                        record("stop", reason="wall_limit_after_fallback_preflight")
                        break
                    record("fallback_request", mode="strict_json_tool_selection", payload=fb_payload)
                    fb, fb_raw, fb_secs, fb_ttft, fb_bytes, fb_complete = await asyncio.to_thread(
                        _post_stream, args.endpoint.rstrip("/") + "/chat/completions", fb_payload,
                        min(args.request_timeout, fallback_remaining), args.max_model_response_bytes)
                    total_model_seconds += fb_secs
                    model_calls_used += 1
                    fb_choice = fb.get("choices", [{}])[0]
                    fb_msg = fb_choice.get("message", {})
                    record("fallback_response", mode="strict_json_tool_selection", payload=fb_raw,
                           assembled_message=fb.get("choices", [{}])[0].get("message"),
                           wall_seconds=fb_secs, ttft_seconds=fb_ttft, response_bytes=fb_bytes, usage=fb.get("usage"))
                    if not fb_complete or fb.get("choices", [{}])[0].get("finish_reason") == "length":
                        reason = "incomplete_request_deadline" if fb_raw.get("response_deadline_hit") else "incomplete_or_token_limited_fallback_stream"
                        record("stop", reason=reason)
                        break
                    try:
                        selected = json.loads(fb_msg.get("content") or "")
                        calls = [{"id": "fallback-1", "type": "function", "function": {
                            "name": selected["tool"], "arguments": json.dumps(selected["arguments"])}}]
                        message = fb_msg
                        choice = fb_choice
                    except (ValueError, KeyError, TypeError):
                        record("stop", reason="fallback_invalid_json")
                        break
                if not calls:
                    record("model_final", content=message.get("content"), finish_reason=choice.get("finish_reason"))
                    break
                if index >= args.max_calls:
                    record("stop", reason="mcp_call_limit", requested_call_count=len(calls))
                    break
                stop_agent = False
                pre_tool_messages = copy.deepcopy(messages)
                batch_results: list[dict[str, Any]] = []
                messages.append({"role": "assistant", "content": message.get("content"), "tool_calls": calls})
                for call in calls:
                    if calls_used >= args.max_calls:
                        record("stop", reason="mcp_call_limit", completed_calls=calls_used,
                               requested_call_count=len(calls))
                        stop_agent = True
                        break
                    fn = call.get("function", {})
                    name = fn.get("name")
                    if name not in allowed:
                        record("tool_rejected", reason="unknown_tool", name=name)
                        stop_agent = True
                        break
                    try:
                        arguments = json.loads(fn.get("arguments") or "{}")
                    except ValueError:
                        record("tool_rejected", reason="invalid_arguments_json", name=name)
                        stop_agent = True
                        break
                    if not isinstance(arguments, dict):
                        record("tool_rejected", reason="arguments_not_object", name=name)
                        stop_agent = True
                        break
                    errors = [error.message for error in validators[name].iter_errors(arguments)]
                    if errors:
                        record("tool_rejected", reason="schema_validation_failed", name=name, errors=errors[:20])
                        stop_agent = True
                        break
                    if name == "run_pipeline" and producer_attempted:
                        record("tool_rejected", reason="producer_retry_blocked_for_workspace", name=name)
                        stop_agent = True
                        break
                    if name == "run_pipeline":
                        producer_attempted = True
                    fingerprint = json.dumps([name, arguments], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    if fingerprint in seen_calls:
                        record("tool_rejected", reason="duplicate_exact_call", name=name, arguments=arguments)
                        stop_agent = True
                        break
                    seen_calls.add(fingerprint)
                    tool_remaining = deadline - time.monotonic()
                    if tool_remaining <= 0:
                        record("stop", reason="wall_limit_before_mcp_call", name=name)
                        stop_agent = True
                        break
                    tool_start = time.perf_counter()
                    record("mcp_call_request", name=name, arguments=arguments, call_id=call.get("id"))
                    try:
                        result = await asyncio.wait_for(session.call_tool(name, arguments), timeout=tool_remaining)
                    except Exception as exc:
                        record("mcp_call_error", name=name, error=f"{type(exc).__name__}:{exc}",
                               wall_seconds=time.perf_counter() - tool_start)
                        stop_agent = True
                        break
                    result_json = _jsonable(result)
                    calls_used += 1
                    record("mcp_call_response", name=name, payload=result_json,
                           wall_seconds=time.perf_counter() - tool_start)
                    raw_event_ref = f"{output.name}#L{len(transcript)}"
                    model_result = _project_model_tool_result(name, result, raw_event_ref)
                    record("mcp_model_delivery", name=name, raw_transcript_event=raw_event_ref,
                           payload=model_result)
                    batch_results.append({"name": name, "arguments": arguments,
                                          "raw_transcript_event": raw_event_ref,
                                          "model_delivery": model_result})
                    serialized = json.dumps({"raw_transcript_event": raw_event_ref,
                                             "model_delivery": model_result}, ensure_ascii=False)
                    if len(serialized.encode("utf-8")) > args.max_tool_output_bytes:
                        record("mcp_output_rejected", name=name, reason="tool_output_limit_exceeded",
                               actual_bytes=len(serialized.encode("utf-8")), limit=args.max_tool_output_bytes,
                               task_eligibility="FAIL_INCOMPLETE_TOOL_RESULT")
                        stop_agent = True
                        break
                    messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": serialized})
                if stop_agent:
                    break
                pending_tokens, pending_bytes, pending_measure_seconds = await asyncio.to_thread(
                    _rendered_token_count, args.endpoint, messages, schemas,
                    min(args.request_timeout, max(0.1, deadline - time.monotonic())))
                main_prompt_limit = context_size - args.max_tokens - args.context_margin_tokens
                pending_context_bytes = len(json.dumps({"messages": messages, "tools": schemas},
                                                        ensure_ascii=False).encode("utf-8"))
                record("post_tool_context_measurement", prompt_tokens=pending_tokens,
                       prompt_bytes=pending_bytes, main_prompt_limit=main_prompt_limit,
                       context_bytes=pending_context_bytes, context_byte_limit=args.max_context_bytes,
                       http_seconds=pending_measure_seconds)
                if pending_tokens > main_prompt_limit or pending_context_bytes > args.max_context_bytes:
                    full_history_summary = await compact_state(messages, [], "resolved_history")
                    if full_history_summary is not None:
                        summary_messages = [{"role": "user", "content":
                                             "Model-authored memory (not an API result):\n" + full_history_summary}]
                    else:
                        result_summary = await compact_state([], batch_results, "latest_tool_results_only")
                        if result_summary is None:
                            stop_reason = ("compaction_summary_incomplete_after_fallback"
                                           if last_compaction_unavailable_reason == "summary_output_token_limit"
                                           else "single_tool_result_exceeds_compaction_context")
                            record("stop", reason=stop_reason,
                                   fallback_unavailable_reason=last_compaction_unavailable_reason,
                                   source_events=[item["raw_transcript_event"] for item in batch_results])
                            break
                        history_summary = await compact_state(pre_tool_messages, [], "resolved_prior_history")
                        if history_summary is None:
                            record("stop", reason="resolved_history_exceeds_compaction_context")
                            break
                        summary_messages = [
                            {"role": "user", "content":
                             "Model-authored resolved-history memory (not an API result):\n" + history_summary},
                            {"role": "user", "content":
                             "Model-authored latest-tool-result memory (not an API result):\n" + result_summary},
                        ]
                    messages = [
                        {"role": "system", "content": _SYSTEM_BASE + "\n\n" + _SYSTEM_POLICY_V3 + _COMPACTED_SYSTEM_SUFFIX},
                        {"role": "user", "content": args.task},
                        *summary_messages,
                    ]
                    compacted_tokens, compacted_bytes, compacted_seconds = await asyncio.to_thread(
                        _rendered_token_count, args.endpoint, messages, schemas,
                        min(args.request_timeout, max(0.1, deadline - time.monotonic())))
                    record("conversation_replaced_by_compacted_state", prompt_tokens=compacted_tokens,
                           prompt_bytes=compacted_bytes, model_calls_used=model_calls_used,
                           compactions_used=compactions_used, raw_history_retained_in_transcript=True,
                           context_bytes=pending_context_bytes,
                           http_seconds=compacted_seconds)
                else:
                    continue
    record("summary", total_wall_seconds=time.perf_counter() - began,
           total_model_seconds=round(total_model_seconds, 6), call_limit=args.max_calls,
           model_calls_used=model_calls_used, compactions_used=compactions_used,
           mode="native_tool_call_with_strict_json_fallback" if args.json_fallback else "native_tool_call_only")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:8080/v1")
    parser.add_argument("--model", default="ornith15-35b-local")
    parser.add_argument("--python", required=True, help="Campaign-local venv Python")
    parser.add_argument("--server-module", default="pg_i7_mcp.server")
    parser.add_argument("--workspace-id", required=True, help="Opaque campaign workspace ID")
    parser.add_argument("--attach", action="store_true", help="Attach to an existing workspace instead of initializing one")
    parser.add_argument("--transcript", required=True)
    parser.add_argument("--max-calls", type=int, default=4)
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--max-tool-output-bytes", type=int, default=131072)
    parser.add_argument("--max-model-response-bytes", type=int, default=4194304)
    parser.add_argument("--max-context-bytes", type=int, default=122880)
    parser.add_argument("--context-margin-tokens", type=int, default=512)
    parser.add_argument("--compaction-max-tokens", type=int, default=2048)
    parser.add_argument("--compaction-min-tokens", type=int, default=1024)
    parser.add_argument("--compaction-temperature", type=float, default=0.0)
    parser.add_argument("--max-compactions", type=int, default=8)
    parser.add_argument("--max-model-calls", type=int, default=64)
    parser.add_argument("--wall-seconds", type=float, default=900)
    parser.add_argument("--request-timeout", type=float, default=300)
    parser.add_argument("--temperature", type=float, default=0.6)
    parser.add_argument("--json-fallback", action="store_true")
    args = parser.parse_args()
    if min(args.max_calls, args.max_tokens, args.max_tool_output_bytes, args.max_model_response_bytes,
           args.max_model_calls, args.compaction_max_tokens, args.compaction_min_tokens, args.max_compactions) < 1 or min(
               args.wall_seconds, args.request_timeout) <= 0 or args.context_margin_tokens < 0:
        parser.error("limits must be positive")
    if args.compaction_max_tokens < args.compaction_min_tokens:
        parser.error("compaction maximum must be at least the minimum available output budget")
    transcript_created = False
    try:
        transcript_path = Path(args.transcript)
        transcript_path.parent.mkdir(parents=True, exist_ok=True)
        with transcript_path.open("x", encoding="utf-8"):
            pass
        transcript_created = True
        return asyncio.run(run(args))
    except Exception as exc:
        if transcript_created:
            path = Path(args.transcript)
            with path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps({"event": "fatal_error", "observed_unix": time.time(),
                                         "client_pid": os.getpid(), "error_type": type(exc).__name__,
                                         "error": _error_summary(exc)}, ensure_ascii=False) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
