"""Focused read-only proof of runtime-generated name lengths and path scope."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pg_i7_mcp import server

workspace = server.RUNTIME_CAMPAIGNS / "boundary-probe-existing-only"
server._workspace = workspace
accepted = {length: server._run_path("r" * length) for length in (1, 80, 91, 97, 128)}
assert all(Path(value).parent == workspace / "runs" for value in accepted.values())
for rejected in ("r" * 129, "..\\outside", "C:\\outside", "runs\\nested"):
    try:
        server._run_path(rejected)
    except ValueError:
        continue
    raise AssertionError(f"unsafe/oversized run ref accepted: {rejected!r}")
run_tool = next(t for t in server.server._tool_manager.list_tools() if t.name == "verify")
assert run_tool.parameters["properties"]["from_run"]["pattern"] == server._RUN_ID.pattern
print({"status": "PASS", "accepted_lengths": sorted(accepted), "rejected": 4,
       "workspace_initialization": "NOT_PERFORMED", "producer_dispatch": "NOT_PERFORMED"})
