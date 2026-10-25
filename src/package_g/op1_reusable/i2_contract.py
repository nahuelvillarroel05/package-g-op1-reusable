"""Frozen I2 state and resource rules; synthetic engineering only."""
from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
from typing import Any, Mapping

from .identity import sha256_bytes, strict_json_loads, validate_id
from .schema_registry import SchemaRegistry


FROZEN_HASHES = {
    "OP1_SESSION_STATE_MACHINE.json": "dbca4f8a8202f7a196ed3fa3bb5954cc8de9cfaf6413db2c172adda22b7aa437",
    "OP1_RUN_STATE_MACHINE.json": "21d9f625ce5d4a533692d2934317f6f32594b6bf59bd63665e8a8cc76b388b06",
    "OP1_SESSION_POLICY.json": "bbe1b8027695f621c3f679626d86544f1e128db22eb592eb8d4a2ce4e0ac0569",
    "OP1_SESSION_CONTINUATION_POLICY.json": "02f293ade568b7ae8c039b7b5a4c6b47396dc5d5a844c382da00da97d5cdd972",
    "OP1_RUN_CLAIM_POLICY.json": "59bc24de030d3b20065ff3d6a2cffbf83d56fc2c9cea165546c1ed82648526c9",
}


class I2ContractError(ValueError):
    """An I2 proposal conflicts with its frozen design."""


def frozen_document(name: str) -> dict[str, Any]:
    expected = FROZEN_HASHES.get(name)
    if expected is None:
        raise I2ContractError("unbound I2 design document")
    raw = resources.files(__package__).joinpath("frozen_i2", name).read_bytes()
    if sha256_bytes(raw) != expected:
        raise I2ContractError("frozen I2 design bytes changed")
    value = strict_json_loads(raw)
    if not isinstance(value, dict):
        raise I2ContractError("frozen I2 document is not an object")
    return value


@dataclass(frozen=True)
class FrozenMachine:
    name: str
    states: frozenset[str]
    terminal_states: frozenset[str]
    edges: frozenset[tuple[str, str]]

    @classmethod
    def load(cls, name: str) -> "FrozenMachine":
        doc = frozen_document(name)
        states = frozenset(doc["states"])
        terminal = frozenset(doc["terminal_states"])
        edges = frozenset(
            (source, row["to"])
            for row in doc["transitions"]
            for source in row["from"].split("|")
        )
        if not terminal <= states or any(a not in states or b not in states for a, b in edges):
            raise I2ContractError("invalid frozen state inventory")
        if any(source in terminal for source, _ in edges):
            raise I2ContractError("terminal state has outgoing edge")
        return cls(name, states, terminal, edges)

    def require(self, previous: str, requested: str) -> None:
        if (previous, requested) not in self.edges:
            raise I2ContractError(f"forbidden {self.name} transition: {previous} -> {requested}")


SESSION_MACHINE = FrozenMachine.load("OP1_SESSION_STATE_MACHINE.json")
RUN_MACHINE = FrozenMachine.load("OP1_RUN_STATE_MACHINE.json")

_SCHEMAS = SchemaRegistry()
_BUDGET_SCHEMA = _SCHEMAS.find_document("OP1_RESOURCE_BUDGET_SCHEMA.json")
_budget_bytes = resources.files(__package__).joinpath("schemas", "OP1_RESOURCE_BUDGET_SCHEMA.json").read_bytes()
if sha256_bytes(_budget_bytes) != _BUDGET_SCHEMA.sha256:
    raise I2ContractError("frozen resource budget bytes changed")
_BUDGET_DOCUMENT = strict_json_loads(_budget_bytes)
SUM_DIMENSIONS = tuple(
    name for name, definition in _BUDGET_DOCUMENT["x-dimensions"].items()
    if definition["aggregation"] == "SUM"
)
MEMORY_DIMENSION = "memory_peak_bytes"
CONCURRENT_DIMENSION = "max_concurrent_runs"


def validate_budget(value: Mapping[str, Any]) -> dict[str, int]:
    result = _SCHEMAS.validate(_BUDGET_SCHEMA.schema_id, _BUDGET_SCHEMA.version, value)
    if not result.valid:
        raise I2ContractError("frozen resource budget schema rejected: " + "; ".join(result.errors))
    return dict(value)


@dataclass(frozen=True)
class BudgetView:
    reservations: Mapping[str, dict[str, int]]
    released: frozenset[str]
    cumulative: Mapping[str, int]
    active_memory: int
    active_runs: int

    @property
    def runs_reserved(self) -> int:
        return len(self.reservations)


def replay_budget(
    session_ceiling: Mapping[str, Any], max_runs: int, events: list[Mapping[str, Any]],
) -> BudgetView:
    """Rebuild balances from ordered, immutable reservation and cleanup events."""
    ceiling = validate_budget(session_ceiling)
    if type(max_runs) is not int or max_runs < 1:
        raise I2ContractError("invalid max_runs")
    reservations: dict[str, dict[str, int]] = {}
    released: set[str] = set()
    event_ids: set[str] = set()
    cumulative = {name: 0 for name in SUM_DIMENSIONS}
    active_memory = 0
    active_runs = 0
    for item in events:
        event_id = validate_id(item["event_id"], "EVENT")
        if event_id in event_ids:
            raise I2ContractError("duplicate budget event")
        event_ids.add(event_id)
        run_id = validate_id(item["run_id"], "RUN")
        kind = item["kind"]
        if kind == "RESERVE":
            if run_id in reservations or len(reservations) >= max_runs:
                raise I2ContractError("duplicate Run reservation or max_runs reached")
            budget = validate_budget(item["budget"])
            if any(budget[name] > ceiling[name] for name in budget):
                raise I2ContractError("Run ceiling exceeds Session ceiling")
            projected = {name: cumulative[name] + budget[name] for name in SUM_DIMENSIONS}
            if any(projected[name] > ceiling[name] for name in SUM_DIMENSIONS):
                raise I2ContractError("Session cumulative budget exceeded")
            if active_memory + budget[MEMORY_DIMENSION] > ceiling[MEMORY_DIMENSION]:
                raise I2ContractError("Session active memory budget exceeded")
            if active_runs + 1 > ceiling[CONCURRENT_DIMENSION]:
                raise I2ContractError("Session concurrent Run budget exceeded")
            reservations[run_id] = budget
            cumulative = projected
            active_memory += budget[MEMORY_DIMENSION]
            active_runs += 1
        elif kind == "RELEASE":
            if run_id not in reservations or run_id in released:
                raise I2ContractError("unknown or duplicate Run release")
            if item.get("durable_terminal_event_id") is None or item.get("cleanup_proven") is not True:
                raise I2ContractError("active reservation requires durable closure and proven cleanup")
            validate_id(item["durable_terminal_event_id"], "EVENT")
            released.add(run_id)
            active_memory -= reservations[run_id][MEMORY_DIMENSION]
            active_runs -= 1
        else:
            raise I2ContractError("unknown budget event")
    return BudgetView(reservations, frozenset(released), cumulative, active_memory, active_runs)
