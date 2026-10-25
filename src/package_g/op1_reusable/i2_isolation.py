"""Read-only, signed isolation observation for synthetic I2 uncertainty only."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .i2_authority import _utc
from .i2_contract import I2ContractError, replay_budget
from .identity import canonical_json, sha256_bytes, validate_id
from .i2_synthetic_executor import evaluate


SCHEMA = "package-g-op1-synthetic-isolation-observation@1"
METHOD = "INDEPENDENT_I1_REPLAY_SYNTHETIC_CAPABILITY_CHECK@1"
UNCERTAIN_STATES = frozenset({"UNKNOWN", "AMBIGUOUS_CONSUMPTION"})
# Engineering-reviewed exact code profile. Update only with a new preserved ENG attempt.
APPROVED_CAPABILITY = {
    "schema": "package-g-op1-i2-synthetic-no-worker-capability@1",
    "scope": "I2_ENGINEERING_SYNTHETIC_ONLY",
    "engine_source_sha256": "84cf12922fa71269b0fe6982fd84c0aa75cc817dbe60b8ff5ef1a150c935d5ed",
    "executor_source_sha256": "eda3a98255520ced3b912a9e6cb8a934aba952bf56a2e8da2b99e3a7fd46885b",
    "executor_code_sha256": "95da95ff54a4e8cc71f3cb91a50621d5c1f5acacb812afd18aca08d5a9f8797f",
    "external_effect_capability": False,
    "worker_dispatch_capability": False,
}


def executor_code_sha256(executor_callable: Any = evaluate) -> str:
    code = executor_callable.__code__
    return sha256_bytes(canonical_json({
        "bytecode_hex": code.co_code.hex(),
        "constants": list(code.co_consts),
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
    }))

def capability_profile_sha256() -> str:
    return sha256_bytes(canonical_json(APPROVED_CAPABILITY))

def verify_current_capability(executor_callable: Any = evaluate) -> dict[str, str]:
    from . import i2_synthetic_executor
    if (executor_callable is not evaluate
            or executor_callable is not i2_synthetic_executor.evaluate
            or executor_callable.__globals__ is not vars(i2_synthetic_executor)
            or executor_callable.__defaults__ is not None
            or executor_callable.__closure__ is not None
            or any(name in executor_callable.__globals__
                   for name in ("type", "str", "ValueError", "OUTCOMES"))):
        raise I2ContractError("synthetic executor callable or dependency differs from review")
    current = source_hashes()
    checks = {
        "engine_source_sha256": current["i2_engine.py"],
        "executor_source_sha256": current["i2_synthetic_executor.py"],
        "executor_code_sha256": executor_code_sha256(executor_callable),
    }
    for name, value in checks.items():
        if APPROVED_CAPABILITY[name] != value:
            raise I2ContractError("synthetic capability differs from reviewed exact code: " + name)
    return current
_CONTEXT_FIELDS = frozenset({
    "schema", "method", "session_id", "run_id", "namespace_id",
    "session_authority_id", "run_authority_id", "claim_id", "claim_event_id",
    "terminal_event_id", "launch_intent_id", "run_state",
    "frontier_event_id", "frontier_sequence", "budget_events_sha256",
    "capability_profile_sha256",
    "exact_binding_manifest_sha256", "source_sha256",
    "owned_worker_count", "owned_resource_count",
    "external_effect_capability", "cleanup_proven",
})
_REPORT_FIELDS = _CONTEXT_FIELDS | frozenset({
    "observer_actor_id", "observed_at_utc", "signature_hex",
})


def source_hashes() -> dict[str, str]:
    """Exact running synthetic control code bytes, independent of mutable snapshots."""
    from . import i2_authority, i2_contract, i2_engine, i2_journal, i2_synthetic_executor
    return {
        "i2_authority.py": sha256_bytes(Path(i2_authority.__file__).read_bytes()),
        "i2_contract.py": sha256_bytes(Path(i2_contract.__file__).read_bytes()),
        "i2_engine.py": sha256_bytes(Path(i2_engine.__file__).read_bytes()),
        "i2_journal.py": sha256_bytes(Path(i2_journal.__file__).read_bytes()),
        "i2_isolation.py": sha256_bytes(Path(__file__).read_bytes()),
        "i2_synthetic_executor.py": sha256_bytes(
            Path(i2_synthetic_executor.__file__).read_bytes()),
    }


def context_for(engine: Any, history: tuple[Any, ...],
                session_id: str, run_id: str,
                sessions: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Reconstruct a narrow no-worker synthetic isolation context from I1 history."""
    if not history:
        raise I2ContractError("isolation requires committed I1 history")
    live_decision = sessions is None
    if sessions is None:
        sessions = engine.replay(history)
    session = sessions.get(session_id)
    run = None if session is None else session.runs.get(run_id)
    if session is None or session.state != "ACTIVE" or run is None:
        raise I2ContractError("isolation requires ACTIVE Session and admitted Run")
    if run.state not in UNCERTAIN_STATES or run.terminal_event_id is None:
        raise I2ContractError("isolation requires terminal uncertain Run")
    if run.claim is None or run.claim["state"] != "CONSUMED" or run.claim_event_id is None:
        raise I2ContractError("isolation requires one consumed claim")
    observations = [
        item for item in history
        if item.payload.get("kind") == "SYNTHETIC_OBSERVATION"
        and item.payload.get("subject_session_id") == session_id
        and item.payload.get("subject_run_id") == run_id
    ]
    if len(observations) != 1:
        raise I2ContractError("isolation requires one synthetic outcome observation")
    observation = observations[0].payload
    reservation = session.reservations[run_id].payload
    profile_hash = reservation.get("capability_profile_sha256")
    execution_source = reservation.get("source_sha256")
    if not isinstance(execution_source, dict):
        raise I2ContractError("synthetic reservation lacks source commitment")
    terminal = [item for item in history if item.event_id == run.terminal_event_id]
    if (len(terminal) != 1 or observation.get("outcome") != "UNKNOWN"
            or observations[0].evidence_id not in terminal[0].payload.get("evidence_ids", [])):
        raise I2ContractError("uncertain terminal lacks matching synthetic observation")
    if (observation.get("adapter") != "I2_DETERMINISTIC_SYNTHETIC"
            or observation.get("synthetic_only") is not True
            or observation.get("physical_c2_executed") is not False
            or observation.get("owned_worker_count") != 0
            or observation.get("owned_resource_count") != 0
            or observation.get("external_effect_capability") is not False):
        raise I2ContractError("synthetic adapter capability boundary unproven")
    namespace_ids = [
        item.payload["namespace_id"] for item in history
        if item.payload.get("kind") == "RUN_RESERVATION"
    ]
    if namespace_ids.count(run.authority["namespace_id"]) != 1:
        raise I2ContractError("synthetic namespace isolation unproven")
    launches = [
        item for item in history
        if item.payload.get("kind") == "RUN_TRANSITION"
        and item.payload.get("subject_session_id") == session_id
        and item.payload.get("subject_run_id") == run_id
        and item.payload.get("resulting_state") == "EXECUTING"
    ]
    if len(launches) != 1 or launches[0].payload.get("launch_intent_id") is None:
        raise I2ContractError("synthetic launch intent history unproven")
    if (launches[0].payload.get("source_sha256") != execution_source
            or launches[0].payload.get("capability_profile_sha256") != profile_hash
            or observation.get("source_sha256") != execution_source
            or observation.get("capability_profile_sha256") != profile_hash):
        raise I2ContractError("synthetic capability commitment changed after reservation")
    if live_decision:
        if verify_current_capability() != execution_source:
            raise I2ContractError("synthetic current code differs from reservation")
        if profile_hash != capability_profile_sha256():
            raise I2ContractError("synthetic reviewed capability profile mismatch")
        exact = engine.read_exact_binding(run.authority["exact_binding_manifest_relative_path"])
        if sha256_bytes(exact) != run.authority["exact_binding_manifest_sha256"]:
            raise I2ContractError("synthetic exact binding changed")
    replay_budget(session.authority["resource_ceilings"],
                  session.authority["max_runs"], session.budget_events)
    result = {
        "schema": SCHEMA, "method": METHOD,
        "session_id": session_id, "run_id": run_id,
        "namespace_id": run.authority["namespace_id"],
        "session_authority_id": session.authority["authority_id"],
        "run_authority_id": run.authority["authority_id"],
        "claim_id": run.claim["claim_id"],
        "claim_event_id": run.claim_event_id,
        "terminal_event_id": run.terminal_event_id,
        "launch_intent_id": launches[0].payload["launch_intent_id"],
        "run_state": run.state,
        "frontier_event_id": history[-1].event_id,
        "frontier_sequence": history[-1].sequence,
        "budget_events_sha256": sha256_bytes(canonical_json(session.budget_events)),
        "exact_binding_manifest_sha256": run.authority["exact_binding_manifest_sha256"],
        "capability_profile_sha256": profile_hash,
        "source_sha256": execution_source,
        "owned_worker_count": 0, "owned_resource_count": 0,
        "external_effect_capability": False, "cleanup_proven": True,
    }
    return result


def signed_report(read_only_engine: Any, session_id: str, run_id: str,
                  observer_actor_id: str, observer_key: Ed25519PrivateKey,
                  observed_at_utc: str) -> dict[str, Any]:
    """An independent observer can only inspect a read-only I1 handle and sign facts."""
    if read_only_engine.journal.store._writer_private_key is not None:
        raise I2ContractError("isolation observer requires read-only I1 handle")
    validate_id(observer_actor_id, "ACTOR")
    if not isinstance(observer_key, Ed25519PrivateKey):
        raise I2ContractError("isolation observer signing key absent")
    history = read_only_engine.journal.history()
    report = context_for(read_only_engine, history, session_id, run_id)
    session = read_only_engine.replay(history)[session_id]
    if observer_actor_id in {
        session.authority["owner_actor_id"], session.authority["issuer_actor_id"],
        read_only_engine.journal.store.actor_id,
    }:
        raise I2ContractError("isolation observer is not independent")
    report.update(observer_actor_id=observer_actor_id, observed_at_utc=observed_at_utc)
    report["signature_hex"] = observer_key.sign(canonical_json(report)).hex()
    return report


def verify_report(report: Mapping[str, Any],
                  trusted_observers: Mapping[str, Ed25519PublicKey],
                  *, owner_actor_id: str, issuer_actor_id: str,
                  store_actor_id: str) -> None:
    if not isinstance(report, Mapping) or set(report) != _REPORT_FIELDS:
        raise I2ContractError("synthetic isolation report shape invalid")
    actor = validate_id(report["observer_actor_id"], "ACTOR")
    if actor in {owner_actor_id, issuer_actor_id, store_actor_id}:
        raise I2ContractError("isolation observer is not independent")
    key = trusted_observers.get(actor)
    if not isinstance(key, Ed25519PublicKey):
        raise I2ContractError("untrusted isolation observer")
    try:
        signature = bytes.fromhex(report["signature_hex"])
        unsigned = dict(report)
        unsigned.pop("signature_hex")
        key.verify(signature, canonical_json(unsigned))
    except (ValueError, InvalidSignature) as exc:
        raise I2ContractError("isolation observer signature invalid") from exc
    for name, kind in (
        ("session_id", "SESSION"), ("run_id", "RUN"),
        ("namespace_id", "NAMESPACE"), ("session_authority_id", "AUTHORITY"),
        ("run_authority_id", "AUTHORITY"), ("claim_id", "CLAIM"),
        ("claim_event_id", "EVENT"), ("terminal_event_id", "EVENT"),
        ("launch_intent_id", "EVENT"), ("frontier_event_id", "EVENT"),
    ):
        validate_id(report[name], kind)
    _utc(report["observed_at_utc"])
    if report["schema"] != SCHEMA or report["method"] != METHOD:
        raise I2ContractError("isolation observation method mismatch")
    if (report["run_state"] not in UNCERTAIN_STATES
            or report["owned_worker_count"] != 0
            or report["owned_resource_count"] != 0
            or report["external_effect_capability"] is not False
            or report["cleanup_proven"] is not True):
        raise I2ContractError("isolation report does not prove synthetic containment")
    if type(report["frontier_sequence"]) is not int or report["frontier_sequence"] < 1:
        raise I2ContractError("isolation frontier sequence invalid")
    if not isinstance(report["source_sha256"], dict) or set(report["source_sha256"]) != {
        "i2_authority.py", "i2_contract.py", "i2_engine.py",
        "i2_journal.py", "i2_isolation.py", "i2_synthetic_executor.py",
    }:
        raise I2ContractError("isolation source inventory invalid")
    for digest in (*report["source_sha256"].values(),
                   report["capability_profile_sha256"],
                   report["budget_events_sha256"],
                   report["exact_binding_manifest_sha256"]):
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise I2ContractError("isolation digest invalid")
