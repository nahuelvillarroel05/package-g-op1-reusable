"""Event-replayed I2 Session/Run control plane for synthetic engineering."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .i2_authority import (
    _utc, claim_slot_preimage, require_time_window, verify_claim_record, verify_run_authority,
    verify_run_record, verify_session_authority,
)
from .i2_contract import (
    I2ContractError, RUN_MACHINE, SESSION_MACHINE, frozen_document, replay_budget,
)
from .i2_journal import I2Journal, JournalRecord
from .i2_isolation import (
    UNCERTAIN_STATES, capability_profile_sha256, context_for,
    verify_current_capability, verify_report,
)
from .i2_synthetic_executor import evaluate
from .identity import canonical_json, generate_id, sha256_bytes, validate_id
from .storage_paths import Scope


TERMINAL_RUN_STATES = RUN_MACHINE.terminal_states
SAFE_CONTINUATION_STATES = {"PASS", "FAIL", "BLOCKED_PRESTATE", "TIMEOUT", "CONSUMED_FAILED"}
CREATED_QUARANTINE_REASONS = {
    "authority_integrity_failure", "protected_source_mismatch", "session_policy_mismatch",
}


@dataclass
class SessionView:
    session_id: str
    authority: dict[str, Any]
    proof: bytes
    state: str
    scope: Scope
    reservations: dict[str, JournalRecord] = field(default_factory=dict)
    runs: dict[str, "RunView"] = field(default_factory=dict)
    budget_events: list[dict[str, Any]] = field(default_factory=list)
    continued_terminals: set[str] = field(default_factory=set)
    used_ids: set[str] = field(default_factory=set)


@dataclass
class RunView:
    run_id: str
    record: dict[str, Any]
    authority: dict[str, Any]
    proof: bytes
    scope: Scope
    state: str = "CREATED"
    claim: dict[str, Any] | None = None
    claim_event_id: str | None = None
    terminal_event_id: str | None = None
    cleanup_proven: bool = False
    prestate_evidence_id: str | None = None
    prestate_pass: bool | None = None
    observation_evidence_ids: list[str] = field(default_factory=list)
    observation_outcomes: dict[str, str] = field(default_factory=dict)
    launch_source_sha256: dict[str, str] | None = None
    launch_capability_profile_sha256: str | None = None
    launch_intent_id: str | None = None
    isolation_report: dict[str, Any] | None = None
    isolation_event_id: str | None = None
    isolation_evidence_id: str | None = None


class I2Engine:
    """No runtime adapter, network, broker, or Physical C2 entrypoint."""
    def __init__(
        self, journal: I2Journal, trusted_issuers: Mapping[str, Ed25519PublicKey],
        read_exact_binding: Callable[[str], bytes],
        trusted_isolation_observers: Mapping[str, Ed25519PublicKey] | None = None,
    ) -> None:
        self.journal = journal
        self.trusted_issuers = trusted_issuers
        self.read_exact_binding = read_exact_binding
        self.trusted_isolation_observers = dict(trusted_isolation_observers or {})
        # This process-local permit is issued only after the claim transaction
        # returns with durable readback. Replay never recreates dispatch custody.
        self._launch_permits: dict[str, str] = {}
        # The synthetic executor may run once only after a durable launch ack.
        # Restart and lost acknowledgement never reconstruct this permit.
        self._execute_permits: dict[str, str] = {}

    def replay(self, history: tuple[JournalRecord, ...] | None = None) -> dict[str, SessionView]:
        records = self.journal.history() if history is None else history
        sessions: dict[str, SessionView] = {}
        seen_ids: set[str] = set()
        for position, item in enumerate(records):
            payload = item.payload
            kind = payload.get("kind")
            if kind == "REJECTION":
                seen_ids.update((item.scope.run_id, item.scope.attempt_id))
                continue
            session_id = payload.get("subject_session_id")
            validate_id(session_id, "SESSION")
            if item.scope.session_id != session_id:
                raise I2ContractError("cross-Session custody injection")
            if kind == "SESSION_CREATED":
                if session_id in sessions:
                    raise I2ContractError("duplicate Session ID in history")
                authority = payload["authority"]
                proof = bytes.fromhex(payload["proof_hex"])
                verify_session_authority(authority, proof, self.trusted_issuers,
                                         payload["observed_at_utc"])
                if authority["session_id"] != session_id:
                    raise I2ContractError("Session authority subject mismatch")
                sessions[session_id] = SessionView(session_id, authority, proof, "CREATED", item.scope,
                                                   used_ids=seen_ids)
                seen_ids.update((session_id, authority["authority_id"],
                                 item.scope.run_id, item.scope.attempt_id))
                continue
            session = sessions.get(session_id)
            if session is None:
                raise I2ContractError("I2 history references unknown Session")
            if kind == "SESSION_TRANSITION":
                previous, next_state = payload["previous_state"], payload["resulting_state"]
                if previous != session.state or next_state != payload["requested_next_state"]:
                    raise I2ContractError("Session transition history rollback or mismatch")
                SESSION_MACHINE.require(previous, next_state)
                if payload.get("session_authority_id") != session.authority["authority_id"]:
                    raise I2ContractError("Session transition authority mismatch")
                if previous == "CREATED" and next_state == "ACTIVE":
                    verify_session_authority(session.authority, session.proof,
                                             self.trusted_issuers,
                                             payload["observed_at_utc"])
                if "terminal_run_id" not in payload:
                    if previous == "ACTIVE" and next_state == "EXPIRED":
                        if (payload.get("reason") != "expiry"
                                or _utc(payload["observed_at_utc"]) < _utc(
                                    session.authority["expires_at_utc"])):
                            raise I2ContractError("Session expiry transition is premature")
                    elif previous == "ACTIVE" and next_state == "TERMINATED":
                        reason = payload.get("reason")
                        if reason == "MAX_RUNS":
                            budget = replay_budget(session.authority["resource_ceilings"],
                                                   session.authority["max_runs"],
                                                   session.budget_events)
                            if (budget.runs_reserved < session.authority["max_runs"]
                                    or budget.active_runs):
                                raise I2ContractError("Session max_runs termination is premature")
                        elif reason in {"OWNER_TERMINATION", "EXPLICIT_REVOKE"}:
                            if payload.get("owner_authorized") is not True:
                                raise I2ContractError("Session owner termination lacks authority")
                        else:
                            raise I2ContractError("Session termination reason is unsupported")
                if next_state == "QUARANTINED" and "terminal_run_id" not in payload:
                    reason = payload.get("reason")
                    quarantine = frozen_document(
                        "OP1_SESSION_CONTINUATION_POLICY.json")["quarantine_or_terminate"]
                    if (reason not in quarantine or quarantine[reason] != "QUARANTINE"
                            or previous == "CREATED" and reason not in CREATED_QUARANTINE_REASONS):
                        raise I2ContractError("Session quarantine reason violates frozen guard")
                if "terminal_run_id" in payload:
                    if previous != "ACTIVE":
                        raise I2ContractError("Session continuation requires ACTIVE predecessor")
                    terminal = payload["terminal_run_id"]
                    run = session.runs.get(terminal)
                    if (run is None or run.state not in TERMINAL_RUN_STATES
                            or terminal in session.continued_terminals):
                        raise I2ContractError("Session continuation lacks fresh terminal Run")
                    budget = replay_budget(session.authority["resource_ceilings"],
                                           session.authority["max_runs"], session.budget_events)
                    prior = records[position - 1] if position else None
                    isolated = bool(run.state in UNCERTAIN_STATES
                                and run.isolation_report is not None
                                and run.isolation_report.get("cleanup_proven") is True
                                and terminal in budget.released
                                and prior is not None
                                and prior.payload.get("kind") == "BUDGET_RELEASE"
                                and prior.payload.get("subject_run_id") == terminal
                                and prior.payload.get("isolation_event_id") == run.isolation_event_id
                                and payload.get("isolation_event_id") == run.isolation_event_id
                                and payload.get("budget_release_event_id") == prior.event_id
                                and run.isolation_evidence_id in payload.get("evidence_ids", []))
                    if payload.get("independent_isolation_proven") is not isolated:
                        raise I2ContractError("Session continuation isolation classification mismatch")
                    mandatory = set()
                    if run.state not in SAFE_CONTINUATION_STATES and not isolated:
                        mandatory.add("UNCONTAINED_RUN_UNCERTAINTY")
                    if not run.cleanup_proven and not isolated:
                        mandatory.add("CLEANUP_NOT_PROVEN")
                    if terminal not in budget.released:
                        mandatory.add("RESOURCE_RESERVATION_NOT_RELEASED")
                    if _utc(payload["observed_at_utc"]) >= _utc(session.authority["expires_at_utc"]):
                        mandatory.add("EXPIRY")
                    if budget.runs_reserved >= session.authority["max_runs"]:
                        mandatory.add("MAX_RUNS")
                    findings = payload.get("applicable_findings")
                    optional = {"PROTECTED_SOURCE_MISMATCH", "AUTHORITY_INTEGRITY_FAILURE"}
                    if (not isinstance(findings, list) or len(findings) != len(set(findings))
                            or not mandatory <= set(findings)
                            or not set(findings) <= mandatory | optional):
                        raise I2ContractError("Session continuation findings differ from history")
                    contaminated = {
                        "UNCONTAINED_RUN_UNCERTAINTY", "CLEANUP_NOT_PROVEN",
                        "RESOURCE_RESERVATION_NOT_RELEASED", *optional,
                    }
                    expected = (
                        "QUARANTINED" if contaminated.intersection(findings) else
                        "EXPIRED" if "EXPIRY" in findings else
                        "TERMINATED" if "MAX_RUNS" in findings and budget.active_runs == 0 else
                        "ACTIVE"
                    )
                    if next_state != expected:
                        raise I2ContractError("Session continuation terminal state differs from frozen policy")
                if next_state == "ACTIVE" and previous == "ACTIVE":
                    terminal = payload["terminal_run_id"]
                    run = session.runs.get(terminal)
                    if (run is None or run.state not in TERMINAL_RUN_STATES
                            or terminal in session.continued_terminals):
                        raise I2ContractError("continuation lacks fresh terminal Run")
                    budget = replay_budget(session.authority["resource_ceilings"],
                                           session.authority["max_runs"],
                                           session.budget_events)
                    if (terminal not in budget.released
                            or _utc(payload["observed_at_utc"]) >= _utc(
                                session.authority["expires_at_utc"])
                            ):
                        raise I2ContractError("continuation violates cleanup or expiry")
                    if run.state not in SAFE_CONTINUATION_STATES and run.state not in UNCERTAIN_STATES:
                        raise I2ContractError("continuation of unsafe terminal Run")
                    if run.state in UNCERTAIN_STATES:
                        prior = records[position - 1] if position else None
                        if (payload.get("independent_isolation_proven") is not True
                                or run.isolation_report is None
                                or terminal not in budget.released
                                or payload.get("isolation_event_id") != run.isolation_event_id
                                or run.isolation_evidence_id not in payload.get("evidence_ids", [])
                                or prior is None
                                or prior.payload.get("kind") != "BUDGET_RELEASE"
                                or prior.payload.get("subject_run_id") != terminal
                                or prior.payload.get("isolation_event_id") != run.isolation_event_id
                                or payload.get("budget_release_event_id") != prior.event_id):
                            raise I2ContractError("uncertain Run continuation lacks fresh independent isolation")
                    session.continued_terminals.add(terminal)
                session.state = next_state
            elif kind == "RUN_RESERVATION":
                run_id = validate_id(payload["subject_run_id"], "RUN")
                if run_id in seen_ids or session.state != "ACTIVE":
                    raise I2ContractError("duplicate Run ID or inactive Session")
                if item.scope.run_id != run_id or item.scope.attempt_id != payload["attempt_id"]:
                    raise I2ContractError("Run reservation custody scope mismatch")
                if session.authority["session_id"] != item.scope.session_id:
                    raise I2ContractError("cross-Session reservation")
                reservation_authority = payload.get("authority")
                if not isinstance(reservation_authority, dict):
                    raise I2ContractError("reservation lacks signed Run authority")
                reservation_proof = bytes.fromhex(payload["proof_hex"])
                verify_run_authority(
                    reservation_authority, reservation_proof, self.trusted_issuers,
                    session.authority, canonical_json(session.authority),
                    payload["observed_at_utc"],
                    lambda _: canonical_json(reservation_authority["exact_binding_manifest"]),
                )
                if (payload["budget"] != reservation_authority["resource_ceilings"]
                        or payload["run_authority_id"] != reservation_authority["authority_id"]
                        or payload["claim_id"] != reservation_authority["claim_id"]
                        or payload["namespace_id"] != reservation_authority["namespace_id"]
                        or payload["attempt_id"] != reservation_authority["attempt_id"]
                        or run_id != reservation_authority["run_id"]):
                    raise I2ContractError("reservation budget or identity differs from signed Run authority")
                source = payload.get("source_sha256")
                if (not isinstance(source, dict)
                        or set(source) != {"i2_authority.py", "i2_contract.py",
                                           "i2_engine.py", "i2_journal.py",
                                           "i2_isolation.py", "i2_synthetic_executor.py"}
                        or any(not isinstance(value, str) or len(value) != 64
                               for value in source.values())
                        or not isinstance(payload.get("capability_profile_sha256"), str)
                        or len(payload["capability_profile_sha256"]) != 64):
                    raise I2ContractError("Run reservation lacks synthetic capability commitment")
                budget_event = {
                    "kind": "RESERVE", "event_id": item.event_id,
                    "run_id": run_id, "budget": payload["budget"],
                }
                session.budget_events.append(budget_event)
                replay_budget(session.authority["resource_ceilings"],
                              session.authority["max_runs"], session.budget_events)
                session.reservations[run_id] = item
                for name in ("run_authority_id", "claim_id", "namespace_id", "attempt_id"):
                    candidate = payload[name]
                    if candidate in seen_ids:
                        raise I2ContractError(f"reused {name}")
                    seen_ids.add(candidate)
                seen_ids.add(run_id)
            elif kind == "RUN_ADMITTED":
                if session.state != "ACTIVE":
                    raise I2ContractError("Run admitted under inactive Session history")
                run_record = payload["run"]
                run_id = run_record["run_id"]
                if item.scope.run_id != run_id or item.scope.attempt_id != payload["authority"]["attempt_id"]:
                    raise I2ContractError("Run admission custody scope mismatch")
                reservation = session.reservations.get(run_id)
                if reservation is None or run_id in session.runs:
                    raise I2ContractError("Run admission without unique reservation")
                auth = payload["authority"]
                proof = bytes.fromhex(payload["proof_hex"])
                verify_run_record(run_record, auth, session.authority, reservation.event_id)
                if (auth != reservation.payload["authority"]
                        or proof.hex() != reservation.payload["proof_hex"]
                        or auth["resource_ceilings"] != reservation.payload["budget"]):
                    raise I2ContractError("Run authority or budget differs from reservation")
                session.runs[run_id] = RunView(run_id, run_record, auth, proof, item.scope)
            elif kind == "PRESTATE_OBSERVATION":
                run_id = validate_id(payload["subject_run_id"], "RUN")
                run = session.runs.get(run_id)
                if item.scope.run_id != run_id or run is None or run.state != "CREATED":
                    raise I2ContractError("prestate observation outside CREATED Run")
                if run.prestate_evidence_id is not None or payload.get("synthetic_only") is not True:
                    raise I2ContractError("duplicate or non-synthetic prestate observation")
                result = payload.get("prestate_result")
                if result not in {"PASS", "FAIL", "UNKNOWN"}:
                    raise I2ContractError("invalid prestate observation result")
                run.prestate_evidence_id = item.evidence_id
                run.prestate_pass = True if result == "PASS" else False if result == "FAIL" else None
            elif kind == "RUN_ATOMIC_PATH":
                run_id = validate_id(payload["subject_run_id"], "RUN")
                run = session.runs.get(run_id)
                if item.scope.run_id != run_id or run is None or run.state != "CREATED":
                    raise I2ContractError("atomic path requires admitted CREATED Run")
                first, second = payload["logical_events"]
                if run.prestate_evidence_id is None or payload.get("prestate_evidence_id") != run.prestate_evidence_id:
                    raise I2ContractError("atomic path lacks bound prestate observation")
                if run.prestate_evidence_id not in first["evidence_ids"] or run.prestate_evidence_id not in second["evidence_ids"]:
                    raise I2ContractError("atomic path lost prestate evidence")
                if first["session_authority_id"] != session.authority["authority_id"] or first["run_authority_id"] != run.authority["authority_id"]:
                    raise I2ContractError("atomic path authority mismatch")
                outcome = second["resulting_state"]
                if outcome == "CLAIMED":
                    if run.prestate_pass is not True or run.claim is not None:
                        raise I2ContractError("atomic claim lacks passing prestate or unique slot")
                    claim = second["claim"]
                    verify_claim_record(claim, run.record, run.authority,
                                        canonical_json(run.authority),
                                        session.reservations[run_id].event_id)
                    if claim["state"] != "CONSUMED":
                        raise I2ContractError("atomic claim not durably consumed")
                    if payload.get("claim_slot_preimage_hex") != claim_slot_preimage(claim).hex():
                        raise I2ContractError("atomic claim slot readback bytes mismatch")
                    run.claim = claim
                    run.claim_event_id = second["event_id"]
                elif outcome == "BLOCKED_PRESTATE":
                    if "claim_slot_preimage_hex" in payload:
                        raise I2ContractError("blocked prestate path contains Claim slot bytes")
                    if run.prestate_pass is True or second.get("cleanup_proven") is not True:
                        raise I2ContractError("atomic prestate block lacks failed/unknown observation or cleanup")
                    run.terminal_event_id = second["event_id"]
                    run.cleanup_proven = True
                else:
                    raise I2ContractError("unsupported atomic Run outcome")
                run.state = outcome
            elif kind == "RUN_TRANSITION":
                run_id = validate_id(payload["subject_run_id"], "RUN")
                if item.scope.run_id != run_id:
                    raise I2ContractError("Run transition custody scope mismatch")
                run = session.runs.get(run_id)
                if run is None:
                    raise I2ContractError("transition for unadmitted Run")
                previous, next_state = payload["previous_state"], payload["resulting_state"]
                if previous != run.state or next_state != payload["requested_next_state"]:
                    raise I2ContractError("Run transition history rollback or mismatch")
                RUN_MACHINE.require(previous, next_state)
                if (payload.get("session_authority_id") != session.authority["authority_id"]
                        or payload.get("run_authority_id") != run.authority["authority_id"]):
                    raise I2ContractError("Run transition authority mismatch")
                if next_state in {"PRESTATE", "CLAIMED", "BLOCKED_PRESTATE"}:
                    raise I2ContractError("standalone fresh Run path bypasses atomic I1 publication")
                if next_state == "EXECUTING":
                    reservation = session.reservations[run_id].payload
                    if (run.claim is None or payload.get("launch_intent_id") != item.event_id
                            or payload.get("dispatch_mode") != "NO_WORKER_SYNTHETIC"
                            or payload.get("source_sha256") != reservation["source_sha256"]
                            or payload.get("capability_profile_sha256") !=
                            reservation["capability_profile_sha256"]):
                        raise I2ContractError("EXECUTING lacks bound synthetic launch intent")
                    run.launch_source_sha256 = dict(payload["source_sha256"])
                    run.launch_capability_profile_sha256 = payload["capability_profile_sha256"]
                    run.launch_intent_id = item.event_id
                if next_state in TERMINAL_RUN_STATES:
                    if run.terminal_event_id is not None:
                        raise I2ContractError("duplicate terminal closure")
                    if next_state in {"PASS", "FAIL", "TIMEOUT", "CRASHED", "INCOMPLETE_EVIDENCE"}:
                        evidence = payload.get("evidence_ids")
                        if (not isinstance(evidence, list) or not evidence
                                or any(run.observation_outcomes.get(item_id) != next_state
                                       for item_id in evidence)):
                            raise I2ContractError("terminal result differs from synthetic observation")
                    run.terminal_event_id = item.event_id
                    run.cleanup_proven = payload.get("cleanup_proven") is True
                run.state = next_state
            elif kind == "SYNTHETIC_OBSERVATION":
                run = session.runs.get(payload["subject_run_id"])
                if item.scope.run_id != payload["subject_run_id"]:
                    raise I2ContractError("synthetic observation custody scope mismatch")
                if run is None or run.state != "EXECUTING":
                    raise I2ContractError("synthetic observation outside execution")
                if (payload.get("adapter") != "I2_DETERMINISTIC_SYNTHETIC"
                        or payload.get("synthetic_only") is not True
                        or payload.get("physical_c2_executed") is not False
                        or payload.get("owned_worker_count") != 0
                        or payload.get("owned_resource_count") != 0
                        or payload.get("external_effect_capability") is not False
                        or payload.get("source_sha256") != run.launch_source_sha256
                        or payload.get("capability_profile_sha256") !=
                        run.launch_capability_profile_sha256):
                    raise I2ContractError("synthetic observation capability mismatch")
                outcome = payload.get("outcome")
                if (run.observation_evidence_ids or outcome not in {
                        "PASS", "FAIL", "TIMEOUT", "CRASHED", "UNKNOWN", "INCOMPLETE_EVIDENCE"}):
                    raise I2ContractError("duplicate or invalid synthetic outcome")
                run.observation_evidence_ids.append(item.evidence_id)
                run.observation_outcomes[item.evidence_id] = outcome
            elif kind == "ISOLATION_OBSERVATION":
                run_id = validate_id(payload["subject_run_id"], "RUN")
                run = session.runs.get(run_id)
                if item.scope.run_id != run_id or run is None or run.state not in UNCERTAIN_STATES:
                    raise I2ContractError("isolation observation outside uncertain Run")
                if run.isolation_report is not None or position == 0:
                    raise I2ContractError("duplicate or unanchored isolation observation")
                report = payload["report"]
                verify_report(report, self.trusted_isolation_observers,
                              owner_actor_id=session.authority["owner_actor_id"],
                              issuer_actor_id=session.authority["issuer_actor_id"],
                              store_actor_id=self.journal.store.actor_id)
                prior = records[position - 1]
                expected = context_for(self, records[:position], session_id, run_id, sessions)
                if any(report[name] != value for name, value in expected.items()):
                    raise I2ContractError("isolation report replay context mismatch")
                if (report["frontier_event_id"] != prior.event_id
                        or report["frontier_sequence"] != prior.sequence
                        or report["session_id"] != session_id
                        or report["run_id"] != run_id
                        or report["namespace_id"] != run.authority["namespace_id"]
                        or report["session_authority_id"] != session.authority["authority_id"]
                        or report["run_authority_id"] != run.authority["authority_id"]
                        or report["claim_id"] != run.claim["claim_id"]
                        or report["claim_event_id"] != run.claim_event_id
                        or report["terminal_event_id"] != run.terminal_event_id
                        or report["run_state"] != run.state
                        or report["budget_events_sha256"] != sha256_bytes(
                            canonical_json(session.budget_events))):
                    raise I2ContractError("isolation report history binding mismatch")
                run.isolation_report = dict(report)
                run.isolation_event_id = item.event_id
                run.isolation_evidence_id = item.evidence_id
            elif kind == "BUDGET_RELEASE":
                run_id = payload["subject_run_id"]
                run = session.runs.get(run_id)
                if run is None or run.terminal_event_id != payload.get("durable_terminal_event_id"):
                    raise I2ContractError("release lacks terminal Run")
                if run.state in UNCERTAIN_STATES:
                    if (run.isolation_report is None
                            or run.isolation_report["cleanup_proven"] is not True
                            or payload.get("isolation_event_id") != run.isolation_event_id
                            or position == 0
                            or records[position - 1].event_id != run.isolation_event_id):
                        raise I2ContractError("uncertain release lacks independent cleanup proof")
                elif run.cleanup_proven is not True:
                    raise I2ContractError("release lacks terminal Run cleanup proof")
                event = {
                    "kind": "RELEASE", "event_id": item.event_id, "run_id": run_id,
                    "durable_terminal_event_id": run.terminal_event_id,
                    "cleanup_proven": payload.get("cleanup_proven"),
                }
                session.budget_events.append(event)
                replay_budget(session.authority["resource_ceilings"],
                              session.authority["max_runs"], session.budget_events)
            else:
                raise I2ContractError("unknown I2 domain record")
        return sessions

    def _decision(self, scope: Scope, build: Callable[..., dict[str, Any]],
                  now: str, *, with_history: bool = False) -> JournalRecord:
        def choose(history: tuple[JournalRecord, ...]) -> dict[str, Any]:
            snapshot = self.replay(history)
            try:
                prior_times = [item.payload["observed_at_utc"] for item in history
                               if item.payload.get("subject_session_id") == scope.session_id
                               and item.payload.get("kind") != "REJECTION"
                               and "observed_at_utc" in item.payload]
                if prior_times and _utc(now) < max(_utc(value) for value in prior_times):
                    raise I2ContractError("clock moved backward or became ambiguous")
                return build(snapshot, history) if with_history else build(snapshot)
            except (I2ContractError, KeyError, TypeError, ValueError, OSError) as exc:
                return {
                    "kind": "REJECTION", "subject_session_id": scope.session_id,
                    "subject_run_id": scope.run_id,
                    "candidate_run_id": scope.run_id,
                    "candidate_attempt_id": scope.attempt_id,
                    "audit_rejection": True,
                    "error_id": generate_id("ERROR"),
                    "reason": str(exc), "candidate_digest": sha256_bytes(
                        canonical_json({"scope": scope.__dict__, "error": str(exc)})),
                    "evidence_ids": [history[-1].evidence_id] if history else [],
                }
        return self.journal.transact(scope, choose)

    def create_session(self, authority: Mapping[str, Any], proof: bytes, now: str) -> JournalRecord:
        session_id = validate_id(authority["session_id"], "SESSION")
        identity = authority["identity"]
        scope = Scope(
            identity["project_id"], authority["product_id"], authority["lineage_id"],
            authority["version_id"], session_id, generate_id("RUN"), generate_id("ATTEMPT"),
        )
        def build(sessions):
            if session_id in sessions:
                raise I2ContractError("duplicate Session ID")
            verify_session_authority(authority, proof, self.trusted_issuers, now)
            policy = frozen_document("OP1_SESSION_POLICY.json")["profiles"][authority["profile"]]
            if not set(authority["allowed_operation_classes"]) <= set(policy["allowed_operation_classes"]):
                raise I2ContractError("Session operation class outside frozen profile")
            if authority["lineage_id"] != self.journal.store.lineage_id:
                raise I2ContractError("Session lineage differs from I1 store")
            if authority["evidence_root"] != str(self.journal.store.root):
                raise I2ContractError("Session evidence root mismatch")
            return {
                "kind": "SESSION_CREATED", "subject_session_id": session_id,
                "authority": dict(authority), "proof_hex": proof.hex(),
                "observed_at_utc": now, "previous_state": None,
                "requested_next_state": "CREATED", "resulting_state": "CREATED",
                "evidence_ids": [],
            }
        return self._decision(scope, build, now)

    def activate_session(self, session_id: str, now: str) -> JournalRecord:
        sessions = self.replay()
        session = sessions[session_id]
        def build(current):
            value = current[session_id]
            if value.state != "CREATED":
                raise I2ContractError("Session not CREATED")
            verify_session_authority(value.authority, value.proof, self.trusted_issuers, now)
            SESSION_MACHINE.require("CREATED", "ACTIVE")
            return {
                "kind": "SESSION_TRANSITION", "subject_session_id": session_id,
                "previous_state": "CREATED", "requested_next_state": "ACTIVE",
                "resulting_state": "ACTIVE", "observed_at_utc": now,
                "session_authority_id": value.authority["authority_id"],
                "evidence_ids": [],
            }
        return self._decision(session.scope, build, now)

    def transition_session(self, session_id: str, next_state: str, now: str,
                           *, reason: str, owner_authorized: bool = False) -> JournalRecord:
        """Administrative expiry, termination, or quarantine with frozen guards."""
        session = self.replay()[session_id]
        def build(sessions):
            current = sessions[session_id]
            SESSION_MACHINE.require(current.state, next_state)
            if next_state == "EXPIRED":
                if _utc(now) < _utc(current.authority["expires_at_utc"]):
                    raise I2ContractError("Session expiry not reached")
            elif next_state == "TERMINATED":
                budget = replay_budget(current.authority["resource_ceilings"],
                                       current.authority["max_runs"], current.budget_events)
                if reason == "MAX_RUNS":
                    if budget.runs_reserved < current.authority["max_runs"] or budget.active_runs:
                        raise I2ContractError("max_runs termination premature")
                elif reason in {"OWNER_TERMINATION", "EXPLICIT_REVOKE"}:
                    if owner_authorized is not True:
                        raise I2ContractError("owner termination or revoke lacks authority")
                else:
                    raise I2ContractError("unsupported termination reason")
            elif next_state == "QUARANTINED":
                if current.state == "CREATED" and reason not in CREATED_QUARANTINE_REASONS:
                    raise I2ContractError("CREATED Session quarantine reason violates frozen edge")
                if reason not in frozen_document(
                    "OP1_SESSION_CONTINUATION_POLICY.json")["quarantine_or_terminate"]:
                    raise I2ContractError("unfrozen quarantine reason")
                if frozen_document("OP1_SESSION_CONTINUATION_POLICY.json")[
                        "quarantine_or_terminate"][reason] != "QUARANTINE":
                    raise I2ContractError("reason does not quarantine")
            else:
                raise I2ContractError("unsupported administrative Session transition")
            return {
                "kind": "SESSION_TRANSITION", "subject_session_id": session_id,
                "previous_state": current.state, "requested_next_state": next_state,
                "resulting_state": next_state, "reason": reason,
                "owner_authorized": owner_authorized, "observed_at_utc": now,
                "session_authority_id": current.authority["authority_id"],
                "evidence_ids": [],
            }
        return self._decision(session.scope, build, now)

    def reserve_run(self, scope: Scope, authority: Mapping[str, Any], proof: bytes,
                    now: str) -> JournalRecord:
        def build(sessions):
            session = sessions[scope.session_id]
            if session.state != "ACTIVE":
                raise I2ContractError("inactive Session")
            for name, candidate in (
                ("RUN_ID", scope.run_id),
                ("ATTEMPT_ID", scope.attempt_id),
                ("RUN_AUTHORITY_ID", authority["authority_id"]),
                ("CLAIM_ID", authority["claim_id"]),
                ("NAMESPACE_ID", authority["namespace_id"]),
            ):
                if candidate in session.used_ids:
                    raise I2ContractError(f"reused {name}")
            if any(run.state in TERMINAL_RUN_STATES and run.run_id not in session.continued_terminals
                   for run in session.runs.values()):
                raise I2ContractError("continuation check pending")
            session_bytes = canonical_json(session.authority)
            verify_run_authority(authority, proof, self.trusted_issuers,
                                 session.authority, session_bytes, now,
                                 self.read_exact_binding)
            if authority["run_id"] != scope.run_id or authority["attempt_id"] != scope.attempt_id:
                raise I2ContractError("Run/Attempt scope mismatch")
            source = verify_current_capability()
            reservation = {
                "kind": "RESERVE", "event_id": generate_id("EVENT"), "run_id": scope.run_id,
                "budget": authority["resource_ceilings"],
            }
            replay_budget(session.authority["resource_ceilings"],
                          session.authority["max_runs"], session.budget_events + [reservation])
            return {
                "kind": "RUN_RESERVATION", "subject_session_id": scope.session_id,
                "subject_run_id": scope.run_id, "attempt_id": scope.attempt_id,
                "run_authority_id": authority["authority_id"],
                "claim_id": authority["claim_id"], "namespace_id": authority["namespace_id"],
                "budget": authority["resource_ceilings"], "observed_at_utc": now,
                "authority": dict(authority), "proof_hex": proof.hex(),
                "source_sha256": source,
                "capability_profile_sha256": capability_profile_sha256(),
                "evidence_ids": [],
            }
        return self._decision(scope, build, now)

    def admit_run(self, run_record: Mapping[str, Any], authority: Mapping[str, Any],
                  proof: bytes, scope: Scope, now: str) -> JournalRecord:
        def build(sessions):
            session = sessions[scope.session_id]
            if session.state != "ACTIVE":
                raise I2ContractError("inactive Session")
            reservation = session.reservations.get(scope.run_id)
            if reservation is None or scope.run_id in session.runs:
                raise I2ContractError("Run reservation absent or already admitted")
            verify_run_authority(authority, proof, self.trusted_issuers,
                                 session.authority, canonical_json(session.authority),
                                 now, self.read_exact_binding)
            verify_run_record(run_record, authority, session.authority, reservation.event_id)
            if (authority != reservation.payload["authority"]
                    or proof.hex() != reservation.payload["proof_hex"]
                    or authority["resource_ceilings"] != reservation.payload["budget"]):
                raise I2ContractError("Run admission authority or budget differs from reservation")
            return {
                "kind": "RUN_ADMITTED", "subject_session_id": scope.session_id,
                "subject_run_id": scope.run_id, "run": dict(run_record),
                "authority": dict(authority), "proof_hex": proof.hex(),
                "previous_state": None, "requested_next_state": "CREATED",
                "resulting_state": "CREATED", "observed_at_utc": now,
                "evidence_ids": [reservation.evidence_id],
            }
        return self._decision(scope, build, now)

    def observe_prestate(self, session_id: str, run_id: str,
                         passed: bool | None, now: str) -> JournalRecord:
        """Record one synthetic prestate observation while Run remains CREATED."""
        run = self.replay()[session_id].runs[run_id]
        def build(sessions):
            session = sessions[session_id]
            current = session.runs[run_id]
            if session.state != "ACTIVE" or current.state != "CREATED" or current.prestate_evidence_id is not None:
                raise I2ContractError("prestate observation requires fresh ACTIVE/CREATED Run")
            if passed is not None and type(passed) is not bool:
                raise I2ContractError("prestate result must be boolean or unknown")
            if self.journal.store.actor_id == session.authority["owner_actor_id"]:
                raise I2ContractError("synthetic prestate observer is not independent")
            require_time_window(session.authority["issued_at_utc"],
                                session.authority["expires_at_utc"], now)
            return {
                "kind": "PRESTATE_OBSERVATION", "subject_session_id": session_id,
                "subject_run_id": run_id,
                "prestate_result": "UNKNOWN" if passed is None else "PASS" if passed else "FAIL",
                "synthetic_only": True, "physical_c2_executed": False,
                "observer_actor_id": self.journal.store.actor_id,
                "observed_at_utc": now, "evidence_ids": [],
            }
        return self._decision(run.scope, build, now)

    def resolve_prestate(self, session_id: str, run_id: str, now: str,
                         *, claim: Mapping[str, Any] | None = None) -> JournalRecord:
        """Choose one frozen path from CREATED under a single journal commit."""
        run = self.replay()[session_id].runs[run_id]
        def build(sessions):
            session = sessions[session_id]
            current = session.runs[run_id]
            if session.state != "ACTIVE" or current.state != "CREATED":
                raise I2ContractError("prestate resolution requires ACTIVE/CREATED Run")
            try:
                verify_run_authority(current.authority, current.proof, self.trusted_issuers,
                                     session.authority, canonical_json(session.authority),
                                     now, self.read_exact_binding)
            except I2ContractError as exc:
                return self._run_transition(
                    session, current, "REJECTED_AUTHORITY", now,
                    reason=str(exc),
                    evidence_ids=[current.prestate_evidence_id]
                    if current.prestate_evidence_id else [],
                )
            if current.prestate_evidence_id is None:
                raise I2ContractError("prestate observation absent")
            outcome = "CLAIMED" if current.prestate_pass is True else "BLOCKED_PRESTATE"
            if outcome == "CLAIMED":
                if claim is None:
                    raise I2ContractError("atomic claim record absent")
                verify_claim_record(claim, current.record, current.authority,
                                    canonical_json(current.authority),
                                    session.reservations[run_id].event_id)
                if claim["state"] != "CONSUMED":
                    raise I2ContractError("ambiguous claim cannot launch")
            evidence = [current.prestate_evidence_id]
            common = {
                "subject_session_id": session_id, "subject_run_id": run_id,
                "session_authority_id": session.authority["authority_id"],
                "run_authority_id": current.authority["authority_id"],
                "evidence_ids": evidence,
            }
            first = {**common, "previous_state": "CREATED",
                     "requested_next_state": "PRESTATE", "resulting_state": "PRESTATE"}
            second = {**common, "previous_state": "PRESTATE",
                      "requested_next_state": outcome, "resulting_state": outcome}
            if outcome == "CLAIMED":
                second["claim"] = dict(claim)
            else:
                second["cleanup_proven"] = True
            return {
                "kind": "RUN_ATOMIC_PATH", "subject_session_id": session_id,
                "subject_run_id": run_id,
                "prestate_evidence_id": current.prestate_evidence_id,
                "logical_events": [first, second],
                **({"claim_slot_preimage_hex": claim_slot_preimage(claim).hex()}
                   if outcome == "CLAIMED" else {}),
                "observed_at_utc": now, "evidence_ids": evidence,
            }
        decision = self._decision(run.scope, build, now)
        if decision.payload.get("kind") == "RUN_ATOMIC_PATH" and (
            decision.payload["logical_events"][1]["resulting_state"] == "CLAIMED"
        ):
            self._launch_permits[run_id] = decision.payload["logical_events"][1]["event_id"]
        return decision

    @staticmethod
    def _run_transition(session: SessionView, run: RunView, next_state: str,
                        now: str, **extras: Any) -> dict[str, Any]:
        RUN_MACHINE.require(run.state, next_state)
        return {
            "kind": "RUN_TRANSITION", "subject_session_id": session.session_id,
            "subject_run_id": run.run_id, "previous_state": run.state,
            "requested_next_state": next_state, "resulting_state": next_state,
            "session_authority_id": session.authority["authority_id"],
            "run_authority_id": run.authority["authority_id"],
            "observed_at_utc": now, "evidence_ids": [],
            **extras,
        }

    def transition_run(self, session_id: str, run_id: str, next_state: str,
                       now: str, **proof: Any) -> JournalRecord:
        """Bounded synthetic transition; missing guard proof rejects and preserves evidence."""
        run = self.replay()[session_id].runs[run_id]
        def build(sessions):
            session = sessions[session_id]
            current = session.runs[run_id]
            if next_state in {"PRESTATE", "CLAIMED", "BLOCKED_PRESTATE",
                              "REJECTED_AUTHORITY"}:
                raise I2ContractError("fresh prestate path requires atomic resolution")
            RUN_MACHINE.require(current.state, next_state)
            if next_state == "EXECUTING":
                if session.state != "ACTIVE" or current.claim is None or proof.get("dispatch_ack") is not True:
                    raise I2ContractError("dispatch lacks active Session, consumed claim or owned ack")
                if self._launch_permits.get(run_id) != current.claim_event_id:
                    raise I2ContractError("claim launch permit absent after restart or lost acknowledgement")
                require_time_window(session.authority["issued_at_utc"],
                                    session.authority["expires_at_utc"], now)
                require_time_window(current.authority["issued_at_utc"],
                                    current.authority["expires_at_utc"], now)
                source = verify_current_capability()
                reservation = session.reservations[run_id].payload
                if (source != reservation["source_sha256"]
                        or capability_profile_sha256() !=
                        reservation["capability_profile_sha256"]):
                    raise I2ContractError("synthetic launch capability changed after reservation")
                # The transition's own PUBLICATION event is the durable launch intent.
                proof["launch_intent_id"] = None
                proof["dispatch_mode"] = "NO_WORKER_SYNTHETIC"
                proof["source_sha256"] = source
                proof["capability_profile_sha256"] = capability_profile_sha256()
            elif next_state in {"PASS", "FAIL", "TIMEOUT", "CRASHED"}:
                if (not proof.get("evidence_ids")
                        or any(current.observation_outcomes.get(item_id) != next_state
                               for item_id in proof["evidence_ids"])):
                    raise I2ContractError("terminal outcome differs from prior synthetic evidence")
                if next_state == "TIMEOUT" and proof.get("effect_classified") is not True:
                    raise I2ContractError("timeout effect/ownership not classified")
            elif next_state in {"AMBIGUOUS_CONSUMPTION", "UNKNOWN"}:
                if current.state not in {"PRESTATE", "CLAIMED", "EXECUTING"}:
                    raise I2ContractError("ambiguity state invalid")
            elif next_state == "ABORTED_OWNER":
                if proof.get("owner_abort") is not True:
                    raise I2ContractError("explicit owner abort required")
            elif next_state == "CONSUMED_FAILED":
                if current.claim is None or proof.get("dispatch_proven") is not False:
                    raise I2ContractError("consumed failure requires claim and no proven dispatch")
            elif next_state == "INCOMPLETE_EVIDENCE":
                if current.claim is None:
                    raise I2ContractError("incomplete evidence requires consumed claim")
                evidence = proof.get("evidence_ids")
                if (not isinstance(evidence, list) or not evidence
                        or (current.state == "EXECUTING" and any(
                            current.observation_outcomes.get(item_id) != "INCOMPLETE_EVIDENCE"
                            for item_id in evidence))):
                    raise I2ContractError("incomplete evidence lacks synthetic provenance")
            value = self._run_transition(session, current, next_state, now, **proof)
            if next_state == "EXECUTING":
                value["launch_intent_id"] = "SELF_PUBLICATION"
            return value
        decision = self._decision(run.scope, build, now)
        if decision.payload.get("kind") == "RUN_TRANSITION":
            state = decision.payload["resulting_state"]
            if state == "EXECUTING":
                self._launch_permits.pop(run_id, None)
                self._execute_permits[run_id] = decision.event_id
            elif state in TERMINAL_RUN_STATES:
                self._launch_permits.pop(run_id, None)
                self._execute_permits.pop(run_id, None)
        return decision

    def observe_synthetic(self, session_id: str, run_id: str, outcome: str,
                          now: str) -> JournalRecord:
        run = self.replay()[session_id].runs[run_id]
        def build(sessions):
            current = sessions[session_id].runs[run_id]
            if current.state != "EXECUTING":
                raise I2ContractError("synthetic observation outside active Run")
            if self._execute_permits.get(run_id) != current.launch_intent_id:
                raise I2ContractError("synthetic execution permit absent after restart or prior execution")
            require_time_window(sessions[session_id].authority["issued_at_utc"],
                                sessions[session_id].authority["expires_at_utc"], now)
            require_time_window(current.authority["issued_at_utc"],
                                current.authority["expires_at_utc"], now)
            executor = evaluate
            source = verify_current_capability(executor)
            if (source != current.launch_source_sha256
                    or capability_profile_sha256() !=
                    current.launch_capability_profile_sha256):
                raise I2ContractError("synthetic outcome capability changed after launch")
            self._execute_permits.pop(run_id, None)
            selected = executor(outcome)
            return {
                "kind": "SYNTHETIC_OBSERVATION", "subject_session_id": session_id,
                "subject_run_id": run_id, "outcome": selected,
                "synthetic_only": True, "physical_c2_executed": False,
                "adapter": "I2_DETERMINISTIC_SYNTHETIC",
                "owned_worker_count": 0, "owned_resource_count": 0,
                "external_effect_capability": False,
                "source_sha256": source,
                "capability_profile_sha256": capability_profile_sha256(),
                "observed_at_utc": now, "evidence_ids": [],
            }
        return self._decision(run.scope, build, now)

    def record_isolation_report(self, session_id: str, run_id: str,
                                report: Mapping[str, Any], now: str) -> JournalRecord:
        """Import one independently signed, read-only synthetic containment proof."""
        run = self.replay()[session_id].runs[run_id]
        def build(sessions, history):
            session = sessions[session_id]
            current = session.runs[run_id]
            if session.state != "ACTIVE" or current.state not in UNCERTAIN_STATES:
                raise I2ContractError("isolation requires ACTIVE Session and uncertain Run")
            if current.isolation_report is not None:
                raise I2ContractError("duplicate isolation observation")
            verify_report(report, self.trusted_isolation_observers,
                          owner_actor_id=session.authority["owner_actor_id"],
                          issuer_actor_id=session.authority["issuer_actor_id"],
                          store_actor_id=self.journal.store.actor_id)
            if _utc(report["observed_at_utc"]) != _utc(now):
                raise I2ContractError("isolation report time differs from observation")
            expected = context_for(self, history, session_id, run_id)
            if {name: report[name] for name in expected} != expected:
                raise I2ContractError("isolation report differs from independent I1 reconstruction")
            return {
                "kind": "ISOLATION_OBSERVATION",
                "subject_session_id": session_id, "subject_run_id": run_id,
                "report": dict(report), "observed_at_utc": now,
                "synthetic_only": True, "physical_c2_executed": False,
                "evidence_ids": list(current.observation_evidence_ids),
            }
        return self._decision(run.scope, build, now, with_history=True)

    def release_run_budget(self, session_id: str, run_id: str,
                           cleanup_proven: bool, now: str) -> JournalRecord:
        run = self.replay()[session_id].runs[run_id]
        def build(sessions, history):
            session = sessions[session_id]
            current = session.runs[run_id]
            if current.terminal_event_id is None or cleanup_proven is not True:
                raise I2ContractError("active reservation cannot release without proven cleanup")
            if current.state in UNCERTAIN_STATES:
                if (current.isolation_report is None
                        or current.isolation_report["cleanup_proven"] is not True
                        or verify_current_capability() != current.isolation_report["source_sha256"]
                        or history[-1].event_id != current.isolation_event_id
                        or sha256_bytes(canonical_json(session.budget_events)) !=
                        current.isolation_report["budget_events_sha256"]):
                    raise I2ContractError("uncertain release lacks current independent cleanup proof")
            elif current.cleanup_proven is not True:
                raise I2ContractError("active reservation cannot release without proven cleanup")
            if run_id in replay_budget(session.authority["resource_ceilings"],
                                       session.authority["max_runs"], session.budget_events).released:
                raise I2ContractError("duplicate resource release")
            return {
                "kind": "BUDGET_RELEASE", "subject_session_id": session_id,
                "subject_run_id": run_id, "durable_terminal_event_id": current.terminal_event_id,
                "cleanup_proven": True, "observed_at_utc": now,
                "isolation_event_id": current.isolation_event_id
                if current.state in UNCERTAIN_STATES else None,
                "evidence_ids": [current.observation_evidence_ids[-1]]
                if current.observation_evidence_ids else [],
            }
        return self._decision(run.scope, build, now, with_history=True)

    def continue_after_run(self, session_id: str, run_id: str, now: str,
                           *, isolation_proven: bool = False) -> JournalRecord:
        session = self.replay()[session_id]
        def build(sessions):
            value = sessions[session_id]
            run = value.runs[run_id]
            if value.state != "ACTIVE" or run.state not in TERMINAL_RUN_STATES:
                raise I2ContractError("continuation requires ACTIVE Session and terminal Run")
            if run_id in value.continued_terminals:
                raise I2ContractError("duplicate continuation")
            budget = replay_budget(value.authority["resource_ceilings"],
                                   value.authority["max_runs"], value.budget_events)
            isolated_uncertainty = False
            release_predecessor_id = None
            if run.state in UNCERTAIN_STATES and run.isolation_report is not None:
                try:
                    latest = self.journal.history()[-1]
                    isolated_uncertainty = (
                        verify_current_capability() == run.isolation_report["source_sha256"]
                        and latest.payload.get("kind") == "BUDGET_RELEASE"
                        and latest.payload.get("subject_run_id") == run_id
                        and latest.payload.get("isolation_event_id") == run.isolation_event_id
                        and run.isolation_report["cleanup_proven"] is True
                    )
                    if isolated_uncertainty:
                        release_predecessor_id = latest.event_id
                except (I2ContractError, OSError, ValueError):
                    isolated_uncertainty = False
            findings = []
            if run.state not in SAFE_CONTINUATION_STATES and not isolated_uncertainty:
                findings.append("UNCONTAINED_RUN_UNCERTAINTY")
            if not run.cleanup_proven and not isolated_uncertainty:
                findings.append("CLEANUP_NOT_PROVEN")
            if run_id not in budget.released:
                findings.append("RESOURCE_RESERVATION_NOT_RELEASED")
            try:
                exact = self.read_exact_binding(run.authority["exact_binding_manifest_relative_path"])
                if sha256_bytes(exact) != run.authority["exact_binding_manifest_sha256"]:
                    findings.append("PROTECTED_SOURCE_MISMATCH")
                # Validate immutable signed content independently of current expiry.
                verify_session_authority(value.authority, value.proof,
                                         self.trusted_issuers,
                                         value.authority["issued_at_utc"])
            except (I2ContractError, OSError, ValueError):
                findings.append("AUTHORITY_INTEGRITY_FAILURE")
            expired = _utc(now) >= _utc(value.authority["expires_at_utc"])
            max_runs_reached = budget.runs_reserved >= value.authority["max_runs"]
            exhausted = max_runs_reached and budget.active_runs == 0
            if expired:
                findings.append("EXPIRY")
            if max_runs_reached:
                findings.append("MAX_RUNS")
            contamination = {
                "UNCONTAINED_RUN_UNCERTAINTY", "CLEANUP_NOT_PROVEN",
                "RESOURCE_RESERVATION_NOT_RELEASED", "PROTECTED_SOURCE_MISMATCH",
                "AUTHORITY_INTEGRITY_FAILURE",
            }
            if contamination.intersection(findings):
                next_state = "QUARANTINED"
            elif expired:
                next_state = "EXPIRED"
            elif exhausted:
                next_state = "TERMINATED"
            else:
                next_state = "ACTIVE"
            SESSION_MACHINE.require("ACTIVE", next_state)
            return {
                "kind": "SESSION_TRANSITION", "subject_session_id": session_id,
                "previous_state": "ACTIVE", "requested_next_state": next_state,
                "resulting_state": next_state, "terminal_run_id": run_id,
                "observed_at_utc": now,
                "caller_isolation_assertion": isolation_proven,
                "independent_isolation_proven": isolated_uncertainty,
                "isolation_event_id": run.isolation_event_id
                if isolated_uncertainty else None,
                "budget_release_event_id": release_predecessor_id,
                "applicable_findings": findings,
                "session_authority_id": value.authority["authority_id"],
                "evidence_ids": (
                    ([run.observation_evidence_ids[-1]] if run.observation_evidence_ids else [])
                    + ([run.isolation_evidence_id] if isolated_uncertainty else [])
                ),
            }
        return self._decision(session.scope, build, now)
