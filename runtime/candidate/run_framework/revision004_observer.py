"""Opt-in literal receipt observation over the existing typed V2 caller.

V2 remains the attempt journal. This observer adds content-addressed literal
receipts before/after callbacks and periodic full checkpoint views. It never
resumes a prior observer, imports producers, or declares semantic qualification.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import time

from .caller import GenericCaller
from .core import FrameworkError, _loads, _path, _write_immutable, canonical, digest
from .incremental import _safe_artifact
from .revision004_sidecar import INDEX_V3, project_v2_receipt_payload, verify_revision004_sidecar
from .revision004_profile import project_unit_metadata
from .revision004_wire import canonical_payload, validate_unit_payload, validated_checkpoint_context


class Revision004Observer:
    """Observe one fresh, same-process typed caller; no restart or redispatch API.

    The immutable profile directory is inside V2's guarded output root, so the
    existing ResourceGuard accounts its writes in the same storage ceiling.
    Callbacks remain trusted in-process functions, with cooperative boundary
    checks only; there is no arbitrary callback duration/RSS isolation claim.
    """
    def __init__(self, caller, *, wall_ns=time.time_ns, clock_ns=time.monotonic_ns):
        if not isinstance(caller, GenericCaller):
            raise FrameworkError("LITERAL_PROFILE_REQUIRES_TYPED_CALLER")
        policy = caller.campaign.config["audit_policy"]["generic_caller"].get("literal_receipt_profile")
        if (not isinstance(policy, dict)
                or set(policy) != {"schema", "directory", "checkpoint_every_units"}
                or policy["schema"] != INDEX_V3 or policy["directory"] != "REV004_WIRE"
                or type(policy["checkpoint_every_units"]) is not int or policy["checkpoint_every_units"] < 1):
            raise FrameworkError("LITERAL_PROFILE_NOT_EXPLICITLY_CONFIGURED")
        self.caller = caller
        self.campaign = caller.campaign
        self.root = self.campaign.output / policy["directory"]
        _path(self.root, False)
        state = self.campaign.recover()
        if (caller._literal_observer is not None or state["receipts"] or self.root.exists()
                or not self.campaign._can_write or self.campaign._write_blocked):
            raise FrameworkError("LITERAL_PROFILE_REQUIRES_FRESH_ATTEMPT; no observer resume")
        self.every = policy["checkpoint_every_units"]
        self.wall_ns, self.clock_ns = wall_ns, clock_ns
        self._rows, self._payloads = [], []
        self._checkpoint = None
        self._checkpoint_count = 0
        self._checkpointed_receipts = 0
        self._completed = 0
        self._blocked = False
        self._finished = False
        self._pending_start = None
        self._executing = False
        caller._literal_observer = self

    def _ensure_active(self):
        if self._blocked or self._finished:
            raise FrameworkError("LITERAL_OBSERVER_BLOCKED_OR_FINISHED; read-only verification only")

    def _publish(self, relative, raw):
        guard = self.campaign._guard()
        path = guard._safe_path(relative)
        _path(path, False)
        guard.before_publication(len(raw))
        try:
            _write_immutable(path, raw)
            guard.account_write(relative, len(raw))
            guard.finish_publication()
        except BaseException:
            self._blocked = True
            # Incomplete files are retained. Recovery must reject an orphan or
            # truncated view, never delete it or silently restart this observer.
            try:
                guard.request_stop("EXTERNAL_INTERRUPTION", {"stage": "literal_receipt_publication"})
            except BaseException:
                pass
            self.campaign._write_blocked = True
            raise

    def _header(self):
        cfg = self.campaign.config
        return {"schema": INDEX_V3, "receipt_index": "VERIFIED_CAMPAIGN_V2_JOURNAL",
                "run_id": self.campaign.run_id, "campaign_id": cfg["campaign_id"],
                "campaign_attempt_id": cfg["campaign_attempt_id"],
                "config_sha256": self.campaign.config_sha256,
                "contract_sha256": cfg["contract_sha256"],
                "expected_units_sha256": digest(canonical(sorted(cfg["expected_units"])))}

    def _base(self, unit_id):
        return project_unit_metadata(self.campaign, unit_id)

    def _fail_closed(self):
        self._blocked = True
        self._pending_start = None
        self.caller._prestarted.clear()
        self.campaign._write_blocked = True
        if (self.campaign.output / "deltas").exists():
            try:
                self.campaign._guard().request_stop("INTEGRITY_FAILURE", {"stage": "literal_observer_failure"})
            except BaseException:
                pass

    def check_start_admission(self, unit_id, v2_start_sha256):
        """Consume no work; require this observer's flushed exact START bytes."""
        self._ensure_active()
        if self._pending_start is None:
            raise FrameworkError("LITERAL_START_NOT_PUBLISHED")
        expected_unit, expected_v2, row = self._pending_start
        if (unit_id, v2_start_sha256) != (expected_unit, expected_v2):
            raise FrameworkError("LITERAL_START_OWNERSHIP_MISMATCH")
        path = _path(self.root / row["path"], True)
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise FrameworkError("LITERAL_START_CHANGED_BEFORE_CALLBACK")

    def _v2_receipt(self, summary):
        raw = _safe_artifact(self.campaign.output, summary["path"], "receipts").read_bytes()
        body = _loads(raw)
        if digest(raw) != summary["sha256"] or canonical(body) != raw:
            raise FrameworkError("LITERAL_V2_RECEIPT_CHANGED")
        return body

    def _append(self, base, summary, started_wall, ended_wall, duration_ns):
        receipt = self._v2_receipt(summary)
        payload = {**base, **project_v2_receipt_payload(receipt),
                   "phase": receipt["phase"].upper(), "attempt_id": receipt["attempt_id"],
                   "sequence": len(self._rows) + 1,
                   "parent_receipt_sha256": self._rows[-1]["sha256"] if self._rows else None,
                   "processing_started_at_unix_ns": started_wall,
                   "processing_ended_at_unix_ns": ended_wall, "processing_duration_ns": duration_ns}
        bounded = self.campaign._guard().payload_bytes(payload, self.campaign.config["resource_budget"].get("max_payload_bytes"))
        raw = validate_unit_payload(payload)
        if bounded != raw:
            raise FrameworkError("LITERAL_PAYLOAD_ENCODING_MISMATCH")
        sha = hashlib.sha256(raw).hexdigest()
        relative = f"receipts/{payload['sequence']:08d}-{sha}.json"
        self._publish("REV004_WIRE/" + relative, raw)
        self._payloads.append(payload)
        self._rows.append({"sequence": payload["sequence"], "path": relative, "sha256": sha,
                           "unit_id": payload["unit_id"], "phase": payload["phase"]})

    def checkpoint(self):
        self._ensure_active()
        state = self.campaign.recover()
        if len(state["receipts"]) != len(self._rows):
            raise FrameworkError("LITERAL_V2_EVENT_CROSSWALK_INCOMPLETE")
        if self._checkpoint is not None and self._checkpointed_receipts == len(self._rows):
            return self._checkpoint.payload_sha256
        cfg = self.campaign.config
        payload = {"schema": "pgop1.run004.checkpoint-payload.rev004", "campaign_id": cfg["campaign_id"],
                   "campaign_attempt_id": cfg["campaign_attempt_id"],
                   "parent_checkpoint_sha256": self._checkpoint.payload_sha256 if self._checkpoint else None,
                   "ordered_receipt_payload_sha256": [row["sha256"] for row in self._rows],
                   "completed_units": sorted(state["completed"]), "pending_units": sorted(state["pending"]),
                   "inflight_units": sorted(state["inflight"]),
                   "bindings": {"config_sha256": self.campaign.config_sha256, "contract_sha256": cfg["contract_sha256"]}}
        context = validated_checkpoint_context(payload, cfg["expected_units"], self._payloads,
                                               predecessor_context=self._checkpoint)
        sequence = self._checkpoint_count + 1
        self._publish(f"REV004_WIRE/checkpoints/{sequence:08d}-{context.payload_sha256}.json", context.payload_bytes)
        self._checkpoint = context
        self._checkpoint_count = sequence
        self._checkpointed_receipts = len(self._rows)
        return context.payload_sha256

    def execute(self, unit_id):
        self._ensure_active()
        if self._executing:
            raise FrameworkError("LITERAL_OBSERVER_REENTRANT_CALLBACK_NOT_SUPPORTED")
        self._executing = True
        try:
            state = self.campaign.recover()
            if len(state["receipts"]) != len(self._rows):
                raise FrameworkError("LITERAL_OBSERVER_FOREIGN_V2_EVENT")
            started_wall, started_mono = self.wall_ns(), self.clock_ns()
            base = self._base(unit_id)
            start = self.caller.begin_unit(unit_id)
            if not self._rows:
                self._publish("REV004_WIRE/INDEX.json", canonical_payload(self._header()))
            self._append(base, start, started_wall, started_wall, 0)
            if self._checkpoint is None:
                self.checkpoint()
            self._pending_start = (unit_id, start["sha256"], deepcopy(self._rows[-1]))
            # START file and the initial checkpoint have completed exclusive
            # flush+fsync before any adapter or auditor callback is invoked.
            terminal = self.caller.execute_started(unit_id)
            ended_mono, ended_wall = self.clock_ns(), self.wall_ns()
            if ended_mono < started_mono:
                raise FrameworkError("LITERAL_MONOTONIC_CLOCK_REGRESSED")
            self._append(base, terminal, started_wall, ended_wall, ended_mono - started_mono)
            self._completed += 1
            if self._completed % self.every == 0:
                self.checkpoint()
            return deepcopy(terminal)
        except BaseException:
            self._fail_closed()
            raise
        finally:
            self._pending_start = None
            self._executing = False

    def finish(self):
        self._ensure_active()
        if not self._rows:
            raise FrameworkError("LITERAL_OBSERVER_HAS_NO_ATTEMPT; no completion claimed")
        self.checkpoint()
        result = verify_revision004_sidecar(self.root, self.campaign)
        self._finished = True
        return result

    def verify_read_only(self):
        return verify_revision004_sidecar(self.root, self.campaign)
