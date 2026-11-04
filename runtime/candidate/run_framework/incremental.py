"""Incremental, immutable checkpoint v2 for prospective reusable campaigns.

This remains orchestration metadata only. It never dispatches unit work. Recovery
validates the journal and returns inflight units as read-only evidence.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
from copy import deepcopy

from . import core
from .core import Campaign as _Campaign, FrameworkError, canonical, digest, _loads, _write_immutable, _path
from .resources import ResourceGuard, ResourceLimitStop
from .provenance import validate_result

MANIFEST_SCHEMA = "pgop1.reusable-run-manifest.v2"
CHECKPOINT_SCHEMA = "pgop1.reusable-run-checkpoint.v2"
DELTA_SCHEMA = "pgop1.reusable-run-event-delta.v2"
RECEIPT_SCHEMA = "pgop1.reusable-run-receipt.v2"
HEX = core.HEX


class _FrozenDict(dict):
    def __deepcopy__(self, memo):
        return {key: deepcopy(value, memo) for key, value in self.items()}
    def _deny(self, *args, **kwargs):
        raise FrameworkError("in-memory v2 campaign configuration is immutable")
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _deny


class _FrozenList(list):
    def __deepcopy__(self, memo):
        return [deepcopy(value, memo) for value in self]
    def _deny(self, *args, **kwargs):
        raise FrameworkError("in-memory v2 campaign configuration is immutable")
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = _deny
    __iadd__ = __imul__ = _deny


def _freeze(value):
    if isinstance(value, dict):
        return _FrozenDict({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return _FrozenList(_freeze(child) for child in value)
    return value


def _safe_artifact(root: Path, relative: str, folder: str) -> Path:
    parts = PurePosixPath(relative).parts
    if len(parts) != 2 or parts[0] != folder or parts[1] in {".", ".."}:
        raise FrameworkError("unsafe v2 artifact path")
    path = root.joinpath(*parts)
    if _path(path, True) != path.resolve(strict=True) or not core._within(path.resolve(), [root]):
        raise FrameworkError("v2 artifact path/reparse rejected")
    return path


class CampaignV2(_Campaign):
    """Campaign with content-addressed selection and incremental journal state."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = _freeze(self.config)
        self._frozen_config = self.config
        self._v2_state = None
        self._v2_manifest = None
        self._v2_manifest_sha = None
        self._v2_guard = None
        self._v2_events_since_checkpoint = 0
        self._config_stat = None
        self._v2_manifest_raw = None
        self._v2_manifest_verified = False
        self._v2_error_count = 0
        self._critical_stats = {}
        self._critical_hashes = {}

    def preflight(self):
        parent_chain = self.config["checkpoint_policy"].get("receipt_parent_chain", False)
        if type(parent_chain) is not bool:
            raise FrameworkError("checkpoint_policy.receipt_parent_chain must be boolean")
        payload_limit = self.config["resource_budget"].get("max_payload_bytes")
        if payload_limit is not None and (type(payload_limit) is not int or payload_limit <= 0):
            raise FrameworkError("resource_budget.max_payload_bytes must be a positive integer")
        result = super().preflight()
        critical = [self.config_path, Path(self.config["contract_path"]),
                    Path(self.config["dataset_manifest_path"]),
                    Path(self.config["selection_manifest"]["path"]),
                    Path(self.config["adapter_registry"]["path"]),
                    Path(self.config["predicate_contracts"]["path"]),
                    Path(self.config["exclusion_ledger"]["path"]),
                    *(Path(item["path"]) for item in self.config["code_files"])]
        self._critical_stats = {path: self._stat_key(path) for path in critical}
        self._critical_hashes = {path: digest(path.read_bytes()) for path in critical}
        self._config_stat = self._critical_stats[self.config_path]
        return result

    @staticmethod
    def _stat_key(path):
        st = path.stat()
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)

    def _manifest_value(self):
        if self._preflight is None:
            raise FrameworkError("preflight required")
        # Independent expected-membership digest: the selected set comes from the
        # original frozen config and its pinned selection file was checked by
        # preflight. The digest binds both sources, rather than trusting a caller
        # supplied manifest or checkpoint.
        selected = sorted(self.config["expected_units"])
        selection = next(x for x in self._preflight["files"] if x["role"] == "selection_manifest")
        expected_digest = digest(canonical({
            "config_sha256": self.config_sha256,
            "selection_manifest_sha256": selection["sha256"],
            "selected_units": selected,
        }))
        value = {"schema": MANIFEST_SCHEMA, "run_id": self.run_id,
                 "campaign_id": self.config["campaign_id"],
                 "campaign_attempt_id": self.config["campaign_attempt_id"],
                 "bindings": self._preflight, "selection_manifest_sha256": selection["sha256"],
                 "selected_units": selected, "expected_units_sha256": expected_digest}
        raw = canonical(value)
        return value, digest(raw), raw

    def _guard(self, *, read_only=False):
        if self._v2_guard is None:
            budget = self.config["resource_budget"]
            run_marker = self.registry_root / ".pgop1-run-registry" / (self.run_id + ".json")
            attempt_key = digest(canonical([self.run_id, self.config["campaign_attempt_id"]]))
            attempt_marker = self.registry_root / ".pgop1-attempt-registry" / (attempt_key + ".json")
            self._v2_guard = ResourceGuard(
                self.output,
                max_bytes=budget.get("max_bytes"), max_seconds=budget.get("max_seconds"),
                max_units=budget.get("max_units", budget.get("max_total_units")),
                max_errors=budget.get("max_errors", self.config["stop_criteria"].get("max_errors", 1 if self.config["stop_criteria"].get("on_error")=="stop" else None)),
                accounted_paths=(run_marker, attempt_marker),
                read_only=read_only or not self._can_write,
            )
        return self._v2_guard

    def _initial_state(self):
        units = set(self.config["expected_units"])
        return {"receipts": [], "checkpoints": [], "completed": set(),
                "pending": units, "inflight": set(), "open_attempts": {}, "result_ids": set(),
                "complete": False, "head": None, "sequence": 0}

    def _manifest_path(self, sha):
        return self.output / "manifest" / (sha + ".json")

    def _ensure_manifest(self, manifest, sha, raw, *, create=False, reserved=False):
        _path(self._manifest_path(sha), False)
        path = _safe_artifact(self.output, f"manifest/{sha}.json", "manifest") if self._manifest_path(sha).exists() else self._manifest_path(sha)
        relative = path.relative_to(self.output).as_posix()
        if not path.exists():
            if not create:
                raise FrameworkError("content-addressed v2 manifest missing; read-only recovery blocked")
            guard = self._guard()
            if not reserved:
                guard.before_publication(len(raw))
            try:
                _write_immutable(path, raw)
            except FileExistsError:
                pass
            guard.account_write(relative, len(raw))
            if not reserved:
                guard.finish_publication()
        if not path.is_file() or path.is_symlink() or path.read_bytes() != raw:
            raise FrameworkError("content-addressed manifest substitution or tampering")
        self._v2_manifest, self._v2_manifest_sha = manifest, sha
        self._v2_manifest_raw = raw

    def recover(self, *, _prefix_max_sequence=None):
        try:
            return self._recover_impl(_prefix_max_sequence=_prefix_max_sequence)
        except FrameworkError:
            raise
        except (OSError, TypeError, KeyError, AttributeError) as exc:
            raise FrameworkError("invalid or unavailable v2 recovery artifact: " + str(exc)) from exc

    def _recover_impl(self, *, _prefix_max_sequence=None):
        if self._preflight is None:
            raise FrameworkError("preflight required")
        self.__dict__.pop("_v2_provenance_index", None)
        frozen = self._preflight
        current = self.preflight()  # one complete binding check on fresh recovery
        if current != frozen:
            raise FrameworkError("bound files changed since preflight; recovery blocked")
        manifest, manifest_sha, manifest_raw = self._manifest_value()
        output = _path(self.output, False)
        if not core._within(output, self.output_roots):
            raise FrameworkError("output root binding changed")
        journal = self.output / "deltas"
        manifest_dir = self.output / "manifest"
        receipt_dir = self.output / "receipts"
        checkpoint_dir = self.output / "checkpoints"
        for directory in (journal, manifest_dir, receipt_dir, checkpoint_dir, self.output / "rejected"):
            _path(directory, False)
        if not journal.exists():
            if any(p.exists() for p in (manifest_dir, receipt_dir, checkpoint_dir, self.output / "writer.owner")):
                raise FrameworkError("orphan/interrupted v2 publication without journal")
            self._v2_manifest, self._v2_manifest_sha = manifest, manifest_sha
            self._v2_state = self._initial_state()
            self._v2_events_since_checkpoint = 0
            return self._v2_state
        self._ensure_manifest(manifest, manifest_sha, manifest_raw, create=False)
        self._verify_reservations_and_owner()
        if journal.is_symlink() or not journal.is_dir():
            raise FrameworkError("v2 delta journal type/reparse rejected")
        entries = list(journal.iterdir())
        for path in entries:
            _path(path, True)
        if any(p.is_symlink() or not p.is_file() for p in entries):
            raise FrameworkError("unsafe v2 delta journal entry")
        entries.sort(key=lambda p: p.name)
        if _prefix_max_sequence is not None:
            entries = [p for p in entries if p.name[:8].isdigit() and int(p.name[:8]) <= _prefix_max_sequence]
            if len(entries) != _prefix_max_sequence:
                raise FrameworkError("verified checkpoint prefix has a missing delta")
        state = self._initial_state()
        previous = None
        previous_cp = None
        checkpoints_by_seq = {}
        actual_checkpoints = set()
        if checkpoint_dir.exists():
            for p in checkpoint_dir.iterdir():
                _path(p, True)
                if p.is_symlink() or not p.is_file():
                    raise FrameworkError("checkpoint directory contains unsafe entry")
                actual_checkpoints.add(p.name)
        interval = self.config["checkpoint_policy"]["interval"]
        expected_checkpoints = set()
        receipt_names = set()
        expected_deltas = set()
        for seq, entry in enumerate(entries, 1):
            delta_raw = entry.read_bytes()
            delta = _loads(delta_raw)
            if canonical(delta) != delta_raw:
                raise FrameworkError("noncanonical v2 journal delta")
            required = {"schema", "sequence", "previous_delta_sha256", "manifest_sha256",
                        "receipt_path", "receipt_sha256", "unit_id", "phase", "disposition",
                        "attempt_id", "payload_sha256", "resource_snapshot"}
            if (not isinstance(delta, dict) or set(delta) != required or delta["schema"] != DELTA_SCHEMA
                    or type(delta["sequence"]) is not int or delta["sequence"] != seq
                    or delta["previous_delta_sha256"] != previous
                    or delta["manifest_sha256"] != manifest_sha
                    or delta["unit_id"] not in manifest["selected_units"]
                    or delta["phase"] not in {"start", "terminal"}
                    or not HEX.fullmatch(delta["receipt_sha256"])
                    or not HEX.fullmatch(delta["payload_sha256"])):
                raise FrameworkError("v2 journal sequence/schema/binding invalid")
            delta_sha = digest(delta_raw)
            delta_name = f"{seq:08d}-{delta_sha}.json"
            if entry.name != delta_name:
                raise FrameworkError("v2 delta content address or sequence mismatch")
            expected_deltas.add(delta_name)
            rp = delta["receipt_path"]
            expected_rp = f"receipts/{seq:08d}-{delta['receipt_sha256']}.json"
            if rp != expected_rp:
                raise FrameworkError("v2 receipt path does not match sequence and digest")
            receipt_path = _safe_artifact(self.output, rp, "receipts")
            receipt_raw = receipt_path.read_bytes()
            if digest(receipt_raw) != delta["receipt_sha256"]:
                raise FrameworkError("v2 receipt digest mismatch")
            receipt = _loads(receipt_raw)
            receipt_fields={"schema","run_id","campaign_id","attempt_id","unit_id","phase","disposition","sequence","manifest_sha256","admission","payload"}
            if self.config["checkpoint_policy"].get("receipt_parent_chain", False):
                receipt_fields.add("parent_receipt_sha256")
            if (not isinstance(receipt, dict) or set(receipt)!=receipt_fields
                    or canonical(receipt) != receipt_raw or receipt.get("schema") != RECEIPT_SCHEMA):
                raise FrameworkError("v2 receipt is noncanonical or unsupported")
            if "parent_receipt_sha256" in receipt_fields:
                expected_parent = state["receipts"][-1]["sha256"] if state["receipts"] else None
                if receipt["parent_receipt_sha256"] != expected_parent:
                    raise FrameworkError("v2 parent receipt chain mismatch")
            limit = self.config["resource_budget"].get("max_payload_bytes")
            if limit is not None and len(canonical(receipt.get("payload"))) > limit:
                raise FrameworkError("v2 recovered payload exceeds configured byte limit")
            if (receipt.get("sequence") != seq or receipt.get("manifest_sha256") != manifest_sha
                    or receipt.get("unit_id") != delta["unit_id"] or receipt.get("phase") != delta["phase"]
                    or receipt.get("disposition") != delta["disposition"]
                    or receipt.get("attempt_id") != delta["attempt_id"]
                    or digest(canonical(receipt.get("payload"))) != delta["payload_sha256"]):
                raise FrameworkError("v2 receipt and delta disagree")
            if receipt.get("run_id") != self.run_id or receipt.get("campaign_id") != self.config["campaign_id"]:
                raise FrameworkError("v2 receipt campaign binding mismatch")
            unit, phase = delta["unit_id"], delta["phase"]
            if phase == "start":
                expected_prefix = f"{self.config['campaign_id']}:{self.run_id}:{self.config['campaign_attempt_id']}:{unit}:"
                if delta["disposition"] != "STARTED" or not delta["attempt_id"].startswith(expected_prefix):
                    raise FrameworkError("invalid v2 start disposition/attempt identity")
                if unit not in state["pending"] or unit in state["inflight"] or unit in state["completed"]:
                    raise FrameworkError("invalid v2 start transition")
                state["pending"].remove(unit); state["inflight"].add(unit)
                state["open_attempts"][unit] = delta["attempt_id"]
            else:
                if not isinstance(delta["disposition"], str) or not delta["disposition"]:
                    raise FrameworkError("invalid v2 terminal disposition")
                admitted = validate_result(self, unit, receipt.get("payload"))
                if ("generic_caller" in self.config.get("audit_policy", {})
                        and delta["disposition"] != receipt["payload"]["result_payload"]["processing_disposition"]):
                    raise FrameworkError("TYPED_TERMINAL_DISPOSITION_MISMATCH")
                if admitted["result_id"] in state["result_ids"]:
                    raise FrameworkError("RESULT_ID_ALREADY_ADMITTED")
                state["result_ids"].add(admitted["result_id"])
                if receipt.get("admission") != admitted:
                    raise FrameworkError("v2 terminal admission metadata mismatch")
                if unit not in state["inflight"] or state["open_attempts"].get(unit) != delta["attempt_id"]:
                    raise FrameworkError("invalid v2 terminal transition")
                state["inflight"].remove(unit); state["completed"].add(unit)
                del state["open_attempts"][unit]
            previous = delta_sha
            state["sequence"] = seq; state["head"] = previous
            state["receipts"].append({"sequence": seq, "path": rp,
                                      "sha256": delta["receipt_sha256"], "unit_id": unit,
                                      "phase": phase})
            receipt_names.add(Path(rp).name)
            if seq % interval == 0:
                cpname, cphash = self._read_checkpoint(seq, previous, previous_cp, state, manifest_sha)
                previous_cp = cphash
                expected_checkpoints.add(cpname)
                state["checkpoints"].append({"sequence": seq, "path": f"checkpoints/{cpname}", "sha256": cphash})
        if ((_prefix_max_sequence is None and actual_checkpoints != expected_checkpoints)
                or (_prefix_max_sequence is not None and not expected_checkpoints.issubset(actual_checkpoints))):
            raise FrameworkError("missing or orphan v2 checkpoint")
        if ((_prefix_max_sequence is None and {p.name for p in journal.iterdir()} != expected_deltas)
                or (_prefix_max_sequence is not None and not expected_deltas.issubset({p.name for p in journal.iterdir()}))):
            raise FrameworkError("missing or orphan v2 delta")
        actual_receipts = {p.name for p in receipt_dir.iterdir()} if receipt_dir.exists() else set()
        if ((_prefix_max_sequence is None and actual_receipts != receipt_names)
                or (_prefix_max_sequence is not None and not receipt_names.issubset(actual_receipts))):
            raise FrameworkError("orphan/missing v2 receipt")
        actual_manifests = {p.name for p in manifest_dir.iterdir()} if manifest_dir.exists() else set()
        if actual_manifests != {manifest_sha + ".json"}:
            raise FrameworkError("orphan or substituted v2 manifest")
        state["complete"] = not state["pending"] and not state["inflight"]
        if _prefix_max_sequence is not None:
            state["complete"] = False
            state["recovery_status"] = "INCOMPLETE_READ_ONLY"
            state["verified_prefix_sequence"] = _prefix_max_sequence
        self._v2_manifest, self._v2_manifest_sha = manifest, manifest_sha
        self._v2_manifest_raw = manifest_raw
        self._v2_manifest_verified = True
        rejected_dir = self.output / "rejected"
        self._v2_error_count = len(list(rejected_dir.glob("*.json"))) if rejected_dir.exists() else 0
        audit_guard = ResourceGuard(
            self.output, read_only=True,
            accounted_paths=(self.registry_root / ".pgop1-run-registry" / (self.run_id + ".json"),
                             self.registry_root / ".pgop1-attempt-registry" / (digest(canonical([self.run_id, self.config["campaign_attempt_id"]])) + ".json")),
        )
        audit_guard.refresh_usage()
        self._v2_state = state
        self._v2_events_since_checkpoint = state["sequence"] % interval
        return state

    def recover_valid_prefix(self):
        """Return the newest independently verified checkpoint prefix read-only.

        This is an inspection result only; it never truncates, resumes, or repairs
        a damaged tail. A caller must keep the run quarantined.
        """
        try:
            return self.recover()
        except (FrameworkError, OSError) as original:
            directory = self.output / "checkpoints"
            _path(directory, False)
            candidates = []
            if directory.is_dir() and not directory.is_symlink():
                for path in directory.iterdir():
                    if path.is_file() and not path.is_symlink() and len(path.name) > 9 and path.name[:8].isdigit():
                        candidates.append(int(path.name[:8]))
            for sequence in sorted(set(candidates), reverse=True):
                try:
                    state = self.recover(_prefix_max_sequence=sequence)
                    state["corruption_after_prefix"] = str(original)
                    return state
                except (FrameworkError, OSError):
                    continue
            return {**self._initial_state(), "recovery_status": "INCOMPLETE_READ_ONLY",
                    "verified_prefix_sequence": 0, "corruption_after_prefix": str(original)}

    def _read_checkpoint(self, seq, head, parent_cp, state, manifest_sha):
        # Names are content addressed; find exactly one checkpoint for this seq.
        directory = self.output / "checkpoints"
        _path(directory, False)
        matches = list(directory.glob(f"{seq:08d}-*.json")) if directory.exists() else []
        if len(matches) != 1:
            raise FrameworkError("required periodic checkpoint missing or ambiguous")
        path = matches[0]
        _path(path, True)
        raw = path.read_bytes(); value = _loads(raw); sha = digest(raw)
        if path.name != f"{seq:08d}-{sha}.json" or canonical(value) != raw:
            raise FrameworkError("checkpoint content address/canonical form mismatch")
        expected = {"schema": CHECKPOINT_SCHEMA, "sequence": seq, "manifest_sha256": manifest_sha,
                    "head_delta_sha256": head, "parent_checkpoint_sha256": parent_cp,
                    "state_sha256": digest(canonical({"completed": sorted(state["completed"]),
                                                       "pending": sorted(state["pending"]),
                                                       "inflight": sorted(state["inflight"])}))}
        if value != expected:
            raise FrameworkError("checkpoint commitment/state mismatch")
        return path.name, sha

    def _verify_reservations_and_owner(self):
        registry = self.registry_root / ".pgop1-run-registry"
        attempts = self.registry_root / ".pgop1-attempt-registry"
        run_marker = registry / (self.run_id + ".json")
        attempt_key = digest(canonical([self.run_id, self.config["campaign_attempt_id"]]))
        attempt_marker = attempts / (attempt_key + ".json")
        try:
            expected_run = {"schema": "pgop1.experimental.run-id-reservation.v1", "run_id": self.run_id,
                            "campaign_id": self.config["campaign_id"]}
            expected_attempt = {"schema": "pgop1.experimental.run-attempt-reservation.v1", "run_id": self.run_id,
                                "campaign_id": self.config["campaign_id"],
                                "campaign_attempt_id": self.config["campaign_attempt_id"],
                                "config_sha256": self.config_sha256}
            for path, expected in ((run_marker, expected_run), (attempt_marker, expected_attempt)):
                _path(path, True)
                if path.is_symlink() or not path.is_file() or _loads(path.read_bytes()) != expected:
                    raise FrameworkError("global run/attempt reservation missing or changed")
            owner_path = self.output / "writer.owner"
            _path(owner_path, True)
            owner = _loads(owner_path.read_bytes()) if owner_path.is_file() and not owner_path.is_symlink() else None
            if (not isinstance(owner, dict) or set(owner) != {"schema", "run_id", "campaign_id", "campaign_attempt_id", "token"}
                    or owner.get("schema") != "pgop1.reusable-run-writer-owner.v1"
                    or owner.get("run_id") != self.run_id or owner.get("campaign_id") != self.config["campaign_id"]
                    or owner.get("campaign_attempt_id") != self.config["campaign_attempt_id"]
                    or not isinstance(owner.get("token"), str) or not owner["token"]):
                raise FrameworkError("writer ownership receipt missing or invalid")
        except OSError as exc:
            raise FrameworkError("reservation/owner artifact unavailable") from exc

    def _ensure_live(self):
        if self._preflight is None:
            raise FrameworkError("preflight required")
        # Rehash critical metadata/code bytes before publication. Stat equality
        # alone cannot detect same-size replacements with restored timestamps.
        # This reads pinned bytes; it never serializes selected populations or
        # repeats the source-file inventory in a durable event.
        if self.config is not self._frozen_config:
            self._write_blocked = True
            raise FrameworkError("in-memory external configuration changed after load")
        try:
            if any(self._stat_key(path) != expected for path, expected in self._critical_stats.items()):
                self._write_blocked = True
                raise FrameworkError("critical bound file identity changed; run quarantined")
            if any(digest(path.read_bytes()) != expected for path, expected in self._critical_hashes.items()):
                self._write_blocked = True
                raise FrameworkError("critical bound file bytes changed; run quarantined")
        except OSError as exc:
            self._write_blocked = True
            raise FrameworkError("critical bound file became unavailable; run quarantined") from exc

    def _record(self, unit, kind, phase, payload):
        self._ensure_live()
        if not self._can_write or self._write_blocked:
            raise FrameworkError("existing or interrupted run is read-only; fresh RUN_ID required")
        if unit not in self.config["expected_units"] or not isinstance(payload, dict):
            raise FrameworkError("unit/payload invalid")
        self.output.mkdir(parents=True, exist_ok=True)
        guard = self._guard()
        try:
            payload_raw = guard.payload_bytes(payload, self.config["resource_budget"].get("max_payload_bytes"))
        except ResourceLimitStop as exc:
            self._write_blocked = True
            raise FrameworkError(str(exc)) from exc
        if (self.output / ".resource-stop.json").exists():
            raise FrameworkError("campaign has a durable resource stop; read-only recovery only")
        # Pre-admit core's one-time lock, reservations and owner receipt before
        # invoking the existing ownership helpers.
        expected_owner = {"schema": "pgop1.reusable-run-writer-owner.v1", "run_id": self.run_id,
                          "campaign_id": self.config["campaign_id"],
                          "campaign_attempt_id": self.config["campaign_attempt_id"], "token": self._writer_token}
        registry = self.registry_root / ".pgop1-run-registry"
        attempts = self.registry_root / ".pgop1-attempt-registry"
        attempt_key = digest(canonical([self.run_id, self.config["campaign_attempt_id"]]))
        run_marker = registry / (self.run_id + ".json")
        attempt_marker = attempts / (attempt_key + ".json")
        run_value = {"schema": "pgop1.experimental.run-id-reservation.v1", "run_id": self.run_id,
                     "campaign_id": self.config["campaign_id"]}
        attempt_value = {"schema": "pgop1.experimental.run-attempt-reservation.v1", "run_id": self.run_id,
                         "campaign_id": self.config["campaign_id"],
                         "campaign_attempt_id": self.config["campaign_attempt_id"],
                         "config_sha256": self.config_sha256}
        startup_paths = []
        if not (self.output / "writer.lock").exists(): startup_paths.append(("writer.lock", 1))
        if not (self.output / "writer.owner").exists(): startup_paths.append(("writer.owner", len(canonical(expected_owner))))
        if not run_marker.exists(): startup_paths.append((run_marker, len(canonical(run_value))))
        if not attempt_marker.exists(): startup_paths.append((attempt_marker, len(canonical(attempt_value))))
        if startup_paths:
            guard.before_publication(sum(size for _, size in startup_paths))
        fd = self._acquire()
        try:
            if self._v2_state is None:
                state = self.recover()
            else:
                state = self._v2_state
            self._claim_writer()
            for path, _ in startup_paths:
                try:
                    guard.account_write(path)
                except ResourceLimitStop as exc:
                    raise FrameworkError(str(exc)) from exc
            if startup_paths:
                guard.finish_publication()
            try:
                if phase == "start":
                    guard.check_limits(unit_count=len(state["completed"]) + len(state["inflight"]))
                if phase == "start" and unit not in state["pending"]:
                    raise FrameworkError("unit is not pending")
                if phase == "terminal" and unit not in state["inflight"]:
                    raise FrameworkError("unit is not inflight")
                admission = {}
                if phase == "terminal":
                    try:
                        admission = validate_result(self, unit, payload)
                        if ("generic_caller" in self.config.get("audit_policy", {})
                                and kind != payload["result_payload"]["processing_disposition"]):
                            raise FrameworkError("TYPED_TERMINAL_DISPOSITION_MISMATCH")
                        if admission["result_id"] in state["result_ids"]:
                            raise FrameworkError("RESULT_ID_ALREADY_ADMITTED")
                    except FrameworkError as rejected:
                        self._store_rejected(payload_raw)
                        self._v2_error_count += 1
                        try:
                            guard.check_limits(error_count=self._v2_error_count)
                        except ResourceLimitStop as stop:
                            self._write_blocked = True
                            raise FrameworkError(str(rejected) + "; " + str(stop)) from rejected
                        raise
                self._publish_v2(state, unit, kind, phase, payload, admission)
            except ResourceLimitStop as exc:
                self._write_blocked = True
                raise FrameworkError(str(exc)) from exc
        except BaseException:
            if phase == "terminal" and self._v2_state is None:
                self._write_blocked = True
            raise
        finally:
            self._release(fd)
        return self._v2_state["receipts"][-1]

    def _store_rejected(self, raw):
        sha = digest(raw); relative = f"rejected/{sha}.json"
        path = self.output / relative
        guard = self._guard()
        if not path.exists():
            guard.before_publication(len(raw))
            _write_immutable(path, raw)
            guard.account_write(relative, len(raw))
            guard.finish_publication()

    def request_stop(self, reason="EXPLICIT_REQUEST", details=None):
        """Request a durable stop; stopped campaigns remain read-only recoverable."""
        self._ensure_live()
        if not self._can_write or self._write_blocked:
            raise FrameworkError("existing or interrupted run is read-only; stop publication forbidden")
        return self._guard().request_stop(reason, details)

    def resources_report(self):
        return self._guard().snapshot()

    def _publish_v2(self, state, unit, disposition, phase, payload, admission):
        if self._v2_manifest is None or not self._v2_manifest_verified:
            manifest, manifest_sha, manifest_raw = self._manifest_value()
        else:
            manifest, manifest_sha = self._v2_manifest, self._v2_manifest_sha
            if not self._v2_manifest_verified:
                self._ensure_manifest(manifest, manifest_sha, self._v2_manifest_raw, create=True)
                self._v2_manifest_verified = True
        seq = state["sequence"] + 1
        attempt_id = state["open_attempts"].get(unit) if phase == "terminal" else (
            f"{self.config['campaign_id']}:{self.run_id}:{self.config['campaign_attempt_id']}:{unit}:{os.urandom(8).hex()}")
        if not attempt_id:
            raise FrameworkError("terminal receipt has no bound start identity")
        receipt = {"schema": RECEIPT_SCHEMA, "run_id": self.run_id,
                   "campaign_id": self.config["campaign_id"], "attempt_id": attempt_id,
                   "unit_id": unit, "phase": phase, "disposition": disposition,
                   "sequence": seq, "manifest_sha256": manifest_sha,
                   "admission": admission, "payload": payload}
        if self.config["checkpoint_policy"].get("receipt_parent_chain", False):
            receipt["parent_receipt_sha256"] = state["receipts"][-1]["sha256"] if state["receipts"] else None
        receipt_raw = canonical(receipt); receipt_sha = digest(receipt_raw)
        receipt_path = f"receipts/{seq:08d}-{receipt_sha}.json"
        delta = {"schema": DELTA_SCHEMA, "sequence": seq, "previous_delta_sha256": state["head"],
                 "manifest_sha256": manifest_sha, "receipt_path": receipt_path,
                 "receipt_sha256": receipt_sha, "unit_id": unit, "phase": phase,
                 "disposition": disposition, "attempt_id": attempt_id,
                 "payload_sha256": digest(canonical(payload)),
                 "resource_snapshot": self._guard().snapshot()}
        delta_raw = canonical(delta)
        interval = self.config["checkpoint_policy"]["interval"]
        cp_raw = cp_path = None
        if seq % interval == 0:
            next_completed = set(state["completed"]); next_pending = set(state["pending"]); next_inflight = set(state["inflight"])
            if phase == "start": next_pending.remove(unit); next_inflight.add(unit)
            else: next_inflight.remove(unit); next_completed.add(unit)
            state_sha = digest(canonical({"completed": sorted(next_completed), "pending": sorted(next_pending), "inflight": sorted(next_inflight)}))
            cp = {"schema": CHECKPOINT_SCHEMA, "sequence": seq,
                  "manifest_sha256": manifest_sha, "head_delta_sha256": digest(delta_raw),
                  "parent_checkpoint_sha256": state["checkpoints"][-1]["sha256"] if state["checkpoints"] else None,
                  "state_sha256": state_sha}
            cp_raw = canonical(cp); cp_sha = digest(cp_raw); cp_path = f"checkpoints/{seq:08d}-{cp_sha}.json"
        delta_sha = digest(delta_raw)
        delta_path = f"deltas/{seq:08d}-{delta_sha}.json"
        publications = [(receipt_path, len(receipt_raw)), (delta_path, len(delta_raw))]
        if not self._v2_manifest_verified:
            publications.append((f"manifest/{manifest_sha}.json", len(manifest_raw)))
        if cp_path:
            publications.append((cp_path, len(cp_raw)))
        guard = self._guard(); guard.before_publication(sum(size for _, size in publications))
        try:
            if not self._v2_manifest_verified:
                self._ensure_manifest(manifest, manifest_sha, manifest_raw, create=True, reserved=True)
                self._v2_manifest, self._v2_manifest_sha = manifest, manifest_sha
                self._v2_manifest_raw = manifest_raw
                self._v2_manifest_verified = True
            _write_immutable(self.output / receipt_path, receipt_raw)
            guard.account_write(receipt_path, len(receipt_raw))
            _write_immutable(self.output / delta_path, delta_raw)
            guard.account_write(delta_path, len(delta_raw))
            if cp_path:
                _write_immutable(self.output / cp_path, cp_raw)
                guard.account_write(cp_path, len(cp_raw))
            guard.finish_publication()
        except BaseException as interrupted:
            self._write_blocked = True
            self._v2_state = None
            try:
                guard.request_stop("EXTERNAL_INTERRUPTION" if isinstance(interrupted, KeyboardInterrupt) else
                                   "RESOURCE_LIMIT" if isinstance(interrupted, MemoryError) else "INTEGRITY_FAILURE",
                                   {"sequence": seq, "issue": type(interrupted).__name__})
            except ResourceLimitStop:
                pass
            raise
        head = delta_sha
        if phase == "start":
            state["pending"].remove(unit); state["inflight"].add(unit)
            state["open_attempts"][unit] = attempt_id
        else:
            state["inflight"].remove(unit); state["completed"].add(unit)
            state["open_attempts"].pop(unit, None)
            state["result_ids"].add(admission["result_id"])
        state.update({"sequence": seq, "head": head,
                      "complete": not state["pending"] and not state["inflight"]})
        state["receipts"].append({"sequence": seq, "path": receipt_path,
                                  "sha256": receipt_sha, "unit_id": unit, "phase": phase})
        if cp_path:
            state["checkpoints"].append({"sequence": seq, "path": cp_path, "sha256": digest(cp_raw)})
        self._v2_state = state
        return receipt

    def begin_unit(self, unit_id: str, payload: dict):
        return self._record(unit_id, "STARTED", "start", payload)

    def complete_unit(self, unit_id: str, disposition: str, payload: dict):
        if not isinstance(disposition, str) or not disposition:
            raise FrameworkError("terminal disposition required")
        return self._record(unit_id, disposition, "terminal", payload)

    def report(self):
        state = self.recover()
        return {"schema": "pgop1.reusable-run-report.v2", "run_id": self.run_id,
                "campaign_id": self.config["campaign_id"], "config_sha256": self.config_sha256,
                "manifest_sha256": self._v2_manifest_sha, "expected_count": len(self.config["expected_units"]),
                "completed_count": len(state["completed"]), "pending_units": sorted(state["pending"]),
                "inflight_units": sorted(state["inflight"]), "status": "COMPLETE_WITH_DISPOSITIONS" if state["complete"] else "PARTIAL",
                "execution_completeness": "NOT_CERTIFIED", "receipt_count": len(state["receipts"]),
                "checkpoint_count": len(state["checkpoints"])}
