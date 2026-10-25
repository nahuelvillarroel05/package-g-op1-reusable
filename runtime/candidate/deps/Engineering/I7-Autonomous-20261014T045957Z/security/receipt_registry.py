"""Local prospective receipt replay/revocation consistency, never authority.

No persistence, process execution, file reads, tokens or real grants. A registry
instance is its own namespace: process instances are declared (PID, start_id)
pairs. Callers must not join receipts from unrelated PID namespaces.
"""
import copy
import hashlib
import json
import threading

from mechanical.process_receipts import validate_receipt


def _plain_snapshot(value, active=None, depth=0):
    """Copy only exact builtin data, never invoking caller object hooks."""
    if depth > 32:
        raise ValueError("receipt data nesting exceeds 32")
    if type(value) in (str, int, bool, bytes, type(None)):
        return value
    if type(value) not in (dict, list):
        raise ValueError("receipt data requires exact builtin types")
    if active is None:
        active = set()
    identity = id(value)
    if identity in active:
        raise ValueError("cyclic receipt data")
    active.add(identity)
    try:
        if type(value) is list:
            return [_plain_snapshot(item, active, depth + 1) for item in value]
        result = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("receipt mapping keys require exact strings")
            result[key] = _plain_snapshot(item, active, depth + 1)
        return result
    finally:
        active.remove(identity)


class ReceiptRegistry:
    """Atomically admit validated synthetic declarations once per identity.

    Revocation preserves local history and permanently reserves admitted IDs.
    It does not revoke a real runtime grant or authenticate receipt provenance.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._runs = {}
        self._invocations = set()
        self._processes = set()
        self._revoked = set()
        self._history = []

    def admit(self, receipt, outputs):
        """Validate a private snapshot before the atomic check-and-admit."""
        candidate = _plain_snapshot(receipt)
        supplied_outputs = _plain_snapshot(outputs)
        result = validate_receipt(candidate, supplied_outputs)
        # Commitments bind supplied declarations/bytes; they are not signatures.
        canonical = json.dumps(candidate, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False).encode("utf-8")
        result["receipt_sha256"] = hashlib.sha256(canonical).hexdigest()
        result["output_sha256"] = {output_id: hashlib.sha256(supplied_outputs[output_id]).hexdigest()
                                   for output_id in sorted(supplied_outputs)}
        run_id = candidate["run_id"]
        invocations = {row["id"] for row in candidate["invocations"]}
        processes = {(row["process_instance"]["pid"], row["process_instance"]["start_id"])
                     for row in candidate["invocations"]}
        with self._lock:
            if run_id in self._revoked:
                raise ValueError("run locally revoked")
            if run_id in self._runs:
                raise ValueError("run replay")
            if invocations & self._invocations:
                raise ValueError("cross-receipt invocation replay")
            if processes & self._processes:
                raise ValueError("cross-receipt process-instance replay")
            entry = {**result, "local_state": "ADMITTED", "registry_scope": "LOCAL_IN_MEMORY"}
            self._runs[run_id] = entry
            self._invocations.update(invocations)
            self._processes.update(processes)
            self._history.append({"action": "ADMITTED", "run_id": run_id})
            return copy.deepcopy(entry)

    def revoke_run(self, run_id):
        """Idempotently mark a run locally revoked; retain admission history."""
        if type(run_id) is not str or not run_id or run_id.strip() != run_id:
            raise ValueError("nonempty exact run identifier required")
        with self._lock:
            if run_id in self._revoked:
                return False
            self._revoked.add(run_id)
            if run_id in self._runs:
                self._runs[run_id] = {**self._runs[run_id], "local_state": "REVOKED"}
            self._history.append({"action": "REVOKED", "run_id": run_id})
            return True

    def snapshot(self):
        """Return isolated local declarations with explicit evidence limits."""
        with self._lock:
            return copy.deepcopy({
                "runs": self._runs, "revoked_runs": sorted(self._revoked), "history": self._history,
                "registry_scope": "LOCAL_IN_MEMORY", "independent_custody": "NOT_PROVEN",
                "process_ownership": "NOT_PROVEN", "native_qualification": False,
            })
