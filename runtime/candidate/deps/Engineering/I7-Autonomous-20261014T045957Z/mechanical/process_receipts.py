"""Validate prospective synthetic Mechanical034 receipts without executing tools.

This checks consistency of caller-supplied declarations and output bytes. It
does not authenticate actors, prove process ownership, or read original bodies.
"""
import hashlib
import re


def _fields(value, fields, label):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError(f"{label}: exact fields required")


def _identifier(value, label):
    if type(value) is not str or not value or value.strip() != value:
        raise ValueError(f"{label}: nonempty exact identifier required")


def _hash(value, label):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label}: lowercase SHA-256 required")


def _process(value):
    _fields(value, ("pid", "start_id"), "process_instance")
    if type(value["pid"]) is not int or value["pid"] <= 0:
        raise ValueError("process_instance: positive integer PID required")
    _identifier(value["start_id"], "process start_id")


def validate_receipt(receipt, outputs):
    """Return a synthetic reconciliation result or raise ValueError, fail closed.

    ``outputs`` maps exact output IDs to supplied bytes. Every output must have
    one OUTPUT event belonging to a started, not yet exited invocation. PIDs
    bind together with launch IDs to prevent accidental PID-reuse attribution.
    Sequence numbers are contiguous across the receipt's event stream. All PIDs
    belong to one declared namespace; simultaneous launches cannot share a PID.
    Resource limits must be imposed by the caller before supplying the receipt.
    """
    _fields(receipt, ("schema", "scope", "run_id", "invocations", "events"), "receipt")
    if (type(receipt["schema"]) is not str or type(receipt["scope"]) is not str
            or receipt["schema"] != "MECHANICAL034_SYNTHETIC_RECEIPT_V1" or receipt["scope"] != "SYNTHETIC_ENGINEERING"):
        raise ValueError("only prospective synthetic receipt scope supported")
    _identifier(receipt["run_id"], "run_id")
    if type(outputs) is not dict:
        raise ValueError("outputs: exact byte mapping required")
    for output_id, body in outputs.items():
        _identifier(output_id, "output_id")
        if type(body) is not bytes:
            raise ValueError("outputs: bytes required")
    if type(receipt["invocations"]) is not list or not receipt["invocations"]:
        raise ValueError("nonempty invocation list required")
    if type(receipt["events"]) is not list:
        raise ValueError("event list required")
    invocations = {}
    processes = set()
    for invocation in receipt["invocations"]:
        _fields(invocation, ("id", "command", "command_sha256", "actor_id", "actor_role", "process_instance"), "invocation")
        for key in ("id", "actor_id", "command"):
            _identifier(invocation[key], key)
        _hash(invocation["command_sha256"], "command_sha256")
        if hashlib.sha256(invocation["command"].encode("utf-8")).hexdigest() != invocation["command_sha256"]:
            raise ValueError("command hash mismatch")
        if type(invocation["actor_role"]) is not str or invocation["actor_role"] not in ("WORKER", "OBSERVER"):
            raise ValueError("unsupported synthetic actor role")
        _process(invocation["process_instance"])
        process = invocation["process_instance"]
        key = (process["pid"], process["start_id"])
        if invocation["id"] in invocations or key in processes:
            raise ValueError("duplicate invocation or process instance")
        invocations[invocation["id"]] = invocation
        processes.add(key)
    states = {key: "NOT_STARTED" for key in invocations}
    active_pids = {}
    event_ids = set()
    verified_outputs = set()
    exit_codes = {}
    base_fields = ("id", "sequence", "kind", "invocation_id", "actor_id", "process_instance")
    for sequence, event in enumerate(receipt["events"], 1):
        if (type(event) is not dict or type(event.get("kind")) is not str
                or event["kind"] not in ("START", "OUTPUT", "EXIT")):
            raise ValueError("unknown event kind")
        kind = event["kind"]
        extras = ("output_id", "sha256") if kind == "OUTPUT" else ("exit_code",) if kind == "EXIT" else ()
        _fields(event, base_fields + extras, "event")
        for field in ("id", "invocation_id", "actor_id"):
            _identifier(event[field], field)
        if type(event["sequence"]) is not int or event["sequence"] != sequence:
            raise ValueError("event sequence is not contiguous")
        if event["id"] in event_ids:
            raise ValueError("duplicate event ID")
        event_ids.add(event["id"])
        invocation = invocations.get(event["invocation_id"])
        if invocation is None:
            raise ValueError("event references unknown invocation")
        _process(event["process_instance"])
        if event["actor_id"] != invocation["actor_id"] or event["process_instance"] != invocation["process_instance"]:
            raise ValueError("event actor/process binding mismatch")
        state = states[invocation["id"]]
        if kind == "START":
            if state != "NOT_STARTED":
                raise ValueError("duplicate or late START")
            pid = invocation["process_instance"]["pid"]
            if pid in active_pids:
                raise ValueError("overlapping process instances share PID")
            active_pids[pid] = invocation["id"]
            states[invocation["id"]] = "RUNNING"
        else:
            if state != "RUNNING":
                raise ValueError("event requires running invocation")
            if kind == "EXIT":
                if type(event["exit_code"]) is not int:
                    raise ValueError("integer exit_code required")
                exit_codes[invocation["id"]] = event["exit_code"]
                states[invocation["id"]] = "EXITED"
                del active_pids[invocation["process_instance"]["pid"]]
            else:
                _identifier(event["output_id"], "output_id")
                _hash(event["sha256"], "output sha256")
                output_id = event["output_id"]
                if output_id in verified_outputs or output_id not in outputs:
                    raise ValueError("duplicate or missing output bytes")
                if hashlib.sha256(outputs[output_id]).hexdigest() != event["sha256"]:
                    raise ValueError("output hash mismatch")
                verified_outputs.add(output_id)
    if any(state != "EXITED" for state in states.values()):
        raise ValueError("incomplete invocation lifecycle")
    if verified_outputs != set(outputs):
        raise ValueError("unbound output bytes")
    return {"receipt_valid": True, "run_id": receipt["run_id"],
            "invocations_verified": len(invocations), "outputs_verified": len(verified_outputs),
            "execution_success": all(code == 0 for code in exit_codes.values()),
            "exit_codes": dict(sorted(exit_codes.items())),
            "actor_classification": "DECLARED_SYNTHETIC",
            "process_ownership": "NOT_PROVEN", "independent_custody": "NOT_PROVEN",
            "historical_process_identity": "UNKNOWN", "native_qualification": False}
