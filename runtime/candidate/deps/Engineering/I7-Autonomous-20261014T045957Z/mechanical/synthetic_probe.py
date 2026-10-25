"""Foreground fixed Python probe: local observations, never ownership proof."""
import datetime
import hashlib
import json
import math
import subprocess
import sys
import time
import uuid

if __package__:
    from .process_receipts import validate_receipt
else:
    from process_receipts import validate_receipt


_PROBE_CODE = "import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1])); sys.stdout.buffer.flush(); sys.stderr.buffer.write(bytes.fromhex(sys.argv[2])); sys.stderr.buffer.flush(); sys.exit(int(sys.argv[3]))"
_CLEANUP_TIMEOUT = 2.0


def _utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def record_synthetic_probe(stdout=b"", stderr=b"", *, exit_code=0, timeout=5.0):
    """Execute only a fixed stdlib probe with ASCII data and return its receipt.

    Bytes travel as hex arguments, never interpolated into executable code.
    Each stream is capped at 4096 bytes to keep argv below Windows limits.
    The launch UUID is local correlation, not an OS process start timestamp.
    Receipt success concerns this synthetic invocation, never native admission.
    ``expectations_met`` compares requested bytes and exit code to observations.
    ``probe_success`` additionally requires a timely zero exit. Receipt validation
    retains its separate exit-code-only execution_success field.
    """
    for body in (stdout, stderr):
        if type(body) is not bytes or len(body) > 4096:
            raise ValueError("each stream requires at most 4096 ASCII bytes")
        try:
            body.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError("ASCII bytes required") from error
    if type(exit_code) is not int or not 0 <= exit_code <= 255:
        raise ValueError("exit code requires integer 0..255")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10:
        raise ValueError("timeout requires finite seconds in (0,10]")
    argv = [sys.executable, "-I", "-B", "-c", _PROBE_CODE, stdout.hex(), stderr.hex(), str(exit_code)]
    launch_id = str(uuid.uuid4())
    invocation_id = "probe:" + launch_id
    actor_id = "engineering-synthetic-recorder"
    command = json.dumps(argv, ensure_ascii=True, separators=(",", ":"))
    started_utc = _utc()
    started_monotonic = time.monotonic()
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=False)
    timed_out = False
    try:
        try:
            observed_stdout, observed_stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            observed_stdout, observed_stderr = process.communicate(timeout=_CLEANUP_TIMEOUT)
        if type(process.returncode) is not int:
            raise RuntimeError("probe terminal exit not observed")
    except BaseException:
        try:
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    # A concurrent terminal exit can race kill. Waiting still
                    # decides whether termination was actually observed.
                    pass
            process.wait(timeout=_CLEANUP_TIMEOUT)
        except BaseException as cleanup_error:
            raise RuntimeError("probe terminal exit could not be observed during cleanup") from cleanup_error
        raise
    ended_utc = _utc()
    elapsed = time.monotonic() - started_monotonic
    process_instance = {"pid": process.pid, "start_id": launch_id}
    invocation = {"id": invocation_id, "command": command,
                  "command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
                  "actor_id": actor_id, "actor_role": "WORKER", "process_instance": process_instance}
    outputs = {"stdout": observed_stdout, "stderr": observed_stderr}
    events = []
    for sequence, kind in enumerate(("START", "OUTPUT", "OUTPUT", "EXIT"), 1):
        event = {"id": f"{launch_id}:{sequence}", "sequence": sequence, "kind": kind,
                 "invocation_id": invocation_id, "actor_id": actor_id,
                 "process_instance": dict(process_instance)}
        if kind == "OUTPUT":
            output_id = "stdout" if sequence == 2 else "stderr"
            event.update(output_id=output_id, sha256=hashlib.sha256(outputs[output_id]).hexdigest())
        elif kind == "EXIT":
            event["exit_code"] = process.returncode
        events.append(event)
    receipt = {"schema": "MECHANICAL034_SYNTHETIC_RECEIPT_V1", "scope": "SYNTHETIC_ENGINEERING",
               "run_id": launch_id, "invocations": [invocation], "events": events}
    expectations_met = (observed_stdout == stdout and observed_stderr == stderr
                        and process.returncode == exit_code)
    return {"receipt": receipt, "outputs": outputs,
            "expectations_met": expectations_met,
            "probe_success": expectations_met and not timed_out and process.returncode == 0,
            "execution_success": not timed_out and process.returncode == 0,
            "probe_status": "TIMEOUT" if timed_out else "EXITED_ZERO" if process.returncode == 0 else "EXITED_NONZERO",
            "validation": validate_receipt(receipt, outputs),
            "observations": {"pid": process.pid, "pid_origin": "LOCAL_POPEN_OBSERVATION",
                             "launch_id_origin": "LOCALLY_GENERATED_UUID",
                             "start_id_semantics": "LOCAL_LAUNCH_CORRELATION_NOT_OS_START_TIME",
                             "started_utc": started_utc, "ended_utc": ended_utc,
                             "elapsed_monotonic_seconds": elapsed, "timed_out": timed_out,
                             "exit_observed": True, "exit_code": process.returncode,
                             "process_ownership": "NOT_PROVEN", "independent_custody": "NOT_PROVEN"}}
