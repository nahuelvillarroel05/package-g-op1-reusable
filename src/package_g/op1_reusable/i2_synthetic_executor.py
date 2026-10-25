"""Pure, no-worker I2 engineering outcome selector; no runtime adapter."""
from __future__ import annotations

def evaluate(outcome: str) -> str:
    if type(outcome) is not str or outcome not in (
        "PASS", "FAIL", "TIMEOUT", "CRASHED", "UNKNOWN", "INCOMPLETE_EVIDENCE",
    ):
        raise ValueError("unsupported synthetic outcome")
    return outcome
