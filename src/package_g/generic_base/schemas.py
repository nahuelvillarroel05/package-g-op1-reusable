"""Small schema helpers used by Package G V2 dryrun components."""
from __future__ import annotations

from typing import Mapping, Sequence


def require_fields(name: str, payload: Mapping[str, object], fields: Sequence[str]) -> None:
    missing = [field for field in fields if field not in payload]
    if missing:
        raise ValueError(f"{name} missing required fields: {missing}")
