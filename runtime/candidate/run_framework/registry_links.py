"""Read-only compatibility resolver for explicit or historical run registry paths."""
from __future__ import annotations

import json
from pathlib import Path


_LINK_FIELDS = ("directory", "public_evidence_path", "contract_path", "result_path",
                "evidence_path", "contract_paths", "result_paths", "evidence_paths")


def _safe_relative(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or any(part in ("..", "") for part in path.parts):
        raise ValueError("registry path must be workspace-relative")
    resolved = (root / path).resolve(strict=False)
    if resolved != root and root not in resolved.parents:
        raise ValueError("registry path escapes repository root")
    return resolved


def verify_run_registry_links(registry: dict, root) -> dict:
    """Check relevant run links without imposing a new schema on old records."""
    base = Path(root).resolve(strict=True)
    runs = registry.get("runs") if isinstance(registry, dict) else None
    if not isinstance(runs, list):
        raise ValueError("registry runs must be a list")
    checked, missing, invalid = [], [], []
    for entry in runs:
        if not isinstance(entry, dict) or not isinstance(entry.get("ID"), str):
            invalid.append({"run_id": "UNKNOWN", "field": "entry"})
            continue
        run_id = entry["ID"]
        if run_id not in {"RUN-002", "RUN-003", "RUN-004", "RUN-006", "RUN-007", "RUN-008", "RUN-009"}:
            continue
        for field in _LINK_FIELDS:
            value = entry.get(field)
            values = value if field.endswith("_paths") and isinstance(value, list) else [value]
            for item in values:
                if item is None or item == "NONE" or item == "NOT_PUBLISHED":
                    continue
                if not isinstance(item, str):
                    invalid.append({"run_id": run_id, "field": field})
                    continue
                try:
                    target = _safe_relative(base, item)
                except (OSError, ValueError):
                    invalid.append({"run_id": run_id, "field": field})
                    continue
                row = {"run_id": run_id, "field": field, "path": item}
                if target.exists():
                    checked.append(row)
                else:
                    missing.append(row)
        # Historical publication structures are read compatibly and only
        # traversed if their optional record_path is explicitly present.
        publication = entry.get("publication_representation")
        if isinstance(publication, dict) and isinstance(publication.get("record_path"), str):
            field, item = "publication_representation.record_path", publication["record_path"]
            try:
                target = _safe_relative(base, item)
            except (OSError, ValueError):
                invalid.append({"run_id": run_id, "field": field})
            else:
                row = {"run_id": run_id, "field": field, "path": item}
                (checked if target.exists() else missing).append(row)
    return {"schema": "pgop1.run-registry-links.v1", "checked": checked,
            "missing": missing, "invalid": invalid,
            "status": "PASS" if not missing and not invalid else "FAIL"}


def verify_registry_file(path, root) -> dict:
    try:
        registry = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("run registry could not be read as UTF-8 JSON") from exc
    return verify_run_registry_links(registry, root)
