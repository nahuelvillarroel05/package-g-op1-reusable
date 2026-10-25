"""Read-only I0 freeze and migration inventory verifier; emits synthetic JSON evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from package_g.op1_reusable.identity import generate_id, sha256_bytes, strict_json_loads
from package_g.op1_reusable.schema_registry import SchemaRegistry

SOURCE_SHA = "bbe63ee96d03712109da9f48f966a6b9c470c050092871cce3e330118ed89465"
DESIGN_SHA = "e2fd2e31fdb65175ef978473d69100c7019fae173f83a492416f8c46a8ad56dd"
SOURCE_ID = "PG-FRZ-e55f2e60890261eb8452d9168f776552"
DESIGN_ID = "PG-FRZ-e4687f341ca61f05dae56d05e893c77c"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify_freeze(root: Path, filename: str, expected_sha: str, expected_id: str, expected_count: int) -> dict:
    raw = (root / filename).read_bytes()
    require(sha256_bytes(raw) == expected_sha, f"freeze SHA mismatch: {filename}")
    manifest = strict_json_loads(raw)
    require(manifest["freeze_id"] == expected_id, "freeze ID mismatch")
    require(manifest["document_count"] == expected_count == len(manifest["documents"]), "freeze member count mismatch")
    rows = []
    seen = set()
    for member in manifest["documents"]:
        rel = member["relative_path"]
        require(rel not in seen and Path(rel).name == rel, "duplicate or unsafe member path")
        seen.add(rel)
        content = (root / rel).read_bytes()
        require(len(content) == member["byte_length"] and sha256_bytes(content) == member["sha256"], rel)
        rows.append({"relative_path": rel, "byte_length": len(content), "sha256": member["sha256"]})
    return {"freeze_id": expected_id, "freeze_sha256": expected_sha, "member_count": len(rows), "members": rows, "status": "PASS"}


def verify_migration(design_root: Path) -> dict:
    plan = strict_json_loads((design_root / "OP1_IMPLEMENTATION_MIGRATION_PLAN.json").read_bytes())
    rows = plan["substantive_rows"]
    props = plan["top_level_property_inventory"]
    require(len(rows) == plan["substantive_row_count"] == 36, "migration row count mismatch")
    require(len(props) == plan["top_level_property_count"] == 148, "migration property count mismatch")
    require(plan["unclassified_top_level_properties"] == 0, "unclassified migration properties")
    allowed = {"KEEP_UNCHANGED", "MOVE_TO_RUN_LEVEL", "MOVE_TO_SESSION_LEVEL", "DEPRECATE_BUT_PRESERVE", "REPLACE"}
    require({row["row"] for row in rows} == set(range(1, 37)), "migration row numbering mismatch")
    require({row["property_row"] for row in props} == set(range(1, 149)), "migration property numbering mismatch")
    require(all(row["classification"] in allowed and row["target_component"] for row in rows + props), "migration classification missing")
    require(len({(row["source_file"], row["source_json_path"]) for row in props}) == 148, "duplicate migration property")
    historical_root = Path(plan["historical_at2_root"])
    historical = plan["historical_member_hashes"]
    for filename, digest in historical.items():
        require(Path(filename).name == filename, "unsafe historical path")
        require(sha256_bytes((historical_root / filename).read_bytes()) == digest, filename)
    return {"substantive_rows": 36, "top_level_properties": 148, "unclassified": 0, "historical_member_hashes_verified": len(historical), "status": "PASS"}


def verify_schema_copies(source_root: Path, package_root: Path) -> dict:
    registry = SchemaRegistry()
    for entry in registry.entries:
        name = entry.document_id
        frozen = (source_root / name).read_bytes()
        copied = (package_root / "schemas" / name).read_bytes()
        require(frozen == copied and sha256_bytes(copied) == entry.sha256, name)
    return {"schema_count": len(registry.entries), "all_frozen_bytes_equal": True, "status": "PASS"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--design-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "artifact_id": generate_id("ARTIFACT"),
        "test_run_id": generate_id("RUN"),
        "phase": "OP1_REUSABLE_IMPLEMENTATION_I0",
        "mode": "READ_ONLY_FROZEN_INPUT_VERIFICATION",
        "source": verify_freeze(args.source_root, "OP1_REUSABLE_EXECUTION_IDENTITY_DESIGN_FREEZE.json", SOURCE_SHA, SOURCE_ID, 26),
        "design": verify_freeze(args.design_root, "OP1_REUSABLE_ARCHITECTURE_IMPLEMENTATION_DESIGN_FREEZE.json", DESIGN_SHA, DESIGN_ID, 17),
        "migration": verify_migration(args.design_root),
        "schema_copies": verify_schema_copies(args.source_root, Path(__file__).resolve().parents[1] / "src/package_g/op1_reusable"),
        "result": "PASS",
    }
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"result": report["result"], "source_members": 26, "design_members": 17, "migration_rows": 36, "migration_properties": 148, "schemas": 15, "test_run_id": report["test_run_id"]}, sort_keys=True))


if __name__ == "__main__":
    main()