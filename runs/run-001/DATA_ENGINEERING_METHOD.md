# Data Engineering method and reproduction

## Scope

This procedure inventories all accessible regular files under <DATA_ROOT> and explicitly excludes <PRIVATE_ENGINEERING_WORKSPACE> so this run's outputs do not become inputs. Enumeration does not follow symbolic links. Files are streamed in 1 MiB blocks for SHA-256. Files are never executed.

The original source snapshot was listed before any file hashing at 2026-10-28T15:26:14Z. It recorded 4,935 directories, 25,580 regular files and 830,354,973 bytes; the snapshot has 25 PermissionError directory enumeration failures. The one excluded workspace root is not an error. No permissions or ACLs were changed.

## Runtime and resource evidence

- Python: 3.11.9 at <DATA_ROOT>\PGOP1_V1_OFFICIAL_REGRADE_NETWORK_RECOVERY_20261028T053443Z\venv\Scripts\python.exe
- pyarrow and datasets: available
- pytest: unavailable in that venv; no tests are part of this inventory operation
- D: free space before hashing: 395,810,045,952 bytes, above the 70 GB minimum
- No models, training, Docker, package installation, or external dataset acquisition

## Reproduction

Run the scripts in this order from PowerShell with the stated Python executable:

1. freeze_input_listing.py creates a new listing and refuses to overwrite existing frozen listing artifacts.
2. finalize_data_inventory.py hashes every listed regular file, compares size and mtime against the frozen listing both before and after each read, assigns source IDs/roles/eligibility, and extracts only instance_id and repo from dataset Parquet.
3. correct_splits.py preserves the first deterministic assignment as SPLIT_ASSIGNMENT_PRELIMINARY.json, applies the append-only split addendum, assigns whole public experiment submission groups using paths only, and updates provenance/report files.

The frozen listing contains the exact snapshot to reproduce; a later fresh listing may differ if the source tree changes. Reproduction must use a fresh output workspace to avoid overwriting frozen evidence.

## Integrity outcomes

All 25,580 files in the frozen listing were streamed through SHA-256 (830,354,973 bytes). Hash read errors: 0. Frozen size/mtime drift: 0. The inventory remains incomplete because the 25 denied directories could not be enumerated. The exact errors are retained in frozen_input_listing_summary.json and inventory_hash_summary.json.
