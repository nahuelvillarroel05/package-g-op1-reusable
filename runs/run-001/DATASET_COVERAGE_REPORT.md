# PGOP1 RUN-001 input inventory and dataset coverage

## Status

Read-only inventory over the frozen pre-hash listing, excluding the current Engineering/PGOP1_RUN_001 workspace. Snapshot coverage is incomplete: 25 protected directory enumeration failures are preserved exactly in frozen_input_listing_summary.json. No permission or ACL changes were attempted.

## File inventory

- Regular files listed and SHA-256 hashed: 25,580/25,580.
- Bytes streamed through SHA-256: 830,354,973.
- Hash read errors: 0.
- Frozen-listing size/mtime drift: 0.
- Unreadable directory enumeration errors: 25.

INPUT_INVENTORY.json retains private paths, hashes, stable source IDs, roles, eligibility and safe publication projections. SOURCE_PROVENANCE.json records file-level provenance. Source revision is assigned only to files independently matched in UPSTREAM_VERIFICATION.json; other revisions remain UNKNOWN.

## Dataset row coverage

Only instance_id and repo columns were read from six dataset shards. Patch, test patch, problem statement, hints, evaluator result, trajectory and claim text were not read.

| Dataset | Unique instance IDs |
|---|---:|
| Full | 2,519 |
| Lite | 323 |
| Verified | 500 |
| Multilingual | 300 |
| Unique across datasets | 2,819 |

Pairwise overlap counts are in inventory_hash_summary.json: {"FULL intersect LITE": 323, "FULL intersect VERIFIED": 500, "LITE intersect VERIFIED": 93}.

## Agent, submission and historical artifacts

The filename-only logs/trajs catalog contains 264 files across 37 provisional repository groups. It includes the twelve historical development IDs. Forty additional IDs share the six historical repositories and are labeled NEW_DEVELOPMENT_ALLOW_HISTORICAL_PROVENANCE. Repository buckets outside those repositories yield 59 NEW_DEVELOPMENT candidates, 49 repository-heldout candidates, and 104 reserve candidates. Because all logs/trajs share one historical source-submission group, independent heldout trajectory count is zero; the 49 are exploratory repository-heldout only. Exact IDs are in SPLIT_ASSIGNMENT.json; the earlier assignment is preserved as SPLIT_ASSIGNMENT_PRELIMINARY.json.

The public experiment catalog contains 285 grouped submission identifiers across 326 dataset-partition directories and 300 chat-transcript files. PUBLIC_SUBMISSION_SPLIT.json gives deterministic whole-submission catalog partitions. The heldout transcript contents remain unopened and this catalog split is not an independent claim-language evaluation.

SWE-bench-main is source/evaluator code, not an agent trajectory. experiments-main/evaluation/**/results/ is third-party evaluator-result material, and chat-transcripts/ is historical agent evidence. PGOP1_* and prior Engineering trees are historical derived artifacts, not fresh raw sources.

## Formats and limits

Observed types include JSON, JSONL, gzip, diff, CSV, Parquet, ORC, Feather, SQLite, YAML/YML, text/Markdown, Python and archives. Exact counts and roles are machine-readable in INPUT_INVENTORY.json. Format presence alone does not establish processing eligibility.

This is an inventory and coverage report, not a processed campaign result. A dataset row is not an agent run or claim. The snapshot remains incomplete because protected directories could not be read.

This document records the inventory stage. Final parser/audit dispositions are in COVERAGE_REPORT.json; all declared supplemental reference inputs are separately accounted for.
