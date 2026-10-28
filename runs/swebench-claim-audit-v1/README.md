# PGOP1 SWE-bench Claim Audit V1

This directory contains the public, non-verbatim V1 evidence layer. The original V4 sample remains frozen at 12 instances. Three runs produced 36 receipts with 6 `SUPPORTED` and 6 `CONTRADICTED` outcomes.

Those verdicts compare a detected statement in a local trajectory with the corresponding archived evaluator report, experiment catalog, and summary. They do not show that PGOP1 resolved SWE-bench issues, authenticate the agent or evaluator, or re-execute any patch.

The Multilingual test Parquet was read as 300 unique rows. Its local SHA-256 matches the file hash shown by the official [SWE-bench Multilingual dataset file page](https://huggingface.co/datasets/SWE-bench/SWE-bench_Multilingual/blob/main/data/test-00000-of-00001.parquet) at revision `846e647` observed on 2026-10-27. The complete dataset is not included.

The archived run and experiment catalog have source URLs and local snapshot hashes in `verification/SOURCE_REFERENCES.json`. The agent run's redistribution license remains unknown; the public evidence includes no trajectories, patches, predictions, or raw evaluator logs.

The official SWE-bench regrade is `BLOCKED`: the local verifier checkout is version 5.0.2, but the current Python environment lacks its CLI dependencies and the stock verifier has no argument for a local Parquet path. No official result is asserted.

## Files

- `campaign-selection/CAMPAIGN_SELECTION_V4_PUBLIC.json` — frozen IDs, selection hash, and non-verbatim claim bindings.
- `results/V4_AGGREGATE_PUBLIC.json` — bounded V4 aggregate.
- `results/V1_OFFICIAL_CROSS_VERIFICATION.json` — twelve row bindings and the blocked official comparison state.
- `receipts/RECEIPT_INDEX_PUBLIC.json` — hashes and verdicts for all 36 V4 receipts; original trajectories and logs are excluded because redistribution rights are unresolved.
- `verification/` — dataset hash/shape, source URLs and local hashes, twelve `repo`/`version`/`base_commit` bindings, and the complete blocked regrade attempt ledger.
- `manifests/TEST_EXECUTION_REPORT_PUBLIC.json` — historical T008, prospective RED/GREEN attempts, and final T018 evidence.

See [`docs/swebench-claim-audit`](../../docs/swebench-claim-audit/README.md) for method, limits, and reproduction instructions.
