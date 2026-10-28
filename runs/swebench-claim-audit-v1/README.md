# PGOP1 SWE-bench Claim Audit V1

This directory contains the public, non-verbatim V1 evidence layer. The original V4 sample remains frozen at 12 instances. Three runs produced 36 receipts with 6 `SUPPORTED` and 6 `CONTRADICTED` outcomes.

Those verdicts compare a detected statement in a local trajectory with the corresponding archived evaluator report, experiment catalog, and summary. They do not show that PGOP1 resolved SWE-bench issues, authenticate the agent or evaluator, or re-execute any patch.

The Multilingual test Parquet was read as 300 unique rows. Its local SHA-256 matches the file hash shown by the official [SWE-bench Multilingual dataset file page](https://huggingface.co/datasets/SWE-bench/SWE-bench_Multilingual/blob/main/data/test-00000-of-00001.parquet) at revision `846e647` observed on 2026-10-27. The complete dataset is not included.

The archived run and experiment catalog have source URLs and local snapshot hashes in `verification/SOURCE_REFERENCES.json`. The agent run's redistribution license remains unknown; the public evidence includes no trajectories, patches, predictions, or raw evaluator logs.

At the original V1 publication checkpoint, the official SWE-bench regrade was `BLOCKED`: the local verifier checkout was version 5.0.2, but the active Python environment lacked its CLI dependencies and the stock verifier had no argument for a local Parquet path. This is preserved as historical status. A separate network-recovery verification dated 2026-10-28 later completed: it regraded 258 archived log instances with the source-checkout CLI (`PASS`) and directly graded the 12 frozen V1 cases (6 resolved, 6 not resolved; 12/12 matched the archived results and V4 verdicts). See [the public recovery evidence](verification/network-recovery-20261028/TECHNICAL_AUDIT_SUMMARY.md) and [campaign summary](CAMPAIGN_SUMMARY.md). The 258-log and 12-case denominators are distinct; no patch rerun or operational I7 qualification is claimed.

## Files

- `campaign-selection/CAMPAIGN_SELECTION_V4_PUBLIC.json` — frozen IDs, selection hash, and non-verbatim claim bindings.
- `results/V4_AGGREGATE_PUBLIC.json` — bounded V4 aggregate.
- `results/V1_OFFICIAL_CROSS_VERIFICATION.json` — twelve row bindings and the original blocked comparison state, preserved as historical evidence.
- `receipts/RECEIPT_INDEX_PUBLIC.json` — hashes and verdicts for all 36 V4 receipts; original trajectories and logs are excluded because redistribution rights are unresolved.
- `verification/` — dataset hash/shape, source URLs and local hashes, twelve `repo`/`version`/`base_commit` bindings, and the historical regrade attempt ledger, followed by the separate [2026-10-28 network-recovery verification](verification/network-recovery-20261028/REGRADE_EXECUTION_PUBLIC.json).
- `manifests/TEST_EXECUTION_REPORT_PUBLIC.json` — historical T008, prospective RED/GREEN attempts, and final T018 evidence.

See [`docs/swebench-claim-audit`](../../docs/swebench-claim-audit/README.md) for method, limits, and reproduction instructions.


## Later verification

- [Campaign summary](CAMPAIGN_SUMMARY.md)
- [Network-recovery technical audit summary](verification/network-recovery-20261028/TECHNICAL_AUDIT_SUMMARY.md)
- [Source manifest for public derivations](verification/network-recovery-20261028/SOURCE_MANIFEST.json)
