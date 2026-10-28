# Reproduction

## Adapter tests

From the repository root, run:

```powershell
python -m pytest tests/test_swebench_claim_audit.py -q -p no:cacheprovider
```

The final closeout run `PGOP1-SWB-TEST-T018` passed 44 focused tests after the prospective ZIP path and portable fixture fixes. The original V4 adapter remains identified by its original hash in the public results; the new tests do not regenerate campaign receipts.

## Dataset

Obtain `data/test-00000-of-00001.parquet` from the official [SWE-bench Multilingual dataset](https://huggingface.co/datasets/SWE-bench/SWE-bench_Multilingual). Verify SHA-256 `92abca7cb527b41a9f66d03a26ce441ff7319e3a49f985998fd56be4bb9b08b2` against the dataset file page before using it. Bind every selected ID to `repo`, `version`, and `base_commit`; do not substitute rows from Full, Lite, or Verified.

## Official regrade

The checked-in SWE-bench 5.0.2 source implements `swebench submit verify RUN_PATH --split multilingual --logs LOGS_DIR`. The verifier re-grades saved `patch.diff` and `test_output.txt[.gz]` against the dataset and does not launch Docker or rerun tests. Its current API loads the dataset by Hugging Face ID and does not accept a local Parquet argument. Confirm the verifier's exact dataset snapshot and dependencies before executing it. Do not alter the official grader or fabricate a submission `results.json`.

The closeout environment stopped before grading because its official CLI dependencies (`typer`; and on direct verifier import, `docker`) and the `datasets` package are absent. See `OFFICIAL_REGRADE_EXECUTION.json` in the final handoff for exact attempts and source hashes.

Official references: [CLI reference](https://github.com/SWE-bench/SWE-bench/blob/main/docs/reference/cli.md) and [verifier source](https://github.com/SWE-bench/SWE-bench/blob/main/swebench/submit/verify.py).
