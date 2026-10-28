# Official regrade report

**Status: `BLOCKED_BEFORE_GRADING`**

The official SWE-bench 5.0.2 verifier source was inspected without modification. The CLI invocation stopped before grading because `typer` is missing. A direct verifier import stopped because the package imports `swebench.harness`, which requires the missing `docker` Python module. The `datasets` package is also absent.

The archived selected cases have patch, report, and compressed test-output files, and the verified Multilingual Parquet contains all twelve selected IDs. However, the verifier's current interface does not accept a local Parquet path; it loads the dataset by Hugging Face ID. No dependency installation or dataset substitution was performed. No case was regraded and no official verdict is asserted.

Local SWE-bench source version: `5.0.2`. The checkout has no Git metadata; the exact source file hashes are recorded in `OFFICIAL_REGRADE_STATUS_PUBLIC.json`. The CLI documentation describes saved-output verification without Docker or task-test re-execution: [SWE-bench CLI reference](https://github.com/SWE-bench/SWE-bench/blob/main/docs/reference/cli.md).
