# Methodology

## Frozen V1 sample

V4 froze the same 12-instance sample selected before adapter execution. Selection and binding hashes are retained in the public run directory. The sample is balanced across six repositories and is descriptive, not a performance estimate.

## Claim comparison

For each selected instance, the adapter finds an explicit completion statement in the archived trajectory and binds it to that instance's prediction, patch, archived test output, report, experiment catalog, and summary records. `SUPPORTED` means the statement's asserted outcome agrees with those local records. `CONTRADICTED` means it disagrees. Source hashes and relationships remain explicit.

This comparison does not establish who produced a file, whether the evaluator process was authentic, whether the issue was objectively solved, or whether the patch passes the benchmark when run again.

## Dataset binding

The local Parquet has 300 unique test rows and includes `repo`, `version`, `base_commit`, `FAIL_TO_PASS`, `PASS_TO_PASS`, `test_patch`, and `eval_script`. All twelve frozen IDs are present and individually bound to row hashes. Its local SHA-256 matches the official Hugging Face file page observed on 2026-10-27. The full Parquet is excluded from this repository and handoff ZIP.

## Post-V4 hardening

Independent review found that `PurePosixPath` normalized `.` and repeated separators before the adapter checked member path components. A prospective change now rejects noncanonical path components and compares duplicate-member keys after separator normalization. Three regression cases failed before the change and the full focused suite passed afterward. The frozen V4 results remain bound to the original code hash.
