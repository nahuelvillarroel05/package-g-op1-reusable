# PGOP1 RUN-001: bounded Level B discrepancy analysis

Status: BOUNDED_ANALYSIS_COMPLETED_WITH_LIMITS.

The six-case inspection establishes a concrete encoding mechanism for the two sampled negative regrades. It does not establish a universal cause for all 54 discrepancies or validate either side as benchmark truth. Existing outcomes remain 258 cases, 247 completed, 193 matches, 54 disagreements (regrade false / archived report true), and 11 terminal errors.

The sample was fixed before opening log bytes: the first mismatch from each of the first two lexicographic repositories; the first matching true and matching false cases; and the first two lexicographic errors. This is a purposive diagnostic sample, not an accuracy sample.

| Case | Existing stratum | Byte-level observation |
|---|---|---|
| babel__babel-13928 | Mismatch | UTF-8 valid: 498 U+2713 and 10,118 U+25CB; CP1252: zero required Jest symbols. |
| briannesbitt__carbon-2665 | Mismatch | UTF-8 valid: 11 U+2714; CP1252: zero required PHPUnit symbols. |
| apache__druid-13704 | Matching true | ASCII only; UTF-8 and CP1252 strings identical. |
| apache__druid-14092 | Matching false | ASCII only; UTF-8 and CP1252 strings identical. |
| astral-sh__ruff-15309 | Terminal error | UTF-8 valid; CP1252 fails at offset 13334, byte 0x81, matching archived error. |
| briannesbitt__carbon-2981 | Terminal error | UTF-8 valid; CP1252 fails at offset 999, byte 0x8f, matching archived error. |

The pinned `_grade` delegates to `get_eval_report`; `grading.py:127` opens the log without an explicit encoding. The current invocation of the same Python 3.11.9 executable reports CP1252, UTF-8 mode 0. This is a current observation; attempt-002 did not record its effective codec.

Static inspection of the pinned Jest and PHPUnit parsers shows that every test-status branch requires a literal Unicode marker absent from the CP1252-decoded sample. The whole-log fallback cannot recover a marker absent from the entire string. The two frozen dataset rows select these exact parsers, use `pass_and_fail`, and contain respectively two and one FAIL_TO_PASS entries. Under that code path, the empty status map cannot yield resolved=true. This proves causal sufficiency of CP1252 marker loss for a negative result in these two cases, conditional on that decoding. It does not establish that a UTF-8 grade would be true, that encoding was the only historical cause, or that the archived positive report is correct.

The two sampled terminal failures separately reproduce the recorded decoder boundary using byte decoding only. The two ASCII controls are unaffected by the encoding choice; their agreement does not establish evaluator accuracy. The remaining 52 discrepancies and nine errors were not opened for this inspection.

All 18 source-file hashes for the six cases match both INPUT_INVENTORY and existing case records. The dataset hash and all 16 source files in UPSTREAM_VERIFICATION were rechecked against their pins. The accompanying JSON records exact source IDs, source hashes, decompressed-log hashes, dataset metadata counts, code references, artifact hashes and observations. Upstream identity remains limited to those 16 files.

No official parser or grader was invoked. No patch, test, Docker workload, model operation or new evaluation was run. Source files and attempt records were not modified. No third-party log/patch/test-name excerpts or local absolute paths are included. This report confers no acceptance, Level C execution, accuracy or operational authority.

Code commit: `0305a35d43661729f4a6061262cd452d62090a98`. Upstream reference: `02e7a74ffd0b707aab73d203fe87bdc7c76afc8e`. Any future encoding-controlled regrade must be a separate prospective attempt that preserves this evidence and acknowledges the already inspected outcomes; none was performed here.
