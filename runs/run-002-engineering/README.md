# PGOP1 RUN-002 engineering evidence

Campaign identity: `PGOP1_RUN_002_ENGINEERING_NONQUALIFYING`.
This is exploratory engineering evidence. Independent semantic evaluation
protocol v1.1 is unchanged: `GATE_11=BLOCKED`,
`INDEPENDENT_SEMANTIC_HOLDOUT_NOT_AVAILABLE`, and
`RUN_002_INDEPENDENT_SEMANTIC_QUALIFICATION=NOT_ACHIEVED`.
No precision, recall, false-positive rate or independent semantic accuracy is
computable from this campaign.

## Exact code and historical repair

The source-processing campaign ran commit
`d589697b9b5e537a93e67480cb0c1f9970745d88`, tree
`79a2a0300c89a723e5ce43c23ace1902347784a1`, selecting
`pgop1.swebench.attribution-ambiguity.v1` explicitly. Its A-010 parent is
`f0ae448d22e6be13731d14bf56c3eb0d7c697f3f`. See `CODE_REFERENCE.json`.

Individual Context Engine verification subsequently exposed two Windows process
launch failures. The original result remains **264 PASS / 2 ERROR**. The failed
calls exceeded Windows command-line capacity before a child process started.
Prospective repair `22434026abb47fb8300ec13f3cea71592ff1944c`, tree
`fec65ed54a71cba15c4eec58cf1ebf24ab3841c7`, sends the same expectations through
JSON stdin while retaining the isolated child and its verification checks.
The two affected real audits passed in new stores, with canonical audit outputs
equal to their original results. Neither the source-processing campaign nor
its historical failed stores were replaced or rerun. The repaired code has
targeted real-case verification and regression evidence, rather than a second
full source-processing campaign. See `PROSPECTIVE_READBACK_REPAIR.json`.

## Populations and denominators

The original accessible snapshot contains 25,580 inventory records. The exact
eligible RUN-001 population has 3,802 sources; 21,778 other inventory records
retain their original reference/exclusion dispositions. No new source population
or independent reference labels were acquired.

| View | Unique source universe | File attempts | Parsed | Unsupported | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| RUN-001 historical / RUN-002 strict parser profile | 3,802 | 3,802 each | 1,744 | 2,045 | 13 |
| Prospective current Aider parser supplement | same 300-source subset | 300 | 300 | 0 | 0 |
| Derived current-parser coverage over original universe | 3,802 | 4,102 across both RUN-002 profiles | 2,044 | 1,745 | 13 |

The strict profile retained the historical parser IDs. It therefore initially
left 300 Aider transcripts unsupported despite the candidate containing an
additive structural parser. That preparation omission is preserved. A separate
prospective plan froze the current parser on only those exact 300 sources;
the earlier results were not edited. This is parsing coverage, not semantic
accuracy or 4,102 distinct source files. Parsed file status `SUPPORTED` means
the declared file parser accepted its structure, not that a claim is true.

There are **266 execution audits**, with 264 `INSUFFICIENT_EVIDENCE` and two
`INTEGRITY_FAILURE`; zero `SUPPORTED`, `CONTRADICTED`, or `VERIFICATION_ERROR`
audit verdicts. The two integrity outcomes retain wrong-instance binding
evidence; absence of evidence was not converted to contradiction. File errors
and audit integrity failures have different denominators.

The audit-only candidate denominator is **106 occurrences**: 61 direct statement
rows and 45 rejected/unknown-attribution rows; ambiguous attribution count is
zero in this source population. Direct attribution describes source content,
not authenticated speaker identity. The 61 statement verdicts are insufficient;
the 45 rejected rows have no individual verdict field and remain `NOT_REPORTED`
in that distribution. RUN-001 had 351 statement occurrences: 61 remain statements,
43 map to rejections, 247 map to nested-extra content exclusions retained as
`EXCLUDED_CONTENT` observations, and two rejections are newly accounted.
Those transitions are not independently labeled improvements or
measurements of false positives/negatives.

## Integrity, derivation and recovery

The complete strict campaign has 4,068 units (3,802 files + 266 audits), bound and
recovered in 167 Context Engine batches. The supplement has 300 units in 21
batches. Thus 4,368 campaign units are covered, with 188 verified batch recoveries.
Aggregate stores explicitly report `DERIVATION_NOT_VERIFIED`; storing normalized
outputs does not establish their semantics. Individual audit rederivation is
separate: historical 264 verified and two failed fresh-process launches, followed
by two successful prospective repaired checks. Evaluator authentication remains
`UNAUTHENTICATED` when checked; byte consistency does not authenticate a producer.

Campaign resume recovered all 4,068 completed units with zero redispatch. One
deterministic replay pass matched all 266 audit outputs. Later reconciliation
reused those exact hash-bound replay records and made no new adapter calls.
All 3,802 file and 266 audit identities matched the historical RUN-001 comparison.

The executed candidate passed 766 fresh Windows regressions; the repaired
candidate passed 767. The historical 762 receipt was independently bound to
its frozen source bytes and remains a separate receipt. `TEST_SELECTION.json`
lists the executed-candidate regression selection. For the repair, add
`tests/test_run002_large_readback.py`. Synthetic tests are software controls,
not independent semantic reference labels.

## Linux and F-16

Bounded checks ran in native ext4 workspaces in an existing WSL2 Ubuntu 24.04
distribution, using Python 3.12.3 and isolated test dependencies. The original
selection passed 22 path checks and skipped one Windows-only case-fold test.
The repaired large-readback test passed Linux; the path selection again passed
22 checks with that expected skip. No demonstrated F-16 repair is claimed:
the exact original Sonnet reproducer is unavailable, so
`F16=DEFERRED_LINUX_VALIDATION_PENDING`. These checks do not qualify general
Linux portability. No datasets or OLMo project files were copied into the test
workspace, and no explicit virtual-disk manipulation was performed.

## Reproduction and public evidence boundary

Use a separate worktree at the exact code commit before running its APIs. Tests
can be run with Python and pytest using the file list in `TEST_SELECTION.json`.
The repaired large-input regression uses only synthetic data and exercises the
real fresh child, Engine verification, rederivation and recovery.

`INPUT_COMMITMENTS.json` and the two unit ledgers publish content commitments,
parser IDs, byte counts, dispositions and result hashes. They contain no source
bodies. `METRICS.json` publishes an explicit aggregate-field projection. The exact
private executable plans, source paths, inventory dispositions, original logs,
normalized source-bearing results and Engine stores remain private; no
redistribution rights are inferred from local access. Their commitments are
retained in `PRIVATE_EVIDENCE_COMMITMENTS.json`.

Consequently the public package supports code/test review and checking the
published accounting and commitments, but does not provide a self-contained
replay of private source processing. A reader needs separately authorized
original bytes and the matching private plan to perform that replay. Do not
substitute public metadata for an independent authentic semantic reference.

See `ASTRA_PUBLIC_AUDIT.md` for the independent technical decision and exact
remaining limits. Sonnet's subsequent public-only review is **PENDING**.
There is no main merge, src promotion, formal I7 completion, independent custody
qualification or Physical C2 advancement.
