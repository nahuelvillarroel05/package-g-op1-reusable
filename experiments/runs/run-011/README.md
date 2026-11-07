# RUN-011 semantic remediation E1

One authentic archived-claim E1 execution completed with exact dispositions and
native recovery. Runtime `8760fa683c3da9235bccdefb15219eaedde59c8a` / tree `a6ada8603c5de944ac4d4269ead0c8f62c1aa903`.
The executable commit and its bytes remain frozen; results are prepared later.

The new cohort contains 13 claims from 5 instances in 24 previously uninspected
trajectories. Ten TASK_RESOLVED claims have positive archived references; three
TESTS_PASS claims have no applicable reference. It is exposed development
evidence, with no independent adjudication or holdout separation.

| Same frozen cohort | Previous candidate | New candidate |
|---|---:|---:|
| Processed claims | 13 | 13 |
| Exact semantic decisions | 1 | 10 |
| SUPPORTED | 1 | 10 |
| VERIFICATION_ERROR | 11 | 0 |
| NOT_EVALUABLE | 1 | 0 |
| ABSTAIN | 0 | 3 |
| Task decision coverage | 1/10 | 10/10 |

Archived-relative TP/FP/TN/FN are 10/0/0/0 for the new candidate and 1/0/0/0
for the previous one. There are zero negative references, so false-support
safety and negative-class coverage are unmeasured. This small clustered,
positive-only comparison does not establish general semantic improvement.

The corrected native helper recovered 13/13 units, 26 receipts/checkpoints,
39 observations and 13 edges in a new process without producer redispatch.
A separate observer matched those counts on the same store; 138 store files
remained byte-identical. This is persistence consistency, not independent truth
or custody. The old control used a separate development store and unmodified
code, including its legacy RUN010 graph labels; RUN010 history was untouched.

255 regressions passed before the executable commit. Postcommit checks passed
identity preflight, actual execution and native recovery. Postfreeze pure
extractor probes accepted 4 non-assertions in 6 synthetic contexts; they made zero
auditor calls and zero definitive decisions. That defect and the remaining
descriptive-negation abstention are preserved for later authorized work.

GATE_11=BLOCKED; independently adjudicated labels=0; independent precision and
recall NOT_COMPUTABLE; custody NOT_PROVEN; I0-I6 frozen; I7 incomplete;
Formal I7 not completed; Physical C2 DEFERRED_NOT_WAIVED. Incident exposure
UNKNOWN; historical global integrity DEFERRED. NO_PUSH=true; no main or src change.

See [results](EXECUTION_RESULTS.json), [code identity](CODE_REFERENCE.json),
[findings](FINDINGS.json) and the frozen [contract](contracts/experimental-e1-v1/RUN_CONTRACT.md).
