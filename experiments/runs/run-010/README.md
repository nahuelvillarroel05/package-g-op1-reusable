# RUN010 archived semantic claim evaluation E1

Execution: **COMPLETE_WITH_DISPOSITIONS**. Existing SWE auditor, Context Engine
and Campaign V1 ran on 63 genuine archived assistant claims.
Selected/attempted/processed: 63/63/63.
Exact associated semantic comparisons: 15; epistemic abstentions:
0; verification errors: 43; not evaluable:
5. [Results](EXECUTION_RESULTS.json) retain every disposition.

Candidate `73f8d5a8d38ef0598b9fe8502eb76e15d397089b`, tree `a59f445f140c4e29e4aae8fecfc46db838810874`. The extractor
was unchanged. [Contract](contracts/experimental-e1-v1/RUN_CONTRACT.md),
[identities](CODE_REFERENCE.json), [receipts](EXECUTION_RECEIPT.json),
[findings](FINDINGS.json), [technical review](SOL_XHIGH_TECHNICAL_AUDIT.md).

The 63-claim cohort came from 240 inspected of 264 known trajectories; 24
additional distinct claims were explicitly excluded by the one-per-trajectory
cohort rule and five exact repeated hits were duplicates. No claim denominator
is inferred for the remaining trajectories or for the 3,642 task memberships /
2,819 unique task IDs. Source selection/predicate applicability review is
MODEL_ASSISTED_PROVISIONAL. 57 task-completion claims have applicable archived
task booleans; six test-pass claims have UNKNOWN references. Compound statements
are compared only for their task-completion proposition.

Results are ARCHIVED_RESULT_RELATIVE, not independently adjudicated semantic
truth, fresh task execution, official regrades or proof of all tests/bugs/safety.
The single final fresh observer recovered 63/63
units without producer redispatch. The unused frozen recovery helper has a
static binding-shape defect; the separately hashed observer verifies all four
Engine binding fields, receipt/capsule hashes, graph memberships and values.

Independent adjudicated claims: 0. Independent precision/recall NOT_COMPUTABLE;
GATE_11 BLOCKED; independent custody NOT_PROVEN; I0-I6 FORMALLY_FROZEN;
I7 INCOMPLETE; FORMAL_I7 NOT_COMPLETED; operational qualification NOT_ACHIEVED;
PHYSICAL_C2 DEFERRED_NOT_WAIVED. INCIDENT_DOC_READ_001 exposure UNKNOWN;
historical global integrity DEFERRED. Documentary validation is separate from this technical result; no global
historical-integrity PASS is claimed. No models, new agent outputs,
benchmark commands, Docker/WSL, training, RUN011, main/src changes or push.

Private trajectories, claim bodies, paths and detailed references are withheld.
This package contains derived counters and cryptographic commitments only.
Preparation and local commits do not establish remote publication. NO_PUSH=true.

The raw auditor produced 18 task-level definite comparisons (13 SUPPORTED / 5 CONTRADICTED); only 15 match the selected claim. Two TESTS_PASS extraction misses and three unmatched raw decisions remain separate. See [metric definitions](METRIC_DEFINITIONS.json).
