# Predicate evidence and reference evaluation contract v1

The current generalized adapter has one explicit comparison contract:
`TASK_RESOLVED` claims may be compared with a parser-produced boolean
`TASK_RESOLVED` evaluator observation when the request, run, and instance
bindings agree. This preserves the existing prospective adapter behavior; it
does not qualify the evaluator as an independent semantic label. Other claim
predicates remain `INSUFFICIENT_EVIDENCE` without a matching explicit predicate
observation. Prediction rows, patch bytes, logs, role labels, and metadata do
not establish task completion, test success, or resolution.

`evaluate_reference_cases` is a deterministic scorer for supplied reference
rows only. Each decided row binds run, instance, scope, timezone-qualified time,
source SHA-256, message ID, half-open message span, concrete predicate,
polarity, evidence commitment, and rationale. Candidate verdicts must match the
full identity exactly. Duplicate IDs/identities, unmatched predictions, bad
verdicts, malformed adjudication, and mismatched identities are rejected.
`UNKNOWN` adjudications are counted and excluded from metric denominators.
Missing predictions are explicit missed extractions; abstentions have separate
positive/negative counts. `INTEGRITY_FAILURE` and `VERIFICATION_ERROR` are
accepted and counted separately; positive error outcomes stay in the recall
denominator and errors do not enter decided accuracy. Empty denominators produce null metrics. The evaluator
does not create labels, adjudicate disagreements, authenticate evidence, read
transcripts, or establish independent accuracy. Synthetic fixtures test only
contract behavior and are not accuracy evidence.

The separate `verify_predicate_claim` helper accepts only TASK_RESOLVED under
the explicit `pgop1.swebench.task-resolved-boolean.v1` contract and requires the
claim and evidence to carry the same complete source, message, span, run,
instance, scope, and time identity. A mismatch or absent contract abstains;
malformed typed values raise a contract error. It compares committed records
but cannot itself authenticate the evidence producer or validate bytes; callers
must establish those facts before invoking it.

## Predicate coverage

| Predicate | Verification status | Minimum evidence contract / limitation |
| --- | --- | --- |
| TASK_RESOLVED | Narrow comparison implemented | Explicit boolean evaluator observation plus matching request/run/instance in `audit_evidence`; strict helper additionally requires exact complete source/message/span/run/instance/scope/time identity and the named contract. It is not independent semantic validation. |
| TASK_COMPLETED | NOT_IMPLEMENTED | Requires direct, identity-bound completion evidence and a defined evaluator contract; available records do not qualify it. |
| ISSUE_RESOLVED | NOT_IMPLEMENTED | Requires an evaluator contract that explicitly defines issue resolution and exact run/instance/scope/time binding. Generic `resolved` is insufficient. |
| TESTS_PASSED | NOT_IMPLEMENTED | Requires committed test execution result, command/environment identity, run/instance/scope/time, and explicit pass/fail semantics. Patch or log presence is insufficient. |
| PATCH_APPLIED | NOT_IMPLEMENTED | Requires execution receipt binding exact patch bytes to target, run, instance, scope, and time. Patch bytes alone do not prove application. |
| FILE_CREATED | NOT_IMPLEMENTED | Requires an execution receipt binding created path/content hash to run, instance, scope, and time. |
| FILE_MODIFIED | NOT_IMPLEMENTED | Requires before/after content commitments and an execution receipt bound to run, instance, scope, and time. |
| COMMAND_EXECUTED | NOT_IMPLEMENTED | Requires a committed execution record with command identity, process/run identity, scope, time, and outcome. Transcript text is not such a record. |

No independent semantic holdout or adjudicated reference set is available in
this preparation. Therefore independent accuracy remains NOT_COMPUTABLE and
RUN-002 readiness remains NOT_READY until eligible independent labels and
source-family lineage are supplied. The strict helper validates structure and
record identity only: it is not a Context Engine readback, byte-authenticity
proof, trusted producer authentication, or authorization to promote a claim.

Existing resolved-map/list parser mappings and their public contracts are not
changed by this work. A protocol-qualified reference must separately establish
that a particular evaluator contract authorizes its predicate; the generic
`resolved` field alone must not be relabeled as `ISSUE_RESOLVED`,
`TASK_COMPLETED`, or `TESTS_PASSED`.
