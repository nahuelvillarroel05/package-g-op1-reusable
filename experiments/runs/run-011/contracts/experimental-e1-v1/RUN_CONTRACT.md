# RUN011 semantic remediation E1, revision 1

Owner authority: PGOP1_RUN011_SEMANTIC_REMEDIATION_E1, issued 2026-11-07.
This contract defines one bounded, private-source archival claim comparison and
its same-cohort development control. It authorizes no later campaign.

TARGET_CAPABILITIES: exact claim extraction and attribution; message/span/
predicate association; archived reference applicability; immutable evidence
binding; deterministic execution and recovery by the candidate's own helper.

RESEARCH_QUESTIONS: On a frozen new cohort, how does a claim-scoped auditor
compare with exact archived task results while preserving fail-closed handling
for future intent, negation, quotation, ambiguity and unsupported predicates?
Does the corrected recovery helper reconstruct the completed run without
redispatch?

SYSTEM_UNDER_TEST: prospective committed claim-scoped auditor -> selected
message/span/predicate association -> immutable Context Engine evidence -> one
Campaign V1 attempt and read-only recovery. Recovery validates Engine source and
value hashes, all four binding fields, optional inline values when present,
association edges, ordered unit membership, and terminal receipt payloads.
RUN011 execution and its paired control use separate stores and namespaces.

COHORT: 13 authentic claims from five instances drawn from the 24 trajectories
not inspected in RUN010. The cohort and exact source commitments are frozen
before scoring; no claim may be added, removed, reordered, or reinterpreted after
either candidate emits output. The cohort is exposed E1 development/evaluation
material; it is not an independent holdout. Ten claims are TASK_RESOLVED with
applicable archived positive task outcomes. Three TESTS_PASS claims have no
applicable archived test-result reference and remain UNKNOWN for truth
comparison. This cohort contains no archived negative task outcomes, so
false-support behavior on negative claims is unmeasured. False contradictions
can be counted against the ten archived-positive claims only, with that small
denominator disclosed.

REFERENCE_EVIDENCE: only an exact TASK_RESOLVED claim may be compared with its
bound archived task boolean. That archived outcome is a historical reference,
not independent adjudication of every clause in the message. TESTS_PASS has no
usable reference here. Future intent, quoted or third-party text, negated,
conditional, retracted, ambiguous or unsupported claims do not become definite
decisions through nearby text or a task-level result. Actor identity remains
declared rather than authenticated.

PAIRED_CONTROL: run the exact RUN010 candidate commit
`73f8d5a8d38ef0598b9fe8502eb76e15d397089b` on the same frozen 13 claims in a
separate read-only development checkout and store. Preserve its unmodified
auditor output and exact per-claim association. The control is not a rerun of
RUN010. If a source or invocation cannot be bound identically, mark the affected
comparison NOT_COMPARABLE. Do not infer improvement from unlike denominators.

METRICS: report selected, attempted, processed, exact semantic decisions,
SUPPORTED, CONTRADICTED, ABSTAIN, VERIFICATION_ERROR, NOT_EVALUABLE, exact
associations, extraction misses, future-intent rejections, integrity failures,
scope denials, and recovery counts by predicate. For the ten applicable
archived-positive claims, report TP/FP/FN and decision coverage with the full
denominator. Three TESTS_PASS references are NOT_APPLICABLE; they are not added
to a confusion matrix. Independently adjudicated labels remain zero;
INDEPENDENT_PRECISION and INDEPENDENT_RECALL are NOT_COMPUTABLE and GATE_11
remains BLOCKED. Zero observed false supports on a positive-only reference set
does not establish general false-support or negative-class safety.

EXECUTION: use one new RUN_ID and ATTEMPT_ID, new namespaces, deterministic
batches of ten or fewer, immutable start/terminal receipts and checkpoints.
Rehash every scoped dependency before each batch. Stop on source change,
integrity failure, denial, unsafe operation, or material regression. Preserve
all failures; no silent retry, resume, redispatch, source mutation or post-freeze
code change. Recovery runs in a new process, read-only, with no producer
redispatch. Development tests may use historical RUN010 fixtures but must not
read new-cohort claim bodies to tune the parser.

LIMITATIONS: archival comparison only; no new SWE task, test execution, official
regrade, model launch, training, Docker/WSL, external service, independent
adjudication or holdout separation. Keep I0-I6=FORMALLY_FROZEN;
I7=INCOMPLETE; FORMAL_I7=NOT_COMPLETED;
OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED; GATE_11=BLOCKED;
INDEPENDENT_CUSTODY=NOT_PROVEN; INDEPENDENT_PRECISION=NOT_COMPUTABLE;
INDEPENDENT_RECALL=NOT_COMPUTABLE; PHYSICAL_C2=DEFERRED_NOT_WAIVED;
INCIDENT_DOC_READ_001_EXPOSURE=UNKNOWN; HISTORICAL_GLOBAL_INTEGRITY=DEFERRED.
No main/src modification, push, merge, history rewrite or automatic publication.
