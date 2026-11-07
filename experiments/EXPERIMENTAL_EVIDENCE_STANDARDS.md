# Experimental evidence standards

Version 1. Design guidance for E1/E2/F; not an additional formal qualification gate for E1. Identify a target capability before selecting a benchmark. Agent task performance, benchmark official score, PGOP1 structural validation, claim audit, provenance audit, operational control, evidence integrity and formal qualification are separate properties. Evidence for one does not accredit another.

| Level | Required observation | Does not establish |
|---|---|---|
| SOURCE_INTEGRITY | Exact bytes, digest, size, membership and stated mutation boundary | Truth, complete capture, authentic producer |
| SOURCE_PROVENANCE | Bound origin/path/revision/blob, declared chain and operation rights | Authentic production, independent custody |
| PRODUCER_AUTHENTICITY | Valid producer binding with applicable authentication evidence | Task success or factual truth |
| OPERATION_OBSERVATION | Trusted observation of a named operation with identity/time/scope | All declared actions occurred or caused a result |
| CLAIM_SUPPORT | Explicit predicate relating claim to relevant bound evidence | Universal truth or reference independence |
| REFERENCE_TRUTH | Valid reference for that exact predicate/version/population | Independence from candidate inputs or development exposure |
| INDEPENDENT_ADJUDICATION | Qualified reference production independent of candidate decisions and forbidden inputs, documented blinding/exposure | Universal validity outside its sampled scope |

A SHA-256 validates byte identity, not a claim's truth. A published trajectory is a record, not necessarily observed execution. An official benchmark result answers only its defined task/version predicate. An unauthenticated publisher/model string remains declared. Preserve incompatible attribution as UNKNOWN.

Label every unit/source as applicable: AUTHENTIC_AGENT_OUTPUT, AUTHENTIC_AGENT_TRAJECTORY, AUTHENTIC_EVALUATOR_RESULT, EXPLICIT_AGENT_CLAIM, RESEARCHER_DERIVED_CLAIM, SYNTHETIC_ADVERSARIAL_CASE, DEVELOPMENT_FIXTURE. Authentic archived artifact does not imply authenticated producer. Preserve verbatim agent claim spans only when actually present. Researcher-derived claims retain author, derivation rule and evidence origin; never quote them as agent speech. Manipulated copies remain synthetic and never become authentic executions. Keep reserved material unconsumed; do not tune with protected labels.

## Independence and circularity

Record separately CONSISTENCY_WITH_SUPPLIED_EVIDENCE, AGREEMENT_WITH_REFERENCE and INDEPENDENT_CORRECTNESS. If an evaluator result is input to PGOP1 and then used to label the same verdict correct, only source-record interpretation/consistency has been measured. Replaying the candidate auditor on the same task/output checks reproducibility/payload binding, not independent correctness. Different reviewers of code are not independently adjudicated semantic labels. Agreement requires a declared compatible reference; independent correctness additionally needs its actual independence, relevance and validity. Never invent missing references.

E1 can legitimately study supplied-record interpretation or structural integration without independent adjudication or GATE_11. Lack of an independent reference limits the correctness claim; it does not impose a general E1 block. Prospective changes preserve old contracts/configuration and exact source commitments.

## Units, denominators and metrics

Preregister TARGET_CAPABILITIES, RESEARCH_QUESTIONS, SYSTEM_UNDER_TEST, DATA_SOURCES, EXPERIMENTAL_UNITS, REFERENCE_EVIDENCE, METRICS, BASELINE_COMPARATORS and LIMITATIONS for every future RUN. Applicability and execution are independent axes. Unit IDs, source rows, predicate opportunities, receipts, cases and events have separate denominators. A processed task definition is not a semantic audit. Report every count with its population, exclusion rule and failure/missing disposition. Missing/undefined denominator is NOT_COMPUTABLE, never zero percent.

| Metric | Numerator / denominator or count | Interpretation |
|---|---|---|
| EXECUTION_COVERAGE | attempted selected units / frozen selected units; separately completed / selected | Not evidence completeness or correctness |
| EVIDENCE_COVERAGE | required evidence items present and verified / preregistered required items | A hash count alone is not sufficient evidence |
| AUDIT_COVERAGE | distinct units with an initial audit / selected; separately decided applicable predicate pairs / applicable considered pairs; raw initial/replay/review invocation counts separately | Count unknown applicability separately |
| DECISION_CORRECTNESS | correct labeled comparable decisions / valid labeled comparable decisions | Report reference validity/independence; exclude no missing errors silently |
| ABSTENTION_BEHAVIOR | abstained / attempted; appropriate abstentions / independently labeled insufficient cases | An always-abstain comparator may match a conservative count |
| INTEGRITY_DETECTION | detected injected mutations / known injected mutations; false alarms / unchanged cases | Limited to explicit mutation classes |
| PROVENANCE_DETECTION | detected swapped/misattributed sources / injected association faults | Not producer authentication |
| RECOVERY_CORRECTNESS | recovered exact completed records / externally committed completed records; duplicates, losses, redispatch count | Recovery must preserve interrupted/ambiguous state |
| RESOURCE_USAGE | observed wall time, output bytes, peak resources only if instrumented | Configured budget is not measured use |

For labeled claim auditing report correct/incorrect decisions, false supports, false contradictions, abstentions, insufficient evidence and errors separately. Precision=TP/(TP+FP), recall=TP/(TP+FN) only for an exact positive predicate with valid complete labels and defensible abstention/error treatment. Do not call supplied-record agreement independent precision/recall. Independent precision/recall remain NOT_COMPUTABLE for current RUN006. No population interval or IID assumption for an ordered, clustered development-exposed prefix.

## Comparators and reporting

Use existing parser, SHA-256, schema validator, exact ID comparator, deterministic boolean comparator, graph/membership check or compatible official evaluator where permitted. Compare same eligible inputs and expected predicates, record implementation/version, limits and runtime. Candidate self-replay is not a baseline. Without an executed compatible comparison, state ADDED_VALUE_NOT_ESTABLISHED. Integrated tracing/recovery can still be useful, but requires its own observable evidence. A new complex baseline system is unnecessary.

Separate method validation, fixture results, authentic campaign results, publication and formal authority. No RUN006 result may be emitted during preparation. I0-I6 FORMALLY_FROZEN; I7 INCOMPLETE; FORMAL_I7 NOT_COMPLETED; GATE_11 BLOCKED; independent custody NOT_PROVEN; PHYSICAL_C2 DEFERRED_NOT_WAIVED.
