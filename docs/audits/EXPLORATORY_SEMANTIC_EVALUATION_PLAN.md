# PGOP1_EXPLORATORY_SEMANTIC_EVALUATION_001

Status: DESIGNED_NOT_EXECUTED. This is engineering diagnosis, separate from frozen independent protocol 1.1. RUN-002=NOT_READY; GATE_11=BLOCKED; INDEPENDENT_SEMANTIC_HOLDOUT_NOT_AVAILABLE. No source selection or evaluation is executed by publishing this plan.

## 1. Selection

Prospective target: at most 12 unique SWE-bench instances, across up to six development-authorized submissions and at least three repositories and two declared agent families where eligible sources permit. These are diagnostic targets, not quotas that justify invented provenance. Include both evaluator-resolved and unresolved outcomes and different trajectory formats. Record unavailable strata and stop rather than substitute private, reserved or unlicensed material. A convenience sample is not representative of the benchmark or real-world agents.

Before source-content/label review for this evaluation, create an immutable selection-config and source-manifest version. Eligible sources must be explicitly authorized for exploratory development and have known redistribution/access conditions. Inventory membership alone grants neither authorization nor independence. An eligible-source list, exact commits/hashes, agent/submission/repository/format strata and rights decisions must be approved in the prospective execution objective. No named case is selected in this design.

Deterministic procedure: sort eligible metadata by repository, declared agent family, submission ID, format and source ID. Rank within each stratum by SHA256 of UTF-8 `PGOP1_EXPLORATORY_SEMANTIC_EVALUATION_001|SOURCE_ID|INSTANCE_ID`. Round-robin strata with a maximum two cases per submission and four per repository. Deduplicate globally by canonical INSTANCE_ID; retain excluded duplicates with reason and submission lineage. Freeze the initial list before reading its claim bodies. Use official outcome metadata only to include both outcomes; document that outcome-stratified selection is intentionally label-aware and not an unbiased holdout. Do not fill a failed case by silently choosing a favorable result; replacement requires a versioned exclusion/replacement record.

## 2. Sources

Use existing authorized SWE-bench development archives and official corresponding evaluator artifacts, never GOLD20, reserved independent references or private trajectories. No acquisition, copying source bodies, new mass campaign or fresh evaluator run is authorized by this plan. Historical exposure matrix is a separate local investigation and does not grant rights. Record source repository URL and commit, artifact locator, source family, license/access basis and prior exposure, including UNKNOWN. Preserve original inventory bytes.

## 3. Identities

Each case-level row requires CASE_ID, SOURCE_ID, SOURCE_SHA256, SUBMISSION_ID, INSTANCE_ID, declared AGENT_ID or UNKNOWN, run ID, source-role evidence, parser ID/version, candidate code/tree and processing disposition. A case owns zero or more claim rows. A zero-extraction case retains its case row, count zero and reason; it must never disappear or receive a fabricated claim span. Every claim row additionally requires MESSAGE_ID, CLAIM_SPAN, CLAIM_PREDICATE, EVALUATOR_RESULT and EVIDENCE_ID, with explicit UNKNOWN or null and a reason when unavailable, plus scope, timezone-qualified time, asserted polarity and original evaluator artifact SHA256 when evidence is available. Missing mandatory comparison identities exclude that claim from comparability without deleting it. CLAIM_SPAN is half-open with explicit BYTE_SPAN or message-local span coordinate system. Distinguish declared AGENT_ID from authenticated attribution; UNKNOWN identities are retained and cannot enter authenticated-attribution counts.

## 4. Evidence

Join an evaluator result only through exact submission/run/instance bindings and the committed evaluator contract. Store evidence artifact hash, record pointer/span, predicate, polarity, scope/time and provenance. Similar instance IDs in different submissions do not establish a join. `resolved=true` is only comparable to TASK_RESOLVED when the exact evaluator contract supports that meaning; never relabel it as TESTS_PASSED, TASK_COMPLETED, ISSUE_RESOLVED, PATCH_APPLIED or file/command evidence. An archived result is not fresh patch execution. If the binding or predicate is missing, record INSUFFICIENT_EVIDENCE or the appropriate integrity/error outcome rather than fabricate a label.

## 5. Predicates

Use existing extraction/comparison contracts without modifying executable code or tuning it on the selected results. TASK_RESOLVED is the current narrow comparison contract. Other authentic claims can be inventoried for diagnostics, but unsupported predicate contracts remain noncomparable and usually abstain. Explicit role/Aider parsers may emit no semantic claims; zero eligible/comparable claims is a valid result. Report extraction misses independently from scorer disagreements.

## 6. Comparisons

Freeze candidate identity, selection and metric definitions before execution. Compare claims to corresponding archived official evaluator observations only within their concrete predicate. Such agreement is an engineering comparison, not independent semantic validation. Independent labels, if legitimately available later, require a separately documented qualified adjudicator, blinded process, exact claim-span identity and rationale. No model or Sonnet is automatically appointed. Keep UNKNOWN adjudication excluded with explicit counts.

## 7. Exclusions

Exclude unauthorized/protected sources, unresolved license/access, duplicates, absent bytes/hash mismatch, mismatched submission/run/instance, malformed spans, missing speaker attribution for authenticated-attribution analyses, absent concrete predicate/evidence contract and invalid adjudication from the corresponding denominator. Retain reason codes and counts for every selected case; errors must not disappear from the case accounting. Distinguish parsing rejection, zero extraction, attribution failure, absent reference and infrastructure error.

## 8. Metrics and denominators

Use claim occurrences with unique complete identities as the primary unit; report files, cases, submissions and unique instances separately. Every metric row stores numerator, denominator, exclusions and definition version. No metric is computed in this design.

| Counter / metric | Denominator and definition |
| --- | --- |
| ELIGIBLE_CLAIMS | All extracted candidate claim occurrences reviewed; eligible means supported claim schema/predicate and valid span, not semantic truth. Also record reviewed messages and independently enumerated expected claims when available, so missed extraction is visible. |
| ATTRIBUTED_CLAIMS | ELIGIBLE_CLAIMS; count only assertions supported by qualifying attribution evidence. Separately count declared-role and UNKNOWN cases. |
| SUPPORTED / CONTRADICTED / INSUFFICIENT_EVIDENCE / INTEGRITY_FAILURE / VERIFICATION_ERROR | All claim audit attempts; mutually exclusive verdict counts must sum to this denominator. Run-level failures without extracted claims are a separate case-error count. |
| COMPARABLE_REFERENCES | All reference candidate claim identities; count only predicate-appropriate, identity-bound references with explicit usable labels; state exclusions. |
| AGREEMENTS / DISAGREEMENTS | COMPARABLE_REFERENCES; decided candidate verdict agrees/disagrees with the concrete reference after asserted polarity is applied. |
| ABSTENTIONS | COMPARABLE_REFERENCES; candidate insufficient evidence. Integrity failures, verification errors and missing extractions get separate counts; require agreements + disagreements + abstentions + errors + missing extractions = comparable references. |
| TRUE_POSITIVES / FALSE_POSITIVES | Valid independent reference rows only; positive prediction means candidate SUPPORTED. Positive truth means the exact assertion/polarity is supported by independent evidence. |
| TRUE_NEGATIVES / FALSE_NEGATIVES | Same independent decided-reference universe; negative prediction means CONTRADICTED, negative truth means exact assertion contradicted. Abstentions/errors/missed extractions are separately counted, not forced into TN/FN. |

With valid independent references only: precision=TP/(TP+FP), decided accuracy=(TP+TN)/(TP+TN+FP+FN), and decided recall=TP/(TP+FN). Label decided recall explicitly because it excludes abstentions/misses; additionally report coverage and end-to-end sensitivity with all independently positive eligible rows, including positive abstentions/errors/misses, in its denominator. Report specificity=TN/(TN+FP) only for that same decided subset. Zero denominators yield null, never zero. Without valid independent labels, TP/TN/FP/FN and semantic precision/recall remain NOT_COMPUTABLE; archived evaluator agreement is named agreement, not accuracy. Never combine execution-level and claim-level denominators.

## 9. Limitations

Development exposure, convenience selection, outcome-aware strata, incomplete formats, unauthenticated roles and narrow predicates limit interpretation. Metadata-only history does not prove nonexposure. Official archived results do not independently adjudicate every utterance. This plan cannot qualify GATE_11, I7, custody or general semantic precision. The frozen 1.1 contamination boundary remains unchanged.

## 10. Completion criteria for a later authorized execution

Require frozen source/selection/code identities, admissible access/rights, valid evidence joins, explicit exclusion ledger, conservation of every selected case and attempted claim, denominator reconciliation, hash-verified result artifacts and technical review. Report failure/zero-claim outcomes without forced success. Any extractor change creates a new candidate and a new diagnostic iteration. Final execution status may be PARTIAL_WITH_EXACT_LIMITATIONS. This objective stops at DESIGNED_NOT_EXECUTED; a new explicit authorization is required to run it.
