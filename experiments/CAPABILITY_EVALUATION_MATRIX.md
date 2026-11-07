# Capability evaluation matrix

Version 1; authority PGOP1_CAPABILITY_EVALUATION_AND_RUN006_ALIGNMENT_001. This is a permanent experimental design aid, not a new execution framework or formal E1 entry gate. Choose the property first, then the input, component, expected observable, error, reference, evidence, metric and dataset. No campaign must cover every row.

The JSON companion is the structured source of all fields. Implemented/tested means bounded test-source evidence, not independent scientific or formal qualification. Current focused results separately identify tests actually executed. Frozen core and experimental candidate evidence are distinct.

| Capability | Family / layer | Status | Code interface |
|---|---|---|---|
| IDENTITY_BINDING | A / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/run_framework/run006.py::_decode_row/read_bfcl_row_pair; runtime/candidate/context_engine.py::admit_source |
| SOURCE_PROVENANCE | B / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/context_engine.py::admit_source/read_source/_validate/verify; runtime/candidate/run_framework/source_bindings.py |
| EVIDENCE_INTEGRITY | C / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/context_engine.py::verify; runtime/candidate/run_framework/core.py; runtime/candidate/run_framework/incremental.py |
| OPERATIONAL_GATE | D / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/run_framework/run006.py::validate_dispatch_config/validate_runner_scope/dispatch |
| CAUSAL_RECORD_GRAPH | E / FROZEN_CORE | IMPLEMENTED_PARTIALLY | src/package_g/op1_reusable/i4_graph.py; src/package_g/op1_reusable/i4_reconstruction.py; src/package_g/op1_reusable/i4_source.py |
| PERSIST_RECOVER | F / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/context_engine.py::ingest/verify; runtime/candidate/run_framework/incremental.py |
| BFCL_STRUCTURE | G/H / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/bfcl_structured_audit_v2.py::audit/_calls/_schema_supported/_matches |
| CLAIM_RECORD_AUDIT | G / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/swebench_claim_audit/adapter.py::audit_instance; runtime/candidate/swebench_claim_audit/generalized.py::audit_file/audit_evidence |
| SUFFICIENCY_ABSTENTION | H / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/bfcl_structured_audit_v2.py::audit; runtime/candidate/swebench_claim_audit/generalized.py::audit_evidence |
| COMPONENT_COMPOSITION | I / EXPERIMENTAL | IMPLEMENTED_AND_TESTED_WITH_SCOPE | runtime/candidate/run_framework/caller.py; runtime/candidate/run_framework/predicates.py; runtime/candidate/run_framework/run006.py::bfcl_row_adapter |
| ADVERSARIAL_RESILIENCE | J / EXPERIMENTAL | IMPLEMENTED_PARTIALLY | runtime/candidate/bfcl_structured_audit_v2.py::_json/_calls; runtime/candidate/run_framework/provenance.py::_read_bound_file; runtime/candidate/run_framework/run006.py |
| FORMAL_IDENTITY_STORE | A/C/F / FROZEN_CORE | IMPLEMENTED_PARTIALLY | src/package_g/op1_reusable/identity.py; src/package_g/op1_reusable/integrity.py; src/package_g/op1_reusable/evidence_store.py; src/package_g/op1_reusable/registry.py |
| FORMAL_SESSION_CONTROL | D / FROZEN_CORE | IMPLEMENTED_PARTIALLY | src/package_g/op1_reusable/i2_engine.py; src/package_g/op1_reusable/i2_authority.py; src/package_g/op1_reusable/i2_isolation.py |
| GENERAL_SEMANTIC_TRUTH | G/H / UNSUPPORTED | NOT_SUPPORTED | runtime/candidate/swebench_claim_audit/generalized.py::audit_evidence; runtime/candidate/bfcl_structured_audit_v2.py::audit |
| FORMAL_ATTRIBUTION | B / FROZEN_CORE | IMPLEMENTED_PARTIALLY | src/package_g/op1_reusable/i5_provenance.py::ProvenanceLedger; src/package_g/op1_reusable/i5_i1.py |
| DATASET_COMPILATION | K / FROZEN_CORE | IMPLEMENTED_PARTIALLY | src/package_g/op1_reusable/i6_admission.py; src/package_g/op1_reusable/i6_compiler.py::ImmutableSources/DatasetCompiler |

## IDENTITY_BINDING

**CAPABILITY_NAME**: Exact unit/source identity

**RESEARCH_QUESTION**: Does a mismatched identity get rejected before audit?

**SYSTEM_UNDER_TEST**: runtime/candidate/run_framework/run006.py::_decode_row/read_bfcl_row_pair; runtime/candidate/context_engine.py::admit_source

**INPUT_TYPE**: Bound task/output rows + expected IDs

**EXPECTED_BEHAVIOR**: Reject mismatched IDs/hashes; retain disposition

**FAILURE_CONDITIONS**: Wrong-source acceptance, silent rebinding

**REFERENCE_TYPE**: Preregistered fixture identity commitments

**REFERENCE_INDEPENDENCE**: Independent fixture expectation; hashes are not producer authentication

**MINIMUM_EVIDENCE**: Expected IDs, exact input bytes/hashes, code/contract, rejection receipt

**METRICS**: mismatches_detected / injected_mismatches; false_rejects / valid_bindings

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE; future authorized archived pairs

**BASELINE_COMPARATORS**: Exact ID equality and SHA-256

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Checks row hashes and exact task-response ID equality in authored fixtures

**UNDEMONSTRATED_PROPERTIES**: Real producer identity and genuine execution

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: Identity strings can be copied; same ID does not prove origin.

**EXISTING_TEST_EVIDENCE**: tests/test_run006_engineering.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## SOURCE_PROVENANCE

**CAPABILITY_NAME**: Byte-bound source and graph attribution

**RESEARCH_QUESTION**: Are wrong-source associations rejected while valid ones survive retrieval?

**SYSTEM_UNDER_TEST**: runtime/candidate/context_engine.py::admit_source/read_source/_validate/verify; runtime/candidate/run_framework/source_bindings.py

**INPUT_TYPE**: Source grant + evidence/source links

**EXPECTED_BEHAVIOR**: Verify exact grants and reject inconsistent source bindings

**FAILURE_CONDITIONS**: Accepted swapped source, omitted source silently treated as verified

**REFERENCE_TYPE**: Frozen provenance map plus explicit tamper cases

**REFERENCE_INDEPENDENCE**: Map author independent of candidate decision; upstream truth remains unproven

**MINIMUM_EVIDENCE**: Source identities/roles, original commitments, mutations, returned graph

**METRICS**: provenance_detection / injected_swaps; valid_bindings_preserved / valid_bindings

**SUITABLE_DATA_SOURCES**: Authored source graph; permitted archived metadata

**BASELINE_COMPARATORS**: Path/hash/ID join verifier

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Exact path/hash/scope grants, source-bound associations and verified graph assertions

**UNDEMONSTRATED_PROPERTIES**: Independent upstream custody, authenticated producer

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: A source-bound declaration is not a verified real-world event.

**EXISTING_TEST_EVIDENCE**: tests/test_context_corrupt_index_recovery.py, tests/test_run_adapter_bridge.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## EVIDENCE_INTEGRITY

**CAPABILITY_NAME**: Tamper and membership verification

**RESEARCH_QUESTION**: Which stored mutations/substitutions/duplicates are detected?

**SYSTEM_UNDER_TEST**: runtime/candidate/context_engine.py::verify; runtime/candidate/run_framework/core.py; runtime/candidate/run_framework/incremental.py

**INPUT_TYPE**: Immutable manifests, receipts, checkpoint, one controlled mutation

**EXPECTED_BEHAVIOR**: Reject changed bytes or incompatible membership; preserve prior attempt

**FAILURE_CONDITIONS**: Mutation accepted, membership changed silently

**REFERENCE_TYPE**: Externally frozen fixture manifest and known mutation ledger

**REFERENCE_INDEPENDENCE**: Independent byte commitments; no semantic truth label

**MINIMUM_EVIDENCE**: Original/mutated bytes, per-case digest and verification receipt

**METRICS**: integrity_detection / injected_mutations; false_alarm / unchanged_cases; membership_missing_and_duplicate_counts

**SUITABLE_DATA_SOURCES**: Synthetic disposable stores

**BASELINE_COMPARATORS**: SHA-256 + membership/set comparison

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Digest, version/chain and checkpoint verification over controlled stored artifacts

**UNDEMONSTRATED_PROPERTIES**: Detection of all omitted unobserved real-world events

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: Cannot discover evidence never captured unless an external denominator exists.

**EXISTING_TEST_EVIDENCE**: tests/test_context_corrupt_index_recovery.py, tests/test_run006_engineering.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## OPERATIONAL_GATE

**CAPABILITY_NAME**: Disabled dispatch and scoped launch gating

**RESEARCH_QUESTION**: Does denied operation remain side-effect free?

**SYSTEM_UNDER_TEST**: runtime/candidate/run_framework/run006.py::validate_dispatch_config/validate_runner_scope/dispatch

**INPUT_TYPE**: Disabled or incompatible authorization/config metadata

**EXPECTED_BEHAVIOR**: Reject before Campaign/source-body read; never synthesize a grant

**FAILURE_CONDITIONS**: Runner invoked or source opened after denial

**REFERENCE_TYPE**: Independent callback/read counters and denied fixture expectations

**REFERENCE_INDEPENDENCE**: Engineered observables; declaration verification is not Owner cryptographic authentication

**MINIMUM_EVIDENCE**: Configuration hashes, read/runner counters, error code, untouched outputs

**METRICS**: denied_operations_blocked / denied_cases; unauthorized_body_reads; unexpected_runner_calls

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE; actual disabled configuration metadata only

**BASELINE_COMPARATORS**: Boolean/allowlist authorization checker

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Disabled dispatch rejects before source reads/runner; exact rights/selection/freeze metadata checked in synthetic tests

**UNDEMONSTRATED_PROPERTIES**: Authentic Owner identity, OS containment, live operational qualification

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: Local assertions do not enforce an entire workstation or external service.

**EXISTING_TEST_EVIDENCE**: tests/test_run006_engineering.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## CAUSAL_RECORD_GRAPH

**CAPABILITY_NAME**: Recorded causal edges and reconstruction

**RESEARCH_QUESTION**: Can recorded relationships reconstruct under their exact contracts?

**SYSTEM_UNDER_TEST**: src/package_g/op1_reusable/i4_graph.py; src/package_g/op1_reusable/i4_reconstruction.py; src/package_g/op1_reusable/i4_source.py

**INPUT_TYPE**: Committed event/edge records and source bindings

**EXPECTED_BEHAVIOR**: Validate declared edge structure and reconstruct contract-bound graph

**FAILURE_CONDITIONS**: Incompatible graph accepted or reconstruction loses records

**REFERENCE_TYPE**: Preregistered event graph and expected reconstruction

**REFERENCE_INDEPENDENCE**: Authored record reference; not independent observation of action

**MINIMUM_EVIDENCE**: Frozen contract, event IDs, graph inputs, expected reconstruction

**METRICS**: reconstructed_records / expected_records; invalid_edges_rejected / injected_invalid_edges

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE; authorized recorded events

**BASELINE_COMPARATORS**: Graph consistency and topological checks

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Implementation exposes recorded graph validation/reconstruction; frozen status from current authority

**UNDEMONSTRATED_PROPERTIES**: Independent causal inference; proof a declared action occurred; intervention effects

**FORMAL_STATUS**: FROZEN_CORE_SCOPE_ONLY; not newly qualified

**LIMITATIONS**: Code availability is not proof of world causality; new frozen-core tests are not performed here.

**EXISTING_TEST_EVIDENCE**: No scoped test receipt inspected; implementation availability only.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## PERSIST_RECOVER

**CAPABILITY_NAME**: Immutable evidence and disposable-index recovery

**RESEARCH_QUESTION**: Are completed bytes exactly recovered without redispatch?

**SYSTEM_UNDER_TEST**: runtime/candidate/context_engine.py::ingest/verify; runtime/candidate/run_framework/incremental.py

**INPUT_TYPE**: Stored results, journal/checkpoint and disposable index

**EXPECTED_BEHAVIOR**: Recover exact membership/hashes read-only; block ambiguity/inflight

**FAILURE_CONDITIONS**: Missing result silently restarted; duplicate dispatch; authoritative tamper accepted

**REFERENCE_TYPE**: Pre-interruption fixture manifest with exact result hashes

**REFERENCE_INDEPENDENCE**: Independent expected membership; recovery is not new audit

**MINIMUM_EVIDENCE**: Original journal/receipts, corruption/interrupt point, fresh-process recovered index

**METRICS**: recovered_verified / expected_completed; missing; duplicates; redispatch_count

**SUITABLE_DATA_SOURCES**: Synthetic disposable persisted evidence

**BASELINE_COMPARATORS**: File manifest rehash and exact set comparison

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Authored store/query read-back; existing Engine corrupt-index recovery test launches a fresh child process; RUN006 checkpoint fixture reloads configuration and recovers in the same process

**UNDEMONSTRATED_PROPERTIES**: Complete authentic campaign recovery, durable terminal accounting for arbitrary callback failures; fresh-process RUN006 campaign checkpoint recovery not established by the current focused fixture

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: Cooperative timeout; callback error can leave inflight without durable terminal cause.

**EXISTING_TEST_EVIDENCE**: tests/test_context_corrupt_index_recovery.py, tests/test_run006_engineering.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## BFCL_STRUCTURE

**CAPABILITY_NAME**: Task-relative function-call structural validation

**RESEARCH_QUESTION**: Which task-relative structural predicates are decidable?

**SYSTEM_UNDER_TEST**: runtime/candidate/bfcl_structured_audit_v2.py::audit/_calls/_schema_supported/_matches

**INPUT_TYPE**: BFCL task definition + inert response object

**EXPECTED_BEHAVIOR**: Emit True/False/None per predicate and scoped pass/reject/abstain

**FAILURE_CONDITIONS**: Unsupported schema certified valid; structural pass promoted to semantic support

**REFERENCE_TYPE**: Explicit structural contract; separately authored rule fixtures

**REFERENCE_INDEPENDENCE**: Candidate replay is consistency only; fixture expected outcomes validate specified rules

**MINIMUM_EVIDENCE**: Task/output hash pair, exact auditor version, raw predicate/status, fixture expected labels

**METRICS**: structural_audited / attempted; decided_predicate_pairs / considered_pairs; unknown_predicate_pairs; fixture_rule_correct / labeled_fixture_pairs

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE; future permitted AUTHENTIC_AGENT_OUTPUT

**BASELINE_COMPARATORS**: JSON parser, strict schema/name/count checks

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Format/name/count and supported argument schema rules; unsupported representation/schema abstention

**UNDEMONSTRATED_PROPERTIES**: Argument intent, right function choice, execution success, official acceptance

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: No independent semantic labels. Three unsupported predicates stay None; no call execution.

**EXISTING_TEST_EVIDENCE**: tests/test_bfcl_structured_audit_v2.py, tests/test_run006_engineering.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## CLAIM_RECORD_AUDIT

**CAPABILITY_NAME**: Explicit completion claim versus local evaluator record

**RESEARCH_QUESTION**: Does an explicit claim agree with the supplied compatible record?

**SYSTEM_UNDER_TEST**: runtime/candidate/swebench_claim_audit/adapter.py::audit_instance; runtime/candidate/swebench_claim_audit/generalized.py::audit_file/audit_evidence

**INPUT_TYPE**: Explicit claim, matching run/instance evaluator record, predictions/patch commitments

**EXPECTED_BEHAVIOR**: Resolve compatible record consistency or abstain/error on missing/conflicting inputs

**FAILURE_CONDITIONS**: Invented agent claim, cross-run attribution, contradiction hidden

**REFERENCE_TYPE**: Frozen local evaluator record for record-consistency; independent adjudication only if actually available

**REFERENCE_INDEPENDENCE**: SUPPLIED_RECORD_CONSISTENCY; same evaluator record as input and label is circular for independent correctness

**MINIMUM_EVIDENCE**: Exact claim span/type, source hashes and run/instance, predicate contract, evaluator provenance

**METRICS**: record_agreement / comparable_claims; contradictions; insufficient; verification_errors; false_support only with separately valid labels

**SUITABLE_DATA_SOURCES**: EXPLICIT_AGENT_CLAIM + AUTHENTIC_EVALUATOR_RESULT; researcher-derived claims clearly labeled

**BASELINE_COMPARATORS**: Exact identity/boolean comparator

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Explicit TASK_RESOLVED claim extraction and supported/contradicted/insufficient/error handling against bound local records

**UNDEMONSTRATED_PROPERTIES**: General arbitrary-claim truth; independent evaluator execution and reference authenticity

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: SWE predicates do not apply to BFCL intent by renaming inputs; unsupported claims remain unassessed.

**EXISTING_TEST_EVIDENCE**: tests/test_swebench_claim_audit.py, tests/test_swebench_generalized.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## SUFFICIENCY_ABSTENTION

**CAPABILITY_NAME**: Insufficiency and unsupported-predicate handling

**RESEARCH_QUESTION**: Does evidence removal cause appropriate abstention rather than favorable default?

**SYSTEM_UNDER_TEST**: runtime/candidate/bfcl_structured_audit_v2.py::audit; runtime/candidate/swebench_claim_audit/generalized.py::audit_evidence

**INPUT_TYPE**: Labeled sufficient/insufficient development cases

**EXPECTED_BEHAVIOR**: Preserve unknown; distinguish not applicable, error and insufficient

**FAILURE_CONDITIONS**: Missing evidence defaults to support; unsupported parser becomes contradiction

**REFERENCE_TYPE**: Preregistered completeness rubric and labels

**REFERENCE_INDEPENDENCE**: Fixture completeness reference independent of candidate; external validity limited

**MINIMUM_EVIDENCE**: Missingness transform, expected state, observed predicates

**METRICS**: abstentions / attempted; appropriate_abstentions / labeled_insufficient; false_support / labeled_insufficient

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE; SYNTHETIC_ADVERSARIAL_CASE

**BASELINE_COMPARATORS**: Always-abstain; schema validator

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Missing/unsupported evidence paths abstain or produce exact insufficiency/error states

**UNDEMONSTRATED_PROPERTIES**: Calibrated uncertainty and real-world false-support rate

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: An abstention count alone is not accuracy or calibrated risk.

**EXISTING_TEST_EVIDENCE**: tests/test_bfcl_structured_audit_v2.py, tests/test_swebench_generalized.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## COMPONENT_COMPOSITION

**CAPABILITY_NAME**: Adapter/caller/predicate/Engine/checkpoint integration

**RESEARCH_QUESTION**: Does composition retain source/result identity and disposition?

**SYSTEM_UNDER_TEST**: runtime/candidate/run_framework/caller.py; runtime/candidate/run_framework/predicates.py; runtime/candidate/run_framework/run006.py::bfcl_row_adapter

**INPUT_TYPE**: One authorized development unit across existing interfaces

**EXPECTED_BEHAVIOR**: Persist exact caller result and bound source/predicate evidence, recover same unit

**FAILURE_CONDITIONS**: Swapped result admitted; disposition lost; repeated unit executed

**REFERENCE_TYPE**: Frozen fixture transition/receipt expectations

**REFERENCE_INDEPENDENCE**: Same auditor replay is reproducibility, not independent correctness

**MINIMUM_EVIDENCE**: Per-stage bindings, raw/final decisions, receipts, recovery hashes

**METRICS**: complete_bound_units / attempted; stage_errors; payload_replay_consistency; recovery_correctness

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE; future selected archived pairs

**BASELINE_COMPARATORS**: Direct parser + hash manifest + record comparator

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Authored row pair integration and exact metadata graph; replays same auditor to validate payload

**UNDEMONSTRATED_PROPERTIES**: Authentic integration; independent verification of semantic correctness

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: Added scientific value over a simple validator has not been established; integrated traceability can still be useful.

**EXISTING_TEST_EVIDENCE**: tests/test_run006_engineering.py, tests/test_convergence_predicates.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## ADVERSARIAL_RESILIENCE

**CAPABILITY_NAME**: Bounded manipulation and untrusted-input resistance

**RESEARCH_QUESTION**: Which explicit attack classes fail closed?

**SYSTEM_UNDER_TEST**: runtime/candidate/bfcl_structured_audit_v2.py::_json/_calls; runtime/candidate/run_framework/provenance.py::_read_bound_file; runtime/candidate/run_framework/run006.py

**INPUT_TYPE**: Labeled manipulated inert bytes and metadata

**EXPECTED_BEHAVIOR**: Treat embedded instructions as data; reject known manipulation within scope

**FAILURE_CONDITIONS**: Input executes commands or unauthorized source read, incorrect acceptance

**REFERENCE_TYPE**: Independent authored attack ledger and expected control outcome

**REFERENCE_INDEPENDENCE**: Synthetic attack labels; does not prove exhaustive security

**MINIMUM_EVIDENCE**: Attack transformation, scope, counters, resulting state and preserved failed case

**METRICS**: detected_attacks / injected_attacks_by_class; false_alarms / valid_cases

**SUITABLE_DATA_SOURCES**: SYNTHETIC_ADVERSARIAL_CASE; DEVELOPMENT_FIXTURE

**BASELINE_COMPARATORS**: Strict parser + allowlist + digest checks

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Selected duplicate-key, mismatch, traversal/reparse and rights-denial tests

**UNDEMONSTRATED_PROPERTIES**: General prompt-injection immunity, arbitrary sandbox escape resistance

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: Finite attacks do not establish general adversarial robustness; no LLM injection classifier demonstrated.

**EXISTING_TEST_EVIDENCE**: tests/test_run006_engineering.py, tests/test_run_adapter_bridge.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## FORMAL_IDENTITY_STORE

**CAPABILITY_NAME**: Frozen identity, schemas, append-only evidence primitives

**RESEARCH_QUESTION**: Are formal object identities/storage rules preserved under the frozen contract?

**SYSTEM_UNDER_TEST**: src/package_g/op1_reusable/identity.py; src/package_g/op1_reusable/integrity.py; src/package_g/op1_reusable/evidence_store.py; src/package_g/op1_reusable/registry.py

**INPUT_TYPE**: Contract-valid identity/schema/evidence records

**EXPECTED_BEHAVIOR**: Apply exact frozen contracts without mutation

**FAILURE_CONDITIONS**: Unbound identity or modified evidence accepted

**REFERENCE_TYPE**: Frozen formal contract and existing qualification evidence, not candidate tests

**REFERENCE_INDEPENDENCE**: Formal authority independent of this methodology; no fresh formal audit claimed

**MINIMUM_EVIDENCE**: Exact contract/implementation refs and bounded applicable historical receipt before guarantee

**METRICS**: contract_validity; exact_byte_preservation where actually measured

**SUITABLE_DATA_SOURCES**: Frozen specification and independently constructed disposable fixtures

**BASELINE_COMPARATORS**: Schema/hash/append-only verifier

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Existing frozen implementation surfaces; no new qualification or execution here

**UNDEMONSTRATED_PROPERTIES**: Whole-system operational qualification; candidate inherits no formal certification

**FORMAL_STATUS**: FROZEN_CORE_SCOPE_ONLY; not newly qualified

**LIMITATIONS**: This inventory reads code; frozen phase status comes from authority, not a new proof of every module.

**EXISTING_TEST_EVIDENCE**: tests/unit/test_op1_reusable_i0_identity.py, tests/unit/test_op1_reusable_i0_schemas.py, tests/unit/test_op1_reusable_i1_storage.py, tests/unit/test_op1_reusable_i1_verifier.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## FORMAL_SESSION_CONTROL

**CAPABILITY_NAME**: Frozen bounded synthetic session lifecycle

**RESEARCH_QUESTION**: Does the exact bounded session reject incompatible authority/state?

**SYSTEM_UNDER_TEST**: src/package_g/op1_reusable/i2_engine.py; src/package_g/op1_reusable/i2_authority.py; src/package_g/op1_reusable/i2_isolation.py

**INPUT_TYPE**: Frozen session/profile and synthetic run records

**EXPECTED_BEHAVIOR**: Enforce named state and reviewed-profile bindings

**FAILURE_CONDITIONS**: Unsupported worker capability inferred from synthetic profile

**REFERENCE_TYPE**: Frozen state/profile rules plus explicit negative fixtures

**REFERENCE_INDEPENDENCE**: Contract consistency; not independent physical execution

**MINIMUM_EVIDENCE**: Profile hashes, authority/state transitions, terminal receipts

**METRICS**: denied_invalid_transitions / injected_invalid_transitions

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE within existing frozen contract

**BASELINE_COMPARATORS**: Finite state machine validator

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Narrow synthetic-only profile with bound reviewed engine/executor hashes; zero workers/external effects

**UNDEMONSTRATED_PROPERTIES**: Production worker dispatch or general-agent operation control

**FORMAL_STATUS**: FROZEN_CORE_SCOPE_ONLY; not newly qualified

**LIMITATIONS**: No I2 dispatch is authorized or executed in this intervention.

**EXISTING_TEST_EVIDENCE**: tests/unit/test_op1_reusable_i2_session_guards.py.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## GENERAL_SEMANTIC_TRUTH

**CAPABILITY_NAME**: General independent claim correctness

**RESEARCH_QUESTION**: Can arbitrary claims be judged independently?

**SYSTEM_UNDER_TEST**: runtime/candidate/swebench_claim_audit/generalized.py::audit_evidence; runtime/candidate/bfcl_structured_audit_v2.py::audit

**INPUT_TYPE**: Arbitrary claim + independently relevant evidence

**EXPECTED_BEHAVIOR**: No general implementation evidenced; do not manufacture verdict

**FAILURE_CONDITIONS**: General capability inferred from narrow parser/record agreement

**REFERENCE_TYPE**: Compatible independent adjudication required for correctness claim

**REFERENCE_INDEPENDENCE**: NOT_AVAILABLE in current RUN006

**MINIMUM_EVIDENCE**: No claimed result without claim/predicate/evidence/reference chain

**METRICS**: INDEPENDENT_PRECISION=NOT_COMPUTABLE; INDEPENDENT_RECALL=NOT_COMPUTABLE

**SUITABLE_DATA_SOURCES**: Future separately authorized adjudicated cases

**BASELINE_COMPARATORS**: Task-specific comparator only where meaningful

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Only narrow record and structural predicates inspected

**UNDEMONSTRATED_PROPERTIES**: General factual, operational and causal truth of arbitrary agent claims

**FORMAL_STATUS**: EXPERIMENTAL; no formal I7 authority

**LIMITATIONS**: Unsupported scope does not block an E1 structural experiment.

**EXISTING_TEST_EVIDENCE**: No scoped test receipt inspected; implementation availability only.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## FORMAL_ATTRIBUTION

**CAPABILITY_NAME**: Frozen source-bound attribution ledger

**RESEARCH_QUESTION**: Does an attribution preserve source certainty and exact frozen context?

**SYSTEM_UNDER_TEST**: src/package_g/op1_reusable/i5_provenance.py::ProvenanceLedger; src/package_g/op1_reusable/i5_i1.py

**INPUT_TYPE**: Typed task/delegation/report/review/tool-invocation records with source evidence

**EXPECTED_BEHAVIOR**: Keep uncertainty and reject incompatible exact attribution

**FAILURE_CONDITIONS**: SELF_REPORTED promoted to observed actor; UNKNOWN erased

**REFERENCE_TYPE**: Frozen attribution contract and independently specified record fixtures

**REFERENCE_INDEPENDENCE**: Source-binding reference only; no independent actor observation established

**MINIMUM_EVIDENCE**: Exact source commitments, identity qualifiers, attribution ledger and validation outcome

**METRICS**: attribution_binding_errors / injected_errors; uncertainty_preserved / ambiguous_cases

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE within frozen interfaces

**BASELINE_COMPARATORS**: Typed ID/source join and exact qualifier comparator

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Digest-bound attribution companions and frozen I4/source/context bindings; SELF_REPORTED retained

**UNDEMONSTRATED_PROPERTIES**: Authenticated actor or real execution; resolution of historical causal findings

**FORMAL_STATUS**: FROZEN_CORE_SCOPE_ONLY; not newly qualified

**LIMITATIONS**: No direct I5 tests located in this checkout tests tree; external qualification evidence not reread. Not an operation grant.

**EXISTING_TEST_EVIDENCE**: No scoped test receipt inspected; implementation availability only.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.

## DATASET_COMPILATION

**CAPABILITY_NAME**: Frozen permission-aware deterministic derived datasets

**RESEARCH_QUESTION**: Does compilation retain source/split/permission boundaries?

**SYSTEM_UNDER_TEST**: src/package_g/op1_reusable/i6_admission.py; src/package_g/op1_reusable/i6_compiler.py::ImmutableSources/DatasetCompiler

**INPUT_TYPE**: Frozen typed source closure, field selectors, explicit permissions and compilation config

**EXPECTED_BEHAVIOR**: Reject restricted/unknown/ungranted training use and forbidden export; derive without changing sources

**FAILURE_CONDITIONS**: Leakage/duplicate admitted, restricted field exported, label truth inferred from signature

**REFERENCE_TYPE**: Frozen compilation contract, independent fixture expected membership/splits

**REFERENCE_INDEPENDENCE**: Compilation determinism reference; signatures prove byte/custody binding, not substantive truth

**MINIMUM_EVIDENCE**: Exact config/source/closure and output hashes, explicit grants and split assignment

**METRICS**: deterministic_output_hash_match; forbidden_uses_rejected / injected_forbidden_uses; split_overlap_count

**SUITABLE_DATA_SOURCES**: DEVELOPMENT_FIXTURE only; no private GOLD or training

**BASELINE_COMPARATORS**: Deterministic selector + schema/split/duplicate checker

**EXPERIMENTAL_MODE**: E1 exploration; E2 only for a prospectively frozen named guarantee; F separate

**DEMONSTRATED_PROPERTIES**: Pinned closure/manifest/source validation, deterministic example compilation, permission/split/leakage checks in code

**UNDEMONSTRATED_PROPERTIES**: Training authority, corpus legal clearance, truth of labels or executed evaluation

**FORMAL_STATUS**: FROZEN_CORE_SCOPE_ONLY; not newly qualified

**LIMITATIONS**: No direct I6 tests located in this checkout tests tree; no compilation/training performed. Internal field-use selectors grant no public/training authority.

**EXISTING_TEST_EVIDENCE**: No scoped test receipt inspected; implementation availability only.

**ADDED_VALUE**: ADDED_VALUE_NOT_ESTABLISHED; comparison is prospective.
