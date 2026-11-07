# Engineering modes - normative version 1

Authority: Owner decision `PGOP1_ENGINEERING_MODES_AND_RUN004_E1_001`. Applies prospectively. Every RUN declares `ENGINEERING_MODE=E1`, `E2`, or `F`; these are experimental assurance modes, not agent reasoning levels. All may reuse the same framework. Existing contracts and historical results keep their original scope.

## E1 - ENGINEERING EXPERIMENT

Purpose: discover defects, measure behavior and capabilities, identify limitations, test integrations, stress components, produce authentic evidence, develop prospective fixes, and prepare future campaigns. An E1 experiment can be correctly executed even when PGOP1 fails. Its result may be a defect or an inability to evaluate.

Entry requires identified code; an applicable versioned experimental contract; identified selection; an executable producer/procedure; authorized operations; suitable resource limits; verifiable result recording; persistence/recovery where the operation requires it; stop conditions; and evidence preservation. The applicable Owner authorization may cover progressive batches without another approval after each batch.

Entry does not require complete semantic coverage, resolved applicability of every predicate, independent authentication of every producer, outputs for every task, complete official evaluators, GATE_11, absence of ordinary functional defects, or favorable PGOP1 results. Formal qualification is not an E1 entry condition.

Admissible results include `SUPPORTED`, `CONTRADICTED`, `ABSTAIN`, `INSUFFICIENT_EVIDENCE`, `NOT_EVALUABLE`, `NOT_APPLICABLE`, `UNKNOWN_APPLICABILITY`, `UNSUPPORTED`, `ERROR`, `INTERRUPTED`, and `NOT_ATTEMPTED`. Use the existing normative spelling and meaning for the applicable interface. These states are not synonyms: applicability, execution, output admission, evidence sufficiency, semantic verdict, and error remain separate dimensions. A metadata disposition is not a semantic audit.

Stop or isolate an operation on integrity loss, incompatible provenance preventing admission, unsafe execution of untrusted code, unauthorized operations, exhausted budget, inability to preserve evidence, or risk of historical corruption. Record `NOT_ATTEMPTED_UNSAFE_EXECUTION` for operations requiring unavailable isolation. An ordinary auditor error is recorded with its receipt and does not stop safe unrelated work. Unresolved processing rights prohibit the affected body read, not every other operation. Protected reserves remain unconsumed.

Exit records actual attempted, processed, semantically audited, failed, interrupted, pending, and not-attempted populations, recovery, evidence, defects, and limits. A partial or failed experiment can meet its evidence objective. Disposing every inventory entry alone does not establish execution completeness.

## E2 - VALIDATED ENGINEERING EXPERIMENT

Purpose: rigorously validate specific technical properties such as complete recovery, checkpoint integrity, predicate accuracy, reproducibility, absence of duplication, or adversarial resistance.

Entry identifies the claim and freezes the contracts, inputs, acceptance criteria, and comparison protocol needed to test it. Require reproducible comparisons, regressions, adversarial tests, independent audits, and evidence of declared guarantees as applicable to that claim. Exit states which properties were demonstrated, contradicted, or remain unknown against those criteria. Missing required evidence prevents the corresponding guarantee; it need not invalidate unrelated observations.

E1 observations may support development and motivate E2, but do not automatically become E2 guarantees. E2 demonstrates concrete properties and does not automatically qualify the complete PGOP1 system.

## F - FORMAL QUALIFICATION

Purpose: establish the project's formal requirements and institutional guarantees, including applicable GATE_11, formal I7, independent evidence, independent custody, formal obligations, and acceptance criteria.

Entry and exit follow the applicable formal contracts and designated approval authority. Retain their full rigor. E1 does not reduce formal requirements, constitute formal approval, or establish independent evidence without proving its required conditions. Formal requirements remain effective but do not automatically block E1.

## Normative comparison

| Characteristic | E1 | E2 | F |
|---|---|---|---|
| Defect discovery | Principal | Complementary | Complementary |
| Incomplete results | Admitted | According to contract | According to formal contract |
| Unknown predicates | Admitted and recorded | Controlled | Subject to formal requirements |
| Independent audit | Subsequent or focused | According to guarantee | Mandatory when applicable |
| Independent evidence | Not universal | According to claim | According to formal contract |
| Recovery | According to risk and operation | Verified | According to formal contract |
| Publication | Results and limits | Validated evidence | According to formal rules |
| Formal qualification | No | Not automatic | Objective |

## Shared lifecycle and versioning

Preparation, operational freeze, authorization, execution, result verification, audit, and publication are distinct events. Record actual timestamps and statuses; do not infer execution from a folder, plan, test, or registry. E1 operational freeze binds exactly the code, contract, selection, authorized source operations, configuration, budget, stops, and attempt that will run. It is not a formal qualification freeze. Store each attempt under a fresh identity; retain negative attempts and earlier bytes.

Prospective corrections create a new code revision and attempt. Never change code silently inside a frozen attempt. Recovery validates the journal, hashes, persisted results, completed/pending/interrupted units, and manifest completeness. Read recovery performs no redispatch; ambiguity blocks the affected recovery rather than silently restarting.

A mode transition requires a prospective contract naming its claim, criteria, and applicable authority. Reuse prior evidence with its original mode, provenance, rights, exclusions, and limits. Do not retrospectively relabel E1 evidence E2/F or infer independence from chronology, agreement, or ancestry.

Publish authorized code, methodology, results, errors, limits, audits, and integrity commitments on the authorized branch. Check processing permission separately from redistribution permission. Withhold private responses, credentials, original bodies lacking redistribution rights, and protected evaluation content. Record local preparation, push, and fresh remote verification separately.

Report processing coverage separately from semantic coverage and sufficient evidence. `EXPERIMENTAL_EFFICIENCY` records preparation time, execution time, processed units, audits, errors, reproducible defects, correction time, and evidence produced. It is informative and never a gate.

I0-I6 remain `FORMALLY_FROZEN`; I7 `INCOMPLETE`; FORMAL_I7 `NOT_COMPLETED`; GATE_11 `BLOCKED`; independent precision/recall `NOT_COMPUTABLE`; independent custody `NOT_PROVEN`; PHYSICAL_C2 `DEFERRED_NOT_WAIVED`. Mode policy grants no production signer, main/src promotion, or other unrequested authority.

## Capability-first experimental design

Prospectively each RUN declares `TARGET_CAPABILITIES`, `RESEARCH_QUESTIONS`, `SYSTEM_UNDER_TEST`, `DATA_SOURCES`, `EXPERIMENTAL_UNITS`, `REFERENCE_EVIDENCE`, `METRICS`, `BASELINE_COMPARATORS`, `LIMITATIONS`. Use [the capability matrix](CAPABILITY_EVALUATION_MATRIX.md) and [evidence standards](EXPERIMENTAL_EVIDENCE_STANDARDS.md). Select only relevant capabilities. This is experimental design guidance, not an added formal E1 qualification gate or a requirement to resolve GATE_11. Separate structural/record consistency from semantic correctness, independent reference truth and formal status; use separate denominators and state ADDED_VALUE_NOT_ESTABLISHED without a valid comparator. Historical RUNs retain their original contracts and outcomes.
