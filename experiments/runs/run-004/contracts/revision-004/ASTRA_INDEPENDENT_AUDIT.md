# Astra adversarial contract audit ? RUN004 rev004

Review mode: REVIEW_ONLY. Report written 2026-11-03. Initial result: COMPLETED_WITH_MATERIAL_DOCUMENTARY_FINDING_PENDING_CORRECTION. This is an advisory review of an unapproved prospective contract, not campaign approval or execution qualification.

## Reviewer identity and separation

Requested role: Astra adversarial reviewer. Coordinator/tool-reported spawn metadata: model `gpt-6-astra`, reasoning effort `high`, fork mode `none`, task `/root/astra_contract_audit`. The reviewer does not independently introspect the hosting model identifier. This separate reviewer read local artifacts and did not author or edit the contract. Shared workspace, common instructions, coordinator-supplied task framing and later communication mean reviewer separation is not formal semantic independence. No qualified blind adjudication, independent custody or unseen semantic reference population is demonstrated.

Applicable skills: package-g-governance-plus and lean-code-quality-plus. Scope is the eight requested rev004 documents, active RUN_REGISTRY, prior rev003 and evaluator-convergence handoff, with referenced manifests inspected only as required to reconcile identity and populations. Memory registry search returned no relevant RUN004/rev003 hits; no memory facts support conclusions.

## Checked snapshot

Workspace: `D:\PGOP1_DATA\PGOP1_BASELINE_001`.
Active checkout: `Engineering/Active_Candidate/repo`; branch `experimental/pgop1-runs`; observed HEAD `c1ec85e337f93952c7aa82ce4adaaef1e739e7d3`; tree `0235e212ff569f5e5849050b60cb0555c70ff370`.

Observed preparation changes were `experiments/RUNS_PURPOSE.md`, `experiments/RUN_REGISTRY.json`, and untracked `experiments/runs/run-004/contracts/revision-004/`. Thus the baseline commit is not a claim that the reviewed draft is committed. Source-bindings initial CLEAN refers to intervention start, not this review snapshot. Git initially rejected the repository ownership; subsequent read-only commands used the operations-documented per-command safe.directory setting. No global configuration or ACL was changed. Remote URL was read locally; no remote contact or publication verification occurred.

Initial reviewed SHA-256 values (exact bytes, before coordinator correction):

| Artifact under Engineering/PGOP1_RUN004_CONTRACT_REV004_001 | SHA-256 |
| --- | --- |
| RUN004_CONTRACT_REV004.md | bf4281c33ea5fc53fd199de061b15549be2700b2350d4351e686dbc6cf0cc759 |
| RUN004_COMPLETENESS_CRITERIA.json | 4d83fa94faba1f59ffdb83ef788ea7c0dac6bd64543e4b3e8751e1e3697a8fdc |
| RUN004_SIX_FAMILY_SCOPE.json | 23ad5f3fb754d98a1339267a992a978583dd1ba41954a4a3f3b146f7093d5a06 |
| RUN004_METRIC_CONTRACT.json | d02f7bbc9519a385ad6ff52aac7b7f57b8a7ad4ed692df38fd6446021b7507c0 |
| RUN004_READINESS_MATRIX.json | ac36dddf2f1b00a076795d62ef2ffa34f6db3c2a49158b0530e6499c524ff15d |
| RUN004_EXPERIMENTAL_EXECUTION_PLAN.md | 939a09abc49349745645fd98a37255304d06ed5cd8a1c906d359ba10227ca10b |
| REV003_REV004_CHANGELOG.md | a0a835c1bf712b1eafcd4d8c16e03c008e620b07b4bbe1e85bdc911d8e0b3417 |
| SOURCE_BINDINGS.json | 3e1d8d2ed4289fa401256b6e4fab2571d446c2db00d2850c123649cb8c399ea7 |

Initial active `experiments/RUN_REGISTRY.json`: `728126bca45fee03f19e1c2554589851bf94b8d243da43d2f202af5187d0d429`. The seven corresponding active revision-004 document copies were byte-hash identical to these reviewed workspace artifacts; RUN_CONTRACT.md corresponds to RUN004_CONTRACT_REV004.md.

All six SOURCE_BINDINGS inputs were rehashed and their byte counts verified:

| Input | Bytes | SHA-256 |
| --- | ---: | --- |
| Active experiments/runs/run-004/contracts/revision-003/RUN_CONTRACT.md | 10669 | dea6f86b07e71635fdc76be605aa42a35e3b0eb5f3b0928317d77f5b52e24cce |
| Active experiments/runs/run-004/RUN004_SOURCE_MANIFEST.json | 19726 | 1b7d9c8f7b77f4c5354e4d57b279a7eeabb60c79eaa830755fe09849d623ca76 |
| PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/FINAL_HANDOFF.md | 10046 | 6e6d7809302a3209a2b03e8ff097882663a548a56df8eb4c047d7de8827ea878 |
| PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/RUN004_READINESS_MATRIX.json | 10826 | e9b81980bd1812fbdfbe0b98ed1824f278522f00c60137a9d3d516a41301dddb |
| PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/OFFICIAL_POPULATION_MANIFEST.json | 493914 | 7a155399cd1d11678bf3c0fca411ca2480c3b18a9341f983b1d98ecf8bddfe73 |
| PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/FULL_TASK_INVENTORY.json | 14739506 | 217ea0e6dddb8fce056c3db758c3f5c193758e1e055fb3db49177dfabfc83a65 |

Paths in the last four rows are under Engineering. No original benchmark source bodies, reserved responses or private GOLD were read. Hash checks establish these manifest identities, not upstream authenticity, present rights, or completeness of every source-body binding.

## Findings and counterexamples

### ASTRA-01 ? MEDIUM, material documentary ambiguity: applicability versus availability

Location: initial RUN004_EXPERIMENTAL_EXECUTION_PLAN.md line 6; RUN004_METRIC_CONTRACT.json lines 31 and 41; corresponding completeness definitions. Classification: REQUIRES_DOMAIN_REVIEW. Initial status: OPEN; coordinator notified and accepted correction.

The denominator is all *planned* unit-predicate pairs, while the plan allows prospective NOT_APPLICABLE allocation with rationale. The contract correctly says unavailable evidence remains in planned denominators, preserves all selected memberships, and requires disclosure of families with no semantic evidence. However, it does not explicitly prohibit using unavailable evidence/runtime as the rationale for NOT_APPLICABLE, nor require reconciliation of a complete candidate predicate universe before the planned subset is selected. Prospective selection alone does not prevent selection informed by already-known development gaps.

Concrete adversarial counterexample (hypothetical, not executed): process all 642 Pro V2 definitions, allocate only SOURCE_INTEGRITY and TASK_BINDING, mark semantic pairs NOT_APPLICABLE because compatible outputs are unavailable, and later report 100% of planned audit pairs decided. All task memberships remain present and the no-output limitation could still be disclosed, yet the semantic pair denominator has disappeared instead of showing insufficient evidence. This is a loophole in predicate allocation, not an observed task deletion or a claim that all-abstention success has occurred.

Required correction: distinguish applicability from evidence sufficiency. Freeze the candidate unit-predicate universe and reconcile applicable/planned versus NOT_APPLICABLE pairs, with rationale and counts. Otherwise-applicable predicates remain in their denominators when output, reference, identity, version compatibility, rights/access or runtime is missing. No NOT_APPLICABLE classification solely for known difficulty, missing evidence or adverse outcome. Retain separate structural/provenance/semantic metrics and visible unavailable populations.

### ASTRA-02 ? LOW, documentary vocabulary mismatch

Location: initial RUN004_METRIC_CONTRACT.json line 119 versus additional_required_observations and contract abstention paragraph. Classification: SAFE_TO_SIMPLIFY. Initial status: OPEN; coordinator notified and accepted correction.

The partition text says `justified/unsupported/unreviewable`, while the defined observation is `abstention_unjustified` and the prose requires justified/unjustified/unreviewable. `unsupported` also risks confusion with semantic claim outcome. A consumer could emit an unsupported bucket without reconciling unjustified abstentions. Use one explicit mutually exclusive vocabulary and conservation rule. UNKNOWN must remain unreviewable rather than forced into justified or unjustified.

## Adversarial checks with no additional established material finding

- **Task scope reduction:** current scope families and selected_source_bindings are exactly equal as parsed JSON to the prior RUN004_SOURCE_MANIFEST. FULL_TASK_INVENTORY contains 10096 rows, 10096 unique membership tuples (benchmark/version/split/task/language) and 9273 distinct logical_task_key values. Counts reconcile: SWE 3642, ProV2 642, Terminal 89, MCPMark 127, BFCL 4696, tau2 900. The initial reconciliation script assumed SPLIT on every family and raised KeyError before output; corrected read-only reconciliation used absent-field handling and language identity. No source was changed and no campaign ran.
- **Opportunistic exclusions:** reserved/pilot evidence remains constrained while task membership cannot be removed. This guards membership denominators; ASTRA-01 identifies the separate predicate-allocation gap. No case cap, success-only task selection, V1/oracle substitution or newly claimed hidden task population was found.
- **Ingestion versus audit:** a valid actual processing attempt can count toward execution completeness while semantic audit remains NOT_EVALUABLE. Structural records do not become semantic verdicts. Whole-family semantic absence is explicitly a material limitation. Source-integrity records still need real audit evidence, not an importer success label.
- **Abstention laundering:** 10096 attempted terminal abstentions could produce complete execution, but cannot demonstrate semantic capability. The contract explicitly prohibits calling that success; semantic audit numerator excludes abstentions/errors, and each of six dimensions remains separately reported. Unattempted bulk placeholders fail completion.
- **Coverage inflation:** empty denominators are NOT_COMPUTABLE; retries are not unique members; SWE overlap and tau locales remain explicit; heterogeneous inventory totals cannot be semantic metrics. For B, 20 valid historical callable results out of a 20-item eligible allocation may support 100% of that allocation only with the full selected-population gap also reported. It cannot become 100% of BFCL's 4696 task definitions, because responses and tasks differ.
- **Archived versus fresh official results:** rev004 requires actual commands, evaluator/input/config identities, timing, exit status and receipts, separating original producer time from current reevaluation. Prior handoff BFCL 20 historical function results (1 valid/19 invalid), and one SWE original-log regrade, remain development components, not fresh task execution. No reevaluation occurred in this review.
- **Retroactive criteria:** replacing rev003 mandatory integral B coverage with complementary B is a material prospective purpose change, explicitly disclosed in the changelog under the Owner concept decision. Rev003 and prior results remain immutable. No executed RUN004 exists to relabel as complete, and historical rev003 readiness is retained with its original scope. A missing B runtime is not universally an A gate.
- **Unsupported qualification:** registry, contract and plan preserve NOT_APPROVED, NOT_ISSUED and NOT_EXECUTED. Independent precision/recall remain NOT_COMPUTABLE, GATE_11 BLOCKED and custody NOT_PROVEN. Sol/Astra review cannot change those states.
- **Future execution readiness:** candidate/config, predicate allocation, final populations, budgets, checkpoints, rights and technical qualification are explicitly not bound for execution. These are real future prerequisites, not evidence that this draft is execution-ready. Freeze and Owner authorization are still required.

## Limits and handoff

This review performed document reading, JSON reconciliation, SHA-256/byte-count checks and read-only Git queries only. Benchmark runs, evaluators/regrades, models/training, ingestion, recovery reruns, source acquisition, tests, private GOLD, credentials, push, merge and runtime/source edits: NOT_PERFORMED. Exact source-body integrity, rights, custody, authentic-output populations and future execution safety remain unqualified. The only reviewer write is this audit report.

The full documentation verifier and final ZIP integrity gates belong to the coordinator's final handoff after integrated corrections; this report does not claim they passed. No standalone final verifier was run by this reviewer while preparation remained dirty. Findings must be resolved on exact new hashes and reviewed below; the initial findings and counterexamples remain preserved.

Preserved authority: RUN004_CONTRACT=NOT_APPROVED; RUN004_FINAL_FREEZE=NOT_ISSUED; RUN004_EXECUTION=NOT_EXECUTED; I0-I6=FORMALLY_FROZEN; I7=INCOMPLETE; FORMAL_I7=NOT_COMPLETED; OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED; GATE_11=BLOCKED; INDEPENDENT_PRECISION=NOT_COMPUTABLE; INDEPENDENT_RECALL=NOT_COMPUTABLE; INDEPENDENT_CUSTODY=NOT_PROVEN; PHYSICAL_C2=DEFERRED_NOT_WAIVED. OD03, Source025 and OD05 remain pending.
