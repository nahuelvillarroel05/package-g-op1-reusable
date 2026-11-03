# Sol XHigh technical coherence audit — RUN004 rev004 draft

## Role, scope and decision

Auditor role: **Sol XHigh technical contract auditor**. Coordinator-reported spawn metadata: `model=gpt-6-sol`, `reasoning_effort=xhigh`, `fork_turns=none`, task `/root/sol_contract_audit`. This is a scoped technical review, not formal independent semantic adjudication or an Owner decision.

**Technical decision on the reviewed bytes: `CORRECTIONS_REQUIRED_BEFORE_DOCUMENTARY_CLOSE`.** The proposed A/B separation and six-dimension framework are coherent in direction, but findings SXH-01 through SXH-03 require prospective correction. This decision does not approve the contract, issue a freeze, authorize RUN004, or claim a campaign outcome. `RUN004_CONTRACT=NOT_APPROVED`, `RUN004_FINAL_FREEZE=NOT_ISSUED`, `RUN004_EXECUTION=NOT_EXECUTED`.

Review mode: `REVIEW_ONLY`. I read the named rev004 draft companions, rev003 contract and preceding handoff. I did not edit the contract, invoke an evaluator, regrade, run a benchmark, use a model, or mutate Git. The audit report is the only output from this role.

## Exact reviewed identities

SHA-256 below identifies the **initial rev004 bytes reviewed for this finding set**. Later repairs require a fresh hash-bound follow-up; they do not change this review's preimages.

| Artifact under `Engineering/PGOP1_RUN004_CONTRACT_REV004_001/` | SHA-256 |
| --- | --- |
| `RUN004_CONTRACT_REV004.md` | `bf4281c33ea5fc53fd199de061b15549be2700b2350d4351e686dbc6cf0cc759` |
| `RUN004_COMPLETENESS_CRITERIA.json` | `4d83fa94faba1f59ffdb83ef788ea7c0dac6bd64543e4b3e8751e1e3697a8fdc` |
| `RUN004_SIX_FAMILY_SCOPE.json` | `23ad5f3fb754d98a1339267a992a978583dd1ba41954a4a3f3b146f7093d5a06` |
| `RUN004_METRIC_CONTRACT.json` | `d02f7bbc9519a385ad6ff52aac7b7f57b8a7ad4ed692df38fd6446021b7507c0` |
| `RUN004_READINESS_MATRIX.json` | `ac36dddf2f1b00a076795d62ef2ffa34f6db3c2a49158b0530e6499c524ff15d` |
| `RUN004_EXPERIMENTAL_EXECUTION_PLAN.md` | `939a09abc49349745645fd98a37255304d06ed5cd8a1c906d359ba10227ca10b` |
| `REV003_REV004_CHANGELOG.md` | `a0a835c1bf712b1eafcd4d8c16e03c008e620b07b4bbe1e85bdc911d8e0b3417` |
| `SOURCE_BINDINGS.json` | `3e1d8d2ed4289fa401256b6e4fab2571d446c2db00d2850c123649cb8c399ea7` |

Source comparisons and binding checks:

| Source | SHA-256 verified |
| --- | --- |
| `Engineering/Active_Candidate/repo/experiments/runs/run-004/contracts/revision-003/RUN_CONTRACT.md` | `dea6f86b07e71635fdc76be605aa42a35e3b0eb5f3b0928317d77f5b52e24cce` |
| `Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/FINAL_HANDOFF.md` | `6e6d7809302a3209a2b03e8ff097882663a548a56df8eb4c047d7de8827ea878` |
| `Engineering/Active_Candidate/repo/experiments/runs/run-004/RUN004_SOURCE_MANIFEST.json` | `1b7d9c8f7b77f4c5354e4d57b279a7eeabb60c79eaa830755fe09849d623ca76` |
| `Engineering/PGOP1_RUN004_CONTRACT_AND_EVALUATOR_CONVERGENCE_001/RUN004_READINESS_MATRIX.json` | `e9b81980bd1812fbdfbe0b98ed1824f278522f00c60137a9d3d516a41301dddb` |
| `Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/OFFICIAL_POPULATION_MANIFEST.json` | `7a155399cd1d11678bf3c0fca411ca2480c3b18a9341f983b1d98ecf8bddfe73` |
| `Engineering/PGOP1_FULL_MULTIBENCHMARK_CORPUS_001/FULL_TASK_INVENTORY.json` | `217ea0e6dddb8fce056c3db758c3f5c193758e1e055fb3db49177dfabfc83a65` |

All six `SOURCE_BINDINGS.json` input byte lengths and hashes matched. The source-plan, population-manifest and inventory hashes in `RUN004_SIX_FAMILY_SCOPE.json` also matched. The active checkout was `experimental/pgop1-runs`, HEAD `c1ec85e337f93952c7aa82ce4adaaef1e739e7d3`, tree `0235e212ff569f5e5849050b60cb0555c70ff370`; status included documentary edits/untracked rev004, so this is not a clean execution candidate. Git inspection used a command-local `safe.directory` setting after the normal call reported dubious ownership; no global Git or ACL setting was changed.

## Findings

### SXH-01 — Major: all-abstention wording exceeds the evidence

`RUN004_CONTRACT_REV004.md:36` says an all-abstention population “demonstrates no semantic capability”; `RUN004_EXPERIMENTAL_EXECUTION_PLAN.md:12` says it “prove[s] no semantic capability.” The same draft's `RUN004_COMPLETENESS_CRITERIA.json:81` correctly says `NO_SEMANTIC_CAPABILITY_DEMONSTRATED`. Missing or unusable evidence can establish that capability **was not demonstrated** in the observed population; it cannot establish that the system has no such ability. The two stronger statements could turn justified abstentions caused by evidence gaps into an unsupported negative ability claim.

**Correction:** use the JSON's precise formulation consistently, and keep all-abstention, zero auditable semantic evidence, and unreviewable sufficiency as visible adverse limitations. Do not turn abstention into semantic success or semantic falsehood.

### SXH-02 — Major: abstention partition has conflicting category names

`RUN004_METRIC_CONTRACT.json:109-119` requires `abstention_justified`, `abstention_unjustified`, and `abstention_unknown_unreviewable`, but its reconciliation sentence says “justified/unsupported/unreviewable counts sum to abstention count.” `RUN004_CONTRACT_REV004.md:38` explicitly requires unsupported sufficiency assertions to remain `UNKNOWN_UNREVIEWABLE`; “unsupported” therefore cannot silently stand for “unjustified.” The partition cannot be reconciled unambiguously as written and could misstate unjustified-abstention counts.

**Correction:** define one exhaustive, mutually exclusive set of `JUSTIFIED`, `UNJUSTIFIED`, and `UNKNOWN_UNREVIEWABLE`; require evidence under frozen predicate sufficiency rules for the first two and put unsupported/uninspectable cases in the last. Sum those exact categories to total actual abstentions, while reporting processing errors and `NOT_PERFORMED` separately.

### SXH-03 — Major before execution freeze: receipt hashing lacks a byte-level rule

`RUN004_CONTRACT_REV004.md:34,50,66` requires a receipt to include its own hash and checkpoint linkage and makes verified receipt/checkpoint integrity a completion condition. `RUN004_EXPERIMENTAL_EXECUTION_PLAN.md:8-9` specifies start/terminal receipts, parent hashes and atomic checkpoints. Neither file defines the receipt-hash preimage, canonical serialization or exclusion of the self-referential hash field, nor a deterministic checkpoint-to-receipt verification rule. Different implementations could both claim compliance yet produce incompatible chains, leaving “verifiable terminal disposition” underspecified.

**Correction:** before approving an executable freeze, bind a versioned receipt/checkpoint schema and hash algorithm; define exact bytes or canonical encoding, which fields are excluded from a self-hash, parent/checkpoint linkage and replay verification in a fresh process. Include a negative control for altered receipt payload or linkage. No historical receipt should be rewritten.

## Coherence checks that passed within this scope

- The six family populations sum to **10,096 selected memberships/localized variants**: SWE 3,642, Pro V2 642, Terminal 89, MCPMark 127, BFCL 4,696, tau2 900. The logical total is **9,273**, replacing SWE memberships with 2,819 distinct tasks. `RUN004_READINESS_MATRIX.json` names the same six family populations. The totals are heterogeneous inventory counts, not a semantic-score denominator.
- `RUN004_COMPLETENESS_CRITERIA.json` and `RUN004_METRIC_CONTRACT.json` define the same six dimensions: execution completeness, PGOP1 audit coverage, evidence sufficiency, official evaluator coverage, engineering quality and independent semantic qualification. No observed campaign numerator or denominator was populated.
- A is mandatory for all selected memberships. Its completion requires an actual attempt and a verifiable terminal disposition for each, exact set reconciliation and receipt integrity. A blocked/unattempted remainder remains incomplete; missing authentic outputs may yield `NOT_EVALUABLE_WITH_CURRENT_EVIDENCE`, counted only as an attempted execution disposition. The draft distinguishes definition/integrity processing from semantic audit success.
- B remains complementary and submode-specific; absent Docker, Harbor, simulators or judges is not a universal A gate. The draft preserves B's selected-population gap, separate eligible denominators and archived-versus-fresh labels. This is a prospective change from rev003's integral two-modality closure, explicitly recorded in the changelog, not a retrospective change to executed results.
- Conceptual Owner approval, final contract approval, freeze, execution, independent semantic qualification and I7/GATE_11/Physical C2 authority remain separate. The preceding rev003 handoff's six-family readiness limitations are still visible. Reserved BFCL responses/references remain excluded as evidence without deleting selected task memberships.

## Limits and follow-up

This is a document and binding-coherence audit. It did not validate adapter behavior, source bodies, evaluator code/dependencies, source rights, runtime isolation, per-task authentic-output eligibility, resource budgets, checkpoint implementation or future execution receipts. Existing hashes establish identity of checked bytes, not truth of upstream claims or authority to execute. A later technical readiness audit must inspect the exact approved candidate, bindings and implementations. Any repaired rev004 files need fresh hashes and a scoped recheck of SXH-01 through SXH-03 before documentary close. Owner approval remains separate.
