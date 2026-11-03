# Sol XHigh follow-up 001 — corrected RUN004 rev004 draft

Auditor role/model: **Sol XHigh technical contract auditor**; coordinator-reported `model=gpt-6-sol`, `reasoning_effort=xhigh`, task `/root/sol_contract_audit`. This recheck addresses the prospective corrections to findings SXH-01 through SXH-03 in `SOL_XHIGH_AUDIT.md` and checks the applicability change raised by Astra. It is a contract-only technical decision, not Owner approval or an execution-readiness audit.

## Corrected bytes reviewed

| Artifact under `Engineering/PGOP1_RUN004_CONTRACT_REV004_001/` | Corrected SHA-256 |
| --- | --- |
| `RUN004_CONTRACT_REV004.md` | `a1db91f6a6905c5c94abbf0e67dca4a411be5ca7ef1a548e0fec1adac4f8d212` |
| `RUN004_COMPLETENESS_CRITERIA.json` | `83c5b81123ff9b78e2ec38ad466f1a3ce79ef5e0376330380744f62ce928644d` |
| `RUN004_METRIC_CONTRACT.json` | `9298a9b346257c211febcceee6eee05e5955d8b7ae55eab2622d2d0eefd0d7b1` |
| `RUN004_EXPERIMENTAL_EXECUTION_PLAN.md` | `ff2e3749a68e36300f5f4f17697a88bb47cfc3b3c7cdfa9ac2e25114581734df` |
| `RUN004_SIX_FAMILY_SCOPE.json` | `23ad5f3fb754d98a1339267a992a978583dd1ba41954a4a3f3b146f7093d5a06` |
| `RUN004_READINESS_MATRIX.json` | `ac36dddf2f1b00a076795d62ef2ffa34f6db3c2a49158b0530e6499c524ff15d` |
| `REV003_REV004_CHANGELOG.md` | `a0a835c1bf712b1eafcd4d8c16e03c008e620b07b4bbe1e85bdc911d8e0b3417` |
| `SOURCE_BINDINGS.json` | `3e1d8d2ed4289fa401256b6e4fab2571d446c2db00d2850c123649cb8c399ea7` |

The seven original document preimages in `review-preimages-001/` retain the hashes listed in `SOL_XHIGH_AUDIT.md`. `CONTRACT_CORRECTIONS_001.md` records the prospective change. Source bindings and selected population hashes were unchanged.

## Resolution

| Finding | Recheck result |
| --- | --- |
| SXH-01, overclaim from abstentions | **Resolved in corrected contract.** `RUN004_CONTRACT_REV004.md:36` and `RUN004_EXPERIMENTAL_EXECUTION_PLAN.md:12` now say an all-abstention population provides no **demonstration** of semantic capability. The completeness JSON retains `NO_SEMANTIC_CAPABILITY_DEMONSTRATED`. This avoids claiming absence of ability. |
| SXH-02, inconsistent abstention categories | **Resolved in corrected contract.** `RUN004_CONTRACT_REV004.md:80` and `RUN004_METRIC_CONTRACT.json` use exactly `JUSTIFIED`, `UNJUSTIFIED`, `UNKNOWN_UNREVIEWABLE`, with evidence conditions and same-partition reconciliation. Unsupported sufficiency remains UNKNOWN. |
| SXH-03, receipt self-hash ambiguity | **Resolved at documentary contract level.** `RUN004_CONTRACT_REV004.md:82` defines exact UTF-8 JSON payload bytes, detached SHA-256, field/ordering constraints, parent/sequence/checkpoint set linkage and fresh-process verification. The execution plan invokes this rule. A real writer/reader and negative controls are still a required later execution gate; no implementation qualification is inferred here. |
| Applicability/availability denominator | **Coherent in corrected contract.** `RUN004_CONTRACT_REV004.md:78`, the execution plan and both normative JSON files require the complete selected membership × eight-predicate candidate universe. Genuine semantic `NOT_APPLICABLE` needs versioned domain rationale; missing output/evidence/reference/runtime or reserved evidence cannot make a pair inapplicable. `UNKNOWN_APPLICABILITY` remains in the conservative applicable denominator. Planned allocation cannot reduce it; structural/provenance/semantic coverage is separate. |

All corrected JSON parsed. The six dimensions in `RUN004_COMPLETENESS_CRITERIA.json` and `RUN004_METRIC_CONTRACT.json` remained identical, as did their applicability policies. The six family counts still sum to 10,096 selected memberships/localized variants and 9,273 logical variants. No campaign measurements were added.

**Technical decision on these corrected bytes: `CONTRACTUAL_COHERENCE_ACCEPTABLE_FOR_DOCUMENTARY_HANDOFF_WITH_EXECUTION_GATES_OPEN`.** No material Sol finding remains open at contract-only scope. Before any executable freeze, the exact candidate, population/evidence bindings, applicable-predicate ledger, rights/safety, resource budgets, receipt writer/reader qualification and technical execution audit must be separately completed and reviewed. `RUN004_CONTRACT=NOT_APPROVED`; `RUN004_FINAL_FREEZE=NOT_ISSUED`; `RUN004_EXECUTION=NOT_EXECUTED`. B remains complementary, with submode gaps reported independently; A completeness cannot imply semantic success, B completion or independent qualification. I7, GATE_11, custody and Physical C2 limits remain unchanged.
