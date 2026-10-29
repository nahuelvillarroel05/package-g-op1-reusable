# PGOP1 — Current State

Updated 2026-10-29. Mutable index, not primary authority. Read [AGENTS.md](AGENTS.md)
and [NEXT_STEP.md](docs/engineering/NEXT_STEP.md); original contracts/evidence prevail.

## Sonnet findings engineering convergence

Owner objective: `PGOP1_SONNET_FINDINGS_REMEDIATION_AND_FULL_ENGINEERING_RUN`.
Prospective branch: `feat/pgop1-sonnet-findings-remediation-001`, based on `f416c8d`;
executable baseline `676f2f08` is preserved. The original checkout remains untouched;
Windows denied sibling creation under Engineering and Git-ref writes there. Work
uses a separate clone in the authorized `PGOP1_SONNET_REMEDIATION_001` workspace.
The original Sonnet report/R01-R15 inputs were not found in the bounded search;
reproductions use the Owner's individual F-01..F-17 descriptions. All 17 baseline
classifications were recorded before implementation. Baseline seven suites were
actually rerun on Windows: 216 passed. Later counts must come from current JUnit.

See [compatibility](docs/audits/SONNET_REMEDIATION_COMPATIBILITY.md). The external
workspace's CODE_REFERENCE.json, SONNET_FINDINGS_RESOLUTION_MATRIX.json,
astra-review/ and FINAL_HANDOFF.md control the final candidate/review/run status;
this index does not predeclare their completion. Astra must inspect the frozen
candidate before the full engineering campaign. The campaign uses its own
post-Sonnet engineering ID, never formal RUN-002. Main and supplemental RUN-001
plans cover 3,802 pertinent sources in the 25,580-file snapshot. All 3,802 source
hashes were rechecked without mismatch; 300 Aider parser assignments are upgraded
prospectively. Sources, old results and 25 inaccessible directories are preserved.

`GATE_11=BLOCKED`, `RUN_002=NOT_READY`,
`INDEPENDENT_SEMANTIC_HOLDOUT_NOT_AVAILABLE`. No push or src promotion. The sections
below preserve the pre-remediation history; their PENDING labels describe that time.

## Retained history and boundaries

```
I0-I6=FORMALLY_FROZEN
I7=INCOMPLETE
FORMAL_I7=NOT_COMPLETED
OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED
INDEPENDENT_CUSTODY=NOT_PROVEN
PHYSICAL_C2=DEFERRED_NOT_WAIVED
```

`src/package_g/` is the historical consolidated core; prospective engineering
remains in `runtime/candidate/`. Preserve I4/I5-NEXT import roots/pins and fixed
providers. Engine byte/provenance integrity is separate from adapter semantics.
[Architecture](docs/ARCHITECTURE.md), [phase matrix](docs/I0_I7_STATUS.md),
[adapter contract](docs/swebench-claim-audit/GENERALIZED_ENGINE.md), and
[qualification obligations](docs/OPERATIONAL_QUALIFICATION_PENDING.md) retain
normative context: Source025 accepted 0/6, OD05 accepted 0/3, E30 not executed,
OD03 expanded deferred by Owner. Engineering tests do not lift these restrictions.

RUN-001 remains `PGOP1_RUN_001_PARTIAL_WITH_EXACT_LIMITATIONS`; executed code
`0305a35d43661729f4a6061262cd452d62090a98`; publication
`af95c484813c8e6180f72be8c86896f5aab23305`. Its
[summary](runs/run-001/CAMPAIGN_SUMMARY.md),
[results](runs/run-001/RESULTS_SUMMARY.json),
[coverage](runs/run-001/COVERAGE_REPORT.json), and
[pins](runs/run-001/CODE_REFERENCE.json) are immutable history.

| Historical denominator | Frozen result |
| --- | --- |
| Accessible source inventory | 25580 files, 830354973 bytes |
| Processing attempts | 3802 = 1744 accepted + 2045 unsupported + 13 errors |
| Execution audits | 266 = 264 insufficient + 2 integrity failures |
| Claim occurrences | 351 insufficient = 235 TASK_COMPLETED + 116 ISSUE_RESOLVED |
| Context Engine campaign units | 4068 = 3802 file results + 266 execution audits |

Historical V1 used twelve selected instances, 36 receipts, six SUPPORTED and six
CONTRADICTED over twelve instances; this was not general accuracy or fresh patch
execution. [V1 evidence](runs/swebench-claim-audit-v1/CAMPAIGN_SUMMARY.md).
Level B native: 247/258 completed, 54 discrepancies and 11 decoding errors;
separate UTF-8 protocol 258/258 concordant with archives. Level C fresh
NOT_PERFORMED. Six dataset shards have 3642 memberships/2819 unique IDs, not
independent problems. The original twelve/49 reserved cases do not establish
independent semantic labels. Twenty-five inaccessible directories remain excluded.

Coverage engineering was consolidated without byte changes in
`46ed62c7fcc2ca08098c0aeae3c42fe7d36eddd5`; initial preparation candidate
`e96dce5297fcfae773d7c33118f7ad885f7c4db5`. Public Sonnet code candidate
`676f2f08a7bb7602bb0bc6e66d845684e1833783`, tree
`c81bb27122a011662e20e52a2645fd3ac119dc6f`; later documentation `f416c8d`.
[Public review](docs/audits/PUBLIC_CANDIDATE_REVIEW.md),
[external scope](docs/audits/EXTERNAL_AUDIT_SCOPE.md), and
[branch comparison](docs/audits/BRANCH_COMPARISON_REPORT.md) describe that baseline.
The public release reused original 216-test receipts; this intervention reran them.

Earlier engineering workspaces under the SWEbench data root are preserved:
`PGOP1_CLAIM_AUDIT_COVERAGE_001`, `PGOP1_RUN_002_PREPARATION`, and
`PGOP1_RUN_002_PREPARATION_STREAMING_001`. Their FINAL_HANDOFF.md,
CODE_REFERENCE.json and TECHNICAL_AUDIT.md control exact historical results.
The preparation ZIP remains committed by SHA-256
`0105ee648a863ae54c96d0ecf88795ba8d773e6ac45e929651599cf6ac0d0575`.
Source-fragment V2 conserves original bytes and mapped/rejected ordinals; range
mapping alone is not semantic validation. Explicit attribution parsers preserve
SOURCE_DECLARED_UNVERIFIED. TASK_RESOLVED boolean evidence is narrow;
TASK_COMPLETED/ISSUE_RESOLVED and other predicates lack universal evidence
contracts and remain insufficient without suitable evidence. Independent reference
qualification remained NOT_READY; exploratory evaluation was designed, not run.

## Observability and continuation

Reuse local `PGOP1_AGENT_USAGE_RECOVERY_001/agent_usage/collector.py`. It is a
compatible reconstruction, ORIGINAL_IMPLEMENTATION_NOT_RECOVERED. Current goal
metadata-only token/call receipts live in the remediation workspace. Cached input
and reasoning output are subsets, not additional totals. Unknown coverage stays
UNKNOWN; response usage is not billing, monetary cost or the /goal counter.

See [NEXT_STEP](docs/engineering/NEXT_STEP.md) and the external remediation
FINAL_HANDOFF.md for remaining work. The separate independent-reference gate
requires new qualified adjudication, frozen source identities and explicit formal
execution authority; no engineering result supplies that authority.
