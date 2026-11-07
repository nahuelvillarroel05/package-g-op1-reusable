# PGOP1 · Autonomous Evolution Campaign 001

**RUN-006 → RUN-009 · Experimental engineering (E1) · Closed**

> **Outcome:** `BOUNDED_ENGINEERING_EVOLUTION_SUPPORTED_WITH_EXACT_LIMITATIONS`
>
> **Not demonstrated:** general semantic accuracy, independent precision/recall, formal I7 qualification or universal benchmark performance.

## At a glance

| Scope | Verified observation |
| --- | --- |
| RUN-006 / RUN-007 | Same **20** BFCL task/output pairs; **19 structural rejects, 1 structural pass** in each RUN. |
| Observed engineering correction | **120** incorrect missing-output explanations in RUN-006; **0** remain in RUN-007. |
| Batch execution | RUN-007 closed **four batches of five**; RUN-006 did not demonstrate enforcement of that requirement. |
| RUN-008 | Preflight failed before unit processing; **0 units** processed. |
| RUN-009 | **4 task definitions**, **2 MCPMark + 2 Terminal-Bench**; recovered without redispatch. |
| Scope of benchmark use | Six families considered; **three** families exercised in the documented execution, at different evidence levels. |
| Semantic conclusions | **0 semantic audits in these four RUNs** and no general semantic improvement demonstrated. |

## Limits before interpreting improvements

The documentary incident remains **`EXPOSURE_STATUS=UNKNOWN`** and historical global integrity remains **`DEFERRED`**, not certified PASS. Engineering scores do not compensate for the incident. BFCL structural dispositions and definition processing do not establish semantic truth, official benchmark acceptance or certified security. See the restrictions below.

## What changed, and why

| Engineering change | Evidence | Safe conclusion |
| --- | --- | --- |
| Corrected reason attribution | [Capability comparison](CAPABILITY_COMPARISON.md) | Explanation fidelity improved on the identical BFCL sample; structural decisions did not change. |
| Explicit batch control | [RUN-007 results](run-007/UNIT_RESULTS.json) | Four batches of five were verifiably closed in RUN-007. |
| Process-local read-scope / Git pipe handling | [RUN-008 failure](run-008/PREFLIGHT_FAILURE.json), [RUN-009 results](run-009/SUMMARY.json) | The repaired runtime processed four eligible definitions. The process-local hook is not an OS sandbox or a general confinement guarantee. |

## Run-by-run evidence

| RUN | Input type | Actual result | Evidence |
| --- | --- | --- | --- |
| **006** | Archived BFCL task/output pairs | 20 processed; baseline limitations retained | [Summary](run-006/SUMMARY.json) · [Unit results](run-006/UNIT_RESULTS.json) |
| **007** | Same 20 BFCL pairs | Reasons corrected; four batches closed | [Summary](run-007/SUMMARY.json) · [Unit results](run-007/UNIT_RESULTS.json) |
| **008** | Planned non-BFCL development composition | Blocked in preflight; no unit result | [Summary](run-008/SUMMARY.json) · [Failure](run-008/PREFLIGHT_FAILURE.json) |
| **009** | MCPMark / Terminal task definitions | Four processed; recovery verified | [Summary](run-009/SUMMARY.json) · [Unit results](run-009/UNIT_RESULTS.json) |

## Technical reviews and reproducibility

- [Astra: final global audit](audits/astra-final/ASTRA_GLOBAL_EVOLUTION_AUDIT.md)
- Astra individual reviews: [RUN-006](audits/astra-final/ASTRA_RUN_006_FINAL_AUDIT.md) · [RUN-007](audits/astra-final/ASTRA_RUN_007_FINAL_AUDIT.md) · [RUN-008](audits/astra-final/ASTRA_RUN_008_FINAL_AUDIT.md) · [RUN-009](audits/astra-final/ASTRA_RUN_009_FINAL_AUDIT.md)
- [Sol XHigh: individual and patch reviews](audits/sol-xhigh/)
- [Runtime and code references](FINAL_CODE_REFERENCE.json)
- [Patch register](PATCH_REGISTER.json) · [Defect register](DEFECT_REGISTER.json)
- [Release manifest and source commitments](PUBLIC_RELEASE_MANIFEST.json)

Astra and Sol are technical subordinate reviewers, not external semantic adjudicators. The historical E1 scores (80/94/67/94 out of 100) are qualitative engineering measures, not accuracy scores. No pooled accuracy denominator is valid: RUN-006/007 comprise 40 run-unit executions over 20 unique pairs; RUN-009 adds four definitions, and its three synthetic denials are separate controls. All 160 BFCL predicate decisions/applicabilities per RUN stayed unchanged; RUN-009 has 32 NOT_EVALUATED slots, no output audits and 4/4 fresh-process recovery with zero redispatch.

Original benchmark bodies are not included in the public release. **Standalone public replay is not claimed.** Engineering scores are not accuracy scores.

## Restrictions, open questions and status

> **Documentary read incident:** an historical verifier was invoked without its required guard and stopped. The set of files read before interruption is **UNKNOWN**. No proof of external disclosure is claimed, and absence of protected-data access is **not** established.
>
> **Historical global integrity:** `DEFERRED` / not certified PASS.
>
> **Formal boundaries:** I0–I6 remain frozen; I7 is incomplete; GATE_11 remains blocked; independent precision and recall are `NOT_COMPUTABLE`; independent custody is `NOT_PROVEN`; Physical C2 remains `DEFERRED_NOT_WAIVED`.

- [Incident record](RESTRICTION_COMPLIANCE_INCIDENT.json)
- [Current publication status](PUBLICATION_STATUS.md)
- [Original historical campaign README](README.md)

**This page is a navigational presentation of existing evidence, not a new experimental result or amended audit.**

[Experiments index](../../README.md) · [Repository and synthetic demo](../../../README.md) · [Execution summary](RUN_EXECUTION_SUMMARY.json)
