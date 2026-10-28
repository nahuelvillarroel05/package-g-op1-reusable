# PGOP1 RUN-001 Audit A

**Status: AUDIT_A_COMPLETE_READY_FOR_CODE_FREEZE.** No open blocking findings remain in the reviewed candidate bytes.

Mode: REVIEW_ONLY. The auditor changed no candidate file. The historical baseline is `1086320b33e37ed07786dad2ecc2fdf34b3bd738`; all differences from that baseline are additions. The reviewed checkout parent is `47ef38455f44f91379f610e71fd1489d61526fdc`, with the exact two-file prospective normalized-claim-ID repair described in the JSON report. Exact candidate, test, documentation and reference-helper hashes are in `AUDIT_A_FINAL.json` and `final-010.json`.

The independent final run passed **136 tests in 6.37 seconds**, including historical regressions, the real adapter-to-bridge comparison path and 14 adversarial auditor probes. Candidate hashes before and after that run were identical. See `final-010.txt` for output and `final-010.json` for the exact Python command and pins. Synthetic files and pytest basetemp stayed beneath the audit workspace.

| Finding | Severity | Corrected behavior |
|---|---|---|
| AUDIT-A-TA-001 | P1 | Resolution claims need exact scope, denial and later correction handling |
| AUDIT-A-TA-002 | P2 | Repeated source descriptors and NTFS case aliases inflated claim identities |
| AUDIT-A-TA-003 | P2 | Canonical path guards must also reject NTFS ADS and aliases in the direct bridge |
| AUDIT-A-TA-004 | P1 | Recovery previously accepted mutable receipt identity unrelated to immutable capsule identity |
| AUDIT-A-TA-005 | P1 | Fresh campaigns must not adopt old completions from an unbound directory |
| AUDIT-A-TA-006 | P2 | Campaign context recovery must verify saved batch receipts against immutable data and completion hashes |
| AUDIT-A-TA-007 | P1 | Parser errors must dominate aggregate and per-claim success verdicts |
| AUDIT-A-TA-008 | P2 | Submission identity must survive slug characters and dataset-partition overlap |
| AUDIT-A-TA-009 | P1 | Actual adapter claim-comparison relationships require a top-level normalized claim identity |

The JSON report preserves exact current code locations, reproduction names, failed-attempt evidence and the limits of pre-fix evidence. All listed findings are RESOLVED_VERIFIED by the final run and source review.

The generalized parser owns claim semantics. The existing PGOP1 Context Engine owns byte admission, graph/provenance consistency and query/recovery. The completed campaign binding records every file/audit unit and its original source bytes in bounded stores. No parallel replacement engine or frozen I7 interface modification was introduced.

Claim recognition remains a narrow English grammar, with task completion and component/issue fixes separate from benchmark resolution. Caller bindings do not authenticate upstream agents or submissions. This review establishes no independent accuracy estimate, benchmark solve rate, fresh patch execution or operational qualification. No held-out outcomes were read by this auditor.

The first implementation commit `47ef38455f44f91379f610e71fd1489d61526fdc` is preserved but is not certified as final execution code. The orchestrator reports that code-hash/clean-tree gates stopped both pre-execution attempts before units or outcomes; Audit B must verify those records and the repaired executed child commit.

Audit B remains required for the actual code commit, source identities, complete snapshot coverage, counts, archived Level B verification, individual results, public scope and final ZIP. Level C remains NOT_PERFORMED. The reference scripts were inspected rather than executed and require a fresh prospective reconstruction workspace.

`I0-I6=FORMALLY_FROZEN; I7=INCOMPLETE; FORMAL_I7=NOT_COMPLETED; OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED; INDEPENDENT_CUSTODY=NOT_PROVEN; PHYSICAL_C2=DEFERRED_NOT_WAIVED`. Technical closure has no operational-authority effect.
