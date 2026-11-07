# RUN contract template - mode-aware version 1

Complete the fields relevant to the operation. This template is not execution authority. E1 uses the minimum controls below; add E2/F evidence obligations only where the declared claim requires them. Link existing manifests and receipts rather than duplicating source bodies or creating unnecessary documents.

| Field | Required content |
|---|---|
| RUN_ID | Unique registered RUN and fresh ATTEMPT_ID |
| ENGINEERING_MODE | E1 / E2 / F |
| PURPOSE | Experiment objective or exact property/qualification claim |
| CANDIDATE | Exact commit/tree and code-byte binding |
| POPULATION | Identified selection, manifest/hash, denominators, exclusions and protected reserves |
| EXECUTION_SCOPE | Executable producer/procedure; permitted operations and per-source rights; applicable Owner authorization; deterministic batches |
| RESOURCE_LIMITS | Output/storage, time, unit/input limits and applicable supervision |
| STOP_CONDITIONS | Integrity/provenance/security/authorization failures, budget exhaustion, evidence loss or historical corruption risk; isolate affected scope |
| RESULT_METRICS | Attempted, processed, semantic audits, sufficient evidence, not-attempted, errors, interruptions, dispositions, defects and informative efficiency |
| EVIDENCE_POLICY | Persistent result/receipt hashes; checkpoint/recovery as needed; no overwrite, no silent redispatch, preserved failures |
| PUBLICATION_POLICY | Permitted result/code/aggregate selection, withheld material, audits, target branch, separate publication and remote verification states |

Before the first result, record an operational freeze identifying the contract revision/hash, inputs, exact code/configuration, authorized source operations, budget, stops, and attempt. E1 freeze is not formal qualification. Record start and terminal outcomes from actual operations. Changes to frozen code/configuration use a new version and identifiable attempt.

E1 may produce errors, abstentions, incomplete evidence, unknown applicability, or no favorable semantic result. Use the applicable normative statuses, keeping processing dispositions distinct from semantic audit. Unresolved processing rights forbid affected body reads; unavailable isolation yields `NOT_ATTEMPTED_UNSAFE_EXECUTION`. Preserve the selected inventory and continue other safe authorized operations.

For E2 add acceptance criteria, frozen comparisons, regressions/adversarial checks, audit and recovery evidence needed for the exact guarantee. For F link the controlling formal contract and all applicable formal approval requirements. Never convert E1 observations automatically into E2 guarantees or F qualification.

See [engineering modes](ENGINEERING_MODES.md) and [policy](EXPERIMENTAL_POLICY.md).

## Capability-first experimental design

Prospectively each RUN declares `TARGET_CAPABILITIES`, `RESEARCH_QUESTIONS`, `SYSTEM_UNDER_TEST`, `DATA_SOURCES`, `EXPERIMENTAL_UNITS`, `REFERENCE_EVIDENCE`, `METRICS`, `BASELINE_COMPARATORS`, `LIMITATIONS`. Use [the capability matrix](CAPABILITY_EVALUATION_MATRIX.md) and [evidence standards](EXPERIMENTAL_EVIDENCE_STANDARDS.md). Select only relevant capabilities. This is experimental design guidance, not an added formal E1 qualification gate or a requirement to resolve GATE_11. Separate structural/record consistency from semantic correctness, independent reference truth and formal status; use separate denominators and state ADDED_VALUE_NOT_ESTABLISHED without a valid comparator. Historical RUNs retain their original contracts and outcomes.
