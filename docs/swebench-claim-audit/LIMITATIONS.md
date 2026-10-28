# Limits and current status

- V1 covers only the frozen 12-instance sample and does not estimate benchmark performance.
- V4 verdicts compare trajectory statements with local archived report/catalog/summary data. They do not authenticate the agent, provider, or evaluator.
- No patch was applied to an issue repository; no SWE-bench task tests or Docker runs occurred.
- No independent custody or cryptographic source attestation is established.
- The official verifier was inspected and invoked, but stopped during CLI/import setup before grading. Its result is `BLOCKED`, not `PASS`.
- Third-party trajectories, predictions, patches, test logs, and evaluator archives are omitted because their redistribution terms are unresolved. Public evidence contains hashes, IDs, and derived non-verbatim classifications.
- The repository commit and CI status are reported by the closeout publication record; a local test pass does not imply remote CI success.
- The prospective ZIP path hardening fix is not the code that generated V4. No V4 verdict or receipt was rewritten.

OP1 state remains:

```text
I0-I6=FORMALLY_FROZEN
I7=INCOMPLETE
FORMAL_I7=NOT_COMPLETED
OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED
INDEPENDENT_CUSTODY=NOT_PROVEN
PHYSICAL_C2=DEFERRED_NOT_WAIVED
```
