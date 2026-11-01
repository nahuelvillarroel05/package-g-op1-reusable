# Public-only Sonnet review handoff

Review status: **PENDING**. This file does not claim Sonnet acceptance.

Use only this public repository and the experimental release branch containing
this package. Inspect the exact source-processing commit
`d589697b9b5e537a93e67480cb0c1f9970745d88` and prospective repair
`22434026abb47fb8300ec13f3cea71592ff1944c`, plus the separate results commit
containing this directory. Do not treat the branch's results tip as the commit
that executed the original campaign.

Read `README.md`, `CODE_REFERENCE.json`, `METRICS.json`, the unit ledgers,
`PROSPECTIVE_READBACK_REPAIR.json`, `ASTRA_PUBLIC_AUDIT.md`, and the committed
`docs/swebench-claim-audit/ATTRIBUTION_AMBIGUITY_V1.md` contract. Reproduce the
synthetic tests, including the large-input readback regression on supported
platforms. Check identity boundaries, conflicting/corrected assertions,
abstentions, source associations, parser exclusions, and whether new adversarial
inputs reveal defects. Report additional defects explicitly.

Important audit limits:

- RUN-002 is nonqualifying engineering. Independent protocol v1.1 is unchanged;
  GATE_11 remains BLOCKED and independent semantic qualification NOT_ACHIEVED.
- Compare like populations and distinguish strict parsing, the 300-source
  supplement, 4,102 attempts, 3,802 unique sources and 266 execution audits.
- Preserve the original 264 PASS / 2 ERROR direct-readback result and the separate
  two-case prospective repair. A later successful check does not rewrite history.
- Public metadata cannot independently establish source truth, evaluator
  authentication, private associations or the correctness of 247 dropped claims.
  Raw source-bearing evidence and the private full plan are intentionally absent
  because redistribution rights were not assumed. State those limits rather
  than claiming full public raw-data reproduction.
- F-16 remains deferred pending its original exact reproducer; passing bounded
  Linux checks does not establish general portability.

No main merge, force push, src promotion, GOLD access, new labels, source-data
execution, model operation, or operational phase advancement is requested.
