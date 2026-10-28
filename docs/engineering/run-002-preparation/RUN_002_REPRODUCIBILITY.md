# Reproducibility v1
Preparation evidence lives beside the checkout, under PGOP1_RUN_002_PREPARATION because creation inside Engineering was OS-denied. CODE_REFERENCE.json pins the consolidation and candidate commits/trees and exact evaluated file hashes. IMPLEMENTATION_DIFF.patch is a review artifact, not a substitute for byte verification.

From the pinned repository checkout, Python 3.14, no installed dependency changes:

```powershell
python -B -m pytest -p no:cacheprovider tests/test_swebench_claim_audit.py tests/test_swebench_generalized.py tests/test_swebench_generalized_bridge.py tests/test_swebench_campaign.py tests/test_swebench_attribution.py tests/test_swebench_batching.py --basetemp NEW_WRITABLE_TEMP --junitxml NEW_RESULTS.xml -q
```

Use fresh temporary directories for each independent attempt; retain failed evidence. Synthetic tests establish deterministic behavior, never independent semantic precision. Authentic source commitments are in COVERAGE_RESULTS.json and source research; original bodies remain local and are excluded from ZIP. Verify original hashes before any preflight. No 25,580-file rescan is required.

Replay batch tests and audit scripts in a new process. Recovery may reconstruct disposable SQLite indexes; it verifies existing Engine objects and checkpoints, not the native producer. No P010 redispatch. Hash every input and durable receipt and reject changed configuration/order/content.

Verify FINAL_INTEGRITY_MANIFEST.json then the external ZIP receipt, safe unique membership, CRC and fresh-extracted file hashes. The integrity manifest excludes itself; ZIP receipt is external to avoid self-hashes. Collect observable usage using the pinned existing collector, not /goal or inferred billing. Cache remains unchanged.

Holdout evaluation is NOT reproducible yet: new independent reference labels and a reserved frozen family manifest are missing. Do not populate campaign results until separately authorized.
