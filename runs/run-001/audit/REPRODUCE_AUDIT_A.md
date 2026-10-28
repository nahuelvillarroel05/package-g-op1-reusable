# Audit A reproduction

`final-010.json` and `.txt` are the sanitized pinned execution receipt/output.
`audit_a_probes.py` and `run_audit_a.py` preserve the exact forensic probe/runner source used in the declared engineering layout. The probe has a fixed original REPO constant; the runner expects its original sibling repo directory. They are reference evidence, not a portable discovery mechanism.

To repeat elsewhere, use a fresh Windows checkout at executed commit 0305a35d43661729f4a6061262cd452d62090a98, copy the probe to a new temporary file, set its REPO constant to that verified checkout, and record the modified probe hash. Run the four public `tests/test_swebench_*.py` modules plus the copied probe with Python 3.14/pytest 9.0.3 and an explicit fresh writable `--basetemp` outside the source tree, with cache disabled. Do not invoke the fixed-layout runner against another repository. Exact code/test hashes are in CODE_REFERENCE.json and the audit receipt; the later public results commit is not the code execution identity.

The historical and generalized public tests exercise the runtime APIs; the additional 14 probes independently exercise the specific failures and repairs recorded by Audit A. Nothing here evaluates classifier accuracy, executes an external patch or grants operational authority.
