# RUN-001 engineering reference scripts

These are exact copies of the inventory/split and Level B preparation scripts
used in the RUN-001 engineering workspace. Their layout constants name the
declared local archive, rather than providing another audit engine. The reusable
parser, explicit join, campaign and Context Engine APIs live under
`runtime/candidate/swebench_claim_audit/`.

The inventory scripts contain fixed output filenames and are supplied for
inspection and reconstruction in a **fresh prospective workspace**. Do not run
them against an existing campaign directory: that would replace derived
inventory or split records. Change their ROOT/WS constants to a new authorized
location when reconstructing a different snapshot. Hashes and timestamps of a
new snapshot will differ; compare the declared raw source closure, not generated
historical engineering files.

`regrade_all.py` has fixed SHA-256 pins for the declared inventory, local dataset
and selected upstream source manifest. It requires a clean exact code freeze,
uses the existing isolated Python 3.11.9 environment and local unmodified
SWE-bench 5.0.2 `_grade` function, and records terminal per-case errors. It parses
archived test logs and patch text. It does not apply patches, run tests or use
Docker. This is Level B evidence; Level C remains NOT_PERFORMED. To reconstruct
the specific campaign, restore the pinned local manifests and source bytes,
then pass its code-freeze manifest and a fresh attempt identifier. Do not relax
pins to make a different source look identical.

Third-party original logs, trajectories, patches and full datasets are not
redistributed with these scripts. The public source index and reproduction
instructions identify permitted sources and exact commitments. Missing source
rights or bytes remain explicit limitations.
