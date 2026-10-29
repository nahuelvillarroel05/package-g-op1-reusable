# RUN-002 resource plan: streamed-source V2

PREPARED_NOT_EXECUTED. Current engineering is CPU-only parsing, hashing, local SQLite and the existing Context Engine. No model, training, GPU workload, Docker/fresh regrade or campaign execution.

Measured controls below are synthetic engineering inputs, not independent semantic reference cases. Windows GetProcessMemoryInfo measured the fresh main worker process per size; aggregate process-tree peak was not measured. A 1 MiB original read request cap is not a 1 MiB process memory claim. Unchanged bridge/runtime allocations contribute to peak usage.

| Original bytes | Fragment bytes | Original reads | Peak working set bytes | Peak private/pagefile bytes | Elapsed seconds |
| --- | --- | --- | --- | --- | --- |
| 8388608 | 1048576 | 9 | 101085184 | 91607040 | 2.784 |
| 33554432 | 1048576 | 33 | 101306368 | 92848128 | 10.324 |

Both cases verified exact original byte totals and parent SHA, then recovered with original and staged fragments unavailable. Preserve caller run identity separately from storage origin identity. Evidence: RESOURCE_PROFILE_RESULTS.json and referenced raw worker results; code hashes must match the candidate.

A second profile actually streamed/spooled/bound/recovered 20,000 small observations from one 1 MiB source using 64 KiB fragments: 320 Engine batches, 16 fragments, zero rejects, exact global/per-fragment input digests. Indexed total time was 152.229s versus 380.133s baseline; spooling after fragmentation 2.581s versus 234.232s. Logical retained output was 476,154,039 bytes for the indexed case. This is one matched logical-workload pair with fresh namespaces; system overlap was not controlled and no statistical/general throughput claim is made. See VOLUME_COMPARISON.json.

Configured bounds: original parent256 MiB, at most4096 fragments, fragment at most64 MiB, manifest4 MiB, 100,000 input records, original normalized row1 MiB, spool256 MiB, rejection/completion ledger8 MiB. Source chunks use a1.25 MiB audit envelope, followed by actual aggregate-fit preflight against unchanged Engine/bridge caps. Out-of-profile/invalid units retain explicit rejection/error; limits are not expanded to force success. Configured maxima are not all physically measured.

Use a single checkpoint writer. Recovery may create a bounded disposable verification SQLite file; it does not redispatch producers. Reserve storage before execution using the existing campaign runner contract (do not reduce its70,000,000,000-byte reserve). Do not automatically reuse orphan/pre-policy/pre-completion contexts.

Legacy audit_file parsers may still materialize bounded files. This source composition route requires a normalized iterator and verified original byte coordinates; it does not qualify every parser as streaming or establish semantic truth. New campaigns must freeze eligible inputs/config/resource caps and honor measured profile limitations; campaign source counts/time/disk amplification remain NOT_MEASURED until an eligible execution manifest exists.

Current local volume snapshot: total960195719168 bytes, free390602358784; logical CPUs12. This is an observation, not reserved capacity. Final handoff excludes test stores/data, raw private logs, caches and installed dependencies and stays below512 MiB.
