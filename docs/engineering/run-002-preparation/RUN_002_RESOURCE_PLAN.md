# Resource plan v1
Preparation is CPU-only Python testing, bounded local authentic parsing, SQLite checkpoints and existing Context Engine storage. No model acquisition, GPU use, training, Docker, fresh SWE-bench evaluation or campaign launch.

Observed logical CPU count 12; free bytes at this snapshot 394170900480; total volume bytes 960195719168. This is a snapshot, not reserved capacity. Recheck space before authorized campaign launch; preserve campaign runner's existing free-space contract and reserve. Do not silently reduce it.

Use one writer per checkpoint/store; validated configurable batch sizes and canonical-byte limits, stable input ordering, streamed iterators, explicit oversized/invalid rejection and recoverable durable receipts. Exact supported bounds and current limitations are in BATCHING_REPORT.md. Per-process peak RSS is not independently instrumented; do not claim measured memory compliance from a configured cap alone.

Final ZIP below 512 MB, excluding full datasets, raw/private logs, temporary test stores, caches and dependencies. RUN-002 source counts, walltime, disk amplification and external-regrade resources are NOT_MEASURED until a new eligible manifest is frozen. Budget and evaluation cardinality follow eligible cases and resource preflight, not a favorable SUPPORTED target.
