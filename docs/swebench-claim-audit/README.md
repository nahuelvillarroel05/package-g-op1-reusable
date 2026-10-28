# PGOP1 SWE-bench Claim Audit

PGOP1 provides a bounded audit of claims in archived SWE-bench agent trajectories. The adapter records agent statements, predictions, archived evaluator results, execution evidence, source provenance, relationships, and advisory verdicts as separate objects.

The V1 campaign is a 12-instance demonstration. Its `SUPPORTED` and `CONTRADICTED` labels describe agreement between explicit trajectory statements and locally archived report/catalog records. They are not SWE-bench task-resolution results.

- [Method](METHODOLOGY.md)
- [Reproduction](REPRODUCIBILITY.md)
- [Limits and current status](LIMITATIONS.md)
- [Separate V2 continuity requirements](V2_CONTINUITY.md)
- [V1 public evidence](../../runs/swebench-claim-audit-v1/README.md)

The original V4 campaign used adapter SHA-256 `0dadf8ea17ead8a1e02106d9d706de7c00ba3b9946e2d3bf4df98d7e94d50a80`. A prospective ZIP path canonicalization fix was added after the campaign. It has its own regression coverage and did not alter or regenerate V4 receipts.
