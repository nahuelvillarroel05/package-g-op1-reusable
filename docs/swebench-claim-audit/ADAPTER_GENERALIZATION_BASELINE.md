# Adapter Generalization Baseline

## Scope and preservation

This note records the published V1 SWE-bench claim-audit adapter and bridge before RUN-001 generalization. It is a source-code and historical-contract baseline, not a statement about the pending local input inventory. The V1 campaign and its receipts remain frozen. The established focused suite is documented as 44 passing tests (`PGOP1-SWB-TEST-T018`); this note does not rerun that suite or regenerate any receipt.

The implementation is in `runtime/candidate/swebench_claim_audit/adapter.py` and `engine_bridge.py`. The public V1 method, limits, and reproduction contract are in `README.md`, `METHODOLOGY.md`, `LIMITATIONS.md`, `REPRODUCIBILITY.md`, and `runs/swebench-claim-audit-v1/`.

## Existing adapter behavior

`audit_instance(data_root, instance_id)` is a read-only, single-instance adapter for one archived mini-SWE-agent Multilingual layout. It uses fixed paths and a fixed run slug. It reads a JSONL prediction index, a JSON trajectory, a per-instance report, a patch, gzip-compressed test output, a per-instance catalog, a result summary, YAML metadata, and a run README. JSONL/JSON and UTF-8 patch/README content are parsed where required; metadata YAML and test output are hashed/bound but not semantically interpreted. The test output is boundedly decompressed, not executed or evaluated. The patch is compared with the prediction text, not applied to an issue checkout.

The recognized input contract is therefore narrower than the set of file extensions it encounters. It is not a general JSON/JSONL/log/YAML parser, does not discover alternate layouts, and has no parser registry or parser identity/version field. Unsupported layouts generally appear as missing required evidence.

The adapter creates one `AGENT_STATEMENT` at most. Its English phrase recognizer conservatively excludes common quoted, hedged, negated, conditional, retracted, interrogative, and Markdown-fenced text. It treats first-person “completed/resolved/fixed/solved” phrasing as a `TASK_RESOLVED` assertion, including plain “I completed the task.” That conflates task completion language with the benchmark-resolution predicate and is not safe to generalize. A resolved evaluator record cannot create a claim when the trajectory has none. Multiple distinct recognized positive statements produce `AMBIGUOUS_AGENT_CLAIM`; identical repeats retain multiple source pointers.

The evaluator comparison requires the report, per-instance catalog, and summary membership to agree on one boolean `resolved` value, with the report and trajectory bound to the requested instance. This supports only a local-record comparison. It does not authenticate the run, agent, provider, evaluator process, or dataset snapshot, and does not establish objective task resolution.

## Existing safety and provenance controls

The adapter validates the data root and relative paths, rejects symlink/reparse components and traversal, bounds reads, checks for source changes during read, hashes exact source bytes, rejects duplicate JSON keys and duplicate prediction instance IDs, checks instance joins, detects evaluator conflicts, and bounds gzip expansion. Its standalone ZIP validator checks path aliases, duplicate names, symlinks/encryption, member count/size, total expansion, compression ratio, and CRC without extracting or executing members. These controls are useful baseline invariants; extensions should preserve or explicitly replace each applicable control.

The adapter's legacy result uses schema `pgop1.swebench.claim-audit.v1`, five verdict values (`SUPPORTED`, `CONTRADICTED`, `INSUFFICIENT_EVIDENCE`, `INTEGRITY_FAILURE`, `VERIFICATION_ERROR`), and source references with `path`, `bytes`, and `sha256`. The references do not carry evidence roles or parser identities.

## Existing Context Engine bridge

`bind_to_context_engine(audit_result, data_root, context_root)` accepts only the legacy schema. It verifies cited file commitments, admits exact source bytes into a fresh local Context Engine, stores a derived capsule, ingests observations and associations, verifies/query-reads the graph, and attempts a fresh-process readback. It does not verify claim semantics. Provider dispatch and recovery are explicitly not performed.

The bridge currently interprets any non-null legacy `AGENT_STATEMENT` as asserted `TASK_RESOLVED=true`, regardless of what the statement actually says. It also uses hard-coded path conventions to find JSON pointers and special-cases the patch path. This is another reason the generalized result needs predicate-specific observations and a prospective bridge API rather than changing historical modules or relying on legacy field names.

## Test coverage recorded by the baseline

The focused suite covers positive/negative and ambiguous statement cases, quoted/hedged/conditional/retracted text, repeated pointers, evaluator agreement/conflicts, wrong-instance joins, patch/prediction mismatch, duplicate prediction rows and JSON keys, missing/corrupt/oversized gzip, traversal and ZIP member safety, plus Context Engine source commitment, graph verification, and fresh-process readback. Fixtures model the fixed mini-SWE-agent layout. They do not establish broad format support, multilingual claim recognition, cross-run/submission joins, or independent generalization performance.

## Prospective contract for RUN-001

The new adapter is additive and must not alter `adapter.py`, `engine_bridge.py`, or historical receipts. The callable contract is:

```python
audit_evidence(data_root, request: dict) -> dict
```

`request` identifies `run_id`, `instance_id`, and a list of explicit evidence descriptors. Each descriptor binds a relative `path`, expected `sha256`, exact `bytes`, evidence `role`, and `parser_id`; a JSON pointer may be supplied when the format requires a caller-selected location. The output uses `pgop1.swebench.generalized-audit.v1`, keeps the five established verdicts, preserves roles and parser identities in source provenance, and contains normalized predicate-specific observations suitable for the new bridge.

Discovery-only `audit_file(data_root, descriptor)` may extract normalized observations and identify a supported parser, but it cannot issue a claim verdict without an explicit, request-bound join. Completion predicates and `TASK_RESOLVED` remain distinct. Only attributable assertions and evaluator observations matching the same predicate, instance, run, and submission can be compared. Missing or ambiguous bindings fail closed; prediction rows and patch artifacts alone never support a success claim. Formats and parser versions will be enabled only when the completed inventory and development evidence establish their actual shapes. Held-out outcomes remain unopened until the code freeze and protocol allow them.

## Baseline decision

The published adapter is a valuable fixed-layout reference with meaningful path, integrity, and bounded-input defenses. It is not itself a reusable multi-format audit engine. Generalization must be additive, inventory-grounded, predicate-aware, and explicitly separated from Context Engine storage/provenance verification. No operational authority or benchmark-performance claim follows from either adapter tests or successful evidence ingestion.
