# Bounded Context Engine batching preparation

**Status:** implementation and bounded verification complete; RUN-002 campaign execution not performed.

## API

`runtime.candidate.swebench_claim_audit.swebench_batching.iter_audit_chunks(...)` accepts an iterable of normalized observations and yields deterministic `{item_id, audit_result}` records. It retains only the current chunk in memory. Default chunks contain at most 64 observations and at most 3 MiB of complete canonical audit payload. A relationship callback can attach relationships for the chunk's observation and claim IDs. A relationship that crosses chunk boundaries must include its endpoint observation as an explicit stub; otherwise the chunk is rejected. Source references, parser IDs, source spans and other observation fields are retained.

`bind_audit_stream(items, data_root, output_root, batch_size=16, resume=False)` binds records incrementally through the existing `bind_generalized_audit` API. `batch_size` is validated from 1 to 64 and is a maximum; the bridge's source and observation limits, plus bounded fresh-process readback arguments, may close a batch sooner. `recover_audit_stream(output_root)` verifies the batch and item hash chains, each existing generalized bridge receipt and store, original full member results in immutable capsules, and checkpoint membership. It does not rerun the adapter or producer.

Each immutable aggregate capsule contains each complete normalized member result, its stable item ID and SHA-256. Recovery recomputes every member hash and verifies ordered membership against the durable SQLite checkpoint. Rejection records have their own hash chain and must agree with rejected item status. Hash chains detect accidental or uncoordinated edits; they are not signed or independent custody evidence.

## Bounds and recovery behavior

- Chunk: at most 64 observations and 3 MiB including metadata and relationships.
- Aggregate: at most 64 unique committed sources, 935 graph observations, 1,000 relationships, 120 readback IDs and 3 MiB canonical aggregate payload. Unique committed source bytes are capped at 128 MiB per batch.
- The 120 readback ID cap keeps the existing fresh-process bridge verification within practical Windows command-line bounds; the bridge's nominal observation capacity is higher.
- Input IDs, input order and exact member hashes are checked on replay. A truncated or reordered replay, changed input, changed receipt or changed checkpoint is rejected. Existing output requires explicit `resume=True`. An orphan Context Engine root blocks recovery and is never rebound.
- Source references declared `RUN_ONLY` remain run scoped. A requested instance ID is retained as metadata but is not asserted as a graph binding. RUN_ONLY evidence cannot support an instance comparison.

The observation iterator does not require the full observation collection in memory. The existing bridge still reads each referenced source file in full under its own per-source byte bound and may read it again for each batch. This work does not change Context Engine or bridge internals. Relationships spanning chunks need the caller's callback and endpoint stubs; this implementation rejects unresolved crossings rather than dropping them silently.

## Verification performed

- Focused suite: `python -B -m pytest -p no:cacheprovider --basetemp D:\PGOP1_DATA\SWEbench\PGOP1_RUN_002_PREPARATION\pytest-tmp tests/test_swebench_batching.py` — **8 passed**.
- The controlled-volume test generated 20,000 observations from an iterator, verified the 64-observation chunk bound across the full stream, and bound/recovered the first 1,024 observations through 16 actual Context Engine roots. It preserves and checks source spans.
- A subprocess test used the real bridge and Engine, exited immediately after the first durable batch, then resumed the exact ordered stream in a fresh process. Two batches recovered; no completed batch was rebound.
- Adversarial synthetic failure/replay probe `audit-batch-attempt-008/RESULTS.json` — **15 passed, 0 failed**, including truncated and reordered replay, orphan roots, receipt/item/rejection tampering, malformed plus valid mixed input, and replay of malformed records. Its fake bridge is failure-control evidence only; actual Engine restart and recovery are covered separately by the focused suite.
- Authentic development sample `SRC-b95e7a4acc3507fee2b1` (`experiments-main/evaluation/lite/20240523_aider/chat-transcripts/sympy__sympy-24909.md`): 119 parser observations, two actual bounded Context Engine batches, two recovered batches, two original member results verified, and fresh-process bridge readback PASS for each batch. Evidence: [AUTHENTIC_BATCH_VALIDATION.json](authentic-batch-validation-004/AUTHENTIC_BATCH_VALIDATION.json).

All observations above are bounded engineering/storage evidence. They do not establish semantic validity, independent evaluation, source authenticity, actor authentication, execution, campaign acceptance, RUN-002 authorization, Formal I7, or Physical C2. The 20,000-record run was a generated controlled-volume check; only the first 1,024 generated observations were bound to the Engine. No model, patch, Docker campaign, or producer dispatch was run.

## Final code hashes

The current frozen snapshot is bound by [AUTHENTIC_BATCH_VALIDATION.json](authentic-batch-validation-004/AUTHENTIC_BATCH_VALIDATION.json): batching module `7dc9b26a92345e61a2afcd9b70af3342d24e5320453e9f86b1cd6e0fa51153ee`, focused test `0ebc24c09e236426992c32a23b84ba57a77b71b4c75d5681e112f03ead27336c`, generalized bridge `e212d84f7b6cbca13f5e3095b3ee3b60a66b28a904e67530f873db8fea52adad`, and Context Engine `1fdbf50fe56e82ec86e96dff3039a0bf5d8cfbddc217d9f2d928b7a62bd62568`. The code was prospective and uncommitted at validation; final local commit/tree are pinned externally in CODE_REFERENCE.json.
