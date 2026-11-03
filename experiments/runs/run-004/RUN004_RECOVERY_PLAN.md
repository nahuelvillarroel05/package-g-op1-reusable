# Recovery plan — prospective rev003

DRAFT_NOT_APPROVED. Original source and failed attempts remain immutable. Before authorized execution bind code/tree, contract/configuration, input/output/reference/evaluator hashes, shard membership/counts, parent receipt and namespace owner. Each checkpoint needs a complete immutable receipt and next safe operation. A terminal or consumed identity is never resumed.

Read recovery in a fresh process revalidates all bindings and exact selected membership. Engine retrieval verifies bytes and associations, not producer authenticity. A missing/corrupt original, mismatched count/hash/revision, incomplete checkpoint or ambiguous ownership => BLOCK and preserve failure. Never silently restart/re-ingest/redispatch. A new attempt requires fresh identity and applicable authority.

Stress controls use disposable copies: altered hash, missing object, incomplete ledger, corrupt index, duplicate/wrong task revision, truncated payload and interrupted write. Recovery must reject each invalid copy and recover unchanged valid copies; original stores are not mutated. This intervention samples two existing shards/1127 descriptors in fresh subprocesses; full796805 recovery is not repeated. See CONTEXT_ENGINE_RECOVERY.json for actual receipts.

To recover this delivery verify ZIP SHA256, CRC, safe membership, FINAL_INTEGRITY_MANIFEST and fresh extraction hashes. Restore only authored plans/code and indexes into a new review location; original datasets/stores/evaluator sources remain at hash-bound external locators. Missing sources require acquisition/authority review, never an automatic producer run. No RUN004 authorization is conveyed by archive restoration.
