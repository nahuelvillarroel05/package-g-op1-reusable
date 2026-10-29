# Streamed source-fragment adapter V2

Status: V2 implementation and measured SQLite lookup index are frozen after
independent audit and controlled-volume comparison. V1 is retained without deletion in
`historical-reference/fragment-v1-pre-conservation/`; its positive results are
not fully qualified because mapped-input conservation was not proven. Its
single-fragment-only span behavior remains a recorded historical negative.

## V2 behavior

V2 remains an adapter around the existing generalized bridge, bounded batcher,
and Context Engine. It does not modify those components.

- `fragment_source` hashes the complete original through bounded reads, records
  fixed-size binary fragments and exact ranges, and verifies parent bytes/hash
  before bind. Its configuration, exact ranges, and verification record are
  cross-checked on staging and recovery.
- Input rows remain capped at 1 MiB. Normalized observation schema, source path
  and hash, run identity, and typed half-open `BYTE_SPAN` are checked before
  mapping. Caller-supplied `origin_*` and adapter-owned field collisions are
  retained as explicit rejections so they cannot impersonate producer metadata.
- V2 supports a parent byte span across one or more fragments. It deterministically
  derives exact overlapping fragment pieces and stores only their count and
  framed digest per row. The original span is retained. The first fragment's
  `source_ref` is explicitly marked `ROUTING_ANCHOR_ONLY`; this verifies source
  routing and byte coordinates, not semantic text correctness.
- `mapping-rejections.json` schema V2 contains total completion counts, a global
  ordered input digest, per-fragment mapped count/digest, and original rejected
  inputs. It is bound immutably. Each member capsule commits the ledger hash.
  Recovery reconstructs every accepted original JSON row by removing adapter
  fields and restoring the original source reference, verifies its input hash,
  checks all per-fragment digests, and uses a temporary disk-backed SQLite
  table to enforce unique contiguous ordinals across fragments. Rejected batch
  items, missing/reordered/duplicated mapped rows, and completion mismatches
  cannot produce whole PASS.
- Chunk composition uses a 1.25 MiB complete audit chunk budget and preflights
  each final member through the existing batch aggregate fit function. The
  original row cap remains 1 MiB. Any downstream batch rejection is returned
  as PARTIAL and causes recovery to fail closed.
- Observation-ID duplicate detection uses one nonunique SQLite index on
  `(record_kind, record_id, status)`. The existing query and duplicate rejection
  rule are unchanged; the index prevents a growing full-spool scan for each
  input row and is recreated idempotently when reopening a durable spool.
- The source reader applies the Engine's excluded absolute path-component rule
  (`holdout`, `secrets`, `.aws`, case-insensitive) before opening input or
  creating outputs. The absolute path is not disclosed: its normalized hash
  and required `CONTEXT_ENGINE_SOURCE_EXCLUSION_V1` /
  `PASS_BEFORE_ORIGINAL_READ` policy record are cross-bound in manifest and
  verification evidence. Pre-policy roots cannot qualify under V2.

V1 history: exact code/test SHA-256 and pre-V2 authentic result are in
`historical-reference/fragment-v1-pre-conservation/REFERENCE.json`. The
earlier crossing-span rejections remain preserved there; V2's authorized
multi-fragment contract is versioned and separately tested.

## Validation

Focused command on the frozen source:

```text
python -B -m pytest -p no:cacheprovider --basetemp <external-temp> tests/test_swebench_source_fragments.py
```

Result on the current frozen source: **39 passed**. Coverage includes the
duplicate-ID query plan and index persistence on reopen, 900 KiB rows, a valid row at 1 MiB minus
16 bytes, 180 observations, two interleaved fragment ordinals, interrupted
Unicode spool resume with byte-cap enforcement, input-completion tampering,
real-Engine omit/duplicate/reorder faults, reserved producer fields, strict
fixed-size manifest layout, boolean/float member-metadata substitution,
empty-source fragment admission, fresh-process
interruption/recovery, and staging-free recovery.

The historical pre-index authentic bind `authentic-batch-v2-002` is recorded in
AUTHENTIC_FRAGMENT_V2_RESULT.json. Current indexed code was separately bound and
recovered at `authentic-v2-index-matched-final-001`; see
AUTHENTIC_FRAGMENT_MATCHED_FINAL.json. All119 original canonical records were
compared exactly with the prior V1 and V2 SQLite spools. The matched input adds
only the known optional source_ref.bytes=24695 to the original frozen JSONL,
reproducing the prior input variant; no source/span/eligibility changed.

On current source858a4ef4...126dea, all119/119 spans mapped, zero were rejected,
and all7 fragment batches reconstructed the exact24,695-byte parent SHA
0eee978aabb3c5982312e3ada86236b613fbb4621ca6df77102c567faef69426.
The matching ordered original-input digest is
0cca6df71444ece4d26e2fd5aed19bc54954b3d515367025dd93e24cd1fef175.
AUTHENTIC_FRAGMENT_FINAL.json is another valid current-code119-row bind using
the unmodified frozen JSONL, without that optional field; its distinct073049b7...
input digest is not presented as canonical-input-identical to the prior variant.
Both are development structural controls, not independent semantic accuracy.

Sol's final current-hash audit passed: **35 basic**, **15 conservation**,
**9 policy**, **3 immutable-object fault**, **9 typed capsule** checks, and
**39 focused pytest**. Both current-hash 8/32 MiB resource children exited
successfully. Peak working set / private commit were 101,085,184 / 91,607,040
bytes at 8 MiB (2.7837 s) and 101,306,368 / 92,848,128 bytes at 32 MiB
(10.3238 s). These are Windows main-worker process peaks; process-tree and OS
file-cache peaks were not measured.

The same controlled 20,000-row workload was run before and after adding only
the SQLite index. Both runs admitted and recovered 20,000 canonical rows with
zero rejects across 16 source fragments and 320 COMPLETE Engine batches; the
ordered input and per-fragment digests matched. The pre-index baseline took
380.1328 s total (234.2324 s spooling, 95.1387 s bind, 50.6097 s recovery).
The indexed run took 152.2285 s total (2.5814 s spooling, 99.0975 s bind,
50.4004 s recovery), reducing measured total elapsed time by about 60% while
preserving the input digest. Peak working set / private commit for the indexed
20k worker were 112,898,048 / 104,271,872 bytes. The durable output retained
476,154,039 logical bytes across 3,246 files. The pre-index source and test
bytes are preserved under `baseline-20k-pre-index-001/` with verified original
hashes; the complete comparison is in `audit-volume-20000-index-final-001/`.
No independent semantic references or claims were evaluated.

## Limits and identity

Configured bounds: 256 MiB parent, 4,096 fragments, 64 MiB maximum configured
fragment, 4 MiB manifest, 100,000 input records, 1 MiB original record, 256 MiB
spool, and 8 MiB rejection ledger. Fragment objects are read one at a time;
the complete parent is never read into one buffer on this explicit path. Existing
`audit_file` parsers are not changed and may still read full sources. This path
does not establish semantics, authenticated custody, actors, execution,
campaign readiness, or RUN-002 authority.

- `source_fragments.py` SHA-256: `858a4ef462923c176e0087f6314a57cfb98f9dae1c4eaaca54b5ef0da0126dea`
- `test_swebench_source_fragments.py` SHA-256: `7565581ab9f7197f8efce7691150677d91cd2d3e258a7ce362bb855b727ab2f0`
- Checkout base HEAD: `e96dce5297fcfae773d7c33118f7ad885f7c4db5`; V2 source/test were uncommitted at validation; final local commit/tree are in external CODE_REFERENCE.json.
