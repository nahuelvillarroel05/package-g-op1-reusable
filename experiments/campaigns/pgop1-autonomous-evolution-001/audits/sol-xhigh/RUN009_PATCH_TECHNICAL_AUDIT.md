Public source-free rendering; private workspace root replaced with PRIVATE_CONTINUITY. Original private report SHA256: cd6630caee1b09d566cd2d35976732a9b8139f4bdaf313526d0a8fcf9a7fea25

# RUN009 independent prospective patch audit

Reviewer: Sol XHigh. Scope: F03 repair and fresh RUN009 integration before commit, clone, freeze, or execution. This audit used code, contract, registry metadata, and authored synthetic test evidence only. It did not read authentic benchmark source bodies, launch a campaign attempt, invoke a model, run the documentary verifier, or modify candidate code.

## Decision

No material blocker found in the reviewed RUN009 patch for a fresh, clean, hash-bound candidate freeze. This is prospective acceptance of the narrow F03 correction, not evidence that RUN009 has processed any definition. RUN008 remains a stopped, immutable preflight attempt.

## F03 correction

`Engineering/Active_Candidate/repo/runtime/candidate/run_framework/read_scope.py:78-87,121-143` now classifies integer `open` targets with `os.fstat`. It permits only FIFO/pipe or socket descriptors needed for trusted process IPC, and rejects regular, unresolved, or other integer descriptors. Named path reads still follow the exact protected-root/allowlisted-source and reparse checks at lines 138-157. This directly addresses the RUN008 reproducer: CPython opens integer read FDs while `core._git_read` captures Git output. The exception is limited to descriptor class, not to any extra named benchmark path; the guard remains process-local and is not an OS sandbox.

`test_exact_read_scope.py` includes an authored protected-root Git `--version` capture after guard installation, an authored regular integer-file-descriptor denial, and the existing sibling-path/read-write/reparse tests. `Temp/pytest/CAMPAIGN001_RUN009_REGRESSION_001/RESULT.json` records exit 0 and `pytest-output.log` records 36 passed in 10.38 seconds. These tests establish the reported synthetic regression result; they are not a real RUN009 preflight or source-processing result.

## New run identity and boundaries

`definition_e1.py:19-46,126-145` accepts the fresh RUN009 identity with exact `PGOP1-RUN009-E1` campaign ID, retains the four-unit 2+2 MCPMark/Terminal DEFINITION_ONLY gate, and derives the producer and Engine event kind from the bound run ID. The candidate preserves RUN008 compatibility in this shared module, but the frozen RUN008 clone is unchanged: its HEAD remains `96b210ff0473fd91270d5a68a55d7f6ea0cfb775`, with a clean tracked tree, and its read-scope file hash differs from the active repaired file. No RUN008 attempt can be recast as RUN009 evidence.

`prepare_run009.py` uses a new operational directory, candidate clone, attempt ID, normative contract, driver, launch authorization, and freeze. It deterministically selects the same four originally permitted primary definitions, rehashes all four RUN004 rights-map inputs and eight verified license documents, and binds only the four primary source path/hash pairs plus first-party metadata. The synthetic denial wrapper remains in a separate protected control root; no original unselected source is a probe. The RUN009 contract retains two sequential batches of two, one-unit checkpoints, zero authentic agent outputs, and no task execution, semantic audit, or output-score claim. These source and freeze checks must be observed again in the actual prepared operational package; this review did not run preparation or read source bodies.

`tools/execute_definition009.py` fixes the RUN009 operational path and records an exclusive result. `supervise.py:61` now reports `cooperative_runner_limit_seconds` from the frozen framework config, rather than its former hardcoded 1800. `integrity/SUPERVISOR_FIELD_CORRECTION.json` identifies the RUN008 receipt's old display value, actual 300-second cooperative limit, and unchanged 420-second supervisor limit without rewriting the historical receipt.

The active canonical `experiments/RUN_REGISTRY.json` labels RUN007 and RUN008 as late observed-result reconciliations and RUN009 as a prospective reservation. `integrity/CENTRAL_RUN_REGISTRATION_TIMING.json` preserves the timing distinction and original registry hash. This is registration evidence, not retroactive launch authority or semantic qualification.

## Acceptance boundary

Commit only the reviewed prospective patch and contract, then prepare RUN009 against a fresh clean candidate with exact code/config/source hashes and the unchanged original campaign deadline. The final operational bindings, read-scope behavior, unit receipts/checkpoints, Engine own-results, two batch closures, and fresh-process recovery require independent review after execution. The preflight repair is supported by synthetic tests; successful authentic composition is still UNKNOWN until RUN009 evidence exists.
