# Prospective Sonnet findings remediation

This engineering branch descends from documentation commit `f416c8d` and preserves
the executable baseline `676f2f08a7bb7602bb0bc6e66d845684e1833783`. Findings are
reconstructed from the Owner's F-01 through F-17 descriptions: the original Sonnet
Markdown and its exact R01-R15 inputs were unavailable in the bounded local search.
No claimed test result substitutes for those missing original reproductions.

The external workspace contains baseline reproduction and prospective resolution
matrices, actual JUnit results, evidence hashes and independent review receipts.
Unfinished findings remain unfinished until tested and reviewed. Original RUN-001,
src, native custody, I0-I6 freezes, protocols v1/v1.1 and private GOLD are preserved.

## Claims, identity and evidence

Extraction observations now own an immutable JSON copy of the extracted value;
the separately returned claim audit record can receive a logical verdict and a
final infrastructure error without mutating that observation. Prospective claim
and observation IDs include the source SHA-256. IDs therefore differ from earlier
candidate IDs; original archived records are not regenerated. `match_span` retains
message-relative character indices, while `byte_span` explicitly denotes
`MESSAGE_RELATIVE_UTF8_BYTES`; neither is a file-relative source byte span.
Rejected candidates and incompatible attribution metadata remain visible with
specific reasons. No declared speaker/evaluator is authenticated by parsing.
Current file/audit/observation/claim outputs identify the additive normalization
contract as `pgop1.swebench.source-bound-normalization.v2`. MiniSwe and catalog
parser versions are now `1.1.0`; their parser IDs still name the same source format.
Other unchanged source-format parsers retain their versions while emitting the
explicit normalization version. The v1 audit-verdict enum meaning is unchanged.
In this prospective normalization contract, missing/unreadable sources or an
unavailable root yield `VERIFICATION_ERROR` with specific `FINAL_ERROR_CODES`.
They are distinct from semantic `INSUFFICIENT_EVIDENCE` with no infrastructure
error. Already computed claim comparisons remain in `COMPUTED_VERDICT`.

The predicate boundary also applies to negative claims and qualifiers:
`unfinished`, `incomplete` and negated completion actions belong to
`TASK_COMPLETED=false`; `unresolved` and negated resolution actions belong to
`TASK_RESOLVED=false`. A `resolved` evaluator boolean supplies no completion
contract, for either polarity. Corrections and uncertainty about one predicate
cannot suppress another. Whole-task object boundaries exclude `task queue`
actions from target-task resolution. Shared predicate fragments retain the same
subject, action, state and modifier grammar across extraction and scope guards.

Known conditional operators `if`, `unless` and `assuming` retain their scope
across coordination, including inline and claim-clause suffix forms. Independent
unquoted sentence/semicolon boundaries end that scope. Recognized quoted content
does not introduce conditional operators or question punctuation. Report/denial
prefix scope resets at an independent semicolon or contrastive `but`, with original
offsets computed against an immutable scan base. These remain bounded English
rules, not general natural-language understanding or an accuracy guarantee.

Bridge v2 receipts distinguish `BYTE_INTEGRITY_VERIFIED` from derivation. Marked
instance audits are rederived from exact Engine-admitted bytes and compared with
the full normalized result, including claim outcomes and relationships. A mismatch
fails. Historical unmarked v1 inputs and storage aggregates remain explicitly
`DERIVATION_NOT_VERIFIED` and `SEMANTIC_VALIDATION_NOT_PROVEN`; their byte-integrity
PASS is not a retrospective semantic approval.

BYTE_SPAN maps verify exact text only with a versioned explicit
`source_text_assertion` contract. Unrelated semantic values are not assumed to be
literal source text and remain `CONTENT_NOT_VERIFIED`. A declared exact span/text
mismatch rejects with `BYTE_SPAN_CONTENT_MISMATCH`, including during recovery from
Engine-stored fragments. Existing range-only mappings retain their historical
meaning, with an explicit content-verification qualifier.

The writer lock file now remains in place under an OS-held exclusive lock. Process
termination releases that exclusion; legacy PID ownership is checked before
takeover. Ambiguous ownership fails closed. The campaign also blocks unfinished
STARTs and orphan result bytes rather than automatically restarting their units.

## Evaluation supplement

`evaluate_reference_cases` retains frozen v1 behavior and exact timestamp spelling.
`evaluate_reference_cases_v2` is an opt-in engineering supplement. It requires
`span_unit=UTF8_BYTES_SOURCE_RELATIVE`, validates every original identity field,
canonicalizes timezone-aware timestamps to UTC instants, and returns the original
and canonical reference timestamps separately. It never rounds or tolerates a
timestamp difference and does not normalize hashes, runs, instances or offsets.
Character-index message spans cannot be passed as source-relative byte spans.

The supplement reports extraction, true-claim detection, false-claim detection,
decision coverage and correct-decision coverage with explicit numerators and
denominators. False abstentions, negative misses and infrastructure errors do not
count as detected falsehoods. UNKNOWN adjudication is excluded from computable
metrics, and absent independent labels remain NOT_COMPUTABLE. Synthetic reference
tests are development tests; they establish no general semantic accuracy.

`compare_boolean_values` owns the shared strict boolean comparison used by the
predicate verifier and generalized adapter. Its result conveys logical agreement,
not evaluator authentication or independently adjudicated correctness.

## Engineering campaign

The prospective campaign ID is
`PGOP1_POST_SONNET_REMEDIATION_FULL_ENGINEERING_RUN_001`. The old RUN-001 ID remains
supported for historical callers. Formal RUN-002 is not accepted by this driver.
The post-Sonnet driver requires an independent Astra decision for the exact clean
Git commit and records the audit's SHA-256. Review metadata is an execution guard,
not cryptographic reviewer authentication or independent operational custody.

The preparation step reuses both RUN-001 main and supplemental plans (2,901 + 901
unique sources), checks the frozen 25,580-file listing commitment and rehashes the
3,802 pertinent source commitments. It explicitly upgrades the 300 Aider parser
assignments prospectively; Aider remains unattributed and emits no agent claims.
The first main-plan-only preflight is retained as an underscoped preparation
attempt; V2 includes the supplemental sources. No full campaign begins before
Astra review. A sequential worker, 70 GB disk reserve, 4 GB available-memory
preflight, immutable checkpoints and recovery constrain resource use.

`GATE_11=BLOCKED`, `RUN_002=NOT_READY`, and
`INDEPENDENT_SEMANTIC_HOLDOUT_NOT_AVAILABLE` remain in force. No push, model,
training, Docker, fresh Level C or Ubuntu workstation operation is authorized here.

## Owner decision: F-16 and future Linux compatibility

`F16=DEFERRED_LINUX_VALIDATION_PENDING` (2026-10-29).
Sonnet reproduced a platform problem on Linux. The latest Codex engineering did
not reproduce it on Windows; Astra classified it NOT_REPRODUCED_WINDOWS_ONLY.
The original NOT_REPRODUCED matrix classification remains unchanged, and is not
FIXED_AND_VERIFIED. Windows non-reproduction does not prove the Linux defect gone.

The final Linux compatibility stage must prepare a reproducible Linux environment,
rerun portable suites, reproduce F-16, correct platform differences, review Windows
runtime dependencies, check paths/locks/file identities, run cross-platform
regressions and request a new technical audit. F-16 is not necessarily the only
Linux qualification requirement. This stage is deferred and is not executed or
authorized by this publication. POSIX grants/locks remain unqualified.

The earlier no-push statement above describes the campaign document's original
scope. The Owner separately authorized the normal experimental-branch publication;
models/training, new campaigns, main merge and src promotion remain outside scope.
See [publication summary](SONNET_REMEDIATION_PUBLICATION.md).
