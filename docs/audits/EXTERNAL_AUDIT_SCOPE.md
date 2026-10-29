# External audit scope

EXTERNAL_SONNET_AUDIT=PENDING. Audit only the publicly accessible GitHub code and documentation. Do not request local checkout access, private source bodies, GOLD, private logs or reserved labels. Read PUBLIC_CANDIDATE_REVIEW.md and use the code identity it pins; identify the actual documentation commit separately.

## Review priorities

A. **Claim extraction:** inspect how adapter parsers identify candidate assertions, exact spans, message IDs and predicates, including quotes, tool output and unsupported formats.

B. **Attribution:** distinguish an actual agent assertion from caller-supplied role/run metadata, quoted material and unauthenticated speaker declarations. Preserve UNKNOWN when the public evidence cannot authenticate a speaker.

C. **Evidence chain:** trace AGENT → MESSAGE → CLAIM → PREDICATE → EVIDENCE → VERDICT. Verify source bytes, run/instance identity, scope/time and predicate-specific evidence. A boolean `resolved` value is not universal proof of success.

D. **Verdicts:** inspect exact SUPPORTED, CONTRADICTED, INSUFFICIENT_EVIDENCE, INTEGRITY_FAILURE and VERIFICATION_ERROR branches in `generalized.audit_evidence`, its parsers and `predicate_evidence`. Look for false support, unjustified contradiction, missed extractions, errors treated as abstentions, and confusion between file-format status and semantic verdict. Report per-claim versus aggregate differences.

E. **Integrity:** inspect hashes, identifiers, cross-instance association, provenance, input validation, duplicate records, path/decompression bounds, completion commitments and recovery. Storage verification must not silently authenticate an evidence producer.

F. **Batch composition:** inspect bounded chunks, original/fragment commitments, cross-boundary spans, complete mapped/rejected ordinals, retries, orphan output, interruption and new-process recovery.

G. **Architecture:** review boundaries between `src/package_g`, experimental runtime, vendored first-party frozen dependencies, adapters and public interfaces. Preserve freezes and import roots.

H. **Differences from main:** use BRANCH_COMPARISON_REPORT.md and the pinned merge-base. A main-only file absent on an older experimental baseline is not automatically an intentional deletion. Identify integration risks without proposing an unreviewed merge or platform migration.

## Finding format

Classify each finding as MATERIAL_DEFECT, SECURITY_RISK, SEMANTIC_RISK, ARCHITECTURAL_RISK, DOCUMENTATION_ISSUE, UNVERIFIED_HYPOTHESIS or RECOMMENDATION.

Each finding must provide file, line or symbol, examined commit, concrete description, verifiable evidence, impact, proposed reproduction and certainty level (CONFIRMED / PROBABLE / HYPOTHESIS with rationale). Separate an observed defect from a test proposal or uncertain concern. Generic unsupported assertions are not findings. Use commit-pinned GitHub links where possible. If tests are not run, say NOT_RUN and do not present predicted failures as observed.

## Authority

External review supplements internal technical audits. It does not replace frozen protocols, physical evidence, I7 operational qualification or independent claim adjudication. Sonnet is not automatically a qualified holdout adjudicator. It cannot lift GATE_11, authorize RUN-002, promote runtime to src or qualify operational I7. Report strengths and unresolved limits alongside defects. Do not claim the audit has happened before its report is received.
