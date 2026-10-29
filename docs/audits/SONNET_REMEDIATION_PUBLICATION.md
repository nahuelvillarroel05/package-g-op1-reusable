# Sonnet remediation: public engineering summary

Code candidate: `e0115476ed46dde3bd583f67f767c501df7979f3`.
Tree: `418b76fe58e5a3160f3d353b9270b82b288aaa67`.
Branch: `feat/pgop1-sonnet-findings-remediation-001`.
Baseline: `676f2f08a7bb7602bb0bc6e66d845684e1833783`;
documentation parent: `f416c8d99c8a17405ba5dd23450846b7f7c1f857`.
The candidate's original bytes and intermediate commits are retained. This is
prospective documentation, not a rewrite of historical results or approvals.
The Owner authorized normal push on 2026-10-29. Remote publication must be verified
separately; no main merge, freeze change or promotion to src is authorized.

## Findings

17 findings: 12 FIXED_AND_VERIFIED, 4 VALID_CONTRACT_WITH_EXPLICIT_SCOPE,
1 NOT_REPRODUCED. This is a sanitized projection of the original resolution matrix.

| Finding | Subject | Original engineering status |
| --- | --- | --- |
| F-01 | Recovery verdict derivation | FIXED_AND_VERIFIED |
| F-02 | Structured malformed-path rejection | FIXED_AND_VERIFIED |
| F-03 | Explicit bounded extraction and rejected candidates | FIXED_AND_VERIFIED |
| F-04 | Attribution metadata scope | VALID_CONTRACT_WITH_EXPLICIT_SCOPE |
| F-05 | Active contradiction and supersession visibility | FIXED_AND_VERIFIED |
| F-06 | Historical extractor regression | VALID_CONTRACT_WITH_EXPLICIT_SCOPE |
| F-07 | Computed verdict and final infrastructure errors | FIXED_AND_VERIFIED |
| F-08 | BYTE_SPAN content verification | FIXED_AND_VERIFIED |
| F-09 | Canonical source counts | FIXED_AND_VERIFIED |
| F-10 | Capacity mismatch and batching route | VALID_CONTRACT_WITH_EXPLICIT_SCOPE |
| F-11 | True/false detection metric supplement | FIXED_AND_VERIFIED |
| F-12 | Canonical identities and shared verdict comparison | VALID_CONTRACT_WITH_EXPLICIT_SCOPE |
| F-13 | Rejected catalog-row conservation | FIXED_AND_VERIFIED |
| F-14 | Immutable observation content identity | FIXED_AND_VERIFIED |
| F-15 | Dead-owner lock recovery and contention | FIXED_AND_VERIFIED |
| F-16 | Platform-specific test condition | NOT_REPRODUCED |
| F-17 | Evaluator authentication qualifier | FIXED_AND_VERIFIED |

`F16=DEFERRED_LINUX_VALIDATION_PENDING`. Preserve Sonnet's Linux reproduction,
Codex's Windows non-reproduction and Astra's NOT_REPRODUCED_WINDOWS_ONLY.
F-16 is not fixed or removed. The [future Linux stage](SONNET_REMEDIATION_COMPATIBILITY.md#owner-decision-f-16-and-future-linux-compatibility)
is not executed here and may require additional work beyond F-16.

## Original evidence reused for publication

Windows: 312 passes, no failures/errors/skips. Astra: 119 independent cases passed,
no failures/errors/skips; PASS_WITH_NONMATERIAL_LIMITATIONS on the exact candidate.
The previously disclosed same-byte duplicate invocation adds no independent
coverage. Prior blocked reviews and internally rejected intermediate candidates
remain preserved locally; they are not represented as approvals.

ENGINEERING_RUN=COMPLETE. Source files 25,580; processing attempts 3,802;
accepted 2,044; unsupported 1,745; errors 13; execution audits 266;
Context Engine campaign units 4,068; additional strict instance derivations 266.
Original fresh-process recovery executed zero new units and recovered 4,068.
Publication runs no tests, campaigns, SWE-bench, models or training.

All 105 extracted logical claims remain INSUFFICIENT_EVIDENCE; logical SUPPORTED
and CONTRADICTED are zero. Format acceptance is separate from logical support.
The historical claim delta is 351 - 247 nested-response exclusions + 1 new direct
claim = 105, with zero lost historical direct-message claims. The exclusions
predate the Sonnet baseline; they are structural contract dispositions reconstructed
in lineage, not 247 runtime CLAIM_REJECTIONS and not evidence of quality gains.
Unknown unextracted claims are not counted as zero. The 25 inaccessible directories
remain excluded. No independent precision/recall or semantic accuracy is computed.

## Astra limitations retained

Technical independence between agents does not establish independent operational
custody or external holdout adjudication. Original Sonnet Markdown and exact
R01-R15 scripts were unavailable locally; probes were reconstructed from Owner
F-01..F-17 descriptions. H02 TOCTOU and H05 unspecified export concern remain
UNKNOWN; H04/POSIX grants and Linux behavior remain unqualified. English extraction
is bounded; universal recall, multilingual semantics and general accuracy are
unproven. Parsed speaker/evaluator identities are unauthenticated. Review metadata
is not cryptographic reviewer authentication. No claim of I7 qualification follows.
Optional CIM sampling was denied; whole-process-tree peak memory is NOT_MEASURED.

## Receipt identities and public scope

The following hashes were checked against original local receipts during
publication. They identify evidence; hashes alone do not let a public reviewer
independently inspect private receipts. These receipts and the continuity ZIP are
not automatically published. Public review must use committed code, synthetic
tests, contracts and this limited summary, and state unavailable evidence.

| Original local receipt (relative logical name) | SHA-256 |
| --- | --- |
| `SONNET_FINDINGS_RESOLUTION_MATRIX.json` | `5233de4e5d73417d0cdd98939a0ea317b0037020f532531c24234839d31fb87f` |
| `candidate4-verification-junit-001.xml` | `8deb1af5c72173cc6f3b89cf2dfd0d6e3ed4e5db05e0105069628493ce9b48b1` |
| `astra-review/ASTRA_INDEPENDENT_FINDINGS_AUDIT.md` | `c57d546410eb8f9e1944a4ec46b64521f38babaabc52b5a52a2527a096644b2e` |
| `astra-review/ASTRA_ADVERSARIAL_TEST_RESULTS.json` | `1c268c701548926e41f72e82608a3d1ab5fece0417844b78ac93f307199a27e4` |
| `astra-review/ASTRA_POST_CAMPAIGN_CLAIM_DELTA_REVIEW.md` | `eeff82bede76615bcc0bc9076a39d0aa54854d329bdde0b685d18762fec2b3d4` |
| `full-engineering-run/RESULTS_SUMMARY.json` | `6cff8bfad5beae7bf0acc591c4ea8fec27bdf68afee444a8ae596b1a18459a4c` |
| `full-engineering-run/INTEGRITY_VERIFICATION.json` | `b5806dcf43b38a5645f976a5e695ffdf669969f88f459c6fda9a29ba7c3fec7e` |
| `full-engineering-run/FRESH_PROCESS_RECOVERY.json` | `2bfead3525955c7676659dca84e1ee37281fb9d8d5b6799b46d16d97ed491320` |

The 2,066,438,492 bytes / 28,972 indexed local output files, original trajectories,
private conversations, internal Codex records, source datasets and continuity ZIP
remain local. Source-only publication retains Apache-2.0 LICENSE, NOTICE and
dependency-license scope; no third-party distributions or new dependencies are
bundled by the remediation.

## Boundaries and next intervention

I0-I6=FORMALLY_FROZEN; I7=INCOMPLETE; FORMAL_I7=NOT_COMPLETED;
OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED; INDEPENDENT_CUSTODY=NOT_PROVEN;
PHYSICAL_C2=DEFERRED_NOT_WAIVED; GATE_11=BLOCKED; RUN_002=NOT_READY.
INDEPENDENT_SEMANTIC_HOLDOUT_NOT_AVAILABLE. No historical campaign result changes.

Next: [public-only Sonnet review](SONNET_PUBLIC_AUDIT_HANDOFF.md) of F-01..F-15,
F-17, material regressions, associations/verdicts and excluded-claim accounting.
NEW_SONNET_REVIEW=PENDING. No new Sonnet approval is claimed. Independent reference
qualification remains a separate requirement before any formal RUN-002 authority.
