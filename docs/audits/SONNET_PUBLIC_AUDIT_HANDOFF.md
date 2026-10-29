# Sonnet public remediation audit handoff

NEW_SONNET_REVIEW=PENDING. No approval of the corrected candidate has been received
or inferred. This prepares the next review; it does not send a review request.

Repository: https://github.com/nahuelvillarroel05/package-g-op1-reusable

Corrected code candidate: [e0115476ed46dde3bd583f67f767c501df7979f3](https://github.com/nahuelvillarroel05/package-g-op1-reusable/commit/e0115476ed46dde3bd583f67f767c501df7979f3);
tree `418b76fe58e5a3160f3d353b9270b82b288aaa67`. Compare against
`676f2f08a7bb7602bb0bc6e66d845684e1833783`. The accompanying documentation is a
prospective descendant on `feat/pgop1-sonnet-findings-remediation-001`.
The earlier handoff at `f416c8d` remains historical baseline context.

Use public GitHub exclusively. Review F-01..F-15 and F-17, material regressions,
integrity of associations and verdicts, and exact treatment of excluded claims.
F-16 remains F16=DEFERRED_LINUX_VALIDATION_PENDING. Sonnet's Linux reproduction
and Astra's NOT_REPRODUCED_WINDOWS_ONLY both stand; Windows cannot close Linux.
Do not classify F-16 as fixed. Linux compatibility requires a separate later stage.

Start with [public findings/evidence summary](SONNET_REMEDIATION_PUBLICATION.md),
[compatibility and platform limits](SONNET_REMEDIATION_COMPATIBILITY.md),
[external scope](EXTERNAL_AUDIT_SCOPE.md), CURRENT_STATE.md and
docs/engineering/NEXT_STEP.md. Older PUBLIC_CANDIDATE_REVIEW.md,
CANDIDATE_TECHNICAL_EVIDENCE.json and BRANCH_COMPARISON_REPORT.md are explicitly
baseline documents; their 216-test figures do not replace corrected-candidate
receipts. New historical receipts report Windows 312 passes and Astra 119 passes
with PASS_WITH_NONMATERIAL_LIMITATIONS; publication did not rerun those tests.

Inspect runtime/candidate/context_engine.py and
runtime/candidate/swebench_claim_audit/{adapter,generalized,generalized_bridge,
predicate_evidence,swebench_batching,source_fragments,campaign,bind_campaign}.py,
the additive tests/test_sonnet_*.py and tools/claim-audit/post_sonnet_engineering.py.
Review synthetic tests from public code and state any tests actually run.
Do not request private sources, trajectories, local access, internal Codex logs,
datasets or the continuity ZIP. Hashes do not expose unavailable private evidence.

Check claim accounting explicitly: 351 - 247 pre-existing nested attribution
exclusions + 1 new direct claim = 105. The 247 are structural lineage dispositions,
not runtime CLAIM_REJECTIONS or proven false claims; no accuracy improvement follows.
Inspect predicate boundaries, corrections, explicit scope, immutable observations,
source-bound derivation, errors versus computed verdicts and evaluator authentication.

Report MATERIAL_DEFECT, SECURITY_RISK, SEMANTIC_RISK, ARCHITECTURAL_RISK,
DOCUMENTATION_ISSUE, UNVERIFIED_HYPOTHESIS or RECOMMENDATION as appropriate.
For each finding provide examined commit, file, line/symbol, description, evidence,
impact, reproduction, certainty and tests actually run. Separate observed defects
from hypotheses and identify unavailable evidence rather than inferring a PASS.

Known limits remain: bounded English extraction, unauthenticated declared roles
and evaluators, no independent semantic holdout, H02/H05 UNKNOWN, Linux/POSIX
unqualified, I7 incomplete, independent custody unproven. GATE_11=BLOCKED and
RUN_002=NOT_READY. Review cannot lift gates or grant operational qualification,
holdout-adjudicator authority, src promotion or campaign execution authority.
