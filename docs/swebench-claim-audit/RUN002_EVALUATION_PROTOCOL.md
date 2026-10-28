# RUN-002 independent semantic evaluation protocol v1.1
Frozen before any new public trajectory download or inspection. Existing twelve V1 cases, 49 RUN-001 cases, three Aider transcripts and all RUN-001 families are DEVELOPMENT only. Synthetic tests are never independent accuracy evidence.

Eligibility: new source-family provenance; immutable original transcript with explicit role records, message IDs and hashes; independently produced concrete-predicate evidence with execution/run/instance/scope/time identities. Public role labels remain SOURCE_DECLARED, not cryptographic agent authentication. Preserve UNKNOWN where binding is unavailable.

Selection: source-family-level split before content inspection. No alternate versions of a problem, agent or trajectory across development and evaluation. Metadata-only eligibility review may enumerate family/ID/hash/size without reading heldout message bodies or labels. Reserve eligible new families exclusively for RUN-002. Download no bulk dataset. If independent labels or lineage are absent, record INDEPENDENT_SEMANTIC_HOLDOUT_NOT_AVAILABLE and readiness NOT_READY.

Reference labels: concrete predicate, polarity, message span, run, instance, scope, timestamp, evidence commitment and rationale. Two independent adjudicators blind to candidate output; unresolved disagreement UNKNOWN, excluded from decided denominators and explicitly counted. resolved=true labels ISSUE_RESOLVED only when its evaluator contract and exact identity authorize that interpretation, never TASK_COMPLETED or TESTS_PASSED.

Development may tune extraction. Heldout bodies, predictions and labels MUST NOT be inspected during preparation. Freeze candidate commit/tree and source manifest before RUN-002. No heldout evaluation during this goal.

Metrics: TP=SUPPORTED on positive reference; FP=SUPPORTED on negative reference; TN=CONTRADICTED on negative reference; FN=CONTRADICTED on positive reference. Abstentions separately include INSUFFICIENT_EVIDENCE; integrity/errors reported separately. Also report missing extractions, positive/negative abstentions, coverage, and all excluded rows. Precision=TP/(TP+FP), recall=TP/(TP+FN+positive abstentions+missed positive reference claims+positive technical failures), decided accuracy=(TP+TN)/(TP+TN+FP+FN). Empty denominators NOT_COMPUTABLE; no zero error claim with zero independent references.

All campaign metrics NOT_MEASURED until authorized RUN-002. Current preparation does not execute it. Protocol changes create a new version and preserve this freeze.

Version 1.1 clarification before any heldout access: preserve INTEGRITY_FAILURE and VERIFICATION_ERROR as separate technical failure counts; positive reference failures enter the recall denominator. Missing/failed execution must not inflate recall. The original v1 text/freeze is retained. This change was prompted by engineering contract review, with no heldout bodies or labels acquired.
