# Experimental publication policy

This policy governs publication packaging for the experimental branch and its historical RUN representations. Owner decision `PGOP1_PUBLIC_EXPERIMENT_BRANCH_AND_RUN004_FINAL_ENGINEERING_001` authorizes normal push `HEAD:refs/heads/experiment` and conditional deletions. Before each deletion, confirm remote identity and HEAD; identify exclusive commits; preserve relevant history; ensure authorized public evidence is recoverable; verify no historical material is lost; check PR/protection impact; publish and freshly verify `experiment`; pass a favorable preservation audit; and reread the same HEAD immediately before deletion. Keep `main`, default, and `experiment`; do not force-push, mirror, or change protections; preserve needed local branches. This policy restates the Owner's exact authorization and adds none. This Purpose/Publication subtask made no push or deletions.

## Publication lifecycle

Track campaign lifecycle using these exact stages, with explicit transition evidence in append-only receipts:

`RUN_PREPARED` → `RUN_FROZEN` → `RUN_EXECUTED` → `RESULTS_VERIFIED` → `ENGINEERING_AUDITED` → `PUBLICATION_PREPARED` → `PUBLICATION_VERIFIED` → `RUN_DOCUMENTARY_CLOSED`.

`RUN_EXECUTION_PARTIAL` and `PUBLICATION_BLOCKED` are allowed states. Partial execution may not skip to a verified result without disposition evidence for every declared unit. A blocked publication may return to preparation only after a new receipt binds the resolved blocker, exact candidate identity, and fresh scope review. No transition is inferred from a directory, test, commit ancestry, or publication package. Historical reconstructions retain `UNKNOWN_HISTORICAL_STAGE` when prior evidence does not bind a lifecycle stage.

Allowed edges are `RUN_PREPARED → RUN_FROZEN`; `RUN_FROZEN → RUN_EXECUTED | RUN_EXECUTION_PARTIAL`; `RUN_EXECUTED | RUN_EXECUTION_PARTIAL → RESULTS_VERIFIED`; `RESULTS_VERIFIED → ENGINEERING_AUDITED`; `ENGINEERING_AUDITED → PUBLICATION_PREPARED | PUBLICATION_BLOCKED`; `PUBLICATION_PREPARED → PUBLICATION_VERIFIED | PUBLICATION_BLOCKED`; `PUBLICATION_BLOCKED → PUBLICATION_PREPARED`; and `PUBLICATION_VERIFIED → RUN_DOCUMENTARY_CLOSED`. Every edge needs a dated receipt with authority and evidence references. The partial-execution edge to `RESULTS_VERIFIED` requires a disposition for every declared unit, including units not run. Returning from `PUBLICATION_BLOCKED` requires a fresh review receipt. No other transition is valid.

Track the separate publication sub-lifecycle as follows:

1. `NOT_PREPARED`: no publication selection has been reviewed.
2. `PREPARATION_BLOCKED`: required provenance, rights, privacy, review, or integrity evidence is missing or failed.
3. `PREPARED_LOCAL`: an exact local artifact set is selected, sanitized, hashed, and linked to the source identities; this does not mean authorized to publish.
4. `AUTHORIZED_FOR_DESTINATION`: explicit authorization identifies the destination and exact candidate identity.
5. `PUBLISHED_UNVERIFIED`: a write completed but fresh remote verification is pending.
6. `VERIFIED_PUBLISHED`: fresh remote reads bind the exact expected commit/tree and selected file bytes.
7. `PUBLICATION_FAILED`: the write failed; retain the receipt and do not claim publication.

Statuses may not be skipped based on a local ref, prepared archive, cached remote-tracking ref, or historical attempt. A new publication attempt gets a new receipt and references the prior receipt. It never rewrites the earlier outcome.

## Required result set and reproducibility class

Every prospective campaign record enumerates all required result artifacts: `CAMPAIGN_SUMMARY.md`, `EXECUTION_RESULTS.json`, `COVERAGE_REPORT.json`, `FAILURES_AND_ABSTENTIONS.json`, `DEFECT_AND_FIX_REPORT.md`, `CODE_REFERENCE.json`, `SOURCE_MANIFEST.json`, `RESULTS_INTEGRITY_MANIFEST.json`, `AUDIT_SUMMARY.md`, `LIMITATIONS.md`, and `PUBLICATION_RECEIPT.json`. If an artifact is not applicable or unavailable, state the reason and exact disposition. Historical reconstructions list each missing artifact as `NOT_PRESENT_IN_HISTORICAL_SCOPE` and do not create backdated results.

Assign exactly one Owner-defined reproducibility class: `PUBLIC_SELF_CONTAINED_REPLAY`, `PUBLIC_CODE_AND_HASH_REFERENCES`, `PRIVATE_SOURCE_DEPENDENCIES`, or `DOCUMENTARY_ONLY`. The class describes only the bound evidence; publication does not strengthen it.

## Selection and privacy

Publish only reviewed first-party code, contracts, documentation, sanitized aggregate results, public manifests, and cryptographic commitments explicitly cleared for release. Exclude original datasets, response corpora, raw logs, private manifests, credentials, personal paths, local host identifiers, and material with unresolved rights or attribution. Do not publish private evidence merely because a hash is present in a registry. A commitment identifies bytes; it is not a rights grant or permission to disclose them.

Review the full reachable history and selected diff for the exact destination candidate. Preserve rejected candidates and negative review records. Reuse an existing candidate only after verifying its recorded commit/tree, selected-file membership, hashes, rights, and privacy review. A separate continuity ZIP is not interchangeable with the reviewed candidate. If checks disagree or are incomplete, publication remains blocked or `UNKNOWN`.

## Remote claim boundary

Remote publication claims require a successful authorized write and subsequent fresh remote observation of the exact commit/tree and expected selected bytes. A locally prepared artifact or commit is not a remote publication. Do not force-push, rewrite published history, or infer a current remote state from a stale local ref. Publication does not imply campaign execution, semantic qualification, formal acceptance, or promotion.

For schema fields and receipt structure see [pgop1.experimental.run-publication.v1](schemas/pgop1.experimental.run-publication.v1.md) and [template](templates/RUN_PUBLICATION_RECEIPT_TEMPLATE.json).
