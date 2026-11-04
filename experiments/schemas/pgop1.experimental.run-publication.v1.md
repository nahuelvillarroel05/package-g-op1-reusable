# `pgop1.experimental.run-publication.v1`

Versioned publication record contract for a RUN public representation. The JSON template is intentionally invalid until placeholders are replaced and `template_only` is set to `false`; it is not itself a receipt. Consumers reject unknown lifecycle values and preserve explicit `UNKNOWN`/`NOT_APPLICABLE` values.

## Required fields

- `schema`: exactly `pgop1.experimental.run-publication.v1`.
- `RUN_ID`: globally unique registered RUN identifier.
- `record_kind`: `HISTORICAL_RECONSTRUCTION` or `PROSPECTIVE_CAMPAIGN`.
- Owner-required canonical fields, spelled exactly: `RUN_ID`, `RUN_CONTRACT_VERSION`, `EXECUTED_CODE_COMMIT`, `EXECUTED_CODE_TREE`, `SOURCE_MANIFEST_SHA256`, `RESULTS_MANIFEST_SHA256`, `EXECUTION_STATUS`, `AUDIT_STATUS`, `PUBLICATION_COMMIT`, `PUBLICATION_BRANCH`, `PUBLIC_FILES`, `WITHHELD_FILES`, `REDISTRIBUTION_STATUS`, and `REMOTE_VERIFICATION_STATUS`.
- `CAMPAIGN_LIFECYCLE_STATUS` and ordered `CAMPAIGN_LIFECYCLE_HISTORY`, with the stages in `PUBLICATION_POLICY.md`. A historical record with no source evidence of lifecycle state uses `UNKNOWN_HISTORICAL_STAGE` and an empty history.
- `REPRODUCIBILITY_CLASS`: exactly `PUBLIC_SELF_CONTAINED_REPLAY`, `PUBLIC_CODE_AND_HASH_REFERENCES`, `PRIVATE_SOURCE_DEPENDENCIES`, or `DOCUMENTARY_ONLY`. Add `HISTORICAL_REPRODUCIBILITY_CLASS=UNKNOWN` when the prior campaign's class is unbound.
- `REQUIRED_RESULT_SET`: a disposition for every required artifact named in `RUNS_PURPOSE.md`.
- `EXECUTED_CODE_COMMIT` / `EXECUTED_CODE_TREE`: executed code identity or an explicit unknown/not-executed disposition; never substitute a prospective correction or publication commit.
- `PUBLICATION_COMMIT`: exact publication candidate or an explicit unknown/not-published disposition. Its presence alone never asserts a successful publication. Historical result/release identity remains in the immutable historical reference and the registry.
- `publication`: lifecycle status, destination, selected artifact manifest, preparation/review evidence, authorization, write receipt, and verification receipt.
- `scope`: included/excluded classes and evidence limitations.
- `EXECUTION_STATUS`, `AUDIT_STATUS`, and `REMOTE_VERIFICATION_STATUS`: separate evidence dispositions, never inferred from one another.
- `lineage`: prior receipt ID/hash where applicable; no mutation of historical receipt content.

## Invariants

`PREPARED_LOCAL` means only locally assembled and checked. `AUTHORIZED_FOR_DESTINATION` must name the approving authority, destination, exact candidate commit/tree, and scope. `PUBLISHED_UNVERIFIED` requires a successful write receipt. `VERIFIED_PUBLISHED` requires a fresh remote verification receipt with expected commit/tree and selected-file membership/hash checks. Missing values stay unknown; they must not be derived from folder names or branch ancestry.

Each public file manifest row includes a stable artifact ID, repository-relative path or `EXTERNAL_COMMITMENT`, SHA-256, byte length, rights/authorization state, privacy review state, and inclusion decision. `WITHHELD_FILES` describes exclusions without exposing private source paths. Personal absolute paths and private source names are prohibited from public records. Private commitments may be represented by opaque IDs and digests only when explicitly authorized.

`REQUIRED_RESULT_SET` contains exactly one entry for each of the eleven required filenames, with `PRESENT`, `NOT_PRESENT_IN_HISTORICAL_SCOPE`, `NOT_APPLICABLE_WITH_REASON`, or `UNKNOWN`. Prospective documentary closure requires a reasoned disposition for each; the registry's campaign lifecycle state and the publication sub-lifecycle state are separate. The JSON Schema covers field/type/enumeration constraints. A transition is valid only when it appears in the explicit lifecycle transition policy; schema validation alone does not authorize transitions.

Historical records may link to earlier evidence and record present-day packaging checks, but must not claim that the new schema or review existed at execution time. New packaging never changes historical outcomes.

## Reusable semantic validation

JSON Schema and semantic validation are both mandatory at receipt gates. After JSON Schema validation, run `python tools/validate_run_publication.py RECEIPT --repository-root .`. The semantic validator checks exact required-result membership, explicit identity/unknown grammar, normalized public paths, manifest byte hashes, ordered allowed transitions and consistency between publication claims and their receipts. `PUBLIC_FILES` contains selected `included=true` files only. A `PRESENT` required result must match its public-file entry. Lifecycle history starts at `RUN_PREPARED`; an incomplete historical reconstruction retains its unknown stage instead. The tool reads only explicitly selected public files, rejects link traversal, and never reads withheld source bodies.

`RUN_EXECUTION_PARTIAL` to `RESULTS_VERIFIED` additionally requires `disposition_review` on the transition: `status=PASS`, positive integer `selected_units`, equal integer `disposed_units`, lowercase `manifest_sha256`, and nonempty `review_reference`. This checks the consistency of an explicit review attestation. It does not read the private disposition manifest or independently establish complete unit coverage; that evidence remains required at the separate audit gate. No full private manifest is duplicated into a publication receipt.

An authorized publication record uses `publication.authorization` with `status=GRANTED` and a nonempty `authority_reference`, exact `candidate_commit`/`candidate_tree`, and `destination=experiment`. A successful write receipt is an object with `status=SUCCESS`, `commit`, and `branch`. A fresh remote verification receipt is an object with `status=PASS`, `observed_utc`, `commit`, `tree`, `branch`, and `files`; each selected-file row carries `path`, `sha256`, and `bytes`. These must agree with the canonical identities and public manifest. The validator checks consistency of recorded evidence; it does not itself contact GitHub, authenticate the authority, or prove that the recorded observation actually occurred. Independent verification remains mandatory.
