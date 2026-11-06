# PGOP1 experimental policy - version 2

Authority: Owner decision `PGOP1_ENGINEERING_MODES_AND_RUN004_E1_001`. This prospective policy adopts [E1/E2/F engineering modes](ENGINEERING_MODES.md). The current Owner instruction authorizes RUN004 E1 bounded execution and progressive continuation within its permitted operations, resources, and stop conditions. Earlier preparation-only restrictions remain historical within their original scope; they do not override this authorization. Historical contracts, including RUN004 rev004, are not edited or retroactively approved.

## Proportionate entry requirements

Every RUN declares its mode and purpose. Use [RUN_TEMPLATE.md](RUN_TEMPLATE.md) for a compact new contract. E1 needs identified code, selection, executable procedure, allowed operations, resources, verifiable recording, applicable persistence/recovery, stop conditions, and evidence preservation. It does not need an F document package, universal semantic qualification, complete official evaluators, or GATE_11. The legacy [RUN_CONTRACT_TEMPLATE.md](RUN_CONTRACT_TEMPLATE.md) remains available for its original contract context; its universal approval/freeze wording does not impose F entry requirements on future E1.

E2 freezes the criteria and evidence needed for a specific guarantee. F retains all applicable formal requirements. Neither mode names nor passing tests grant execution authority. Bind applicable Owner authorization to the actual operation. Changes inside that authorization use prospective versions; obtain additional authority only when the operation exceeds its scope.

## Identity, freeze, and states

Reserve unique RUN identities in [RUN_REGISTRY.json](RUN_REGISTRY.json), considering aliases and historical publications. Each attempt has a fresh unique identity, including an explicitly Owner-named attempt; never reuse a consumed namespace. A RUN may have many attempts, including failed, stopped, and incomplete ones. Pilots, synthetic campaigns, and preparation interventions retain separate identities.

Before the first result, write a verifiable operational freeze binding exact code commit/tree and relevant bytes, versioned contract/hash, selection/manifest, authorized sources and operations, configuration/hash, resource budget, stops, and attempt identity. E1 operational freeze is not a formal certification. Preserve the original contract and freeze; write terminal receipts separately. Code/input/configuration changes require a new prospective revision and identifiable attempt; do not mutate an active frozen attempt.

Report preparation, authorization, operational freeze, execution, terminal state, recovery, audit, and publication separately. A start failure is `NOT_STARTED`, not inferred execution. RUN004 uses `NOT_EXECUTED` if no authentic unit operation runs; `PARTIAL_EXECUTED` after authentic execution with incomplete population; and `COMPLETED_WITH_EXACT_DISPOSITIONS` only when the campaign's permitted operations are complete with exact limitations. Do not claim completion just because all units have metadata dispositions. Record ordinary failures and continue safe authorized units; isolate material integrity/security failures.

## Operations, rights, and safety

Assess rights for each actual operation: `PROCESSING_PERMITTED`, `PROCESSING_RESTRICTED`, or `RIGHTS_UNRESOLVED`; independently record `REDISTRIBUTION_PERMITTED`, `REDISTRIBUTION_RESTRICTED`, or `REDISTRIBUTION_UNKNOWN`. Unresolved rights are not read permission. Retain restricted/unresolved units in the inventory with no-body dispositions. Do not let one source's uncertainty block unrelated permitted work. Preserve protected reserves without consuming them.

Reuse the existing framework, generic caller, Context Engine, experimental I4-NEXT/I5-NEXT, Checkpoint V2, adapters, manifests, resource controls, and PGOP1 Attest where applicable. No new engine or repeated full synthetic qualification is needed for E1. Callbacks must be controlled or effectively supervised. Do not execute untrusted benchmark code without sufficient isolation. Record unsafe operations as `NOT_ATTEMPTED_UNSAFE_EXECUTION`; do not require Docker/Harbor/WSL universally for modality A.

Stop/isolate on integrity loss, incompatible provenance preventing admission, unauthorized/unsafe execution, exhausted budget, inability to preserve evidence, or historical corruption risk. Ordinary audit errors are results. For RUN004 retain the shared 20 GiB output ceiling and the Owner's prohibitions on workstation use, paid APIs/infrastructure, permission changes, sandbox bypass, reserved evidence, and production signing.

## Recovery, defects, and metrics

Use persistent results and Checkpoint V2 where applicable. Verify journal integrity, result hashes, completed/pending/interrupted unit membership, completeness, and duplicate absence. Read recovery never redispatches. Block ambiguous/corrupt recovery and preserve bytes; do not silently restart or overwrite completed units.

Record reproducible defects with original RUN/attempt, exact inputs/hashes, observed result, component, and correction revision. Preserve failed reproducers and UNKNOWN causes. Corrections use a fresh attempt and focused verification. Compare only compatible populations/configurations or report differences. Keep task definitions, model responses, agent trajectories, official evaluations, PGOP1 audits, and processing dispositions distinct. Inventory, attempted, processed, semantically audited, sufficient-evidence, and not-attempted denominators are separate.

Measure errors, abstentions, verdicts, applicability, interruptions, recovery, storage, duration, and defects. Record informative `EXPERIMENTAL_EFFICIENCY`; never turn it into an entry gate. Sol XHigh and Astra review actual evidence and faithful reporting after execution; they need not require perfect PGOP1 behavior before E1 begins.

## Preservation and publication

Use `experiments/runs/run-NNN/` for contract, attempts, results, evidence, audits, and publication, adapting existing directories without duplicating history. Code remains in `runtime/candidate/`; preserve `src/package_g/`, main, historical reports, sources, failed attempts, receipts, absolute private evidence paths, and hashes. Avoid corpus/store duplication. Indexes are derived and never override original contracts or Owner decisions.

The authorized public branch is `experiment`; no force push, main change, merge, or promotion is granted by this policy. Publish only permitted code, contracts, safe results/aggregates, audit conclusions, and integrity commitments. Inspect selected artifacts and reachable history for rights/privacy. Withhold credentials, private responses, personal paths, restricted originals, and material with unresolved redistribution rights. Do not copy credentials into isolated identities. If authentication is unavailable, preserve local commits and an exact Owner publication instruction. Claim remote publication only after fresh verification of commit/tree and selected bytes.

[PUBLICATION_POLICY.md](PUBLICATION_POLICY.md) and its [receipt contract](schemas/pgop1.experimental.run-publication.v1.md) govern publication records and documentary closure. Their document set may reference equivalent evidence or give reasoned applicability dispositions; it is not an E1 execution-entry checklist. Publication state, result validity, formal qualification, and promotion remain distinct. This policy does not authorize branch deletions or relax any separately applicable deletion controls.

I0-I6/I7, GATE_11, independent evidence/custody, and Physical C2 retain the explicit states in ENGINEERING_MODES.md. E1 evidence is not retroactively independent or formally qualified.
