# Six-family nightly engineering composition

Owner target: PGOP1_SIX_FAMILY_FULL_SCALE_NIGHTLY_CONVERGENCE_001.

This is experimental engineering separate from RUN-004. The existing Context
Engine stores every source-free processing descriptor in bounded shards. Original
benchmark bodies remain in their pinned local corpus; descriptors retain exact
paths, hashes and row pointers. No benchmark producer, tool call or official
evaluator is dispatched by this composition.

`batch_context.py build PLAN.json` requires caller-authorized, hash-bound JSONL
sources and explicit expected row counts. It writes new immutable attempts under
the nightly workspace's context_engine directory. `recover ATTEMPT` verifies every
stored value against its externally committed descriptor input from a different
process. `rebuild ATTEMPT` additionally rebuilds all disposable indexes. `controls
ATTEMPT` operates on preserved stores and disposable corruption clones. `resume
ATTEMPT` accepts only a nonterminal attempt with unchanged driver/Engine/plan,
complete verified shard receipts and no orphan partial shard. It processes pending
units only. Ambiguous partial stores block recovery; never redispatch producers.

All task/output material used in this intervention is development evidence.
Preserve the 2,180 BFCL reserve exclusions and UNKNOWN_PENDING_ACCESS_REVIEW.
Structural acceptance, source integrity, published path bindings and stored
metadata do not authenticate producer execution or establish semantic truth.

Authoritative local reports and exact execution identities live in
Engineering/PGOP1_SIX_FAMILY_NIGHTLY_CONVERGENCE_001. External family drivers are
separately hash-bound, not retroactively attributed to this Git tree.

RUN004_CONTRACT=NOT_APPROVED; RUN004_FINAL_FREEZE=NOT_ISSUED;
RUN004_EXECUTION=NOT_EXECUTED. No promotion to src, main, formal I7, GATE_11 or
Physical C2 follows from this work.
