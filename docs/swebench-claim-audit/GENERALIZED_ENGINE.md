# Generalized claim-audit engineering interfaces

RUN-001 adds prospective modules beside the unchanged historical adapter. It
reuses PGOP1's existing Context Engine and I4-NEXT/I5-NEXT implementation. It does
not change a frozen core or fixed I7 interface.

## Evidence and claims

`generalized.audit_file(data_root, descriptor)` parses one hash-committed file.
Each descriptor identifies a relative path, SHA-256, exact byte count, evidence
role and versioned parser. Optional run and instance identifiers are caller
bindings; they do not authenticate an upstream agent or execution. Discovery
returns observations and a supported, unsupported or error status, without a
claim verdict.

`generalized.audit_evidence(data_root, request)` compares explicitly joined
evidence for one run and instance. Predictions, evaluator results, assistant
statements, execution evidence and provenance remain separate. Benchmark
resolution, task completion and component/issue fixes are different predicates.
An archived `resolved=true` cannot create an assistant statement. An unmatched
predicate or absent attributable statement yields insufficient evidence.

The registry names narrow JSON/JSONL trajectory, prediction, report, catalog and
positive-membership summary schemas; bounded UTF-8 execution text and gzip;
unified-diff artifacts; and a restricted flat YAML scalar subset. Registry IDs
and parser versions are included in each output. Unattributed logs, patches and
metadata never create success claims. Unrecognized schemas, including unsupported
Markdown transcript conventions and nested YAML, remain explicit limitations.
No general multilingual recognition or classifier accuracy is claimed. English
phrase recognition is a conservative bounded extractor, not language reasoning.

Sources are inert data. The parsers enforce rooted paths, exact commitments,
duplicate checks, bounded input/decompression and instance/run consistency.
They never execute a patch, trajectory command or embedded instruction.

## PGOP1 binding and recovery

`generalized_bridge.bind_generalized_audit(result, data_root, context_root)`
admits exact source bytes and the complete normalized adapter result into the
existing Engine. It ingests source-bound observations, verifies the actual
I4-NEXT graph and I5-NEXT provenance, queries observations and checks readback
in a fresh Python process. Explicit batch aggregates preserve their member
identities. Semantic verdicts belong to the adapter; PGOP1 verifies recorded
bytes, bindings and graph/provenance consistency.

`recover_generalized_audit(context_root)` verifies and reads the existing store.
It does not rerun the adapter, original evaluator, patch or provider. The Engine
may rebuild its disposable SQLite index, so recovery is not represented as
filesystem-read-only. Mutable receipt fields must agree with the immutable
capsule and verified graph.

## Frozen campaigns

`prepare_plan.build_plan` is a separate versioned discovery profile for the
declared local archive layout. It inventories dispositions for every supplied
source and creates explicit joins only within the local logs collection. It
does not associate an experiment submission with that collection from matching
instance IDs. Supporting documents and unknown formats receive explicit status;
evaluator source code and historical generated copies are excluded from fresh
agent evidence. Source-manifest classification is distinct from claim verdicts.

`campaign.run_campaign` processes a frozen plan serially, one bounded source or
execution at a time. Production requires an exact Git commit and implementation
hashes. An explicit development API option is available for synthetic checks;
the production CLI does not expose it. The driver keeps append-only START and
COMPLETE events, fsyncs result bytes before recording completion and prevents
concurrent writers. Recovery validates the same plan, code, source hashes and
completed result hashes; it processes only units without durable completion.
It rejects unbound old results instead of silently starting again. Failed and
interrupted attempts remain recorded. The default free-storage reserve is
70,000,000,000 bytes. Output beneath an input root requires an explicit frozen
exclusion that contains no input sources.

`bind_campaign.bind_campaign` separately binds every completed processing/audit
unit and its original source bytes in bounded Context Engine batches. Each unit's
complete normalized output is retained as an immutable source object; the graph
records unit observations, not an invented semantic validation by PGOP1. It
verifies and recovers each batch. Existing batch receipts must match both the
verified store and their append-only completion commitments. An adapter-only
execution is not reported as having completed this separate integration stage.

After freezing code and constructing a manifest, run from its exact checkout:

```powershell
python -B -m runtime.candidate.swebench_claim_audit.prepare_plan --data-root DATA_ROOT --inventory INPUT_INVENTORY.json --code-freeze CODE_FREEZE.json --output PLAN.json
python -B -m runtime.candidate.swebench_claim_audit.campaign --data-root DATA_ROOT --plan PLAN.json --output NEW_OUTPUT_DIRECTORY
python -B -m runtime.candidate.swebench_claim_audit.campaign --data-root DATA_ROOT --plan PLAN.json --output NEW_OUTPUT_DIRECTORY --resume
python -B -m runtime.candidate.swebench_claim_audit.bind_campaign --data-root DATA_ROOT --plan PLAN.json --campaign-root NEW_OUTPUT_DIRECTORY --context-parent FROZEN_EXCLUDED_CONTEXT_DIRECTORY
```

Use the campaign's public manifest and pinned source locations to reconstruct
the inputs. Private original paths and third-party content are not part of the
public results. A local manifest verifies identity, not redistribution rights,
source authenticity or independent custody.

## Validation and authority

Focused synthetic tests cover predicate boundaries, integrity, paths, duplicate
identifiers, decompression, source commitment, engine ingestion and recovery.
Historical tests remain intact. Development, repository-heldout exploratory
checks and whole-submission catalog checks have different scopes. A shared
historical submission prevents an independent cross-submission claim-language
evaluation; no accuracy, false-positive rate or false-negative rate is inferred
without independent explicit labels and a stated denominator.

Level A means file integrity; B means reconstruction from archived logs; C means
fresh patch/test execution; D means claim audit. B does not establish C. Neither
the parsers nor a successful PGOP1 storage check proves a benchmark problem was
solved by PGOP1.

```text
I0-I6=FORMALLY_FROZEN
I7=INCOMPLETE
FORMAL_I7=NOT_COMPLETED
OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED
INDEPENDENT_CUSTODY=NOT_PROVEN
PHYSICAL_C2=DEFERRED_NOT_WAIVED
```
