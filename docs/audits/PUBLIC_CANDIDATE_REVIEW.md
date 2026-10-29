# PGOP1 public engineering candidate review

ENGINEERING_CANDIDATE · NOT_OPERATIONALLY_QUALIFIED · RUN_002_NOT_READY · GATE_11_BLOCKED

## Project overview

PGOP1 is experimental infrastructure for storing evidence, preserving provenance and auditing narrowly defined claims in agent records. It aims to distinguish what an agent said, what corresponding evidence records say, and what can actually be verified. Byte integrity, declared attribution, semantic support and operational authority are separate claims.

## Architecture

The historical core is in `src/package_g/`. This candidate remains in `runtime/candidate/` and has not been promoted to `src`.

* **Context Engine:** `runtime/candidate/context_engine.py` stores immutable source/version objects, observations and graph commitments with a rebuildable SQLite index. Verification and recovery check recorded bytes, associations and provenance. Storage PASS does not establish semantic truth.
* **Evidence Engine and bridge:** `swebench_claim_audit/adapter.py`, `engine_bridge.py` and `generalized_bridge.py` bind adapter results and original sources to the existing Engine. The bridge checks graph/provenance/readback; it does not run the original evaluator or authenticate an agent.
* **Claim Audit:** `generalized.py` registers explicit formats and implements `audit_file` and `audit_evidence`. Input records are inert data. Output file-format status SUPPORTED must not be confused with a claim verdict SUPPORTED.
* **Parsers:** prediction JSONL, MiniSwe trajectories, explicit role exports, evaluator maps/lists/catalogs, bounded logs, YAML, unified patches and Aider Markdown have distinct contracts. Unattributed formats emit no authenticated agent claims. Declared role metadata is not verified speaker identity.
* **Predicates:** `predicate_evidence.py` implements strict identity-bound reference scoring and a narrow TASK_RESOLVED boolean comparison. See the predicate contract below. TASK_COMPLETED, ISSUE_RESOLVED, TESTS_PASSED, PATCH_APPLIED, FILE_CREATED, FILE_MODIFIED and COMMAND_EXECUTED lack new concrete verification contracts.
* **Batching:** `swebench_batching.py` composes bounded observations. `source_fragments.py` provides an explicit V2 route for original bytes, cross-fragment BYTE_SPANs and mapped/rejected observation conservation. It does not turn every legacy parser into a streaming parser.
* **Recovery:** immutable capsules, hashes, completion records and fresh-process readback preserve the prior identity. Orphan output prevents redispatch. Recovery may rebuild SQLite and is not a filesystem-read-only operation.
* **Interfaces:** Python adapter/bridge APIs, `prepare_plan`, `campaign` and `bind_campaign` CLIs, and broader experimental `i7_api.py`/`pg_i7.py` interfaces exist. Their availability grants no campaign or physical execution authority. This review does not request a campaign.

## Implementation identity

Code commit: [`676f2f08a7bb7602bb0bc6e66d845684e1833783`](https://github.com/nahuelvillarroel05/package-g-op1-reusable/commit/676f2f08a7bb7602bb0bc6e66d845684e1833783). Tree: `c81bb27122a011662e20e52a2645fd3ac119dc6f`.

The later documentation commit is identified in the external publication handoff; its SHA is not embedded recursively in its own contents. Review executable code at the code commit, and the public documents at the later documentation commit.

Primary contracts:

* [Generalized Engine](../swebench-claim-audit/GENERALIZED_ENGINE.md)
* [Attribution](../swebench-claim-audit/RUN002_ATTRIBUTION.md)
* [Predicate evidence](../swebench-claim-audit/RUN002_PREDICATE_EVIDENCE.md)
* [Batching](../swebench-claim-audit/RUN002_BATCHING.md)
* [Source fragments V2](../swebench-claim-audit/RUN002_STREAMING_SOURCE_V2.md)
* [Frozen semantic protocol](../swebench-claim-audit/RUN002_EVALUATION_PROTOCOL.md)
* [Reference eligibility](../swebench-claim-audit/RUN002_REFERENCE_ELIGIBILITY.md)

Seven synthetic regression suites documented 216 passing tests, zero failures/errors/skips. These results were reused after exact file/hash checks; they were **not rerun during publication**. The private continuity package's 63/63 packaging checks concern artifact integrity/usability, not 63 semantic tests or public semantic accuracy. Public [technical evidence](CANDIDATE_TECHNICAL_EVIDENCE.json) provides the original result commitments and tested-file hashes, without private artifacts. The publication team verified the original JUnit and package receipts locally; GitHub-only reviewers cannot inspect the unredistributed original package/JUnit from these commitments alone.

## Known limitations

I0-I6=FORMALLY_FROZEN; I7=INCOMPLETE; FORMAL_I7=NOT_COMPLETED; OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED; INDEPENDENT_CUSTODY=NOT_PROVEN; PHYSICAL_C2=DEFERRED_NOT_WAIVED.

Independent adjudicated semantic holdout references are unavailable: GATE_11=BLOCKED, RUN_002=NOT_READY. No general semantic precision, recall or accuracy has been established. UNKNOWN provenance remains UNKNOWN. English phrase recognition is bounded extraction, not general language understanding. Source parsing success is not successful task resolution. Hashes bind bytes without proving trusted authorship, independence or custody. Windows-specific locking/native paths exist, including `msvcrt`; Linux portability is unqualified. Resource probes and 20,000 synthetic observations establish only their tested profiles. Authentic development-file results cannot be reproduced from GitHub alone because original source bodies and local Engine stores are not distributed.

## Reproduction using public files

Use a fresh Windows checkout, Python 3.14 and a writable temporary directory. Inspect the pinned code first. Install test dependencies only if you choose to reproduce the synthetic suites:

```powershell
git clone https://github.com/nahuelvillarroel05/package-g-op1-reusable.git pgop1-public-review
Set-Location pgop1-public-review
git checkout --detach 676f2f08a7bb7602bb0bc6e66d845684e1833783
git rev-parse HEAD 'HEAD^{tree}'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r tests/requirements.txt
.\.venv\Scripts\python.exe -B -m pytest -p no:cacheprovider tests/test_swebench_claim_audit.py tests/test_swebench_generalized.py tests/test_swebench_generalized_bridge.py tests/test_swebench_campaign.py tests/test_swebench_attribution.py tests/test_swebench_batching.py tests/test_swebench_source_fragments.py --basetemp "$env:TEMP/pgop1-public-review-unique" -q
```

Choose a new basetemp path for each invocation. This recipe targets only the seven listed synthetic suites. Broader MCP/native interfaces have separate dependencies recorded in `mcp/INSTALL_FREEZE.txt` and are outside this reproduction command. These suites use repository synthetic fixtures and temporary Engine stores, not GOLD or private trajectories. They do not reproduce the archived authentic source probes or qualify RUN-002. Installation needs package-index access; no offline or all-platform guarantee is made. No test execution is required of Sonnet to provide a source review. No workflow is present on this experimental branch, so CI PASS must not be inferred from main's workflow.
