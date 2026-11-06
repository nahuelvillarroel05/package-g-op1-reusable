# Current mode-aware preparation policy

First declare [E1, E2, or F](ENGINEERING_MODES.md) and use [RUN_TEMPLATE.md](RUN_TEMPLATE.md). For E1, its operational minimums supersede universal legacy formal-approval/document-package requirements in older preparation material. Existing implementation requirements for trusted roots, exact bindings, authorization, safe producers, budgets, and verifiable recovery remain applicable. Do not repeat complete synthetic development campaigns or general preflight as a universal E1 prerequisite; validate only the changes and concrete operational risks. The commands below are existing framework interfaces, not an instruction to rerun every preparation step. An applicable Owner authorization can already cover execution and progressive batches.

---

# Prepare a new experimental RUN

Start with the current Owner authorization, [experimental policy](EXPERIMENTAL_POLICY.md), [purpose](RUNS_PURPOSE.md) and [registry](RUN_REGISTRY.json). Reserve a new series ID without reusing historical execution identities. A development fixture or preflight never registers itself as a real campaign. Do not infer approval from successful preparation.

Use the existing `runtime.candidate.run_framework` implementation. The versioned [configuration template](framework/v1/RUN_CONFIGURATION_TEMPLATE.json) lists all required fields. Replace every placeholder; hash actual contract, dataset, selection, adapter, predicate and exclusion files. `selection_manifest` contains an explicit unique `expected_units` list identical to the configuration; benchmark count and terminal vocabulary are not fixed by the framework. Supply candidate commit/tree and exact tracked code files, including the dependency closure used by your producer. A clean candidate is required. Obtain trusted config, input/code and output roots from the caller; configuration cannot expand those grants.

Use a fresh `campaign_attempt_id` under `<trusted-output-root>/<run_id>/attempts/<campaign_attempt_id>`. The framework reserves campaign identity and attempt identity on the first explicit write; preflight creates no registry or attempt. Different attempts retain separate files. Conflicting campaign ownership, duplicate attempt ownership and interrupted publication block writes. Existing attempts can be inspected in another process; they cannot be resumed by these interfaces.

Invoke the existing Python module from the selected clean checkout, replacing all arguments with exact prospective paths:

```powershell
python -B -m runtime.candidate.run_framework preflight --config CONFIG.json --config-root CONFIG_ROOT --trusted-root INPUT_AND_CODE_ROOT --output-root OUTPUT_ROOT --output OUTPUT_ROOT/RUN_ID/attempts/ATTEMPT_ID
python -B -m runtime.candidate.run_framework verify --config CONFIG.json --config-root CONFIG_ROOT --trusted-root INPUT_AND_CODE_ROOT --output-root OUTPUT_ROOT --output OUTPUT_ROOT/RUN_ID/attempts/ATTEMPT_ID
python -B -m runtime.candidate.run_framework recover --config CONFIG.json --config-root CONFIG_ROOT --trusted-root INPUT_AND_CODE_ROOT --output-root OUTPUT_ROOT --output OUTPUT_ROOT/RUN_ID/attempts/ATTEMPT_ID
python -B -m runtime.candidate.run_framework report --config CONFIG.json --config-root CONFIG_ROOT --trusted-root INPUT_AND_CODE_ROOT --output-root OUTPUT_ROOT --output OUTPUT_ROOT/RUN_ID/attempts/ATTEMPT_ID
```

Repeat `--trusted-root` for independently granted roots. Exactly one output namespace root is required. These commands read and verify; they do not invoke adapters, agents, evaluators, tasks or an automatic resume. No new executable or provider-specific dependency is required. Existing pinned I7 interfaces remain unchanged.

For planning, `Campaign.shard_plan()` uses configured shard size, checkpoint interval and policies. The pure `planning.plan_shards` / `verify_shards` APIs also work without a campaign. They sort explicit IDs and reconcile exact union and disjoint membership. Freeze the plan/hash externally after the applicable authority approves it. A policy commitment is not proof of budget enforcement or available resources.

After separate execution authorization, an authorized producer may bracket its actual processing using `begin_unit` and `complete_unit`. The generic journal persists detached canonical receipts/checkpoints and checks exact sets. The producer must separately validate its campaign-specific evidence, timing, benchmark revisions, predicate applicability, semantics, rights, safety and budgets. `COMPLETE_WITH_DISPOSITIONS` means the supplied lifecycle records reconcile; `execution_completeness=NOT_CERTIFIED` remains explicit. Arbitrary terminal text cannot certify benchmark execution. This version provides no external execution dispatcher or authorized-resume implementation.

Use the existing benchmark registry/parsers and Context Engine. The task-definition adapter bridge supports discovery/validation/normalization/persistence/readback; semantic audit is explicitly unsupported by that bridge. Extend the existing family adapter only when a new benchmark contract requires semantic behavior. Do not copy a prior RUN's code or put benchmark-specific logic in the generic journal. Do not equate source integrity or task ingestion with authentic agent output or a semantic result.

Run the explicit authored-development validation driver only under engineering authorization:

```powershell
python -B experiments/engineering/reusable_run_framework_001/validate_development.py --output FRESH_DEVELOPMENT_DIRECTORY
```

It uses two configurations with different family distributions and resource metadata; it never reads original benchmark cases. Preserve every failure and correction. Run the focused framework/adapter/planner tests and applicable existing regressions using the workspace's controlled pytest wrapper. Obtain technical and adversarial reviews of the exact final bytes. Bind engineering candidate commit/tree, source/input commitments and limitations before handoff. Campaign approval, final freeze, publication and execution remain separate decisions.
