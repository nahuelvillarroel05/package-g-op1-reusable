Public source-free rendering; private workspace root replaced with PRIVATE_CONTINUITY. Original private report SHA256: a708c141d4c39a3b1b8c69e9927538aaf7669ce3c153ea7c674004ecf8f0910c

# RUN008 independent technical attempt audit

Reviewer: Sol XHigh. Attempt: `RUN008-E1-20261107T022418Z-06bdc874`. This is the terminal first RUN008 attempt, not a source-processing result. No original benchmark task was executed or replayed for this audit; source bytes were used only for exact SHA-256 checks, not inspected as task content.

## Attempt outcome

`runs/run-008/operational/EXECUTION_RESULT.json` reports `status=ERROR`, `error_type=FrameworkError`, `error=candidate Git identity could not be verified`. `EXECUTE_SUPERVISOR.json` records child PID 21708, return code 1, no timeout, and 0.328 seconds elapsed. The child's stdout repeats the error; stderr is empty. `runs/run-008/evidence` contains no attempt, unit receipt, delta, checkpoint, batch observation, Engine own-result, or context directory. Therefore processed definitions, completed units, output audits, semantic audits, and recovered units are all **zero or NOT_PERFORMED**, not a failed semantic score. Do not recover, resume, or redispatch this consumed attempt.

## Independent binding checks

- Rehashed all five `FINAL_OPERATIONAL_BINDINGS.json` references: 5/5 matched. The launch authorization and freeze commit to the actual framework config hash; the freeze commits to the launch authorization hash. The admission specifies a newly authored synthetic denial wrapper and two protected roots.
- Rehashed all 22 configured candidate code files and all four selected authentic primary definitions: 22/22 and 4/4 matched their frozen hashes. The four units are the two deterministic permitted MCPMark definitions followed by two deterministic permitted Terminal definitions. No authentic agent outputs are bound.
- The frozen candidate checkout is clean on branch `experiment`; actual HEAD `96b210ff0473fd91270d5a68a55d7f6ea0cfb775` and tree `e06c4426ad4dfd67495809329906cd2058800316` match the framework config. Direct Git identity succeeds outside the guard. These checks localize the failure to guarded preflight integration, not a changed source or candidate byte.

## F03 — process-local read hook rejects Git capture pipes

**Severity: material launch blocker, no unselected-source read observed.** Frozen `runtime/candidate/run_framework/read_scope.py:118-123` classifies every nonpath `open` target as an unclassifiable read and raises `PermissionError`. Frozen `core.py:150-155` invokes `_git_read` in preflight and translates subprocess/OSError failures into the generic `FrameworkError` observed above; `_git_read` uses `subprocess.run(..., capture_output=True, text=True)` at lines 65-73. Reaching that call means preflight had already rehashed its bound inputs, including the four admitted primary source files; that read was permitted and produced no unit result.

I reproduced the failure independently with a newly authored temporary protected directory and synthetic allowed file, after installing the frozen guard: `subprocess.run(['git','--version'], check=True, capture_output=True, text=True)` raised `PermissionError [Errno 13] read scope denied unclassifiable open: '3'`. The guard recorded exactly one event, `path='3'`, `mode='r'`, `flags=32896`, `reason='open target is not a path'`. A second authored-only probe without the rejecting guard observed CPython integer `open` events for FDs 3 and 4 during the same Git capture; `os.fstat` classified both as FIFO. This confirms the causal path that the stopped attempt's terse error did not expose by itself.

The prior `RUN008_PATCH_TECHNICAL_AUDIT.md` preacceptance conclusion is superseded for launch readiness: its synthetic read tests did not exercise a subprocess with captured pipes after guard installation. RUN006 and RUN007 results are unaffected. A prospective repair can permit integer targets only when `os.fstat` proves a FIFO/pipe descriptor in this trusted process, while denying regular or unknown integer descriptors and retaining the exact named-path restrictions. Add a synthetic regression for guarded Git capture and a regular-descriptor negative control. Freeze that patch under a fresh RUN009 identity; do not alter or reuse RUN008's candidate, config, or attempt.

## Claim boundary

RUN008 establishes one reproducible integration defect and a fail-stop before unit processing. It provides no evidence about the four definitions' parser dispositions, 32 predicate slots, two batch closures, Engine persistence, or fresh recovery. The stopped documentary verifier incident remains separate with exposure UNKNOWN; this attempt does not resolve it or establish process-independent read confinement.
