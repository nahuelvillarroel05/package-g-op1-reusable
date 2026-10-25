# Public maintenance audit, 2026-10-25

Scope: derivative public repository maintenance after original commit `7cab0ed7213712e8b41c4bf0ddb9d669511d8137`. The outer Git commit binds these files and the regenerated public tree manifest. No engine, runtime, schema, provider or MCP server functionality was changed. The local-model client relocation in `fb08d26` preserved its exact bytes (SHA-256 `f097ff6979f9e8a2881761d9973b61d4ff924e357dab25ea535ec5407d317fbe`).

Pre-publication checks actually performed on the public clone:

- Pinned runtime/test dependencies installed in a new isolated Python 3.14 environment; `pip check` passed.
- Runtime, API, MCP and relocated client imports passed; CLI help passed.
- Two relocated-client tests passed. Four public-manifest tests passed, including refusal of changed bytes, missing members, additional tracked members and duplicate manifest entries.
- CLI synthetic demo: `PASS`. Python API example: `PASS` for verify/query/graph/provenance/recover.
- Real MCP SDK demonstration: ten tools enumerated, pipeline/verification/query/graph/provenance/recovery passed. Recovery reported `dispatch=NOT_PERFORMED`, `redispatch=PROHIBITED`, replay rejection and unchanged workspace file membership/hashes. Negative input/path checks passed.
- Run-reference boundaries and private-policy/formal-fixture refusal scripts passed.
- Original LICENSE, NOTICE, dependency locks, historical validation records and frozen engine bytes were preserved. Installed versions of all 35 dependencies and 91 recorded metadata/license objects matched the historical dependency-license audit. Dependencies remain external and retain their own terms, including the documented pywin32 component-license distinctions.
- Reviewed all added/changed public files and exact manifest membership. A bounded scan for GitHub token, AWS access-key, OpenAI project-key and private-key PEM patterns found no matches. Manual and independent review observed no private data in the changes. This is a scoped check, not proof that every possible secret form is detectable.
- An independent AI reviewer inspected the diff, demo contracts, workflow permissions and application statements, with no blocking findings. This is technical review of these changes, not human adjudication, native qualification or a certified security audit. Its suggestion to validate member paths before manifest writing was applied and tested.

The selected I0/I1/I2 full suite is run by public CI; use the actual commit-bound [GitHub Actions results](https://github.com/nahuelvillarroel05/package-g-op1-reusable/actions) and release notes for final outcomes. This pre-push audit does not claim that an uncompleted hosted run has passed. Original public-source results remain separate historical evidence.

The new workflow uses public checkout/dependencies, Windows/Python 3.14, minimal read permissions, immutable action pins and no repository secrets. Fork PRs do not use a privileged `pull_request_target` context. Generated local workspaces, venvs and timing logs are excluded from publication. Release assets must not include private evidence, models or local workspaces.

The initial hosted push/PR runs for `68b6506` failed at the CLI demo because global Python 3.14.9 exposed a nonexistent user-site path (`PATH_NOT_FOUND`). Earlier dependency, integrity, import and focused-test steps passed; later pipeline/core stages were not reached. [The failed push run](https://github.com/nahuelvillarroel05/package-g-op1-reusable/actions/runs/40236171069) and [failed PR run](https://github.com/nahuelvillarroel05/package-g-op1-reusable/actions/runs/40236171571) remain public. The workflow was corrected to create a venv and assert that the isolated interpreter is selected, matching the documented local setup. No engine path guard, dependency pin or test assertion was relaxed. A second [push run](https://github.com/nahuelvillarroel05/package-g-op1-reusable/actions/runs/40236386672) on `fb5c8ae` passed the isolated-interpreter guard but failed the same CLI check: isolation alone does not remove the runtime's unconditional user-site existence requirement. The next correction explicitly prepares that Python-derived directory and asserts JSON Schema's origin under the venv, without installing packages in user-site. The setup commands now document this prerequisite. Success must be established by subsequent hosted runs.

The application remains a manual Owner submission. Its three bounded answers contain 416, 424 and 430 characters. Repository adoption is reported without invented users or activity. [Issue #2](https://github.com/nahuelvillarroel05/package-g-op1-reusable/issues/2) records a concrete dependency-boundary task derived from the existing public portability/SDK limitations; it does not authorize new engine work.

```text
PROJECT_STATUS=WORK_IN_PROGRESS
I7_STATUS=INCOMPLETE
FORMAL_I7=NOT_COMPLETED
OPERATIONAL_QUALIFICATION=NOT_ACHIEVED
ORIGINAL_NATIVE_OD05_E30_FORMAL_I7_ORNITH=NOT_PERFORMED
```
