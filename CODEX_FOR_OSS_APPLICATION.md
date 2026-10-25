# Codex for Open Source application draft

Prepared for Owner review and manual submission. NOT_SUBMITTED. This document does not claim selection, eligibility approval or guaranteed credits.

Official sources checked on 2026-10-25: [program](https://developers.openai.com/community/codex-for-oss) and [application form](https://openai.com/form/codex-for-oss/). The [program terms](https://learn.chatgpt.com/docs/codex-for-oss-terms) require accurate application information and a valid ChatGPT account; OpenAI may verify identity, role and repository control. Additional API-credit/security review may apply, and selection is discretionary. The program considers usage, ecosystem importance and active maintenance. A repository without broad adoption can explain its potential importance; reproducibility does not establish adoption. The form asks for three free-text answers of at most 500 characters each.

Package-G OP1 Reusable is experimental Python infrastructure for bounded execution and source-bound evidence. It aims to let agent clients consume verified run records, query causal/provenance information and recover existing work without redispatch. The public distribution contains selected reusable core code, a local synthetic runtime, Python API/CLI, a ten-tool MCP stdio adapter, a llama.cpp local-model MCP client, fixtures and tests under Apache-2.0.

MCP provides the tool-discovery and invocation interface between a client and the bound workspace. Potential ecosystem value lies in inspectable execution/evidence contracts and reproducible failure handling, rather than a claim of universal agent compatibility or certified security.

The Owner maintains the repository and controls scope, public contributions and releases. AI-assisted implementation/review is documented; this draft does not invent human contributors or independent organizational adoption. At preparation, GitHub reported 0 stars and 0 forks, with no existing public issues or PRs before this maintenance work. No external users, downloads or production deployments are substantiated. Re-check metrics before submission; do not treat this newly created maintenance activity as historical adoption.

Reproducible evidence: [public demo](docs/PUBLIC_DEMO.md), [validation commands and limits](docs/PUBLIC_VALIDATION.md), [actual CI runs](https://github.com/nahuelvillarroel05/package-g-op1-reusable/actions), [source manifest](manifests/PUBLIC_TREE_MANIFEST.json), and unchanged [historical public-source results](manifests/PUBLIC_SOURCE_TEST_RESULTS.json). Release and final CI links must be verified at handoff. No original native or model benchmark evidence is claimed to have been rerun.

Proposed Codex use: review contributions and evidence-binding changes, triage reproducible bugs, maintain Windows tests, detect regression risks, and prepare documentation/releases for Owner review. API credits would fund scoped review/triage automation and regression-analysis experiments on public synthetic data. No autonomous qualification, promotion or submission authority is proposed.

## Form fields

Owner must supply/confirm first name, last name, ChatGPT-account email, public GitHub profile visibility and OpenAI Organization ID. Do not publish private account details here.

- GitHub username: `nahuelvillarroel05`
- Repository: `https://github.com/nahuelvillarroel05/package-g-op1-reusable`
- Role: Primary maintainer (Owner to confirm).
- Interest: API credits for the project; Codex Security only if the Owner requests it and the program approves access.

### Why does this repository qualify?

<!-- FORM_QUALIFY_START -->
Package-G explores bounded agent execution with source-bound evidence, provenance queries and recovery without redispatch. Its public Python/MCP synthetic path and Windows tests make these contracts inspectable. It is early work: no external users or production adoption are substantiated. The application rests on potential ecosystem value and reproducibility, not popularity or completed operational qualification.
<!-- FORM_QUALIFY_END -->

### How will you use API credits for your project?

<!-- FORM_CREDITS_START -->
Use Codex/API credits for scoped pull-request review, reproducible issue triage, Windows regression analysis, evidence/manifest consistency checks and release documentation. Automation would use public source and synthetic fixtures, preserve failure records and leave merge, release and qualification decisions to the maintainer. Credits would not fund fabricated activity or substitute for independent operational evidence.
<!-- FORM_CREDITS_END -->

### Anything else we should know?

<!-- FORM_OTHER_START -->
This Apache-2.0 project is WORK_IN_PROGRESS. I7_STATUS=INCOMPLETE; FORMAL_I7=NOT_COMPLETED; OPERATIONAL_QUALIFICATION=NOT_ACHIEVED. Historical Ornith agent-quality FAIL results remain documented. Public synthetic CI does not establish native readiness, independent custody or universal agent compatibility. The original engineering-snapshot-20261025 freeze is preserved. The Owner will review and submit this application manually.
<!-- FORM_OTHER_END -->

These three answer blocks must each remain within the official 500-character limit. Program terms and form fields may change; the Owner should re-check the official form before submission.
