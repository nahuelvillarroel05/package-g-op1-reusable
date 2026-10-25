# Contributing

Package-G OP1 Reusable welcomes reproducible bug reports, documentation corrections and focused changes to published components. Start with the [architecture](docs/ARCHITECTURE.md), [public demo](docs/PUBLIC_DEMO.md), [limitations](docs/LIMITATIONS.md) and [roadmap](docs/ROADMAP.md).

```text
PROJECT_STATUS=WORK_IN_PROGRESS
I7_STATUS=INCOMPLETE
FORMAL_I7=NOT_COMPLETED
OPERATIONAL_QUALIFICATION=NOT_ACHIEVED
```

## Reproduce first

Use Windows, Python 3.14, a short disposable checkout and a new branch. Create a venv and install both pinned requirement files using the exact [demo commands](docs/PUBLIC_DEMO.md). Run the checks in [public validation](docs/PUBLIC_VALIDATION.md); the public workflow is the executable reference. Keep the historical `src` import root confined to the separate core-test process.

Use fresh workspaces and synthetic fixtures. Preserve existing outputs and ambiguous attempts. Recover existing evidence rather than redispatching work. Include the tested commit, OS/Python versions, exact command, expected result and observed error when reporting a bug. Reduce it to public synthetic data. Do not upload a whole local workspace or transcript without reviewing every file for private content.

## Propose a focused change

Open an issue for a concrete reproducible defect or a defined roadmap task. State current behavior, the proposed result, public reproduction and acceptance checks. Do not manufacture activity, duplicate historical tasks or imply that original gated work has execution authorization.

Use a new branch and PR. Explain what changed, why, and which checks actually ran. Keep test failures and NOT_RUN checks visible. Update affected docs and manifests, preserve source pins, evidence identities, historical failures and no-redispatch recovery. Stage only reviewed public files, regenerate the derivative tree manifest with `python -B tools/verify_public_tree.py --write`, review it, then verify without `--write`. Request independent technical review before publication; automated review is scoped evidence and must be identified accurately.

## Preserve the baseline and authority

Never move or replace `engineering-snapshot-20261025` or rewrite original history. Changes to frozen contracts require a separately identified derivative; never describe it as the original freeze. Public maintenance does not reopen I7, accept Formal I7, authorize original native campaigns, grant operational custody, or waive Physical C2. Engineering checks do not grant operational authority. Original gated work needs its own applicable authorization.

Private operational evidence, original corpus/native campaigns and model benchmarks cannot be reproduced from this selected public tree. Their historical status remains in the documentation. Retain Ornith FAIL records and distinguish synthetic CI, historical results and model quality.

## License and disclosure

Contributions intentionally submitted for inclusion use the repository Apache-2.0 terms. Preserve LICENSE, NOTICE and existing attributions. External dependencies retain their licenses and are installed separately; do not vendor them incidentally. Do not submit credentials, private operational evidence, model weights or third-party code without redistribution rights.

For suspected sensitive exposure, do not paste secrets into a public issue. Use any private reporting channel the repository exposes; otherwise contact the Owner privately through an available contact. Do not claim a private reporting service exists when none is configured.
