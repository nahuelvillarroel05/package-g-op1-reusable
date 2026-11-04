# Experimental RUN purpose

> Los RUN de PGOP1 son campañas experimentales destinadas a evaluar sus componentes mediante evidencias verificables, descubrir defectos reproducibles, medir capacidades y limitaciones y producir resultados que puedan auditarse y publicarse para documentar la evolución del proyecto.

`RUN-001` onward are prospective experimental campaign identifiers. Each RUN identifies one campaign contract and its evidence lineage. A RUN may have multiple immutable attempts, including failed, stopped, blocked, and successful attempts. A pilot, engineering intervention, preflight, or synthetic validation is not a RUN unless the registry explicitly identifies it as one.

The purpose of this series is to produce reproducible, bounded engineering evidence about the selected Package-G candidate and its declared inputs. Reports must preserve the difference between implementation behavior, structural validity, semantic quality, independent qualification, and release authority. A result in one dimension does not imply another.

This series has two obligations:

1. **Experimental:** preserve the inputs, configuration, code and versions, results, errors, abstentions, defects, evidence, and audits for every attempt, including failures and incomplete runs.
2. **Publication:** document the public purpose, method, code, selection, metrics, results, limitations, evidence, non-redistributable references, audit state, and exact Git identity. Missing rights to redistribute a source do not permit inventing or silently omitting its results. Publish only lawful aggregates, commitments, and indexes, together with clear public reproducibility limits.

Execution is allowed only when the campaign has a complete versioned contract, approved freeze bound to an exact revision and SHA-256, fresh execution identity, and explicit Owner authorization. Registry entries, tests, preparation, documentation, publication, and branch names do not authorize execution. RUN-004 remains a preparation locator and is not approved or executed.

Finishing tests does not close the RUN documentary lifecycle. `RUN_DOCUMENTARY_CLOSED` requires the campaign's complete result set, verified integrity, engineering audit, publication receipt, and exact public Git identity. Closure records evidence completeness; it does not itself mean acceptance, independent qualification, or promotion.

Historical RUN-001, RUN-002, and RUN-003 records are reconstructions from their verified prior records. This purpose statement is prospective and does not retrofit contracts, alter execution results, or relabel historical limitations.

## Required reporting distinctions

- execution code identity, result/release identity, and publication identity are separate fields;
- declared, attempted, completed, failed, stopped, blocked, and not-run units have separate denominators;
- structural, semantic, independent-reference, custody, and authority conclusions are reported separately;
- unknown, missing, and inaccessible evidence remain `UNKNOWN` or the exact blocked state;
- publication readiness, local artifact preparation, remote publication, and remote verification are separate lifecycle events.

See [publication policy](PUBLICATION_POLICY.md), [policy](EXPERIMENTAL_POLICY.md), and the versioned [run-publication contract](schemas/pgop1.experimental.run-publication.v1.md).

Every prospective campaign includes the Owner-required result set: `CAMPAIGN_SUMMARY.md`, `EXECUTION_RESULTS.json`, `COVERAGE_REPORT.json`, `FAILURES_AND_ABSTENTIONS.json`, `DEFECT_AND_FIX_REPORT.md`, `CODE_REFERENCE.json`, `SOURCE_MANIFEST.json`, `RESULTS_INTEGRITY_MANIFEST.json`, `AUDIT_SUMMARY.md`, `LIMITATIONS.md`, and `PUBLICATION_RECEIPT.json`. Each file is backed by applicable frozen execution, audit, and publication evidence. Historical gaps are listed explicitly and are not filled retrospectively.
