# RUN_CONTRACT — plantilla v1 (DRAFT; NO AUTORIZA EJECUCIÓN)

Copiar al directorio del RUN. Sustituir todos los REQUIRED y resolver UNKNOWN que afecten elegibilidad antes de freeze. Preservar revisiones con nombres únicos, SHA-256 y recibos de aprobación; `RUN_CONTRACT.md` localiza la revisión inicial, sin reemplazar originales congelados. Una revisión posterior usa `contracts/revision-NNN/RUN_CONTRACT.md`. Repetir la aprobación del Owner para todo cambio material. Fecha por sí sola no prueba preinspección.

## RUN_ID

REQUIRED

## RUN_TYPE

REQUIRED

## PURPOSE

REQUIRED

## SCOPE

REQUIRED

## BASELINE_COMMIT

REQUIRED

## CANDIDATE_COMMIT

REQUIRED

## BENCHMARKS

REQUIRED

## DATASET_REVISIONS

REQUIRED

## POPULATION

REQUIRED

## SELECTION_METHOD

REQUIRED

## EVIDENCE_REQUIREMENTS

REQUIRED

## PREDICATE_CONTRACTS

REQUIRED

## METRICS

REQUIRED

## EXPECTED_LIMITATIONS

REQUIRED

## SUCCESS_CRITERIA

REQUIRED

## STOP_CRITERIA

REQUIRED

## RECOVERY_POLICY

REQUIRED

## AUDIT_REQUIREMENTS

REQUIRED

## FORMAL_QUALIFICATION_SCOPE

REQUIRED

## FREEZE_AND_AUTHORIZATION

CONTRACT_REVISION: REQUIRED
PREVIOUS_REVISION_SHA256: REQUIRED_OR_NOT_APPLICABLE
CONTRACT_SHA256: detached receipt; no hash autorreferencial
OWNER_APPROVAL_REFERENCE: REQUIRED
APPROVED_UTC: REQUIRED
EXECUTION_AUTHORIZATION_REFERENCE: REQUIRED
CODE_TREE: REQUIRED
INPUT_MANIFEST_SHA256: REQUIRED
CONFIGURATION_SHA256: REQUIRED
RIGHTS_AND_PRIVACY_REVIEW: REQUIRED
COMPARABILITY_AND_EXCLUSIONS: REQUIRED

POPULATION debe enumerar todas las unidades seleccionadas mediante manifiesto/hash, revisión exacta, exclusiones, solapamientos y regla de exhaustividad. DATASET_REVISIONS fija todas las familias y fuentes. EVIDENCE_REQUIREMENTS debe vincular tarea, output auténtico, productor/evaluador y referencias verificables; ausencia => UNKNOWN/ABSTAIN, no autenticidad inferida. METRICS fija unidades y denominadores. STOP_CRITERIA incluye alteración de hashes, derechos no resueltos, corrupción, incompatibilidad y límites contractuales. RECOVERY_POLICY fija checkpoints seguros y bloqueo ante ambigüedad. FORMAL_QUALIFICATION_SCOPE debe indicar NONE salvo autorización formal separada; esta plantilla no otorga esa autorización.
