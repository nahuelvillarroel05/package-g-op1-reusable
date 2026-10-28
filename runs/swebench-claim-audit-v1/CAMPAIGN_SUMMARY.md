# PGOP1 — SWE-bench Claim Audit V1

## Purpose

PGOP1 audits explicit agent claims against archived evidence. V1 checks whether recorded issue-resolution claims agree with archived evaluator records and frozen campaign evidence. It does not authenticate agents or establish general software engineering ability.

## Implementation

The SWE-bench adapter connects to Context Engine, identifies resolution claims, binds logs, patches, and evaluator results, then emits verdicts and integrity receipts. Three Engineering runs generated 36 receipts for 12 instances: six `SUPPORTED`, six `CONTRADICTED`. Historical tests passed 39/39 at T008 and 44/44 in a later focused suite. These bounded results do not qualify operations.

## Results and independent cross-verification

The network-recovery verification used Python 3.11.9 and SWE-bench 5.0.2. Its source-checkout CLI regraded 258 archived log instances and returned `PASS` for the full entry. This is distinct from the 12 selected PGOP1 claims. A separate direct grading step found six resolved and six not resolved; all 12 matched the entry claims, archived evaluator records, and V4 verdicts. The denominators and results are separated in [`REGRADE_EXECUTION_PUBLIC.json`](verification/network-recovery-20261028/REGRADE_EXECUTION_PUBLIC.json), [`REGRADE_RESULTS_PUBLIC.json`](verification/network-recovery-20261028/REGRADE_RESULTS_PUBLIC.json), and [`V1_RECONCILIATION_PUBLIC.json`](verification/network-recovery-20261028/V1_RECONCILIATION_PUBLIC.json).

## Limitations

No patches were rerun through Docker; grading used recorded output. Provider identity was not cryptographically authenticated. The 12 cases are not representative and do not establish 100% general accuracy. The wheel and source checkout both declare 5.0.2 but have different CLI surfaces. Sixteen inspected files matched upstream commit [`02e7a74`](https://github.com/SWE-bench/SWE-bench/commit/02e7a74ffd0b707aab73d203fe87bdc7c76afc8e); full checkout identity remains unproven. Dataset: [`SWE-bench/SWE-bench_Multilingual`](https://huggingface.co/datasets/SWE-bench/SWE-bench_Multilingual). I7 is incomplete and not operationally qualified. I0–I6 remain frozen; Formal I7 was not completed; independent custody is unproven; Physical C2 is `DEFERRED_NOT_WAIVED`.

## Source and commits

Repository: [package-g-op1-reusable](https://github.com/nahuelvillarroel05/package-g-op1-reusable). Implementation and V4 results: [commit `d97d7cee59bf2ae93bed61413a822ac9d9776ed8`](https://github.com/nahuelvillarroel05/package-g-op1-reusable/commit/d97d7cee59bf2ae93bed61413a822ac9d9776ed8). Upstream evaluator source: [SWE-bench commit `02e7a74ffd0b707aab73d203fe87bdc7c76afc8e`](https://github.com/SWE-bench/SWE-bench/commit/02e7a74ffd0b707aab73d203fe87bdc7c76afc8e).

Relevant manifest SHA-256 values: [V1 source manifest](manifests/V1_SOURCE_MANIFEST.json), `ac2bf5ce5dae7d2e9d5ba1504790be58704b23dd0a0bddebb16e78f3428aebce`; [V4 aggregate](results/V4_AGGREGATE_PUBLIC.json), `7c4618f45c73c682f972ffa69a1b6846c2317b2fbb472ebcb2aad3dc65b18c9b`; [dataset verification](verification/MULTILINGUAL_DATASET_VERIFICATION.json), `d0adb176485a4aa59bbf5f2901c2b03326deeea133e16f6dcd3e0c15a300ba43`; [cross-verification](results/V1_OFFICIAL_CROSS_VERIFICATION.json), `1c48490d49e29a267a3c1fb455d5972713206faa4b1f53ef193ecc0caaa6fa70`. Supplement source and derived hashes are indexed in [`SOURCE_MANIFEST.json`](verification/network-recovery-20261028/SOURCE_MANIFEST.json).

### Resumen en español

PGOP1 V1 compara afirmaciones explícitas de resolución con evidencia archivada. Tres corridas generaron 36 recibos para 12 casos: seis `SUPPORTED` y seis `CONTRADICTED`. La verificación independiente dio `PASS` para 258 logs del envío completo; en el grading individual separado, seis casos resultaron resueltos y seis no, con concordancia 12/12. Esto no mide precisión general, no autentica al proveedor ni califica I7 operacionalmente.