# PGOP1 — Current State

Verificado: 2026-10-28. Índice mutable; no sustituye evidencia primaria, contratos, freezes o decisiones del Owner. Verificar afirmaciones críticas antes de actuar. Entrada: [AGENTS.md](AGENTS.md); siguiente intervención: [NEXT_STEP.md](docs/engineering/NEXT_STEP.md).

## Identidad y checkout

PGOP1 (Package-G OP1 Reusable): infraestructura de ejecución controlada, evidencia verificable, causalidad, procedencia y auditoría consultiva de afirmaciones de agentes.

Repositorio: [package-g-op1-reusable](https://github.com/nahuelvillarroel05/package-g-op1-reusable). Checkout: `Engineering/PGOP1_RUN_001/repo` bajo SWEbench, separado del histórico Package-G-OP1. Rama `feat/pgop1-run-001`; HEAD verificado: `af95c484813c8e6180f72be8c86896f5aab23305`. Árbol versionado inicialmente limpio. Consulta remota: misma rama/HEAD y `main=b2483bed23be2ccbcdcc1e5e4c8e26943758b874`. RUN-001 está publicado en su rama; estos documentos quedan para revisión/commit.

## Implementación disponible

- `src/package_g/`: selección del núcleo histórico consolidado I0–I6. Sus freezes conservan identidades y ámbitos originales; la publicación no incluye todos los helpers nativos privados. [Matriz de fases](docs/I0_I7_STATUS.md).
- `runtime/candidate/`: composición experimental I7, no promovida. Proveedores fijos, Evidence Engine, API [i7_api.py](runtime/candidate/i7_api.py), CLI [pg_i7.py](runtime/candidate/pg_i7.py), recuperación y consultas; MCP stdio de diez herramientas en `pg_i7_mcp/`. Implementados y validados en ámbitos acotados.
- [Context Engine v0.1](runtime/candidate/context_engine.py): objetos fuente y JSON versionados inmutables; índice SQLite reconstruible. Verifica bytes, asociaciones y consistencia de grafo/procedencia, sin resolver la semántica de los predicados. [Arquitectura](docs/ARCHITECTURE.md).
- I4-NEXT/I5-NEXT integran grafos y atribución prospectiva mediante `runtime/candidate/deps/i4_i5/`; son distintos de formal I4/I5. Preservar orígenes de importación y pins; no anteponer `src` histórico al entorno del runtime/MCP.
- Adaptador SWE-bench V1 en [adapter.py](runtime/candidate/swebench_claim_audit/adapter.py), conservado. La generalización aditiva en [generalized.py](runtime/candidate/swebench_claim_audit/generalized.py) expone `audit_file` y `audit_evidence`, parsers explícitos/versionados y predicados separados. [generalized_bridge.py](runtime/candidate/swebench_claim_audit/generalized_bridge.py) conecta resultados con el Engine real; `prepare_plan.py`, `campaign.py` y `bind_campaign.py` gestionan planes congelados, ejecución durable e integración por lotes.

Contrato: [GENERALIZED_ENGINE.md](docs/swebench-claim-audit/GENERALIZED_ENGINE.md). Pruebas: [histórico](tests/test_swebench_claim_audit.py), [generalización](tests/test_swebench_generalized.py), [bridge](tests/test_swebench_generalized_bridge.py), [campañas](tests/test_swebench_campaign.py). [Audit A](runs/run-001/audit/AUDIT_A_FINAL.md) registra 136 pruebas aprobadas, no reejecutadas aquí. No trasladar el adaptador a `src` sin decisión del Owner.

## Restricciones históricas vigentes

```text
I0-I6=FORMALLY_FROZEN
I7=INCOMPLETE
FORMAL_I7=NOT_COMPLETED
OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED
INDEPENDENT_CUSTODY=NOT_PROVEN
PHYSICAL_C2=DEFERRED_NOT_WAIVED
```

[Calificación pendiente](docs/OPERATIONAL_QUALIFICATION_PENDING.md): Source025 original cerrado/aceptado 0/6; OD05 aceptado 0/3; E30 no ejecutado; OD03 ampliado diferido por Owner. Las validaciones de ingeniería no cierran estas obligaciones. El cliente Ornith está publicado, pero su calidad requerida conserva FAIL y validación final V6 PENDING.

## Campañas y commits

Primera campaña/V1: 12 instancias seleccionadas, tres corridas, 36 recibos; seis `SUPPORTED` y seis `CONTRADICTED` sobre esas 12 instancias. La reconstrucción oficial posterior cubrió 258 logs; la comparación individual separada concordó 12/12. No es precisión general ni ejecución fresca de patches. [Resumen V1](runs/swebench-claim-audit-v1/CAMPAIGN_SUMMARY.md).

Commits verificados, ancestros del HEAD publicado:

| Commit | Función |
| --- | --- |
| `d97d7cee59bf2ae93bed61413a822ac9d9776ed8` | Implementación V1 y resultados V4 |
| `1086320b33e37ed07786dad2ecc2fdf34b3bd738` | Publicación de regrade y resumen V1 |
| `47ef38455f44f91379f610e71fd1489d61526fdc` | Generalización inicial; no es el código final ejecutado |
| `0305a35d43661729f4a6061262cd452d62090a98` | Reparación de identidad de claims; código ejecutado RUN-001 |
| `af95c484813c8e6180f72be8c86896f5aab23305` | Publicación de resultados RUN-001 |

RUN-001: `PGOP1_RUN_001_PARTIAL_WITH_EXACT_LIMITATIONS`. [Resumen](runs/run-001/CAMPAIGN_SUMMARY.md), [resultados](runs/run-001/RESULTS_SUMMARY.json), [cobertura](runs/run-001/COVERAGE_REPORT.json) y [código/hash por archivo](runs/run-001/CODE_REFERENCE.json).

| Medida | Valor y denominador |
| --- | --- |
| SOURCE_FILES | 25.580 archivos accesibles inventariados y hasheados; 830.354.973 bytes |
| PROCESSING_ATTEMPTS | 3.802 archivos pertinentes: 2.901 principales + 901 referencias suplementarias |
| SUPPORTED_FORMATS | 1.744/3.802 archivos aceptados por parsers acotados; no cantidad de tipos de formato |
| UNSUPPORTED_FORMATS | 2.045/3.802 archivos sin soporte de parser |
| PROCESSING_ERRORS | 13/3.802; rechazos incluidos, no adicionales |
| AUDITS | 266 registros de ejecución asociados: 264 INSUFFICIENT_EVIDENCE + 2 INTEGRITY_FAILURE |
| CLAIMS_WITH_INSUFFICIENT_EVIDENCE | 351/351 ocurrencias: 235 TASK_COMPLETED + 116 ISSUE_RESOLVED |
| CONTEXT_ENGINE_VERIFIED_UNITS | 4.068 = 3.802 procesamientos + 266 auditorías; 163 lotes |

1.744 + 2.045 + 13 = 3.802. Hay 264 trayectorias JSON, distintas de las 266 auditorías. Ninguna afirmación resultó SUPPORTED o CONTRADICTED: falta evidencia correspondiente a sus predicados reales.

Level B nativo: 247/258 completados, 193 acuerdos, 54 discrepancias, 11 errores de decodificación. Protocolo UTF-8 separado, con el mismo código: 258/258 completados y concordantes con informes archivados (201 true, 57 false). Ambos intentos quedan preservados; Level C fresco `NOT_PERFORMED`. [Audit B](runs/run-001/audit/AUDIT_B_FINAL.md).

## Observabilidad local

`PGOP1_AGENT_USAGE_RECOVERED_AND_VALIDATED`: reconstrucción compatible validada, `ORIGINAL_IMPLEMENTATION_NOT_RECOVERED`, no ejecutable histórico original. Herramienta local y experimental, fuera del repositorio; raíz local relativa al checkout: `../../../PGOP1_AGENT_USAGE_RECOVERY_001/`. Referencias locales: `FINAL_HANDOFF.md`, `TECHNICAL_AUDIT.md`, `results/HISTORICAL_VALIDATION.json`, `results/RUN001_AGENT_USAGE.json` y `results/RUN001_USAGE_SUMMARY.md` bajo esa raíz. No están publicadas en Git.

RUN-001: AGENTS=7, MODEL_RESPONSES=682, RECORDED_TOOL_CALLS=596, OBSERVED_TOKENS=102601824. Tokens = 102124120 entrada + 477704 salida; caché y razonamiento son subconjuntos. Siete sesiones vinculadas; no facturación ni consumo global. No equivalen a `/goal` (1658570) ni a capturas parciales. ZIP local `PGOP1_AGENT_USAGE_RECOVERY_HANDOFF.zip`, SHA-256 `21f908e9c65f30bcc24bed7b1b9e89bcec21398cb9f4aad00dd8fd40ba73edd5`; recibo `FINAL_ZIP_VERIFICATION.json`.

## Límites y siguiente acción

Persisten formatos sin soporte (incluidas 300 transcripciones Markdown), 13 errores, 25 directorios inaccesibles, extractor inglés acotado y cobertura incompleta. Seis shards suman 3.642 membresías y 2.819 instance IDs únicos; los solapamientos no son problemas independientes. Los 49 casos reservados por repositorio comparten procedencia histórica: holdout de trayectorias independiente=0 y denominador de etiquetas semánticas independientes=0. No hay métricas de precisión/FP/FN acreditadas ni autenticación de procesos upstream; revisiones de fuentes no verificadas permanecen UNKNOWN. [Cobertura de datos](runs/run-001/DATASET_COVERAGE_REPORT.md).

Objetivo preparado: `PGOP1_CLAIM_AUDIT_COVERAGE_AND_SEMANTIC_VALIDATION`, en [NEXT_STEP.md](docs/engineering/NEXT_STEP.md). No inicia V2, RUN-002 ni procesamiento masivo; no concede promoción o autoridad operacional.
