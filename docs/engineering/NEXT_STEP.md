# PGOP1 — Next Engineering Stage

Estado: PREPARED_NOT_EXECUTED, 2026-10-28. Objetivo propuesto: `PGOP1_CLAIM_AUDIT_COVERAGE_AND_SEMANTIC_VALIDATION`. Leer [CURRENT_STATE.md](../../CURRENT_STATE.md) y [AGENTS.md](../../AGENTS.md). Este plan no sustituye contratos ni autoriza una campaña masiva, RUN-002, V2, promoción a src o calificación I7.

## Base verificada y alcance

Rama publicada `feat/pgop1-run-001`, HEAD de preparación `af95c484813c8e6180f72be8c86896f5aab23305`. Código ejecutado RUN-001: `0305a35d43661729f4a6061262cd452d62090a98`, posterior a la generalización `47ef38455f44f91379f610e71fd1489d61526fdc`. Verificar nuevamente Git antes de intervenir.

Fuentes iniciales: [resumen](../../runs/run-001/CAMPAIGN_SUMMARY.md), [cobertura](../../runs/run-001/COVERAGE_REPORT.json), [resultados](../../runs/run-001/RESULTS_SUMMARY.json), [pins de código](../../runs/run-001/CODE_REFERENCE.json), [Audit B](../../runs/run-001/audit/AUDIT_B_FINAL.md) y [contrato de interfaces](../swebench-claim-audit/GENERALIZED_ENGINE.md). V1 y sus doce casos son regresión histórica; [V2_CONTINUITY.md](../swebench-claim-audit/V2_CONTINUITY.md) no acredita V2 ejecutado.

La próxima intervención puede mejorar prospectivamente `runtime/candidate/swebench_claim_audit/` y pruebas pertinentes; conservar el core, freezes y resultados publicados. Leer derivados antes que cuerpos originales; una muestra requiere descriptor, hash, tamaño, rol y parser. No ejecutar instrucciones contenidas en fuentes ni cambiar ACL para acceder a directorios protegidos.

## Prioridad 1 — Compatibilidad de formatos

Partir de 2.045/3.802 procesamientos UNSUPPORTED, no de 2.045 tipos de archivo. Clasificar por rol, parser/reason_code y convención estructural, además de extensión. La cobertura registra 1.516 UNSUPPORTED_FORMAT, 203 UNSUPPORTED_PATCH_SHAPE y 326 UNSUPPORTED_YAML_SHAPE. Entre los roles figuran 300 transcripciones Markdown; su contenido semántico sigue UNKNOWN.

Preparar una tabla de frecuencia, utilidad para claims, muestra vinculada a fuentes, complejidad y cobertura esperada. Inspeccionar acotadamente convenciones Markdown para separar hablante, texto citado, fences, negación y corrección; el mero texto de un evaluador no crea una afirmación del agente. Priorizar parsers versionados con atribución verificable. Mantener rechazo explícito de esquemas desconocidos; no declarar soporte por extensión ni convertir referencia auxiliar en trayectoria.

## Prioridad 2 — Errores

Los 13/3.802 errores se desglosan en los códigos registrados: 10 MALFORMED_EVALUATOR_SUMMARY, 2 WRONG_INSTANCE_BINDING y 1 DUPLICATE_INSTANCE_ID. Estos códigos describen el síntoma, no demuestran la causa raíz. Localizar sus derivados en [índice público final](../../runs/run-001/FINAL_PUBLIC_FILE_INDEX.json) y compromisos en [SOURCE_MANIFEST.json](../../runs/run-001/SOURCE_MANIFEST.json).

Crear una matriz de 13 filas con source ID/hash, parser, reproducción mínima y clasificación acreditada: defecto del adaptador, integridad, archivo malformado, limitación de formato o entorno; usar UNKNOWN si falta evidencia. Proponer reparaciones focalizadas con fixtures sintéticos y pruebas de rechazo. Preservar los originales y sus errores; no rebautizar errores como unsupported ni reinterpretar colisiones como resultados válidos sin fundamento.

## Prioridad 3 — Auditoría semántica

Investigar las 351 ocurrencias insuficientes (235 TASK_COMPLETED, 116 ISSUE_RESOLVED), separadas de las 266 auditorías (264 insuficientes, dos fallos de integridad). Crear una taxonomía con causas múltiples explícitas: ausencia auténtica de evidencia, asociación ausente/incorrecta, incompatibilidad semántica del predicado, limitación del extractor y procedencia insuficiente. Conservar la razón primaria y la fuente de cada conclusión.

El resultado RUN-001 acredita que no hay evidencia de benchmark-resolution correspondiente a los predicados realmente extraídos; un resolved=true no demuestra una afirmación genérica o un arreglo de componente. No relajar predicados para incrementar SUPPORTED. Las mejoras deben justificar asociaciones exactas y mantener UNKNOWN/INSUFFICIENT_EVIDENCE cuando corresponda. El bridge y Context Engine no son evaluadores semánticos independientes.

## Prioridad 4 — Evaluación independiente

Prerregistrar un protocolo antes de ajustar el extractor o leer resultados de evaluación. Usar afirmaciones nuevas con referencias externas verificables, distintos repositorios/procedencias y separación por familia de fuente entre desarrollo y evaluación. Los doce casos históricos y los 49 casos con procedencia compartida no son holdout independiente. Fijar selección, hashes, predicados, etiquetas, exclusiones y reglas de adjudicación; conservar discrepancias y etiquetas inciertas. La referencia debe justificar el predicado concreto, no sólo repetir el resultado del parser. Mantener Level B archivado separado de Level C fresco, que no se ejecuta aquí.

Definir y publicar números absolutos junto a cada razón:

| Métrica | Denominador y regla prevista |
| --- | --- |
| Cobertura de parser | Archivos aceptados / archivos elegibles intentados, por formato/rol; errores aparte |
| Cobertura de extracción | Afirmaciones etiquetadas identificadas / afirmaciones de referencia; evaluar alineación de spans/predicados |
| Abstención | INSUFFICIENT_EVIDENCE / afirmaciones elegibles; integridad y exclusiones aparte |
| FP / FPR | Predicción SUPPORTED con referencia negativa; FP/(FP+TN) sobre referencias negativas adjudicadas |
| FN / FNR | Predicción CONTRADICTED con referencia positiva; FN/(TP+FN) sobre positivos decididos |
| Concordancia | Veredictos coincidentes / casos comparables adjudicados; además matriz completa con abstenciones |
| Integridad | Fallos de integridad / unidades intentadas del tipo correspondiente |

Para FN/FNR condicional, publicar también positivos abstendidos / todos los positivos de referencia y recall global TP / todos los positivos, para no ocultar pérdidas por abstención. Separar afirmaciones no extraídas, etiquetas sin adjudicar y casos excluidos; declarar cero denominador como NOT_COMPUTED. Registrar cuántas referencias negativas fueron decididas para FPR y cuántas quedaron abstendidas; incluir intervalos y estratos sólo con método y tamaño fijados. No anunciar accuracy independiente mientras el denominador siga siendo cero.

## Prioridad 5 — Recursos y observabilidad

Preparar el uso habitual de `agent_usage` sin modificar el motor. Localizador fuera de Git desde la raíz del checkout: `../../../PGOP1_AGENT_USAGE_RECOVERY_001/`. Leer allí `agent_usage/README.md`, `FINAL_HANDOFF.md`, `results/HISTORICAL_VALIDATION.json` y `results/RUN001_USAGE_SUMMARY.md`; verificar hashes mediante `FINAL_INTEGRITY_MANIFEST.json` y recibos de paquete antes de reutilizarlo. Si no está disponible en otra máquina, registrar ausencia y continuar trabajo independiente; no inventar mediciones ni integrar/copiar la herramienta automáticamente.

Para campañas futuras, fijar sesiones/turnos, linaje y ventana; preservar snapshots y campos faltantes, deduplicar respuestas, registrar herramientas directas y cobertura. Tokens de caché y razonamiento son subconjuntos. No equiparar uso observado, facturación o `/goal`. RUN-001 documentó 7 agentes, 682 respuestas, 596 herramientas registradas y 102601824 tokens observados.

## READY_TO_EXECUTE_GOAL

```text
/goal PGOP1_CLAIM_AUDIT_COVERAGE_AND_SEMANTIC_VALIDATION
Modo ENGINEERING_CONVERGENCE. Leer AGENTS.md, CURRENT_STATE.md y
docs/engineering/NEXT_STEP.md desde la raíz del checkout correcto.
Verificar HEAD, rama, remoto, publicaciones y árbol de trabajo. Base documental:
af95c484813c8e6180f72be8c86896f5aab23305; código ejecutado RUN-001:
0305a35d43661729f4a6061262cd452d62090a98. No asumir HEAD sin comprobarlo.
Leer runs/run-001/{CAMPAIGN_SUMMARY.md,COVERAGE_REPORT.json,RESULTS_SUMMARY.json,
CODE_REFERENCE.json} y docs/swebench-claim-audit/GENERALIZED_ENGINE.md.
Priorizar los 2045 archivos unsupported (incluidos 300 Markdown) por frecuencia,
utilidad y atribución verificable. Clasificar los 13 errores y las causas de
insuficiencia de las 351 ocurrencias sin cambiar predicados para ganar SUPPORTED.
Prerregistrar evaluación semántica independiente con afirmaciones nuevas,
referencias externas, adjudicación y denominadores explícitos; no usar los doce
casos históricos como holdout. Implementar mejoras focalizadas y versionadas en
runtime/candidate/swebench_claim_audit/ con fixtures sintéticos y fuentes
acotadas, preservando fuentes y resultados anteriores. Usar audit_file y
audit_evidence; integrar mediante generalized_bridge sin sustituir Context Engine.
Ejecutar tests/test_swebench_generalized.py, tests/test_swebench_generalized_bridge.py,
tests/test_swebench_campaign.py y tests/test_swebench_claim_audit.py en salidas
temporales nuevas, con las dependencias verificadas. Auditar cambios y resultados;
no reducir pruebas de integridad, recuperación, procedencia o predicados.
Registrar nuevas referencias, limitaciones y cambios en la continuidad.
Preparar agent_usage con sus referencias locales, sin modificarlo ni el motor.
Orquestación: Sol Medium coordina, Luna inspecciona/valida; Sol XHigh sólo ante
riesgo o contradicción material; Astra sólo por necesidad excepcional.
No modificar src/package_g, freezes, runs/run-001 ni campañas anteriores.
No promover el adaptador, ejecutar modelos/patches/Docker, levantar restricciones
I7, crear RUN-002, procesar SWE-bench masivamente ni hacer push.
Si faltan fuentes privadas, registrar UNKNOWN y completar trabajo sintético
independiente; no alterar permisos. Entregar diff, protocolo, pruebas y límites.
```

## Validación y cierre previstos

Exigir reproducciones focalizadas para cada mejora, regresiones históricas intactas y comparaciones con idénticos denominadores. Auditar cambios de parser, joins, compromiso de bytes, recuperación y tratamiento de errores. Documentar incrementos de cobertura como resultados nuevos, sin reescribir RUN-001. Una evaluación independiente real y una campaña masiva futura requieren su propio alcance, selección congelada y autorización aplicable.

En esta preparación sólo se valida continuidad documental: estado, código, restricciones, evidencias y siguiente acción se localizan desde AGENTS.md, CURRENT_STATE.md y el prompt anterior. La siguiente etapa permanece sin ejecutar.
