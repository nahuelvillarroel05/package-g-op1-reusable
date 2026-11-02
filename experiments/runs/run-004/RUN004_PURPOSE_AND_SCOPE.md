# RUN-004: propósito y alcance prospectivos

Evaluación experimental completa de la capacidad de PGOP1 para procesar y auditar evidencias auténticas de seis familias de benchmarks, detectar defectos reproducibles y medir cobertura, robustez, comparabilidad e integridad.

Familias: SWE-bench; SWE-bench Pro V2; Terminal-Bench 2.0; MCPMark Verified; BFCL V4; τ²-bench 2.0.

Integración exhaustiva del corpus público seleccionado: inventariar la población completa de cada revisión elegida, asociar tareas a outputs auténticos y evidencia oficial compatible, justificar toda exclusión y medir cobertura sobre denominadores explícitos. Los 155 slots históricos son una propuesta anterior preservada; NO son una cuota ni límite de esta campaña. No ampliar silenciosamente sus freezes ni reutilizar sus 20 casos BFCL como contrato final completo. La selección revisada exige manifiesto nuevo, revisión prospectiva y aprobación antes de ejecutar.

Distinguir tareas inventariadas, casos con resultados auténticos, casos elegibles y casos efectivamente evaluados. No sumar sin compatibilidad los conteos heredados: BFCL source_available=20 representa selección previa; otros campos describen corpus/tareas o archivos, no universos equivalentes. Casos efectivamente evaluados por RUN-004: 0. El piloto separado de 55 casos no cuenta como RUN-004 ni como calificación semántica independiente.

Las seis fichas de preparación existentes fueron inspeccionadas y referenciadas por SHA-256 en SIX_FAMILY_READINESS.json. Ninguna familia acredita preparación completa. SWE tiene solapamientos y método/evidencia incompletos; Pro V2 carece de outputs asociados; Terminal-Bench y MCPMark tienen adquisiciones parciales pero faltan compatibilidad exacta, derechos, piloto y método; BFCL conserva selección parcial, custodia/revisión incompleta y desarrollo expuesto; τ² carece de outputs/evidencia asociada y validación de método. UNKNOWN no se convierte en PASS.

Resolver revisiones y hashes exactos, derecho de redistribución por artefacto, autenticidad/joins task-output-evaluator, predicados, recuperación, exclusiones, comparabilidad y auditoría de las seis familias antes de declarar preparación completa. Mantener BFCL 0–19 y 40–59 y SWE15 del piloto fuera de la selección prospectiva independiente; dos reservas adicionales de piloto permanecen excluidas. El incidente de acceso BFCL metadata-only mantiene elegibilidad UNKNOWN. Desarrollo reutilizado debe declararse desarrollo, nunca holdout independiente.

Estado: RUN-004=NOT_EXECUTED; preparación=BLOCKED_WITH_EXACT_LIMITATIONS; contrato final=NOT_APPROVED; freeze final=NOT_ISSUED. No nuevas adquisiciones ni benchmark/model/tool calls en esta intervención. La futura ejecución exige contrato completo, aprobación/freeze verificables y autorización explícita adicional. Alcance de calificación formal: NONE.
