# Arquitectura experimental permanente PGOP1

Rama central: `experimental/pgop1-runs`, desde publicación revisada RUN-003 `5d692882bdd625ca57d82f77d62b1ea830fe9c15`. Ver [arquitectura](experiments/README.md), [política](experiments/EXPERIMENTAL_POLICY.md), [registro](experiments/RUN_REGISTRY.json). Los commits de esta intervención sólo agregan gobernanza y actualizan índices actuales; los contratos/resultados anteriores se preservan.

El candidato piloto `f424c86fc73b077606f5ca7a092f9f29c42485ee` permanece en `feat/pgop1-independent-pilot-001`; no se integró automáticamente. El índice central refiere sus evidencias privadas mediante compromisos SHA-256. La base central no equivale al código más reciente del piloto ni declara su ejecución.

RUN-001/002 conservan publicación histórica por recibos; estado remoto actual no consultado. RUN-003 publicación histórica BLOCKED_AUTHENTICATION; rama central local sin push. No se probaron credenciales. RUN-004=NOT_EXECUTED; seis familias con preparación incompleta, contrato DRAFT sin aprobación/freeze final. Sin cuota de 155. Piloto separado: 55 casos de desarrollo, no calificación semántica independiente.

I0-I6=FORMALLY_FROZEN; I7=INCOMPLETE; FORMAL_I7=NOT_COMPLETED; OP1_OPERATIONAL_QUALIFICATION=NOT_ACHIEVED; INDEPENDENT_CUSTODY=NOT_PROVEN; PHYSICAL_C2=DEFERRED_NOT_WAIVED; GATE_11=BLOCKED. OD03/Source025/OD05 no cerrados por esta intervención. Independencia semántica NOT_ACHIEVED; precisión/recall NOT_COMPUTABLE. No campaña, modelos, entrenamiento, GOLD, main, src promotion ni cambio de freezes.

Siguiente: [preparación contractual y revisión](docs/engineering/NEXT_STEP.md). Ningún índice concede autoridad de ejecución.
