# Agentes del backend

Este directorio implementa las etapas que reciben una tarea de auditoría,
preparan objetivos, validan evidencia y generan el informe. Los componentes se
ejecutan como servicios independientes, excepto Recon, que se ejecuta dentro del
orquestador.

## Flujo de una tarea

```text
API
  -> orchestrator_queue
  -> Orquestador (LLM y estado temporal)
       -> prepare_targets: Recon local a partir del scraping_report
       -> validate_agent: RPC a validate_queue
            -> estrategia de validación -> RPC a skills_queue
            -> evidencia -> ValidateOutput -> guard de duplicados
       -> reporter_agent: RPC a reporter_queue
            -> ReporterInput -> informe Markdown
  -> scan_events_queue -> API -> WebSocket del cliente
```

La API crea el `task_id` y envía el objetivo, el tipo de ataque, el reporte de
scraping y, cuando existe, el token. El orquestador solicita al LLM que invoque
las tres herramientas en ese orden; esta secuencia está indicada en el prompt,
no garantizada por una máquina de estados independiente.

Recon valida el reporte de scraping y selecciona solicitudes observadas como
objetivos; no llama a un agente remoto. El orquestador envía estos objetivos a
Validate. Las estrategias JWT y criptográfica pueden ejecutarse sin objetivos
de Recon; para los demás tipos, el orquestador omite la validación si no hay
objetivos. Validate selecciona la estrategia según el tipo de ataque y puede
producir una salida determinística o combinar evidencia con una respuesta
estructurada del LLM. El worker aplica el guard antes de devolver los datos.

Reporter valida los datos con `ReporterInput`, genera el Markdown y lo completa
con información determinística cuando corresponde. Si falla la validación del
contrato o la generación con el LLM, usa un informe de respaldo. Los contratos
del backend conservan `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` e `INFO`. Para la
presentación y los conteos, el informe y el panel agrupan `CRITICAL` en `HIGH`.
El informe conserva los hallazgos `INFO` en una sección informativa separada,
sin contarlos como vulnerabilidades; el panel no los muestra en ese listado.

El reportador solicita una narración clara y concisa en español y comprueba
localmente si contiene prosa claramente en inglés. En ese caso solicita una
corrección una vez; si vuelve a detectar inglés o el modelo falla, genera un
informe de respaldo y marca el resultado como parcial. La detección automática
es heurística y no garantiza identificar todos los fragmentos. Los nombres,
identificadores, comandos, cadenas de ataque y pruebas originales se conservan,
incluso cuando contienen texto en otro idioma. En el respaldo, las descripciones
idénticas de pruebas repetidas se agrupan sin eliminar sus valores de prueba.

Para los tipos XSS reconocidos que no traen clasificación OWASP de la
herramienta, el reportador añade una referencia orientativa separada:
[OWASP Top 10 A05:2025 — Inyección](https://owasp.org/Top10/2025/A05_2025-Injection/)
y CWE-79. No sustituye las clasificaciones originales ni infiere equivalencias
para otros tipos. El informe de respaldo evita desgloses de herramientas sin
hallazgos y señala cuando la referencia de ejecución del navegador no contiene
el plan necesario para reproducirla.

Para XSS confirmado por el navegador, la evidencia describe el método, el
endpoint, el parámetro y la ejecución observada; si el validador proporciona el
valor sintético enviado, también lo incluye. En XSS almacenado se indica la
limpieza cuando fue confirmada. El panel no muestra «Cómo verificar» para XSS;
el campo de pasos de verificación se conserva en los datos del backend. Para
Dalfox, la descripción identifica lo reportado por la herramienta e incluye el
contexto y la prueba únicamente cuando están disponibles. Los valores de prueba
de más de 1000 caracteres se muestran truncados y se identifican como tales.

## Archivos principales

| Ruta | Responsabilidad |
| --- | --- |
| `contract_schemas.py` | Contratos Pydantic entre Recon, Validate y Reporter. |
| `attack_types.py` | Identificadores, alias y selección de tipos de ataque. |
| `llm_factory.py` | Configuración compartida de modelos Ollama. |
| `orchestrator/main.py` | Recepción de tareas, estado de resultados, servidor HTTP y ciclo principal. |
| `orchestrator/tools.py` | Herramientas de etapas, RPC, eventos y estado intermedio. |
| `recon/main.py` | Validación del scraping y preparación determinística de objetivos. |
| `validate/worker.py` y `validate/main.py` | Recepción RPC, proyección de objetivos y proceso de validación. |
| `validate/attack_validators.py` | Estrategias, ejecución de herramientas y procesamiento de evidencia. |
| `validate/mcp_skills.py` | Comunicación RPC con el controlador de skills. |
| `validate/output_guard.py` | Protección y deduplicación de la salida de Validate. |
| `validate/helpers.py`, `context_utils.py` y `dalfox_output.py` | Contexto, normalización y procesamiento específico de resultados. |
| `validate/validate_prompts/` | Prompts de validación por tipo de ataque. |
| `reporter/worker.py`, `main.py` y `helpers.py` | Recepción RPC, generación y finalización del informe. |

Cada servicio copia explícitamente sus archivos en la imagen mediante su
Dockerfile. Si se agrega un módulo importado en ejecución, hay que incluirlo en
la imagen correspondiente.

## Estado, errores y observabilidad

- El estado intermedio (`TASK_STATE`) y los resultados consultables
  (`TASKS_RESULTS_DB`) están en memoria del proceso del orquestador; no son
  persistentes y se pierden al reiniciarlo. `GET /api/task/{task_id}` del
  orquestador consulta esos datos.
- El orquestador publica eventos de progreso y hallazgos, y al finalizar envía
  `SCAN_COMPLETE` o `SCAN_ERROR`. La publicación de eventos registra errores,
  pero no detiene la tarea si falla.
- Un fallo de Recon marca la tarea `FAILED` y hace que Validate se omita. Un
  error de Validate también marca `FAILED`. Reporter puede recibir estructuras
  vacías con la forma esperada para generar un informe, sin borrar un fallo
  previo. Una etapa con respaldo puede dejar el estado final en `PARTIAL`;
  si no hay fallos ni respaldos, Reporter lo establece como `COMPLETED`.
- La respuesta RPC incluye tiempos de procesamiento y espera cuando están
  disponibles. El orquestador agrega tiempos por etapa y duración total.
- Validate guarda snapshots de contexto en `VALIDATE_CONTEXT_OUTPUT_DIR` (por
  defecto, `validate/validate_context`). Pueden contener evidencia y datos
  sensibles. `LOG_RPC_PAYLOADS` habilita registros completos de payloads y está
  desactivado por defecto; no debe activarse sin proteger los registros.

## Pruebas sin iniciar servicios ni ejecutar ataques

Desde `code/`, con las dependencias de los tres archivos `requirements.txt`
de los agentes instaladas en un entorno virtual:

```sh
PYTHONPATH=agents:agents/orchestrator python -m unittest discover -s agents/orchestrator/tests -v
PYTHONPATH=agents:agents/recon python -m unittest discover -s agents/recon/tests -v
PYTHONPATH=agents:agents/validate python -m unittest discover -s agents/validate/tests -v
PYTHONPATH=agents:agents/reporter python -m unittest discover -s agents/reporter/tests -v
```

Las suites se ejecutan por separado porque los servicios usan nombres de
módulo iguales, como `main` y `config`. Estas pruebas ejercitan la lógica con
datos y dependencias simulados; no sustituyen una prueba de integración con
RabbitMQ, el controlador de skills y Ollama.
