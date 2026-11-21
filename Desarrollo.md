# Manual de desarrollo — SECURE

## 1. Propósito del documento

Este manual describe cómo comprender, mantener y extender SECURE. Está dirigido a quienes desarrollen el frontend, la API, los agentes, el controlador de herramientas o el laboratorio. Complementa la [guía de instalación](./Instalacion.md), que contiene el procedimiento de preparación inicial, y el [informe final](./InformeFinal.md).

> **Uso autorizado:** SECURE y Dulce Nube están destinados a laboratorios o entornos de prueba autorizados. Dulce Nube es deliberadamente vulnerable. No despliegues esta configuración en producción ni la expongas a Internet. El controlador y Portainer tienen acceso al socket Docker, que concede control privilegiado sobre el host.

Los comandos de este manual usan PowerShell y parten del directorio `code`, salvo que se indique lo contrario. En otros sistemas, adapta las rutas y el separador de `PYTHONPATH`.

## 2. Descripción general del proyecto desde la perspectiva de desarrollo

SECURE es una plataforma web para asistir el análisis de seguridad. Su arquitectura combina una interfaz cliente-servidor con mensajería asíncrona y eventos de progreso. La API encola una tarea; el orquestador prepara objetivos a partir de un reporte de scraping y coordina la validación y el reporte. Las herramientas se solicitan al controlador mediante mensajes MCP sobre RabbitMQ. El panel recibe eventos a través de la API.

La aplicación no demuestra por sí sola que un objetivo sea seguro. Los resultados deben ser revisados por una persona; los errores y resultados inconclusos no equivalen a ausencia de vulnerabilidades.

### 2.1 Tecnologías principales

| Área | Tecnologías y función |
|---|---|
| Frontend | TypeScript, React y Next.js; interfaz y panel de análisis. |
| API | Python, FastAPI y Pydantic; recepción de tareas y WebSocket. |
| Agentes | Python, LangChain/LangGraph y Pydantic; orquestación, validación y reporte. |
| Modelo | Ollama y un modelo configurado localmente; la plantilla propone Qwen 2.5. |
| Mensajería | RabbitMQ y `aio-pika`; tareas, solicitudes RPC y eventos. |
| Herramientas | Controlador MCP, adaptadores, Python y contenedores Docker. |
| Laboratorio | Node.js, Express y SQLite mediante `better-sqlite3`; frontend HTML/CSS/JavaScript. |
| Infraestructura local | Docker Compose, redes bridge y volúmenes. |
| Automatización de navegador | Playwright para el scraper y los escenarios que requieren navegador. |

### 2.2 Componentes principales

| Componente | Responsabilidad |
|---|---|
| Frontend | Recibe el objetivo, el tipo de análisis y el informe JSON; muestra eventos y reporte. |
| API Gateway | Valida la solicitud, crea un `task_id`, publica la tarea y transmite eventos por WebSocket. |
| Orquestador | Coordina las etapas y mantiene el estado de trabajo en memoria. |
| Reconocimiento | Valida el reporte de scraping y prepara objetivos dentro del orquestador. |
| Validación | Selecciona una estrategia y transforma evidencia de herramientas en resultados estructurados. |
| Reportador | Genera y completa un informe Markdown; dispone de una salida alternativa ante ciertos fallos. |
| Skills Controller | Publica el catálogo y procesa solicitudes de herramientas; puede lanzar contenedores temporales. |
| RabbitMQ | Transporta tareas, respuestas RPC y eventos de progreso. |
| Dulce Nube (`weak-page`) | Aplicación vulnerable y base SQLite para pruebas controladas. |

## 3. Estructura del repositorio

### 3.1 Árbol general del repositorio

```text
SECURE/
├── README.md
├── Instalacion.md
├── Desarollo.md
├── InformeFinal.md
├── PrimerInforme.md
├── SegundoInforme.md
└── code/
    ├── .env.example
    ├── docker-compose.yml
    ├── api/
    ├── frontend/
    ├── agents/
    │   ├── orchestrator/
    │   ├── recon/
    │   ├── validate/
    │   └── reporter/
    ├── skills_controller/
    │   ├── docker_images/
    │   ├── handlers/
    │   ├── tests/
    │   └── tools/
    ├── scripts/
    └── weak_page/
        ├── backend/
        ├── css/
        └── js/
```

### 3.2 Descripción de directorios y archivos relevantes

| Ruta | Contenido |
|---|---|
| `code/docker-compose.yml` | Servicios, redes, puertos y volúmenes del entorno local. |
| `code/.env.example` | Plantilla de configuración; copiar a `.env` y sustituir valores locales. |
| `code/frontend/` | Aplicación Next.js, componentes, hooks, servicios, tipos y pruebas del panel. |
| `code/api/` | FastAPI, modelos de entrada, cliente RabbitMQ y gestor WebSocket. |
| `code/agents/` | Contratos compartidos, configuración del LLM y etapas del flujo. Véase [agentes](./code/agents/README.md). |
| `code/skills_controller/` | Catálogo MCP, worker, ejecutor Docker, adaptadores e imágenes de herramientas. |
| `code/scripts/` | Scraper del laboratorio, imagen auxiliar, pruebas y reporte JSON de ejemplo. |
| `code/weak_page/` | Dulce Nube: aplicación vulnerable, backend, datos y escenarios configurables. |

## 4. Organización de la solución a nivel de código

### 4.1 Organización por módulos o capas

El proyecto separa presentación (`frontend`), entrada (`api`), coordinación y análisis (`agents`), ejecución de herramientas (`skills_controller`) y aplicación objetivo (`weak_page`). RabbitMQ es el intermediario de mensajería. Ollama se ejecuta en el host para proporcionar inferencia a los componentes configurados.

Las colas transportan tareas y eventos, además de solicitudes y respuestas RPC: no toda comunicación es un evento. El panel usa HTTP y WebSocket con la API. La separación en contenedores no implica que todos los módulos sean agentes independientes: Recon se ejecuta dentro del orquestador.

### 4.2 Relación entre componentes del sistema y código fuente

```text
Panel -> API -> orchestrator_queue -> Orquestador
                                      -> Recon local
                                      -> validate_queue -> Validación
                                            -> skills_queue -> Skills Controller
                                      -> reporter_queue -> Reportador
      <- WebSocket <- API <- scan_events_queue <- eventos
```

1. `api/main.py` recibe `POST /api/task`, genera el identificador y publica el mensaje. El cuerpo requiere `target_url`, `category`, `attack_type` y `scraping_report`; `token` es opcional.
2. `agents/orchestrator/main.py` y `tools.py` coordinan la tarea y publican eventos. El orden de etapas se indica al modelo en un prompt; no lo garantiza una máquina de estados independiente.
3. `agents/recon/main.py` valida el reporte y selecciona solicitudes observadas. No ejecuta un crawler remoto en cada tarea.
4. `agents/validate/worker.py`, `main.py` y `attack_validators.py` procesan objetivos, seleccionan estrategias y estructuran evidencia. `mcp_skills.py` realiza solicitudes RPC al controlador.
5. `skills_controller/worker.py` recibe `tools/list` y `tools/call`; `mcp_server.py` consulta `tools/mcp_tools_registry.py`, ejecuta handlers o usa `docker_runner.py`.
6. `agents/reporter/` valida la entrada y genera el informe. La API consume eventos y los transmite a `/ws/scans/{task_id}`.

Los contratos compartidos están en `agents/contract_schemas.py`. Algunos tipos, como JWT y criptografía, pueden ejecutarse sin objetivos preparados por Recon. Consulta [el README de agentes](./code/agents/README.md) para estados, contratos y recuperación.

## 5. Contenedores

### 5.1 Contenedores utilizados

| Servicio de Compose | Función |
|---|---|
| `frontend` | Panel Next.js. |
| `api` | API Gateway. |
| `rabbitmq` | Broker AMQP y consola de administración. |
| `orchestrator` | Coordinación y Recon local. |
| `validate-agent` | Validación de evidencia y ejecución de estrategias. |
| `reporter-agent` | Generación del informe. |
| `skills-controller` | Catálogo MCP y ejecución de herramientas. |
| `weak-page` | Laboratorio Dulce Nube y su backend SQLite. |
| `portainer` | Administración local de Docker; también monta el socket del host. |
| `build-*` | Construcción y preparación de imágenes auxiliares de herramientas. |
| `scrapper` | Scraper opcional, activado mediante el perfil `scraper`. |

El controlador puede crear contenedores efímeros para herramientas; no son servicios permanentes de Compose. Algunas herramientas tienen handlers propios, por lo que su ruta de ejecución debe verificarse en el registro y en el handler correspondiente.

### 5.2 Archivos relacionados con contenedores

- `code/docker-compose.yml`: configuración principal.
- `code/frontend/Dockerfile.frontend` y `code/api/Dockerfile.api`: imágenes del panel y la API.
- `code/agents/orchestrator/`, `validate/` y `reporter/`: Dockerfiles y dependencias de cada etapa.
- `code/skills_controller/Dockerfile.skills_controller` y `docker_images/`: controlador e imágenes de herramientas.
- `code/weak_page/Dockerfile`: laboratorio.
- `code/scripts/Dockerfile.scrapper`: scraper y Chromium.

Los Dockerfiles de los agentes copian archivos explícitamente. Si un módulo nuevo es necesario en ejecución, revisa que se copie en la imagen correspondiente.

### 5.3 Construcción y ejecución de contenedores

Desde `code`, después de configurar `.env` y arrancar Docker y Ollama:

```powershell
docker compose up --build -d
docker compose ps
docker compose logs -f api orchestrator validate-agent reporter-agent skills-controller
```

Para terminar la lectura de registros, usa `Ctrl+C`. Para detener los servicios:

```powershell
docker compose down
```

La primera construcción descarga dependencias e imágenes y puede tardar. `down` conserva los volúmenes nombrados; no los elimines si necesitas los datos del laboratorio o de Portainer.

### 5.4 Redes, puertos y volúmenes

| Recurso | Uso |
|---|---|
| `public-net` | Frontend, API y orquestador. |
| `internal-net` | API, RabbitMQ, orquestador, validación, reporte y controlador. |
| `sec-net` | Laboratorio, controlador, validación, reporte y, por defecto, herramientas efímeras. |
| `3000`, `8000`, `8001` | Frontend, API y orquestador, respectivamente. |
| `5672`, `15672` | AMQP y administración de RabbitMQ. |
| `127.0.0.1:3009` | Laboratorio accesible desde el host; entre contenedores se usa `http://weak-page:3009`. |
| `127.0.0.1:9443` | Interfaz local de Portainer. |
| `weak-page-db` y `portainer_data` | Persistencia del laboratorio y de Portainer. |
| Montajes del controlador y de validación | Salidas de herramientas y snapshots de contexto en directorios del host. |

Las redes son de tipo `bridge`, no una garantía de aislamiento completo. Compose publica algunos puertos sin restringirlos a `127.0.0.1`; protege el host y revisa la exposición antes de iniciar el entorno. El controlador y Portainer montan el socket Docker: limitar el acceso a sus contenedores y al host es esencial.

### 5.5 Recomendaciones para modificar contenedores

- Revisa `depends_on`, nombres de red y rutas de montaje antes de cambiar un servicio.
- Reconstruye la imagen afectada cuando cambien sus archivos o dependencias; comprueba el estado y los registros.
- Las etiquetas `latest` no son versiones inmutables. Registra las versiones o identificadores de imágenes cuando necesites reproducir una ejecución.
- No elimines volúmenes, bases de datos ni artefactos de otros usuarios sin confirmar su alcance.
- No expongas el socket Docker, RabbitMQ, el laboratorio ni los servicios de administración a redes no confiables.

## 6. Scripts y automatizaciones

### 6.1 Scripts principales

| Ubicación | Comando o archivo | Propósito |
|---|---|---|
| `frontend/` | `corepack pnpm dev` | Servidor de desarrollo Next.js. |
| `frontend/` | `corepack pnpm build` | Construcción de producción. |
| `frontend/` | `corepack pnpm start` | Arranque de una construcción existente. |
| `frontend/` | `corepack pnpm lint` | Ejecuta ESLint. |
| `frontend/` | `node --test .\tests\panel-view.test.mjs` | Prueba del panel con el runner de Node. |
| `scripts/` | `scrapper.py` | Captura información del laboratorio y produce un reporte de scraping. |
| `weak_page/backend/` | `npm run dev`, `npm start` | Desarrollo o inicio del backend del laboratorio. |
| `weak_page/backend/` | `npm run seed` | Inicialización de datos del laboratorio. |
| `agents/` | `python -m unittest discover` | Suites de las etapas, ejecutadas por separado. |

Los scripts del `package.json` en la raíz de `weak_page` no sustituyen al backend del laboratorio levantado mediante Compose. En particular, su script `test` es un marcador que termina con error.

### 6.2 Ubicación de scripts auxiliares

`code/scripts/` contiene el scraper, su Dockerfile y pruebas. `code/skills_controller/tools/` y `handlers/` contienen adaptadores y lógica de herramientas; `docker_images/` contiene Dockerfiles auxiliares. `code/weak_page/backend/` contiene scripts de inicio y preparación de datos del laboratorio.

Para ejecutar el scraper opcional contra el laboratorio local:

```powershell
docker compose --profile scraper run --rm scrapper
```

El servicio imprime el reporte en la terminal y está configurado para `weak-page`. El archivo `code/scripts/scraping-report.json` es un ejemplo de entrada para el panel. Comprueba que el objetivo y el reporte correspondan entre sí.

### 6.3 Consideraciones para su uso

Los scripts que interactúan con un objetivo deben ejecutarse únicamente con autorización. No uses credenciales reales ni datos de terceros en los reportes. `npm run seed` modifica datos del laboratorio y `npm run reset` elimina su base SQLite antes de recrearla; no los ejecutes sobre datos compartidos o que deban conservarse. El script `reset` usa `rm -f` y no es directamente portable a PowerShell.

## 7. Variables de entorno

### 7.1 Variables requeridas

| Variables | Uso |
|---|---|
| `RABBITMQ_USER`, `RABBITMQ_PASS`, `RABBITMQ_URL` | Credenciales y URL AMQP coherentes para el broker y los componentes. |
| `OLLAMA_BASE_URL`, `OLLAMA_DEFAULT_MODEL` | Dirección de Ollama y modelo predeterminado para los agentes. |
| `MODEL_ORCHESTRATOR`, `MODEL_VALIDATE`, `MODEL_REPORTER` | Selección de modelo por etapa; la plantilla también incluye `MODEL_RECON`. |
| `NEXT_PUBLIC_API_URL`, `INTERNAL_API_URL` | URLs de la API utilizadas por el frontend; Compose proporciona valores predeterminados. |
| `JWT_SECRET` | Secreto del laboratorio cuando se utiliza su configuración correspondiente. |
| `ACCESS_CONTROL_*` | Identidades, tokens y rutas para escenarios de control de acceso del laboratorio. |

Revisa los valores efectivos de Compose y de `.env.example`: algunas variables tienen valores predeterminados y otras deben configurarse para el escenario concreto. Las credenciales y tokens de control de acceso deben corresponder al laboratorio que se está probando.

### 7.2 Variables por ambiente

La configuración incluida está orientada al desarrollo local, no es una configuración de producción. El host de Ollama, las URL de la API, las credenciales de RabbitMQ y los datos del laboratorio dependen del entorno. `LLM_NUM_CTX`, `OLLAMA_KEEP_ALIVE` y `MAX_TOKENS_*` ajustan el uso del modelo; `LOG_RPC_PAYLOADS` controla registros detallados y debe permanecer desactivado salvo necesidad justificada.

`DOCKER_NETWORK` puede modificar la red predeterminada de los contenedores de herramientas. `VALIDATE_CONTEXT_OUTPUT_DIR` controla dónde se guardan snapshots de validación. Verifica los defaults en el código y los valores declarados en Compose antes de cambiarlos.

### 7.3 Archivos de configuración

Desde `code`, crea la configuración local si no existe:

```powershell
Copy-Item .env.example .env
```

Completa los valores necesarios sin copiar secretos al repositorio. Compose usa `.env` para interpolar variables y lo pasa a los servicios que lo declaran mediante `env_file`; además, algunas variables se establecen explícitamente en `environment`. Si existen ambas, verifica el valor efectivo y evita mostrar secretos al compartir diagnósticos.

La guía de instalación incluye el procedimiento completo de configuración de Ollama y RabbitMQ. Las claves de proveedores externos o de trazado se necesitan únicamente si se habilitan esas integraciones.

### 7.4 Manejo seguro de secretos

- No subas `.env`, claves de API, contraseñas, tokens ni reportes con datos sensibles.
- Usa credenciales diferentes a las de otros entornos y solo en el laboratorio.
- Los snapshots y registros pueden incluir solicitudes o evidencia sensible; restringe su acceso y revisa su contenido antes de compartirlos.
- Evita activar `LOG_RPC_PAYLOADS` en entornos con información sensible.
- No publiques la salida completa de configuración o registros sin revisar y redactar secretos.

## 8. Flujo de trabajo de desarrollo

### 8.1 Preparación del entorno

1. Clona el repositorio y entra en `code`.
2. Instala y arranca Docker y Ollama; descarga el modelo configurado.
3. Crea y configura `.env` con credenciales locales.
4. Levanta los servicios con `docker compose up --build -d` y revisa `docker compose ps`.
5. Para desarrollo local fuera de Docker, utiliza Node.js 24 para el frontend y Python 3.12 para los agentes. La instalación de dependencias y el primer análisis se detallan en [Instalacion.md](./Instalacion.md).

### 8.2 Desarrollo de nuevas funcionalidades

1. Identifica la etapa y su contrato: entrada de API, preparación de objetivos, estrategia de validación, salida estructurada o presentación.
2. Mantén consistentes los contratos de `agents/contract_schemas.py` y sus consumidores si cambia la forma de los datos.
3. Para una herramienta, revisa el esquema y configuración en `skills_controller/tools/mcp_tools_registry.py`, el handler o adaptador correspondiente, la imagen y la estrategia de validación. Registrar una herramienta no la incorpora automáticamente a todos los flujos.
4. Si el panel debe mostrar campos nuevos, revisa sus tipos, transformación y componentes junto con las pruebas.
5. Actualiza los Dockerfiles cuando sea necesario copiar módulos nuevos y documenta cambios de configuración, contratos y limitaciones.

### 8.3 Ejecución de pruebas y validaciones

Ejecuta la prueba más cercana al cambio. Los siguientes comandos parten de `code`; instala las dependencias locales descritas en [Instalacion.md](./Instalacion.md) si aún no están disponibles.

**Frontend:**

```powershell
Set-Location .\frontend
node --test .\tests\panel-view.test.mjs
corepack pnpm lint
Set-Location ..
```

Para comprobar la construcción del frontend, ejecuta `corepack pnpm build` desde `code/frontend`.

**Agentes:** desde `code`, con el entorno virtual y las dependencias de los agentes ya instalados:

```powershell
$env:PYTHONPATH = "agents;agents\orchestrator"
.\.venv\Scripts\python.exe -m unittest discover -s agents\orchestrator\tests -v

$env:PYTHONPATH = "agents;agents\recon"
.\.venv\Scripts\python.exe -m unittest discover -s agents\recon\tests -v

$env:PYTHONPATH = "agents;agents\validate"
.\.venv\Scripts\python.exe -m unittest discover -s agents\validate\tests -v

$env:PYTHONPATH = "agents;agents\reporter"
.\.venv\Scripts\python.exe -m unittest discover -s agents\reporter\tests -v
```

Ejecuta las suites por separado: los servicios tienen módulos con nombres iguales, como `main` y `config`. Las pruebas unitarias con simulaciones no sustituyen una integración real. Algunas pruebas del controlador importan el cliente Docker y requieren que el motor esté disponible o que se simule explícitamente.

**Laboratorio:** para el middleware de protección de pruebas sintéticas, con las dependencias del backend ya instaladas:

```powershell
Set-Location .\weak_page\backend
node --test .\test\syntheticCrawlerGuard.test.js
Set-Location ..\..
```

Otras pruebas del laboratorio pueden necesitar datos inicializados o modificar el estado. Revisa cada caso y utiliza una base de pruebas aislada antes de ejecutarlas. Las validaciones en vivo deben dirigirse exclusivamente a laboratorios autorizados.

### 8.4 Integración de cambios

Como práctica recomendada, trabaja en una rama, revisa el diff, ejecuta las comprobaciones pertinentes y solicita revisión antes de integrar. Incluye en la descripción las pruebas ejecutadas, sus resultados y las limitaciones. No se presupone una convención de nombres de ramas o commits obligatoria que no esté documentada por el equipo.

## 9. Dependencias y servicios externos

### 9.1 Servicios externos integrados

- **Ollama:** proceso local que expone el modelo a los agentes configurados.
- **RabbitMQ:** broker del entorno Compose para tareas, RPC y eventos.
- **Docker Engine:** construye y ejecuta servicios y herramientas efímeras.
- **Registros de paquetes e imágenes:** necesarios para instalar dependencias o descargar imágenes durante la construcción.
- **Proveedores y trazado opcionales:** las variables de la plantilla contemplan claves externas; no son necesarias para el flujo local documentado con Ollama.

### 9.2 Requisitos de acceso

Para el entorno local se necesita acceso al host, al motor Docker, al modelo de Ollama y a las credenciales configuradas para RabbitMQ. El análisis de control de acceso o JWT puede requerir identidades o tokens del laboratorio. Acceder a un sistema externo para analizarlo requiere autorización explícita y conectividad configurada.

### 9.3 Consideraciones de desarrollo y pruebas

Usa `weak-page` como objetivo de pruebas y datos sintéticos. Los tests unitarios pueden simular servicios y respuestas; una ejecución completa requiere las dependencias reales. Las herramientas pueden necesitar imágenes locales o descargables. Las versiones de modelos, imágenes y datos afectan la reproducibilidad; registra la configuración de las pruebas cuando sea relevante.

## 10. Convenciones del proyecto

### 10.1 Convenciones de código

- Sigue los nombres y la organización existentes en el módulo modificado.
- Mantén los contratos Pydantic, tipos del frontend y productores/consumidores sincronizados.
- En Python, ejecuta las suites de agentes por separado para evitar colisiones de imports.
- Respeta la configuración de ESLint y las dependencias fijadas por el frontend.
- Gestiona explícitamente errores, resultados parciales y casos inconclusos; no los presentes como hallazgos negativos.
- No supongas que una salida generada por el LLM está validada solo por tener la estructura esperada.

### 10.2 Convenciones de repositorio

El repositorio contiene archivos de configuración de Docker, manifiestos y lockfiles por componente. Cuando cambies dependencias, actualiza el manifiesto y el lockfile correspondientes y documenta la razón. Revisa los archivos ignorados antes de compartir salidas. Las prácticas de ramas y revisión deben acordarse con el equipo si no existe una política adicional.

### 10.3 Convenciones de documentación

Mantén [Instalacion.md](./Instalacion.md) alineado con los comandos de puesta en marcha y este manual con la estructura y el flujo actuales. Actualiza el [README de agentes](./code/agents/README.md) cuando cambien contratos, estados o etapas. Distingue entre comportamiento implementado, diseño propuesto, resultados medidos y trabajo pendiente.

## 11. Problemas frecuentes y recomendaciones

### 11.1 Problemas frecuentes

| Síntoma | Comprobación inicial |
|---|---|
| Docker no responde o falla el acceso al socket | Confirma que Docker Desktop o Docker Engine esté iniciado y que el usuario tenga acceso. |
| Un servicio no arranca | Consulta `docker compose ps` y los registros del servicio. Verifica `.env` y dependencias. |
| RabbitMQ rechaza la conexión | Comprueba que `RABBITMQ_USER`, `RABBITMQ_PASS` y `RABBITMQ_URL` coincidan. |
| El modelo no responde | Verifica que Ollama esté activo, el modelo descargado y `OLLAMA_BASE_URL` accesible desde los contenedores. |
| El objetivo no responde | Comprueba el nombre y la red; `localhost` dentro de un contenedor no identifica al host ni a `weak-page`. |
| No aparecen objetivos para validar | Verifica que el JSON de scraping sea compatible, corresponda al objetivo y contenga solicitudes relevantes. |
| Una herramienta falla o vence su tiempo | Revisa su imagen, argumentos, conectividad y registros. Un timeout es inconcluso, no una prueba de seguridad. |
| La API devuelve error al encolar | Comprueba RabbitMQ y los registros de la API antes de reintentar. |
| Fallan imports en pruebas Python | Comprueba las dependencias, el directorio de trabajo y `PYTHONPATH`; ejecuta cada suite de agentes por separado. |

### 11.2 Deuda técnica conocida

- El estado de tarea y los resultados consultables del orquestador se guardan en memoria y se pierden al reiniciar el proceso.
- La secuencia de etapas se solicita al LLM mediante instrucciones y no está garantizada por una máquina de estados independiente.
- El reporte de scraping es una entrada del flujo actual; la preparación de objetivos no ejecuta automáticamente un crawler remoto.
- La configuración usa algunas etiquetas de imagen `latest`, por lo que no fija completamente las versiones.
- La resiliencia bajo fallos, la precisión por escenario y la usabilidad requieren evidencia adicional; no se deben inferir a partir de la existencia de colas o contenedores.
- El socket Docker, los puertos publicados y los registros de evidencia requieren controles acordes con el entorno.

### 11.3 Recomendaciones para continuidad

Prioriza la conservación segura de resultados y la verificación de estados ante errores. Añade pruebas focalizadas cuando cambie un contrato o una estrategia, y registra las condiciones de las pruebas de integración. Evalúa la autorización del objetivo, el aislamiento de red y la protección de datos antes de ampliar el despliegue. Mantén la documentación sincronizada con los cambios.

## 12. Historial de decisiones técnicas relevantes

| Decisión | Motivo y consecuencia |
|---|---|
| Mensajería con RabbitMQ | Desacoplar la entrega de tareas y eventos; introduce la operación y configuración de un broker. |
| Catálogo y controlador MCP | Ofrecer una interfaz común para herramientas; cada integración aún necesita adaptadores, imágenes y estrategias apropiadas. |
| Ollama y modelo local | Reducir la dependencia de cuotas del proveedor remoto; requiere recursos y disponibilidad en el host. |
| Recon local desde scraping | Preparar objetivos a partir de un reporte proporcionado; no implica que el sistema capture automáticamente la superficie en cada tarea. |
| Contenedores para herramientas | Separar ejecuciones y gestionar imágenes; el acceso al socket Docker y las redes requieren protección. |
| Dulce Nube | Disponer de un laboratorio configurable; su vulnerabilidad deliberada impide tratarlo como un entorno de producción. |

## 13. Referencias relacionadas

- [Guía de instalación y ejecución](./Instalacion.md).
- [Informe final](./InformeFinal.md).
- [Flujo, contratos y pruebas de agentes](./code/agents/README.md).
- [Laboratorio Dulce Nube](./code/weak_page/README.md).
- [Docker Compose](https://docs.docker.com/compose/).
- [RabbitMQ](https://www.rabbitmq.com/docs).
- [Model Context Protocol](https://modelcontextprotocol.io/).
- [Ollama](https://docs.ollama.com/).
- [FastAPI](https://fastapi.tiangolo.com/), [Pydantic](https://docs.pydantic.dev/) y [Next.js](https://nextjs.org/docs).
