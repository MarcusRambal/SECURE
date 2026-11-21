# Guía de instalación, ejecución y pruebas — SECURE

Esta guía explica cómo clonar el repositorio, configurar sus servicios, iniciar la aplicación y comenzar a probarla. La instalación principal usa Docker Compose, que instala las dependencias de cada contenedor automáticamente.

> **Uso autorizado:** para empezar, utiliza únicamente el laboratorio local `weak-page` incluido en el repositorio. Ejecuta análisis contra otros sistemas solo si tienes autorización explícita. El controlador de herramientas monta el socket de Docker del host; no expongas esta instalación a Internet ni la ejecutes en un equipo compartido o de producción.

## 1. Requisitos

- Git.
- Docker Desktop con integración WSL 2 en Windows, o Docker Engine en Linux/macOS.
- Docker Compose v2 (`docker compose`; no el ejecutable antiguo `docker-compose`).
- Ollama instalado y con el servicio activo en el host.
- Al menos 16 GB de RAM y espacio libre para las imágenes y el modelo; 32 GB de RAM son recomendables. El modelo Qwen 2.5 de 7B puede funcionar sin GPU, pero será más lento.

Node.js 24 y Python 3.12 solo son necesarios para ejecutar las pruebas locales opcionales de frontend y agentes. No hacen falta para levantar la aplicación con Docker.

Comprueba que Docker está iniciado:

```powershell
docker --version
docker compose version
```

En Windows, abre Docker Desktop y espera a que indique que el motor está en ejecución. En Linux, comprueba que el servicio de Docker esté iniciado y que tu usuario pueda ejecutar `docker`.

## 2. Clonar el repositorio

Desde PowerShell, una terminal de Linux o macOS:

```sh
git clone https://github.com/MarcusRambal/SECURE.git
cd SECURE
cd code
```

Los siguientes comandos de Docker Compose deben ejecutarse desde el directorio `code`, donde están `docker-compose.yml` y `.env.example`.

## 3. Instalar y preparar Ollama

Instala Ollama desde [ollama.com](https://ollama.com). Luego, descarga el modelo que usan los agentes:

```sh
ollama pull qwen2.5:7b-instruct
ollama list
```

En Windows y macOS, el instalador suele iniciar Ollama automáticamente. En Linux, si no está activo como servicio, inicia `ollama serve` en otra terminal y déjalo ejecutándose. La configuración de Compose usa `http://host.docker.internal:11434` para que los contenedores lleguen al Ollama del host.

## 4. Configurar las variables de entorno

Desde `code`, crea el archivo local `.env` a partir de la plantilla:

```powershell
Copy-Item .env.example .env
```

En Linux/macOS:

```sh
cp .env.example .env
```

Abre `.env` y comprueba la configuración de Ollama. Para una instalación local estándar puedes conservar:

```dotenv
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_DEFAULT_MODEL=qwen2.5:7b-instruct
MODEL_ORCHESTRATOR=qwen2.5:7b-instruct
MODEL_RECON=qwen2.5:7b-instruct
MODEL_VALIDATE=qwen2.5:7b-instruct
MODEL_REPORTER=qwen2.5:7b-instruct
```

Configura también `RABBITMQ_USER`, `RABBITMQ_PASS` y `RABBITMQ_URL` con el mismo usuario y contraseña. La plantilla contiene `change-me`; sustitúyelo por credenciales de uso local, sencillas y sin caracteres reservados para evitar problemas con la URL AMQP. Por ejemplo, si eliges `securelocal` y `cambiame123`, configura:

```dotenv
RABBITMQ_USER=securelocal
RABBITMQ_PASS=cambiame123
RABBITMQ_URL=amqp://securelocal:cambiame123@rabbitmq-broker:5672/
```

Las claves `GEMINI_API_KEY`, `GROQ_API_KEY` y `LANGCHAIN_API_KEY` solo se necesitan si configuras esos servicios opcionales; no hacen falta para usar Ollama. No compartas ni subas `.env` al repositorio.

## 5. Construir e iniciar la aplicación

Desde `code`, con Docker y Ollama activos:

```sh
docker compose up --build -d
```

La primera ejecución puede tardar porque construye el frontend, la API, los agentes, el controlador de herramientas, el laboratorio vulnerable y las imágenes auxiliares de las herramientas. Para comprobar qué servicios están activos:

```sh
docker compose ps
```

Consulta los registros si un servicio no inicia:

```sh
docker compose logs -f api orchestrator validate-agent reporter-agent skills-controller
```

Pulsa `Ctrl+C` para dejar de seguir los registros; esto no detiene los contenedores.

## 6. Comprobar los servicios

Con los contenedores iniciados, abre:

| Servicio | Dirección local |
| --- | --- |
| Interfaz SECURE | [http://localhost:3000](http://localhost:3000) |
| Panel de análisis | [http://localhost:3000/dashboard](http://localhost:3000/dashboard) |
| Documentación de la API | [http://localhost:8000/docs](http://localhost:8000/docs) |
| Estado de la API | [http://localhost:8000/](http://localhost:8000/) |
| Estado del orquestador | [http://localhost:8001/health](http://localhost:8001/health) |
| Laboratorio local | [http://localhost:3009](http://localhost:3009) |
| Administración de RabbitMQ | [http://localhost:15672](http://localhost:15672) |

RabbitMQ solicita las credenciales `RABBITMQ_USER` y `RABBITMQ_PASS` definidas en `.env`. El laboratorio está publicado solo en la interfaz local del equipo.

## 7. Primera prueba desde el panel

1. Confirma que `weak-page` y los demás servicios están activos con `docker compose ps`.
2. Abre [http://localhost:3000/dashboard](http://localhost:3000/dashboard).
3. En **URL**, escribe `http://weak-page:3009`. Ese nombre es accesible entre los contenedores de la red de pruebas; para abrir el laboratorio manualmente desde el navegador del host usa `http://localhost:3009`.
4. En **Informe de scraping (.json)**, selecciona el archivo existente `code/scripts/scraping-report.json`. La interfaz requiere un JSON con `target`, `observed_endpoints` y `requests`; este archivo de ejemplo ya tiene esa estructura.
5. Selecciona una categoría y el tipo de prueba que quieras ejecutar en el laboratorio local. Algunos tipos, como JWT, requieren un token; el panel indica si es obligatorio.
6. Pulsa **Iniciar Escaneo** y observa en el panel el progreso, los hallazgos y el informe final. Si aparece un error, revisa los registros de los servicios con `docker compose logs -f`.

El informe de ejemplo está preparado para `http://weak-page:3009`. Si capturas datos para otro objetivo, asegúrate de que la URL y el contenido del informe correspondan entre sí. El crawler incluido puede ejecutarse únicamente contra el laboratorio del proyecto con:

```sh
docker compose --profile scraper run --rm scrapper
```

El comando imprime el nuevo informe JSON en la terminal. No lo envíes a un objetivo externo sin autorización; el servicio `scrapper` está limitado al laboratorio `weak-page`.

## 8. Ejecutar pruebas automatizadas (opcional)

### Frontend

Requiere Node.js 24. Desde PowerShell:

```powershell
cd .\frontend
corepack pnpm install --frozen-lockfile
node --test .\tests\panel-view.test.mjs
cd ..
```

### Agentes Python

Desde `code`, crea un entorno virtual e instala las dependencias de desarrollo de los agentes:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r agents\orchestrator\requirements.txt -r agents\validate\requirements.txt -r agents\reporter\requirements.txt
```

Ejecuta cada suite por separado. En Windows, usa `;` para separar rutas en `PYTHONPATH`:

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

Las pruebas unitarias no requieren iniciar los servicios ni ejecutar análisis. En Linux/macOS, activa el entorno con `source .venv/bin/activate`, usa `python` en lugar de la ruta de Windows y separa las rutas de `PYTHONPATH` con `:`.

## 9. Detener la aplicación

Desde `code`:

```sh
docker compose down
```

Esto detiene y elimina los contenedores, pero conserva los volúmenes con los datos del laboratorio y de Portainer. Para volver a iniciar la aplicación, repite `docker compose up -d`.
