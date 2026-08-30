import uuid
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas.task import TaskRequest, TaskResponse
from app.core.rabbitmq import rabbitmq_client

logging.basicConfig(level=logging.INFO)

#Ciclo de vida de la aplicacion FastAPI: Conectar y desconectar de RabbitMQ
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Código al arrancar el contenedor: Conectar a RabbitMQ
    await rabbitmq_client.connect()
    yield
    # Código al detener el contenedor: Cerrar conexión
    await rabbitmq_client.close()

app = FastAPI(
    title="Multiagent MCP Scanner - API Gateway",
    version="1.0.0",
    lifespan=lifespan
)


#Configuración de CORS para permitir solicitudes desde cualquier origen, sin embargo esto debe cambiar en producción para restringir a dominios específicos.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "online", "service": "API Gateway"}

@app.post("/api/task", response_model=TaskResponse)
async def start_scan(request: TaskRequest):
    # 1. Generamos un UUID único para este escaneo
    task_id = str(uuid.uuid4())
    
    # 2. Construimos el payload estandarizado que procesará el Orquestador
    payload = {
        "task_id": task_id,
        "target_url": request.target_url,
        "attack_type": request.attack_type,
        "status": "INITIATED"
    }

    try:
        # 3. Enviamos el trabajo a RabbitMQ
        await rabbitmq_client.publish_task_request(payload)
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error interno al comunicar con el broker de mensajes: {str(e)}"
        )

    return TaskResponse(
        task_id=task_id,
        status="ACCEPTED",
        message="Tarea encolada correctamente en orchestrator_queue."
    )