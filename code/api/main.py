import uuid
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.schemas.task import TaskRequest, TaskResponse
from app.core.rabbitmq import rabbitmq_client
from app.websockets.manager import websocket_manager

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
    allow_origins=["*"], # Reemplazar por el dominio exacto del frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"status": "online", "service": "API Gateway"}


@app.websocket("/ws/scans/{task_id}")
async def scan_events(websocket: WebSocket, task_id: str):
    await websocket_manager.connect(task_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await websocket_manager.disconnect(task_id, websocket)
    except Exception:
        await websocket_manager.disconnect(task_id, websocket)


@app.post("/api/task", response_model=TaskResponse)
async def start_scan(request: TaskRequest):
    # 1. Generamos un UUID único para este escaneo
    task_id = str(uuid.uuid4())
    
    # 2. Construimos el payload estandarizado que procesará el Orquestador
    payload = {
        "task_id": task_id,
        "target_url": request.target_url,
        "category": request.category,
        "attack_type": request.attack_type,
        "agent_models": request.agent_models.model_dump() if request.agent_models else None,
        "status": "INITIATED"
    }

    try:
        # 3. Enviamos el trabajo a RabbitMQ
        print("Payload enviado a rabbitmq: ", payload)
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