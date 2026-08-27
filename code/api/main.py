import uuid
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas.scan import ScanRequest, ScanResponse
from app.core.rabbitmq import rabbitmq_client

logging.basicConfig(level=logging.INFO)

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

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    # 1. Generamos un UUID único para este escaneo
    scan_id = str(uuid.uuid4())
    
    # 2. Construimos el payload estandarizado que procesará el Orquestador
    payload = {
        "scan_id": scan_id,
        "target_url": request.target_url,
        "scan_type": request.scan_type,
        "status": "INITIATED"
    }

    try:
        # 3. Enviamos el trabajo a RabbitMQ
        await rabbitmq_client.publish_scan_request(payload)
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error interno al comunicar con el broker de mensajes: {str(e)}"
        )

    return ScanResponse(
        scan_id=scan_id,
        status="ACCEPTED",
        message="Escaneo encolado correctamente en orchestrator_queue."
    )