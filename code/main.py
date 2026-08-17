#Recibe la peticion https del frontend y lo manda al workflow

from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field
from graph.workflow import run_audit_workflow

app = FastAPI(
    title="Multi-Agent Security Orchestrator API",
    description="API Gateway para orquestar la auditoría con LangGraph y MCP",
    version="1.0.0"
)

class ScanRequest(BaseModel):
    target_url: str = Field(
        default="http://webgoat:8080/WebGoat", 
        description="URL objetivo a analizar"
    )
    attack_type: str = Field(
        default="scanWeb", 
        description="Tipo de análisis/ataque a ejecutar (ej: scanWeb)"
    )

@app.get("/")
def root():
    return {
        "status": "online",
        "service": "Backend Security Orchestrator",
        "mcp_server": "http://mcp-tools-server:5000"
    }

@app.post("/api/v1/scan")
async def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Endpoint que recibe la URL objetivo y el tipo de ataque desde la UI.
    Inicia la orquestación en segundo plano.
    """
    if not request.target_url:
        raise HTTPException(status_code=400, detail="Debes proporcionar una URL objetivo válida.")
    
    # Agregar la ejecución del grafo de LangGraph en segundo plano
    background_tasks.add_task(run_audit_workflow, request.target_url, request.attack_type)
    
    return {
        "status": "accepted",
        "message": f"Orquestación iniciada para '{request.target_url}' con la estrategia '{request.attack_type}'.",
        "details": {
            "target": request.target_url,
            "attack_type": request.attack_type
        }
    }