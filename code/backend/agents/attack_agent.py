import os
import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="SECURE - Attack Agent",
    description="Microservicio para la ejecución de pruebas de inyección SQL con sqlmap.",
    version="1.0.0"
)

class AttackPayload(BaseModel):
    request_file: str = "request.txt"

@app.post("/attack")
async def execute_attack(payload: AttackPayload):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, payload.request_file)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Archivo {payload.request_file} no encontrado.")

    cmd = [
        "sqlmap",
        "-r", file_path,
        "--batch",
        "--random-agent",
        "--risk=1",
        "--level=1"
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "status": "success",
            "stdout": result.stdout[:2000],
            "returncode": result.returncode
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=508, detail="La prueba con sqlmap superó el tiempo límite de 120s.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error ejecutando sqlmap: {str(e)}")