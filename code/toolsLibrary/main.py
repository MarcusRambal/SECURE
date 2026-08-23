# toolsLibrary/main.py

import uvicorn
import importlib
import pkgutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

from registry import registry
import tools as tools_package

# --- CARGA AUTOMÁTICA DE HERRAMIENTAS ---
# Importa automáticamente todos los archivos dentro de la carpeta /tools
for _, module_name, _ in pkgutil.iter_modules(tools_package.__path__):
    importlib.import_module(f"tools.{module_name}")

app = FastAPI(title="MCP Tools Server")

class ToolCallRequest(BaseModel):
    name: str
    arguments: Dict[str, Any]

@app.get("/tools")
def list_tools():
    """Retorna los schemas de todas las herramientas auto-registradas."""
    return {"tools": registry.get_schema_list()}

@app.post("/call_tool")
def execute_tool(request: ToolCallRequest):
    print(f"⚙️ [MCP SERVER] Ejecutando: {request.name}")
    try:
        res = registry.execute(request.name, request.arguments)
        if res.get("status") == "success":
            return {"result": f"=== RESULTS FOR {request.name} ===\n{res['output']}"}
        return {"result": f"=== ERROR IN {request.name} ===\n{res.get('message', 'Error desconocido')}"}
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Herramienta '{request.name}' no encontrada.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)