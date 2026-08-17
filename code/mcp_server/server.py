import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, Any
from mcp_server.tools.nikto import run_nikto_scan

app = FastAPI(title="MCP Tools Server")

class ToolCallRequest(BaseModel):
    name: str
    arguments: Dict[str, Any]

@app.post("/call_tool")
def execute_tool(request: ToolCallRequest):
    print(f"⚙️ [MCP SERVER] Ejecutando tool '{request.name}' con args: {request.arguments}")
    
    if request.name == "nikto_scan":
        # Extrae la target_url enviada dinámicamente por el agente
        target = request.arguments.get("target_url")
        if not target:
            raise HTTPException(status_code=400, detail="Falta el argumento requerido 'target_url'")
            
        res = run_nikto_scan(target)
        
        if res["status"] == "success":
            return {"result": f"=== NIKTO SCAN RESULTS FOR {target} ===\n{res['output']}"}
        else:
            return {"result": f"=== NIKTO SCAN ERROR ===\n{res.get('message', res.get('error'))}"}
    else:
        raise HTTPException(status_code=404, detail=f"Herramienta '{request.name}' no encontrada.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)