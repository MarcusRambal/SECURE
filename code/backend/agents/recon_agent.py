from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import json

app = FastAPI(title="Recon Agent")

class ReconRequest(BaseModel):
    target_url: str

@app.post("/recon")
def run_recon(data: ReconRequest):
    try:
        # Comando de Katana para crawl activo
        cmd = ["katana", "-u", data.target_url, "-jc", "-jsonl"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        endpoints = []
        for line in result.stdout.strip().split("\n"):
            if line:
                item = json.loads(line)
                endpoints.append(item.get("endpoint", item.get("request", {}).get("endpoint")))
                
        return {"status": "success", "discovered_urls": list(set(filter(None, endpoints)))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))