import subprocess
from typing import Dict, Any

def run_nikto_scan(target_url: str) -> Dict[str, Any]:
    try:
        cmd = [
            "nikto",
            "-h", target_url,
            "-Tuning", "123b",
            "-maxtime", "45s"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        output = result.stdout if result.stdout else result.stderr
        
        return {
            "status": "success",
            "output": output
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "El escaneo de Nikto superó el tiempo límite."}
    except Exception as e:
        return {"status": "error", "message": str(e)}