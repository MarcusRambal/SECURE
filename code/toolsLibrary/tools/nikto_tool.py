#  toolsLibray/tools/nikto_tool.py


from registry import registry
import subprocess

NIKTO_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "target_url": {
            "type": "STRING",
            "description": "URL completa o IP del servidor objetivo (ej. http://10.10.10.5)."
        }
    },
    "required": ["target_url"]
}

@registry.register(
    name="nikto_scan",
    description="Ejecuta un escaneo de vulnerabilidades en un servidor web mediante Nikto.",
    parameters=NIKTO_SCHEMA
)
def run_nikto_scan(args: dict) -> dict:
    target = args.get("target_url")
    
    try:
        cmd = [
            "nikto",
            "-h", target,
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