from registry import registry
import subprocess

NMAP_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "target_host": {
            "type": "STRING",
            "description": "Dirección IP o dominio a escanear (ej. 10.10.10.5 o ej.com)."
        },
        "ports": {
            "type": "STRING",
            "description": "Puertos a escanear separados por coma. Opcional.",
            "default": "80,443,8080,22"
        }
    },
    "required": ["target_host"]
}

@registry.register(
    name="nmap_scan",
    description="Ejecuta un escaneo de puertos y detección de versiones usando Nmap.",
    parameters=NMAP_SCHEMA
)
def run_nmap_scan(args: dict) -> dict:
    target = args.get("target_host")
    ports = args.get("ports", "80,443,8080,22")
    
    try:
        cmd = [
            "nmap",
            "-sV",
            "-p", ports,
            target
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90
        )
        
        output = result.stdout if result.stdout else result.stderr
        
        return {
            "status": "success",
            "output": output
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "El escaneo de Nmap superó el tiempo límite."}
    except Exception as e:
        return {"status": "error", "message": str(e)}