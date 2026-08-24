from registry import registry
import subprocess
from urllib.parse import urlparse

NIKTO_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "target_url": {
            "type": "STRING",
            "description": "Dominio, IP o URL a escanear (ej. 10.10.10.5 o http://ejemplo.com)."
        },
        "port": {
            "type": "STRING",
            "description": "Puerto del servicio web. Opcional.",
            "default": "80"
        },
        "maxtime": {
            "type": "STRING",
            "description": "Tiempo máximo de ejecución para el escaneo (ej. '10m'). Opcional.",
            "default": "10m"
        }
    },
    "required": ["target_url"]
}

@registry.register(
    name="nikto_scan",
    description="Ejecuta un análisis de vulnerabilidades web usando Nikto.",
    parameters=NIKTO_SCHEMA
)
def run_nikto_scan(args: dict) -> dict:
    target = args.get("target_url", "")
    port = str(args.get("port", "80"))
    maxtime = args.get("maxtime", "10m")

    # Si la URL incluye esquema (http:// o https://), construimos el comando sin la opción -p
    if target.startswith("http://") or target.startswith("https://"):
        cmd = [
            "nikto",
            "-h", target,
            "-maxtime", maxtime,
            "-nointeractive"
        ]
    else:
        cmd = [
            "nikto",
            "-h", target,
            "-p", port,
            "-maxtime", maxtime,
            "-nointeractive"
        ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600
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