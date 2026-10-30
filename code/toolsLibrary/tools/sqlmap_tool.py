from registry import registry
import subprocess

SQLMAP_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "url": {
            "type": "STRING",
            "description": "URL de destino con parámetros a evaluar (ej. http://example.com/item.php?id=1)."
        },
        "level": {
            "type": "STRING",
            "description": "Nivel de pruebas (1 a 5).",
            "default": "1"
        },
        "risk": {
            "type": "STRING",
            "description": "Riesgo de las pruebas (1 a 3).",
            "default": "1"
        },
        "dbms": {
            "type": "STRING",
            "description": "Forzar motor de base de datos específico."
        }
    },
    "required": ["url"]
}

@registry.register(
    name="sqlmap_scan",
    description="Ejecuta un análisis de inyección SQL usando SQLMap.",
    parameters=SQLMAP_SCHEMA
)
def run_sqlmap_scan(args: dict) -> dict:
    target_url = args.get("url")
    level = str(args.get("level", "1"))
    risk = str(args.get("risk", "1"))
    dbms = args.get("dbms")

    try:
        cmd = [
            "python3", "/opt/sqlmap/sqlmap.py",
            "-u", target_url,
            "--batch",
            "--random-agent",
            "--level", level,
            "--risk", risk
        ]

        if dbms:
            cmd.extend(["--dbms", dbms])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout if result.stdout else result.stderr

        return {
            "status": "success",
            "output": output
        }
    except subprocess.TimeoutExpired:
        return {"status": "error", "message": "El análisis de SQLMap superó el tiempo límite."}
    except Exception as e:
        return {"status": "error", "message": str(e)}