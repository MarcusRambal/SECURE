import os
import httpx
from fastapi import FastAPI, HTTPException
from playwright.async_api import async_playwright
from contract_schemas import DiscoveredEntryPoint

app = FastAPI(title="SECURE - Recon Agent (Agnóstico)")

TESTER_AGENT_URL = os.getenv("TESTER_AGENT_URL", "http://validate-agent:8002/validate")
TARGET_URL = os.getenv("TARGET_URL", "http://juice-shop:3000/#/login")

@app.post("/scan")
async def scan_target():
    print(f"[RECON] Iniciando análisis estático/pasivo en: {TARGET_URL}")
    print("[RECON] Paso 1: inicializando Playwright")
    
    discovered_endpoint = None

    async with async_playwright() as p:
        print("[RECON] Paso 2: lanzando navegador")
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        try:
            # 1. Cargar la página
            print("[RECON] Paso 3: cargando la página objetivo")
            await page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=15000)
            await page.wait_for_timeout(1000) # Tiempo mínimo de inicialización
            print(f"[RECON] Paso 3.1: página cargada correctamente: {TARGET_URL}")

            # 2. Estrategia A: Analizar el DOM (Formularios HTML tradicionales)
            print("[RECON] Paso 4: revisando formularios del DOM")
            forms = await page.query_selector_all("form")
            print(f"[RECON] Formularios encontrados: {len(forms)}")
            if forms:
                for idx, form in enumerate(forms, start=1):
                    print(f"[RECON] Formulario #{idx}: analizando...")
                    action = await form.get_attribute("action")
                    method = (await form.get_attribute("method") or "POST").upper()
                    print(f"[RECON] Formulario #{idx} -> action={action}, method={method}")
                    
                    # Extraer inputs
                    inputs = await form.query_selector_all("input")
                    payload_template = {}
                    target_field = "email"
                    print(f"[RECON] Formulario #{idx} -> inputs detectados: {len(inputs)}")

                    for inp in inputs:
                        name = await inp.get_attribute("name") or await inp.get_attribute("id")
                        inp_type = await inp.get_attribute("type") or "text"
                        if name and inp_type not in ["submit", "button", "hidden"]:
                            payload_template[name] = ""
                            print(f"[RECON] Campo útil detectado: name={name}, type={inp_type}")
                            if "email" in name.lower() or "user" in name.lower():
                                target_field = name

                    if action and payload_template:
                        api_url = action if action.startswith("http") else f"{TARGET_URL.split('#')[0].rstrip('/')}/{action.lstrip('/')}"
                        print(f"[RECON] Formulario #{idx} -> endpoint candidato: {api_url}")
                        discovered_endpoint = DiscoveredEntryPoint(
                            target_url=api_url,
                            http_method=method,
                            entry_point_type="sql_injection",
                            headers={"Content-Type": "application/json"},
                            payload_template=payload_template,
                            target_field=target_field
                        )
                        print(f"[RECON] Formulario #{idx} -> contrato generado desde DOM")
                        break

            # 3. Estrategia B: Fallback para Single Page Applications (Juice Shop / React / Angular)
            # Si el DOM no tiene un <form action=...>, inferimos el endpoint REST estandar de Auth/Login
            if not discovered_endpoint:
                print("[RECON] Paso 5: no se encontró formulario; aplicando fallback para SPA")
                
                # Para Juice Shop / REST APIs de Auth comunes
                base_url = TARGET_URL.split('#')[0].rstrip('/')
                api_url = f"{base_url}/rest/user/login"
                print(f"[RECON] Fallback -> endpoint inferido: {api_url}")
                
                discovered_endpoint = DiscoveredEntryPoint(
                    target_url=api_url,
                    http_method="POST",
                    entry_point_type="sql_injection",
                    headers={"Content-Type": "application/json"},
                    payload_template={"email": "", "password": ""},
                    target_field="email"
                )
                print("[RECON] Fallback -> contrato generado")

        finally:
            print("[RECON] Paso 6: cerrando navegador")
            await browser.close()

    if not discovered_endpoint:
        print("[RECON] ERROR: no se pudo identificar ningún endpoint vulnerable")
        raise HTTPException(status_code=404, detail="No se pudieron identificar endpoints vulnerables.")

    print(f"[RECON] Endpoint descubierto: {discovered_endpoint.http_method} {discovered_endpoint.target_url}")
    print(f"[RECON] Objeto descubierto: {discovered_endpoint.model_dump_json(indent=2)}")

    # 4. Delegar al validate-agent
    async with httpx.AsyncClient(timeout=30.0) as client:
        print(f"[RECON] Paso 7: enviando contrato a {TESTER_AGENT_URL}...")
        payload = discovered_endpoint.model_dump()
        print(f"[RECON] Payload JSON a tester_agent: {payload}")
        res = await client.post(TESTER_AGENT_URL, json=payload)
        print(f"[RECON] Respuesta recibida del tester_agent: {res.status_code} - {res.text}")
        return res.json()