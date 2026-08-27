import json
from langchain_core.tools import tool
from playwright.sync_api import sync_playwright

SESSION_FILE = "/app/session.json"
TARGET_URL = "http://webgoat:8080/WebGoat"

@tool
def navigate_and_inspect(lesson_path: str) -> str:
    """
    Navega a una lección específica dentro de WebGoat usando la sesión guardada
    y devuelve los formularios e inputs presentes en la página para analizarlos.
    
    Args:
        lesson_path: Ruta relativa de la lección (ejemplo: 'start.mvc#lesson/SqlInjection.lesson')
    """
    full_url = f"{TARGET_URL.rstrip('/')}/{lesson_path.lstrip('/')}"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
        context = browser.new_context(storage_state=SESSION_FILE)
        page = context.new_page()
        
        page.goto(full_url)
        page.wait_for_load_state("networkidle")
        
        # Extraer elementos interactivos del DOM
        inputs = page.query_selector_all("input, textarea, select")
        elements_info = []
        for inp in inputs:
            name = inp.get_attribute("name") or inp.get_attribute("id") or inp.get_attribute("type")
            elements_info.append(f"Input Name/ID/Type: {name}")
            
        page_text = page.inner_text("body")
        browser.close()
        
        return json.dumps({
            "url": full_url,
            "inputs_found": elements_info,
            "content_preview": page_text[:1200]
        })

@tool
def test_sql_payload(lesson_path: str, input_selector: str, payload: str) -> str:
    """
    Envía un payload de prueba de SQL Injection directamente a un campo del formulario en WebGoat.
    
    Args:
        lesson_path: Ruta relativa de la lección en WebGoat.
        input_selector: Selector CSS o atributo name del campo objetivo (ej: 'account_name').
        payload: La cadena o payload de prueba a inyectar (ej: "' OR '1'='1").
    """
    full_url = f"{TARGET_URL.rstrip('/')}/{lesson_path.lstrip('/')}"
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
        context = browser.new_context(storage_state=SESSION_FILE)
        page = context.new_page()
        
        page.goto(full_url)
        page.wait_for_load_state("networkidle")
        
        # Intentar llenar por selector directo o por atributo name
        try:
            page.fill(input_selector, payload)
        except Exception:
            page.fill(f"input[name='{input_selector}']", payload)
            
        # Enviar formulario
        submit_btn = page.query_selector("button[type='submit'], input[type='submit']")
        if submit_btn:
            submit_btn.click()
        else:
            page.keyboard.press("Enter")
            
        page.wait_for_timeout(2000)
        response_text = page.inner_text("body")
        browser.close()
        
        # Validar si la lección fue completada
        is_solved = "Congratulations" in response_text or "Lesson solved" in response_text
        
        return json.dumps({
            "payload_sent": payload,
            "lesson_completed": is_solved,
            "response_snippet": response_text[:1000]
        })