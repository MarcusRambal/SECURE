import sys
import os
import json
import urllib.parse
from playwright.sync_api import sync_playwright

OUTPUT_REQ_DIR = "/app/captured_requests"

def save_raw_request(request, index):
    try:
        parsed_url = urllib.parse.urlparse(request.url)
        path = parsed_url.path or "/"
        if parsed_url.query:
            path += f"?{parsed_url.query}"

        headers_text = f"{request.method} {path} HTTP/1.1\n"
        headers_text += f"Host: {parsed_url.netloc}\n"

        for key, value in request.headers.items():
            if key.lower() != "host":
                headers_text += f"{key}: {value}\n"

        post_data = request.post_data or ""
        if post_data:
            headers_text += f"\n{post_data}"
        else:
            headers_text += "\n"

        clean_path = path.replace("/", "_").replace("?", "_").replace("&", "_")[:35]
        filename = os.path.join(OUTPUT_REQ_DIR, f"req_{index:03d}_{request.method}{clean_path}.req")

        with open(filename, "w", encoding="utf-8") as f:
            f.write(headers_text)
    except Exception as e:
        sys.stderr.write(f"Error guardando petición raw: {str(e)}\n")

def interact_and_submit_forms(page):
    """Detecta inputs de formulario, los rellena con datos de prueba y hace submit."""
    try:
        # 1. Rellenar campos de email/usuario
        user_inputs = page.query_selector_all('input[type="email"], input[name*="user"], input[name*="email"], input[id*="email"], input[aria-label*="Email"]')
        for inp in user_inputs:
            if inp.is_visible():
                inp.fill("test@example.com")

        # 2. Rellenar campos de contraseña
        pass_inputs = page.query_selector_all('input[type="password"], input[name*="pass"], input[id*="pass"]')
        for inp in pass_inputs:
            if inp.is_visible():
                inp.fill("password123")

        # 3. Rellenar inputs de texto genéricos (búsquedas, comentarios)
        text_inputs = page.query_selector_all('input[type="text"]:not([readonly]), textarea')
        for inp in text_inputs:
            if inp.is_visible():
                inp.fill("test_query")

        page.wait_for_timeout(500)

        # 4. Hacer clic en el botón Submit / Login / Search
        submit_btn = page.query_selector('button[type="submit"], button#loginButton, button[aria-label*="Log in"], button[aria-label*="login"]')
        if submit_btn and submit_btn.is_visible():
            submit_btn.click(timeout=3000)
            page.wait_for_timeout(1500)
    except Exception as e:
        # Ignorar fallos de interacción en páginas sin formulario
        pass

def crawl_and_capture(target_url):
    endpoints = set()
    api_requests = set()
    req_counter = 0

    if not os.path.exists(OUTPUT_REQ_DIR):
        os.makedirs(OUTPUT_REQ_DIR, exist_ok=True)

    # Cada reconocimiento debe producir un conjunto coherente de artefactos.
    for filename in os.listdir(OUTPUT_REQ_DIR):
        if filename.endswith((".req", ".har")) or filename == "spa_crawler_output.json":
            try:
                os.remove(os.path.join(OUTPUT_REQ_DIR, filename))
            except OSError as cleanup_error:
                sys.stderr.write(f"Error limpiando artefacto anterior {filename}: {cleanup_error}\n")

    har_path = os.path.join(OUTPUT_REQ_DIR, "session_traffic.har")
    output_json_path = os.path.join(OUTPUT_REQ_DIR, "spa_crawler_output.json")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )

        context = browser.new_context(record_har_path=har_path)
        page = context.new_page()

        def handle_request(request):
            nonlocal req_counter
            url = request.url
            if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ttf"]):
                return

            api_requests.add(url)
            req_counter += 1
            save_raw_request(request, req_counter)

        page.on("request", handle_request)

        try:
            # FASE 1: Carga inicial y recolección de rutas
            page.goto(target_url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(2000)

            # Extraer enlaces
            links = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.getAttribute("href"))')
            for link in links:
                if link and ("#" in link or link.startswith("/")):
                    if link.startswith("#"):
                        endpoints.add(f"{target_url.rstrip('/')}/{link.lstrip('/')}")
                    elif link.startswith("/"):
                        endpoints.add(f"{target_url.rstrip('/')}{link}")

            router_links = page.eval_on_selector_all('[routerlink]', 'els => els.map(e => e.getAttribute("routerlink"))')
            for rlink in router_links:
                if rlink:
                    endpoints.add(f"{target_url.rstrip('/')}/#/{rlink.strip('/')}")

            # FASE 2: Navegar a cada vista e INTERACTUAR con sus formularios
            nav_list = [url for url in endpoints if target_url in url]
            for nav_url in nav_list:
                try:
                    page.goto(nav_url, wait_until="networkidle", timeout=10000)
                    page.wait_for_timeout(1000)
                    
                    # Intentar rellenar y enviar formularios en esta vista (ej: /#/login)
                    interact_and_submit_forms(page)
                except Exception as nav_err:
                    sys.stderr.write(f"Error visitando {nav_url}: {str(nav_err)}\n")

        except Exception as e:
            sys.stderr.write(f"Error durante la ejecución: {str(e)}\n")
        finally:
            context.close()
            browser.close()

    result = {
        "target": target_url,
        "captured_requests_count": req_counter,
        "har_file": har_path,
        "navigation_routes": sorted(list(endpoints)),
        "api_endpoints": sorted(list(api_requests))
    }

    result["output_json_file"] = output_json_path

    try:
        with open(output_json_path, "w", encoding="utf-8") as output_file:
            json.dump(result, output_file, ensure_ascii=False, indent=2)
            output_file.write("\n")
    except OSError as output_error:
        sys.stderr.write(f"Error guardando salida JSON del crawler: {output_error}\n")
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python spa_crawler.py <URL>")
        sys.exit(1)

    target = sys.argv[1]
    result = crawl_and_capture(target)
    print(json.dumps(result, indent=2))