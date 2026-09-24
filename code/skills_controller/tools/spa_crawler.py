import sys
import json
from playwright.sync_api import sync_playwright

def serialize_request(request, index, route_url):
    """Convierte una petición Playwright al contrato JSON del crawler."""
    try:
        return {
            "request_id": f"req_{index:03d}",
            "route_url": route_url,
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "body": request.post_data or "",
            "resource_type": request.resource_type,
        }
    except Exception as e:
        sys.stderr.write(f"Error serializando petición: {str(e)}\n")
        return None

def fill_input_heuristically(element):
    """Inserta datos válidos según el tipo y los atributos del input."""
    try:
        input_type = (element.get_attribute("type") or "text").lower()
        name_attr = (element.get_attribute("name") or "").lower()
        id_attr = (element.get_attribute("id") or "").lower()
        placeholder_attr = (element.get_attribute("placeholder") or "").lower()
        aria_attr = (element.get_attribute("aria-label") or "").lower()

        combined_attrs = f"{name_attr} {id_attr} {placeholder_attr} {aria_attr}"

        if input_type in ["email"] or "email" in combined_attrs:
            element.fill("user@example.com")
        elif input_type in ["password"] or "pass" in combined_attrs:
            element.fill("ValidPass123!")
        elif input_type in ["number"] or "qty" in combined_attrs or "quantity" in combined_attrs:
            element.fill("1")
        elif input_type in ["tel", "phone"]:
            element.fill("5551234567")
        elif input_type in ["date"]:
            element.fill("2026-01-01")
        else:
            element.fill("test_payload")
    except Exception:
        pass

def discover_and_interact_forms(page):
    """Mapea los formularios e inputs de la vista actual y fuerza el envío."""
    discovered_forms_metadata = []

    # 1. Detectar formularios explícitos <form>
    forms = page.query_selector_all("form")

    for idx, form in enumerate(forms):
        form_info = {
            "form_index": idx,
            "action": form.get_attribute("action") or "",
            "method": (form.get_attribute("method") or "GET").upper(),
            "inputs": []
        }

        inputs = form.query_selector_all("input:not([type='hidden']), textarea, select")
        for inp in inputs:
            if inp.is_visible():
                form_info["inputs"].append({
                    "name": inp.get_attribute("name") or "",
                    "id": inp.get_attribute("id") or "",
                    "type": inp.get_attribute("type") or "text",
                    "placeholder": inp.get_attribute("placeholder") or ""
                })
                fill_input_heuristically(inp)

        discovered_forms_metadata.append(form_info)

    # 2. Detectar inputs sueltos (muy común en SPAs como Angular/React fuera de un <form>)
    standalone_inputs = page.query_selector_all("input:not([type='hidden']), textarea")
    for inp in standalone_inputs:
        if inp.is_visible():
            fill_input_heuristically(inp)

    page.wait_for_timeout(500)

    # 3. Mapear enlaces secundarios de acción (ej: "Forgot password", "Register")
    action_links = set()
    links = page.query_selector_all("a[href], button")
    for link in links:
        try:
            text = (link.inner_text() or "").lower()
            href = link.get_attribute("href") or ""
            if any(keyword in text for keyword in ["forgot", "reset", "register", "signup", "crear cuenta"]):
                if href:
                    action_links.add(href)
        except Exception:
            pass

    # 4. Disparar botones de envío
    submit_buttons = page.query_selector_all("button[type='submit'], input[type='submit'], button#loginButton, button[aria-label*='Log in'], button[aria-label*='Search']")
    for btn in submit_buttons:
        if btn.is_visible():
            try:
                btn.click(timeout=3000)
                page.wait_for_timeout(1500)
                break
            except Exception:
                pass

    return discovered_forms_metadata, list(action_links)

def run_form_crawler(target_url):
    captured_requests_info = []
    req_counter = 0

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        context = browser.new_context()
        page = context.new_page()

        # Interceptor de peticiones HTTP
        def handle_request(request):
            nonlocal req_counter
            url = request.url
            if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".svg", ".woff", ".woff2", ".ttf"]):
                return

            req_counter += 1
            req_data = serialize_request(request, req_counter, page.url)
            if req_data:
                captured_requests_info.append(req_data)

        page.on("request", handle_request)

        # FASE 1: Obtener lista de rutas de la SPA
        page.goto(target_url, wait_until="networkidle", timeout=30000)
        page.wait_for_timeout(2000)

        nav_routes = set()
        links = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.getAttribute("href"))')
        for link in links:
            if link and ("#" in link or link.startswith("/")):
                if link.startswith("#"):
                    nav_routes.add(f"{target_url.rstrip('/')}/{link.lstrip('/')}")
                elif link.startswith("/"):
                    nav_routes.add(f"{target_url.rstrip('/')}{link}")

        router_links = page.eval_on_selector_all('[routerlink]', 'els => els.map(e => e.getAttribute("routerlink"))')
        for rlink in router_links:
            if rlink:
                nav_routes.add(f"{target_url.rstrip('/')}/#/{rlink.strip('/')}")

        # FASE 2: Recorrer cada ruta, mapear formularios e interactuar
        full_mapping = []
        for nav_url in sorted(list(nav_routes)):
            try:
                page.goto(nav_url, wait_until="networkidle", timeout=10000)
                page.wait_for_timeout(1000)

                forms_meta, secondary_links = discover_and_interact_forms(page)

                full_mapping.append({
                    "route_url": nav_url,
                    "forms_found": forms_meta,
                    "action_links_found": secondary_links
                })
            except Exception as e:
                sys.stderr.write(f"Error procesando vista {nav_url}: {str(e)}\n")

        browser.close()

    return {
        "target": target_url,
        "total_requests_captured": req_counter,
        "discovered_forms_structure": full_mapping,
        "captured_requests": captured_requests_info
    }

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SPA Form Crawler Skill")
    parser.add_argument("--target-url", required=True, help="URL objetivo para crawlear")
    args = parser.parse_args()

    # Ejecutar el crawler y emitir únicamente el JSON por stdout
    results = run_form_crawler(args.target_url)
    print(json.dumps(results, ensure_ascii=False, indent=2))