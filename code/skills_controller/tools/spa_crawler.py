import sys
import json
from playwright.sync_api import sync_playwright

def crawl_spa(target_url):
    endpoints = set()
    api_requests = set()

    with sync_playwright() as p:
        # Lanzar navegador headless con flags de seguridad para contenedores
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        context = browser.new_context()
        page = context.new_page()

        # 1. Escuchar peticiones XHR/Fetch de fondo (Backend REST API)
        def handle_request(request):
            url = request.url
            if any(ext in url for ext in [".js", ".css", ".png", ".jpg", ".svg", ".woff"]):
                return
            api_requests.add(url)

        page.on("request", handle_request)

        try:
            # Navegar a la URL objetivo
            page.goto(target_url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(3000)  # Esperar a que Angular/React se hidrate

            # 2. Extraer enlaces tradicionales y rutas con Hash (#)
            links = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.getAttribute("href"))')
            for link in links:
                if link:
                    if link.startswith("#") or "#" in link:
                        endpoints.add(f"{target_url.rstrip('/')}/{link.lstrip('/')}")
                    elif link.startswith("http"):
                        endpoints.add(link)
                    elif link.startswith("/"):
                        endpoints.add(f"{target_url.rstrip('/')}{link}")

            # 3. Extraer directivas específicas de frameworks (ej. routerlink de Angular)
            router_links = page.eval_on_selector_all('[routerlink]', 'els => els.map(e => e.getAttribute("routerlink"))')
            for rlink in router_links:
                if rlink:
                    endpoints.add(f"{target_url.rstrip('/')}/#/{rlink.strip('/')}")

        except Exception as e:
            sys.stderr.write(f"Error durante el rastreo: {str(e)}\n")
        finally:
            browser.close()

    return {
        "target": target_url,
        "navigation_routes": sorted(list(endpoints)),
        "api_endpoints": sorted(list(api_requests))
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python spa_crawler.py <URL>")
        sys.exit(1)

    target = sys.argv[1]
    result = crawl_spa(target)
    print(json.dumps(result, indent=2))