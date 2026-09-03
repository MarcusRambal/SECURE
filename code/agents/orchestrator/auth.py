import time
from playwright.sync_api import sync_playwright

def ensure_webgoat_session(target_url: str, username: str = "marcus", password: str = "123456", session_path: str = "/app/session.json"):
    """
    Se conecta a WebGoat, realiza el registro/login si es necesario
    y guarda el estado de la sesión en session_path.
    """
    login_url = f"{target_url.rstrip('/')}/login"
    print(f"[AUTH] Conectando a {login_url}...")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox'])
        context = browser.new_context()
        page = context.new_page()

        # Reintentos por si WebGoat aún está arrancando en el composer
        max_retries = 10
        for i in range(max_retries):
            try:
                page.goto(login_url, timeout=10000)
                break
            except Exception as e:
                print(f"[AUTH] Esperando a que WebGoat responda ({i+1}/{max_retries})...")
                time.sleep(5)
        else:
            raise RuntimeError("No se pudo conectar a WebGoat en la red de Docker.")

        # Si WebGoat permite registro o exige login directo:
        try:
            # Llenar formulario de login
            page.fill("input[name='username']", username)
            page.fill("input[name='password']", password)
            page.click("button[type='submit']")
            page.wait_for_load_state("networkidle")
        except Exception as e:
            print(f"[AUTH] Nota durante el login: {e}")

        # Guardar cookies y storage
        context.storage_state(path=session_path)
        print(f"[AUTH] Sesión guardada exitosamente en {session_path}")
        browser.close()