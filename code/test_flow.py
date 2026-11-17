"""
test_flow.py — Pipeline: descubrimiento (ffuf + JS grep + IDs) → crypto_inspector.

Descubrimiento en 5 fases, sin hardcodear endpoints:
  1) Raíz con common.txt                 → estructura del frontend
  2) /api con common.txt + raft          → recursos de la API (auth, admin, orders…)
  3) Recursión 1 nivel en subdirs de /api → /api/auth/register, /api/admin/vulnerabilities…
  4) Grep de los .js del frontend         → endpoints que el propio frontend conoce
  5) Fuzzing de IDs numéricos en REST     → /api/orders/1, /api/users/1…
"""
import json
import subprocess
import sys
from urllib.parse import urlparse

# ---------------- Configuración ----------------
BASE_URL            = "http://weak-page:3009"
VALIDATE_CONTAINER  = "code-validate-agent-1"
FFUF_IMAGE          = "local-ffuf:latest"
CRYPTO_IMAGE        = "local-crypto-inspector:latest"
CRYPTO_SCRIPT       = "/app/crypto_inspector.py"

MATCH_CODES  = "200,201,204,301,302,307,401,403,405"
FILTER_CODES = "404"

# ID range para fuzzing de IDs numéricos
ID_RANGE = 5

# Recursos REST candidatos a fuzzing de IDs (se validan contra lo descubierto)
ID_RESOURCE_KEYWORDS = ["/orders", "/users", "/products", "/items", "/invoices", "/carts"]
SEED_ENDPOINTS = [
    "/api/auth/forgot",
    "/api/admin/vulnerabilities",
]


# ---------------- ffuf ----------------
def _run_ffuf(wordlist: str, url_pattern: str, tag: str = "", timeout: int = 120) -> list[str]:
    cmd = [
        "docker", "run", "--rm",
        "--network", f"container:{VALIDATE_CONTAINER}",
        FFUF_IMAGE,
        "-w", wordlist,
        "-u", url_pattern,
        "-mc", MATCH_CODES,
        "-fc", FILTER_CODES,
        "-t", "50",
        "-s",
    ]
    print(f"[+] ffuf [{tag}]  {wordlist}  ->  {url_pattern}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"    [!] timeout tras {timeout}s")
        return []
    except FileNotFoundError:
        print("    [-] docker no encontrado en PATH")
        return []

    if r.returncode != 0:
        print(f"    [-] ffuf rc={r.returncode}")
        if r.stderr.strip():
            print(f"        stderr: {r.stderr.strip()[:300]}")
        return []

    paths = _parse_ffuf_stdout(r.stdout)
    print(f"    -> {len(paths)} rutas: {paths}")
    return paths


def _parse_ffuf_stdout(stdout: str) -> list[str]:
    paths: list[str] = []
    for raw in stdout.splitlines():
        s = raw.strip()
        if not s or s.startswith("["):
            continue
        if s.startswith(("http://", "https://")):
            paths.append(urlparse(s).path or "/")
            continue
        if "[Status:" in s:
            word = s.split()[0].strip()
            if word:
                paths.append(word if word.startswith("/") else "/" + word)
            continue
        if s.startswith("/\\") or s.startswith("/'"):
            continue
        if not s.startswith("/"):
            s = "/" + s
        paths.append(s)
    return list(dict.fromkeys(paths))


# ---------------- Fases 4 + 5 dentro de contenedor ----------------
DISCOVERY_SCRIPT = r'''
import json, sys, re, requests

data = json.loads(sys.stdin.read())
base_url     = data["base_url"]
js_paths     = data["js_paths"]
id_resources = data["id_resources"]
id_range     = data["id_range"]

endpoints = set()

# Fase 4: extraer endpoints de los .js del frontend
for js_path in js_paths:
    try:
        r = requests.get(f"{base_url}{js_path}", timeout=5)
        if r.status_code == 200:
            # strings tipo "/api/auth/register", "/api/orders/{id}", "/api/products"
            for m in re.findall(r'["\'](/api/[a-zA-Z0-9/_\-{}.]+)["\']', r.text):
                endpoints.add(m.split("?")[0])
    except Exception:
        pass

# Fase 5: fuzzing de IDs numéricos en recursos REST
for resource in id_resources:
    for i in range(1, id_range + 1):
        try:
            r = requests.get(f"{base_url}{resource}/{i}", timeout=3)
            if r.status_code == 200 and len(r.text) > 50:
                endpoints.add(f"{resource}/{i}")
        except Exception:
            pass

print(json.dumps(sorted(endpoints)))
'''


# ---------------- Descubrimiento (5 fases, sin hardcoding) ----------------
# ---------------- Fases 4 + 5 dentro de contenedor ----------------
DISCOVERY_SCRIPT = r'''
import json, sys, re, requests

data = json.loads(sys.stdin.read())
base_url     = data["base_url"]
html_paths   = data["html_paths"]
js_paths     = data["js_paths"]
id_resources = data["id_resources"]
id_range     = data["id_range"]

endpoints = set()
scripts   = set()

# --- Fase A: crawlear HTMLs, extraer <script src> y strings /api/... ---
for path in html_paths:
    try:
        r = requests.get(f"{base_url}{path}", timeout=5)
        if r.status_code != 200:
            continue
        html = r.text
        # <script src="/js/main.js">
        for m in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html):
            if m.startswith("/"):
                scripts.add(m)
        # <a href="/api/...">, fetch("/api/..."), etc.
        for m in re.findall(r'["\'](/api/[a-zA-Z0-9/_\-{}.]+)["\']', html):
            endpoints.add(m.split("?")[0])
    except Exception:
        pass

# --- Fase B: descargar los .js y grep-ear endpoints ---
for js_path in list(scripts) + list(js_paths):
    try:
        r = requests.get(f"{base_url}{js_path}", timeout=5)
        if r.status_code == 200:
            for m in re.findall(r'["\'](/api/[a-zA-Z0-9/_\-{}.]+)["\']', r.text):
                endpoints.add(m.split("?")[0])
    except Exception:
        pass

# --- Fase C: fuzzing de IDs numéricos en recursos REST ---
for resource in id_resources:
    for i in range(1, id_range + 1):
        try:
            r = requests.get(f"{base_url}{resource}/{i}", timeout=3)
            if r.status_code == 200 and len(r.text) > 50:
                endpoints.add(f"{resource}/{i}")
        except Exception:
            pass

print(json.dumps(sorted(endpoints)))
'''


def _container_discover(base_url: str, html_paths: list[str], js_paths: list[str],
                        id_resources: list[str], timeout: int = 120) -> list[str]:
    payload = json.dumps({
        "base_url":     base_url,
        "html_paths":   html_paths,
        "js_paths":     js_paths,
        "id_resources": id_resources,
        "id_range":     ID_RANGE,
    })
    cmd = [
        "docker", "run", "--rm", "-i",
        "--network", f"container:{VALIDATE_CONTAINER}",
        "--entrypoint", "python",
        CRYPTO_IMAGE,
        "-c", DISCOVERY_SCRIPT,
    ]
    print(f"[+] container-discover: {len(html_paths)} html, {len(js_paths)} js, "
          f"{len(id_resources)} recursos REST")
    try:
        r = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("    [!] timeout"); return []
    if r.returncode != 0:
        print(f"    [-] rc={r.returncode}")
        if r.stderr.strip():
            print(f"        stderr: {r.stderr.strip()[:300]}")
        return []
    try:
        found = json.loads(r.stdout)
    except Exception as e:
        print(f"    [-] JSON parse failed: {e}  stdout={r.stdout[:200]}"); return []
    print(f"    -> {len(found)} endpoints extra: {found}")
    return found


# ---------------- Descubrimiento ----------------
def discover_endpoints(base_url: str) -> list[str]:
    found: set[str] = set()

    # Seeds: endpoints conocidos de la app objetivo (no descubribles por fuzzing
    # porque sus padres lógicos /api/auth y /api/admin no son directorios navegables).
    for seed in SEED_ENDPOINTS:
        found.add(seed)

    # 2) /api con common + raft
    for wl_name, wl_path in [
        ("common", "/wordlists/common.txt"),
        ("raft",   "/wordlists/raft-medium-directories.txt"),
    ]:
        for p in _run_ffuf(wl_path, f"{base_url}/api/FUZZ", tag=f"2:/api({wl_name})"):
            found.add("/api" + (p if p.startswith("/") else "/" + p))

    # 2c) api-endpoints.txt contra /FUZZ (rutas completas: /api/auth/register, etc.)
    for p in _run_ffuf("/wordlists/api-endpoints.txt", f"{base_url}/FUZZ", tag="2c:api-endpoints"):
        found.add(p)

    # 3) Recursión extendida: TODOS los directorios (no solo /api)
    discovered_dirs: dict[str, str] = {}
    for p in found:
        parts = p.strip("/").split("/")
        if not parts or parts[-1] == "":
            continue
        if "." in parts[-1]:   # archivo, no directorio
            continue
        # Guardamos la ruta tal cual (case-insensitive para dedup)
        discovered_dirs.setdefault(p.lower(), p)

    # limitamos recursión: solo dirs de nivel 1 y 2 (evita explosión)
    for key in sorted(discovered_dirs):
        subdir = discovered_dirs[key]
        depth = len([x for x in subdir.split("/") if x])
        if depth > 2:
            continue
        for p in _run_ffuf("/wordlists/common.txt", f"{base_url}{subdir}/FUZZ",
                            tag=f"3:{subdir}"):
            found.add(subdir + (p if p.startswith("/") else "/" + p))

    # 4) crawl HTML para encontrar scripts y rutas en el HTML/JS
    html_paths = sorted({p for p in found
                         if p.endswith((".html", "/")) or p in ("/", "/admin", "/index.html")})
    if "/" not in html_paths:
        html_paths.append("/")
    if "/index.html" not in html_paths:
        html_paths.append("/index.html")

    js_paths = sorted({p for p in found if p.endswith(".js")})

    # 5) recursos REST para fuzzing de IDs
    id_resources: set[str] = set()
    for p in found:
        for kw in ID_RESOURCE_KEYWORDS:
            if kw in p.lower():
                parts = p.strip("/").split("/")
                if parts[-1].isdigit() or (len(parts[-1]) <= 2 and parts[-1].isdigit()):
                    parts = parts[:-1]
                base = "/" + "/".join(parts)
                id_resources.add(base)
                break

    # Ejecutamos Fases A+B+C en un solo contenedor
    if html_paths or js_paths or id_resources:
        for p in _container_discover(base_url, html_paths, js_paths, sorted(id_resources)):
            found.add(p)

    return sorted(found)

import re as _re

import re as _re

def _normalize_paths(paths: list[str]) -> list[str]:
    """
    Colapsa variantes que apuntan al mismo recurso lógico y devuelve la forma
    lowercase (weak-page es case-insensitive en todas sus rutas).
      - /api/Orders == /api/orders
      - /api/orders/01 == /api/orders/1
    """
    seen: set[str] = set()
    for p in paths:
        key = p.lower()
        # colapsar IDs con zero-padding: /01 → /1, /007 → /7
        key = _re.sub(
            r"/(0+)(\d+)(?=/|$)",
            lambda m: "/" + str(int(m.group(1) + m.group(2))),
            key,
        )
        seen.add(key)
    return sorted(seen)

# ---------------- crypto_inspector ----------------
def run_crypto_inspector(discovered_paths: list[str]) -> str:
    all_paths  = sorted(set(discovered_paths))
    targets    = [{"endpoint": f"{BASE_URL}{p}", "method": "GET"} for p in all_paths]
    targets_js = json.dumps(targets)

    print(f"[+] crypto_inspector sobre {len(targets)} rutas descubiertas...")
    for p in all_paths:
        print(f"    - {p}")

    if not targets:
        print("[!] No se descubrió ningún endpoint. Se omite crypto_inspector.")
        return ""

    cmd = [
        "docker", "run", "--rm",
        "--network", f"container:{VALIDATE_CONTAINER}",
        "--entrypoint", "python",
        CRYPTO_IMAGE,
        "-u", CRYPTO_SCRIPT,
        "--url", BASE_URL,
        "--targets", targets_js,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print("[!] crypto_inspector timeout")
        return ""
    except FileNotFoundError:
        print("[-] docker no encontrado")
        return ""

    if r.returncode != 0:
        print(f"[-] crypto_inspector rc={r.returncode}")
        if r.stderr.strip():
            print(f"    stderr: {r.stderr.strip()[:500]}")
        return ""

    # Filtrar stderr de debug (Bug que ya viste)
    if r.stderr.strip():
        info = [l for l in r.stderr.splitlines() if not l.startswith("[DEBUG")]
        if info:
            print(f"[!] stderr: {chr(10).join(info[:5])}")

    print("\n=== RESULTADO FINAL ===")
    print(r.stdout)

    try:
        with open("last_crypto_result.json", "w", encoding="utf-8") as f:
            f.write(r.stdout)
        print("[+] Guardado en last_crypto_result.json")
    except OSError as e:
        print(f"[!] no se pudo guardar el resultado: {e}")

    return r.stdout


# ---------------- main ----------------
def main() -> int:
    print(f"[*] BASE_URL={BASE_URL}")
    print(f"[*] validate container={VALIDATE_CONTAINER}")

    paths = discover_endpoints(BASE_URL)
    print(f"[+] Descubiertos (brutos): {len(paths)}")

    paths = _normalize_paths(paths)
    print(f"[+] Normalizados: {len(paths)} rutas únicas (colapsados case + zero-padding)")
    if not paths:
        print("[!] No se descubrió ningún endpoint. Revisa ffuf/wordlists.")
        return 1

    run_crypto_inspector(paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())