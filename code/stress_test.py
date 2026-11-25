"""Pruebas HTTP de control de acceso contra el laboratorio weak-page.

El resumen conserva los nombres solicitados: login corresponde a /api/me y
search al acceso IDOR a un pedido. No ejecuta el escaner Access Control.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import os
import sys

import requests


ITERATIONS = 20
TIMEOUT = 10
TESTS = {
    "login": {"path": "/api/me", "flag": "MISSING_AUTH_ME"},
    "search": {"path": "/api/orders/{id}", "flag": "IDOR_ORDERS"},
}
SCENARIOS = {
    "ambas-activas": {"IDOR_ORDERS": True, "MISSING_AUTH_ME": True},
    "solo-idor": {"IDOR_ORDERS": True, "MISSING_AUTH_ME": False},
    "solo-auth": {"IDOR_ORDERS": False, "MISSING_AUTH_ME": True},
    "ambas-desactivadas": {"IDOR_ORDERS": False, "MISSING_AUTH_ME": False},
}


def override(flags):
    return {"X-Vulnerability-Override": ",".join(
        f"{flag}={'true' if enabled else 'false'}"
        for flag, enabled in flags.items()
    )}


def get_json(response):
    try:
        value = response.json()
    except requests.exceptions.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def login(base_url, email, password):
    response = requests.post(
        base_url + "/api/auth/login",
        json={"email": email, "password": password},
        headers=override({"SQLI_LOGIN": False, "WEAK_MD5_LEGACY": True,
                          "PLAINTEXT_PASSWORDS": True}),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    data = get_json(response)
    if response.status_code != 200 or not data or not isinstance(data.get("token"), str) or not data["token"]:
        raise ValueError(f"No se pudo autenticar {email}: HTTP {response.status_code}")
    return data["token"]


def identity(base_url, token):
    response = requests.get(
        base_url + "/api/auth/whoami",
        headers={"Authorization": f"Bearer {token}"},
        timeout=TIMEOUT, allow_redirects=False,
    )
    data = get_json(response)
    user = data.get("user") if data else None
    if response.status_code != 200 or not isinstance(user, dict) or user.get("id") is None:
        raise ValueError(f"No se pudo verificar una identidad: HTTP {response.status_code}")
    return user


def validate_identities(base_url, victim_token, attacker_token, order_id):
    victim = identity(base_url, victim_token)
    attacker = identity(base_url, attacker_token)
    if victim["id"] == attacker["id"] or attacker.get("role") == "admin":
        raise ValueError("Se requieren usuarios distintos y un atacante que no sea administrador")
    headers = override({"IDOR_ORDERS": False, "MISSING_AUTH_ME": False})
    headers["Authorization"] = f"Bearer {victim_token}"
    response = requests.get(
        f"{base_url}/api/orders/{order_id}", headers=headers,
        timeout=TIMEOUT, allow_redirects=False,
    )
    order = get_json(response)
    if response.status_code != 200 or not order or order.get("user_id") != victim["id"] or str(order.get("id")) != str(order_id):
        raise ValueError("El pedido no existe o no pertenece a la victima")
    return victim["id"]


def run_attempt(base_url, test_name, flags, attacker_token, victim_id, order_id):
    headers = override(flags)
    try:
        # El control de configuracion usa el mismo override, permitiendo al
        # atacante consultar el scoreboard sin depender de su rol.
        check_headers = override({**flags, "MISSING_ROLE_CHECK_ADMIN": True})
        check_headers["Authorization"] = f"Bearer {attacker_token}"
        check = requests.get(
            base_url + "/api/admin/vulnerabilities", headers=check_headers,
            timeout=TIMEOUT, allow_redirects=False,
        )
        data = get_json(check)
        resolved = data.get("flags") if data else None
        if check.status_code >= 500:
            print(f"Error al consultar flags: HTTP {check.status_code}", file=sys.stderr)
            return "error"
        if check.status_code != 200 or not isinstance(resolved, dict) or any(
            resolved.get(flag) is not value for flag, value in flags.items()
        ):
            print("Configuracion no verificable: override ignorado o JSON invalido", file=sys.stderr)
            return "inconclusa"

        test = TESTS[test_name]
        path = test["path"].replace("{id}", str(order_id))
        if test_name == "search":
            headers["Authorization"] = f"Bearer {attacker_token}"
        response = requests.get(
            base_url + path, headers=headers, timeout=TIMEOUT, allow_redirects=False,
        )
        if response.status_code >= 500:
            print(f"Error en {path}: HTTP {response.status_code}", file=sys.stderr)
            return "error"
        if response.status_code == 200:
            body = get_json(response)
            if test_name == "login":
                valid = bool(body and isinstance(body.get("user"), dict) and body["user"].get("id") is not None)
            else:
                valid = bool(body and body.get("user_id") == victim_id and str(body.get("id")) == str(order_id))
            if not valid:
                return "inconclusa"
            detected = True
        elif response.status_code == (401 if test_name == "login" else 403):
            detected = False
        else:
            return "inconclusa"
        return "OK" if detected == flags[test["flag"]] else "fallo"
    except requests.Timeout as exc:
        print(f"Timeout en {test_name}: {exc}", file=sys.stderr)
        return "timeout"
    except requests.RequestException as exc:
        print(f"Error de red en {test_name}: {exc}", file=sys.stderr)
        return "error"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://localhost:3009")
    parser.add_argument("--iterations", type=int, default=ITERATIONS)
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--order-id", type=int, default=1)
    parser.add_argument("--victim-email", default="maria@example.com")
    parser.add_argument("--attacker-email", default="pedro@example.com")
    args = parser.parse_args(argv)
    if args.iterations < 1 or args.workers < 1 or args.order_id < 1:
        parser.error("iterations, workers y order-id deben ser positivos")
    base_url = args.base_url.rstrip("/")
    victim_token = os.environ.get("VICTIM_TOKEN")
    attacker_token = os.environ.get("ATTACKER_TOKEN")
    victim_password = os.environ.get("VICTIM_PASSWORD")
    attacker_password = os.environ.get("ATTACKER_PASSWORD")
    if not victim_token and not victim_password or not attacker_token and not attacker_password:
        parser.error("Indica VICTIM_TOKEN y ATTACKER_TOKEN, o las variables VICTIM_PASSWORD y ATTACKER_PASSWORD correspondientes")
    try:
        if not victim_token:
            victim_token = login(base_url, args.victim_email, victim_password)
        if not attacker_token:
            attacker_token = login(base_url, args.attacker_email, attacker_password)
        victim_id = validate_identities(base_url, victim_token, attacker_token, args.order_id)
    except (requests.RequestException, ValueError) as exc:
        print(f"Error de preparacion: {exc}", file=sys.stderr)
        return 2

    results = {}
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        for scenario, flags in SCENARIOS.items():
            for name in TESTS:
                results[scenario, name] = [
                    executor.submit(run_attempt, base_url, name, flags, attacker_token, victim_id, args.order_id)
                    for _ in range(args.iterations)
                ]
        counts = {
            key: Counter(future.result() for future in futures)
            for key, futures in results.items()
        }

    print("Resumen (cada combinación debe coincidir en login y búsqueda):")
    for scenario in SCENARIOS:
        print(f"{scenario}:")
        for name in TESTS:
            count = counts[scenario, name]
            print(f"  {name}: OK={count['OK']}/{args.iterations} fallo={count['fallo']} "
                  f"inconclusa={count['inconclusa']} timeout={count['timeout']} error={count['error']}")
    return int(any(count["OK"] != args.iterations for count in counts.values()))


if __name__ == "__main__":
    sys.exit(main())
