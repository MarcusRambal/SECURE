#!/usr/bin/env python3
"""Compare SQLI_LOGIN and SQLI_SEARCH across the weak_page flag matrix."""

import argparse
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


SCRIPT = Path(__file__).with_name("sqli_map.py").resolve()
IMAGE = "local-sqli-map:latest"
DEFAULT_TARGET = "http://weak-page:3009"
HEALTH_URL = "http://127.0.0.1:3009/api/health"
REPORT_MARKER = "SQLI_MAP_REPORT="
CONTAINER_TIMEOUT_SECONDS = 330


def check_health(health_url: str) -> bool:
    try:
        with urllib.request.urlopen(health_url, timeout=5) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def build_request(target: str, mode: str, login: bool, search: bool) -> str:
    host = urlsplit(target).netloc
    override = (
        f"SQLI_LOGIN={str(login).lower()},"
        f"SQLI_SEARCH={str(search).lower()}"
    )
    headers = [
        f"Host: {host}",
        f"X-Vulnerability-Override: {override}",
        "Connection: close",
    ]

    if mode == "login":
        body = '{"email":"test@example.test","password":"test123"}'
        headers.extend([
            "Content-Type: application/json",
            f"Content-Length: {len(body.encode('utf-8'))}",
        ])
        return (
            "POST /api/auth/login HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
            + body
        )
    if mode == "search":
        return (
            "GET /api/products?q=cake HTTP/1.1\r\n"
            + "\r\n".join(headers)
            + "\r\n\r\n"
        )
    raise ValueError(f"Unsupported SQLi mode: {mode}")


def classify(report: object, container_exit: int) -> str:
    if not isinstance(report, dict) or report.get("error") or container_exit != 0:
        return "ERROR"
    result = report.get("result")
    if not isinstance(result, dict):
        return "ERROR"
    if result.get("status") == "timeout":
        return "TIMEOUT"
    if result.get("exit_code") != 0:
        return "ERROR"
    if result.get("injectable") is True:
        return "DETECTADA"
    diagnostics = result.get("diagnostics")
    diagnostic_text = "\n".join(
        line.casefold()
        for line in diagnostics
        if isinstance(line, str)
    ) if isinstance(diagnostics, list) else ""
    conclusive_negative = (
        "all tested parameters do not appear to be injectable" in diagnostic_text
        or "does not seem to be injectable" in diagnostic_text
        or "does not appear to be injectable" in diagnostic_text
    )
    if any(
        marker in diagnostic_text
        for marker in (
            "[error]",
            "unable to connect",
            "connection timed out",
            "connection refused",
            "failed to connect",
            "unable to parse",
        )
    ):
        return "INCONCLUSA"
    if "[critical]" in diagnostic_text and not conclusive_negative:
        return "INCONCLUSA"
    if result.get("injectable") is False:
        return "NO DETECTADA"
    return "ERROR"


def should_stop(outcome: str) -> bool:
    return outcome in {"ERROR", "TIMEOUT"}


def test_cases() -> tuple[tuple[str, bool, bool], ...]:
    return (
        ("ambas-activas", True, True),
        ("solo-login-activa", True, False),
        ("solo-busqueda-activa", False, True),
        ("ambas-desactivadas", False, False),
    )


def _read_report(stdout: str) -> dict | None:
    marker = next(
        (
            line[len(REPORT_MARKER):]
            for line in stdout.splitlines()
            if line.startswith(REPORT_MARKER)
        ),
        None,
    )
    if marker is None:
        return None
    report = json.loads(marker)
    return report if isinstance(report, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compara SQLI_LOGIN y SQLI_SEARCH en las cuatro combinaciones; "
            "UNION_SQLI_DUMP no se modifica."
        )
    )
    parser.add_argument("--runs", type=int, default=20, help="Rondas por combinación.")
    parser.add_argument("--target-url", default=DEFAULT_TARGET)
    parser.add_argument("--health-url", default=HEALTH_URL)
    parser.add_argument(
        "--output-dir",
        help="Directorio de resultados (por defecto, se crea uno en el directorio actual).",
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs debe ser al menos 1")
    target_parts = urlsplit(args.target_url)
    if (
        target_parts.scheme not in {"http", "https"}
        or not target_parts.netloc
        or target_parts.username
        or target_parts.password
        or target_parts.path not in {"", "/"}
        or target_parts.query
    ):
        parser.error("--target-url debe ser un origen HTTP(S) sin ruta ni query")
    target = f"{target_parts.scheme}://{target_parts.netloc}"

    output = (
        Path(args.output_dir)
        if args.output_dir
        else Path.cwd() / f"sqli-map-tests-{datetime.now():%Y%m%d-%H%M%S-%f}"
    )
    output.mkdir(parents=True, exist_ok=True)
    print(f"Resultados: {output}", flush=True)
    if not check_health(args.health_url):
        print(
            f"ERROR: weak_page no responde en {args.health_url}.",
            file=sys.stderr,
        )
        return 1

    totals = defaultdict(
        lambda: defaultdict(
            lambda: {
                "ok": 0,
                "fallo": 0,
                "inconcluso": 0,
                "error": 0,
                "timeout": 0,
            }
        )
    )
    with tempfile.TemporaryDirectory(prefix="sqli-matrix-") as temp_dir:
        request_path = Path(temp_dir) / "request.txt"
        for round_number in range(1, args.runs + 1):
            for case_name, login, search in test_cases():
                for mode in ("login", "search"):
                    if not check_health(args.health_url):
                        print(
                            "ERROR: weak_page dejó de responder; se detienen las pruebas.",
                            file=sys.stderr,
                        )
                        return 1

                    label = f"{round_number:02d}-{case_name}-{mode}"
                    request_path.write_text(
                        build_request(target, mode, login, search),
                        encoding="utf-8",
                        newline="",
                    )
                    expected = "DETECTADA" if (
                        login if mode == "login" else search
                    ) else "NO DETECTADA"
                    container_name = f"secure-sqli-matrix-{uuid.uuid4().hex}"
                    command = [
                        "docker", "run", "--rm", "--name", container_name,
                        "--pull=never", "--network", "sec-net",
                        "--memory", "1024m", "--shm-size", "1g",
                        "-v", f"{SCRIPT}:/app/sqli_map.py:ro",
                        "-v", f"{request_path}:/tmp/request.txt:ro",
                        IMAGE,
                        "--action", "detect",
                        "--technique", "BEU",
                        "--request-file", "/tmp/request.txt",
                        "--param", "email" if mode == "login" else "q",
                        "--output", "/tmp/report.json",
                    ]
                    print(
                        f"Iniciando {label}: esperado {expected}",
                        flush=True,
                    )
                    started = time.monotonic()
                    try:
                        run = subprocess.run(
                            command,
                            capture_output=True,
                            text=True,
                            timeout=CONTAINER_TIMEOUT_SECONDS,
                        )
                        log = run.stdout + "\n" + run.stderr
                        report = _read_report(run.stdout)
                        outcome = classify(report, run.returncode)
                    except subprocess.TimeoutExpired as error:
                        cleanup = subprocess.run(
                            ["docker", "rm", "-f", container_name],
                            capture_output=True,
                            text=True,
                        )
                        outcome, report = "TIMEOUT", None
                        log = f"Timeout: {error}\nLimpieza: {cleanup.stderr}\n"
                    except (OSError, json.JSONDecodeError) as error:
                        outcome, report = "ERROR", None
                        log = f"{type(error).__name__}: {error}\n"

                    status_key = (
                        "ok" if outcome == expected else
                        "inconcluso" if outcome == "INCONCLUSA" else
                        "timeout" if outcome == "TIMEOUT" else
                        "error" if outcome == "ERROR" else "fallo"
                    )
                    totals[case_name][mode][status_key] += 1
                    (output / f"{label}.log").write_text(log, encoding="utf-8")
                    (output / f"{label}.json").write_text(
                        json.dumps(
                            {
                                "case": case_name,
                                "mode": mode,
                                "login_vulnerable": login,
                                "search_vulnerable": search,
                                "expected": expected,
                                "observed": outcome,
                                "report": report,
                            },
                            ensure_ascii=False,
                            indent=2,
                        ) + "\n",
                        encoding="utf-8",
                    )
                    print(
                        f"{label}: {status_key.upper()} ({outcome}) "
                        f"{time.monotonic() - started:.1f} s",
                        flush=True,
                    )

                    if not check_health(args.health_url):
                        print(
                            "ERROR: weak_page dejó de responder; se detienen las pruebas.",
                            file=sys.stderr,
                        )
                        return 1
                    if should_stop(outcome):
                        print(
                            "Pruebas detenidas por error o tiempo agotado.",
                            file=sys.stderr,
                        )
                        return 1

    all_ok = True
    print("\nResumen (cada combinación debe coincidir en login y búsqueda):")
    for case_name, _, _ in test_cases():
        print(f"{case_name}:")
        for mode in ("login", "search"):
            counts = totals[case_name][mode]
            print(
                f"  {mode}: OK={counts['ok']}/{args.runs} "
                f"fallo={counts['fallo']} inconclusa={counts['inconcluso']} "
                f"timeout={counts['timeout']} error={counts['error']}"
            )
            if (
                counts["ok"] != args.runs
                or counts["fallo"]
                or counts["inconcluso"]
                or counts["timeout"]
                or counts["error"]
            ):
                all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
