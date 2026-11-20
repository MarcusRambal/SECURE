#!/usr/bin/env python3
"""Run repeated reflected/stored XSS checks against the local weak_page lab."""

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from collections import defaultdict
from datetime import datetime
from pathlib import Path


SCRIPT = Path(__file__).with_name("browser_xss_validator.py").resolve()
IMAGE = "local-browser-xss-validator:latest"
DEFAULT_TARGET = "http://weak-page:3009"
HEALTH_URL = "http://127.0.0.1:3009/api/health"
STORED_VALIDATION_HEADER = {"x-weak-page-xss-validation": "stored-contact"}
VULNERABILITY_FLAGS = {
    "reflected": "XSS_REFLECTED_SEARCH",
    "stored": "XSS_STORED_CONTACT",
}


def check_health(health_url: str) -> bool:
    try:
        with urllib.request.urlopen(health_url, timeout=5) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def build_plan(target: str, mode: str, reflected: bool, stored: bool) -> dict:
    override = (
        f"XSS_REFLECTED_SEARCH={str(reflected).lower()},"
        f"XSS_STORED_CONTACT={str(stored).lower()}"
    )
    override_header = {"x-vulnerability-override": override}

    if mode == "reflected":
        return {
            "mode": "reflected_dom",
            "source_url": f"{target}/#/catalog",
            "parameter": "q",
            "input_selector": "#catalog-search",
            "marker_prefix": "weakpage-xss-probe-",
            "request": {
                "method": "GET",
                "path": "/api/products",
                "query_parameter": "q",
            },
            "request_headers": override_header,
        }

    if mode == "stored":
        return {
            "mode": "stored_dom",
            "source_url": f"{target}/#/contact",
            "parameter": "message",
            "marker_prefix": "weakpage-xss-probe-",
            "form_selector": "#contact-form",
            "form_fields": ["name", "email", "subject", "message"],
            "submit_selector": "#contact-form button[type='submit']",
            "request": {"method": "POST", "path": "/api/contact"},
            "request_headers": {
                **STORED_VALIDATION_HEADER,
                **override_header,
            },
            "verification_url_template": (
                f"{target}/#/contact-inbox?probeId={{id}}&marker={{marker}}"
            ),
            "verification_request": {
                "method": "GET",
                "path_template": "/api/contact/xss-inbox/{id}",
                "headers": {
                    **STORED_VALIDATION_HEADER,
                    **override_header,
                },
            },
            "cleanup": {
                "method": "DELETE",
                "path_template": "/api/contact/{id}",
                "headers": {
                    **STORED_VALIDATION_HEADER,
                    "content-type": "application/json",
                },
                "body": {"marker": "{marker}"},
            },
        }

    raise ValueError(f"Unsupported test mode: {mode}")


def classify(report: object, container_exit: int, mode: str, target: str) -> str:
    if not isinstance(report, dict) or container_exit != 0:
        return "ERROR"
    if (
        report.get("tool") != "browserXssValidator"
        or report.get("target") != target
    ):
        return "ERROR"
    outcome = report.get("outcome")
    if outcome == "INCONCLUSIVE":
        return "INCONCLUSO"
    if outcome not in {"VULNERABLE", "NO_XSS"}:
        return "ERROR"

    expected_mode = "reflected_dom" if mode == "reflected" else "stored_dom"
    if report.get("mode") != expected_mode:
        return "ERROR"

    if mode == "stored" and report.get("cleanup") != "success":
        return "INCONCLUSO"
    return outcome


def test_cases() -> tuple[tuple[str, bool, bool], ...]:
    return (
        ("ambas-vulnerables", True, True),
        ("solo-almacenado-vulnerable", False, True),
        ("solo-reflejado-vulnerable", True, False),
        ("ambas-seguras", False, False),
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compara las cuatro configuraciones XSS de weak_page."
    )
    parser.add_argument("--runs", type=int, default=20, help="Repeticiones por combinación.")
    parser.add_argument("--target-url", default=DEFAULT_TARGET)
    parser.add_argument("--health-url", default=HEALTH_URL)
    parser.add_argument(
        "--output-dir",
        help="Directorio de resultados (por defecto, se crea uno en el directorio actual).",
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs debe ser al menos 1")
    target = args.target_url.rstrip("/")
    if not target.startswith("http://") and not target.startswith("https://"):
        parser.error("--target-url debe ser una URL HTTP(S)")

    output = (
        Path(args.output_dir)
        if args.output_dir
        else Path.cwd() / f"browser-xss-tests-{datetime.now():%Y%m%d-%H%M%S-%f}"
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
            lambda: {"ok": 0, "fallo": 0, "inconcluso": 0, "error": 0}
        )
    )
    for round_number in range(1, args.runs + 1):
        for case_name, reflected, stored in test_cases():
            for mode in ("reflected", "stored"):
                label = f"{round_number:02d}-{case_name}-{mode}"
                plan = build_plan(target, mode, reflected, stored)
                expected = "VULNERABLE" if (
                    reflected if mode == "reflected" else stored
                ) else "NO_XSS"
                container_name = f"browser-xss-lab-{uuid.uuid4().hex}"
                command = [
                    "docker", "run", "--rm", "--name", container_name,
                    "--pull=never", "--network", "sec-net",
                    "--memory", "1024m", "--shm-size", "1g",
                    "-v", f"{SCRIPT}:/app/browser_xss_validator.py:ro",
                    IMAGE,
                    "--target-url", target,
                    "--plan-json", json.dumps(plan, separators=(",", ":")),
                ]
                print(
                    f"Ejecutando {label}: esperado {expected}",
                    flush=True,
                )
                try:
                    run = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    log = run.stdout + "\n" + run.stderr
                    report = json.loads(run.stdout.strip()) if run.stdout.strip() else None
                    observed = classify(report, run.returncode, mode, target)
                    result = "ok" if observed == expected else (
                        "inconcluso" if observed == "INCONCLUSO" else
                        "error" if observed == "ERROR" else "fallo"
                    )
                except subprocess.TimeoutExpired as error:
                    cleanup = subprocess.run(
                        ["docker", "rm", "-f", container_name],
                        capture_output=True,
                        text=True,
                    )
                    report = None
                    observed = "INCONCLUSO"
                    result = "inconcluso"
                    log = f"Timeout: {error}\nLimpieza: {cleanup.stderr}\n"
                except (OSError, json.JSONDecodeError) as error:
                    report = None
                    observed = "ERROR"
                    result = "error"
                    log = f"{type(error).__name__}: {error}\n"

                totals[case_name][mode][result] += 1
                (output / f"{label}.json").write_text(
                    json.dumps(
                        {
                            "case": case_name,
                            "mode": mode,
                            "expected": expected,
                            "observed": observed,
                            "result": result,
                            "report": report,
                        },
                        ensure_ascii=False,
                        indent=2,
                    ) + "\n",
                    encoding="utf-8",
                )
                (output / f"{label}.log").write_text(log, encoding="utf-8")
                print(f"{label}: {result.upper()} ({observed})", flush=True)

                if not check_health(args.health_url):
                    print(
                        "ERROR: weak_page dejó de responder; se detienen las pruebas.",
                        file=sys.stderr,
                    )
                    return 1

    all_ok = True
    print("\nResumen (cada flujo debe coincidir con su resultado esperado):")
    for case_name, _, _ in test_cases():
        print(f"{case_name}:")
        for mode in ("reflected", "stored"):
            counts = totals[case_name][mode]
            print(
                f"  {mode}: OK={counts['ok']}/{args.runs} "
                f"fallo={counts['fallo']} inconcluso={counts['inconcluso']} "
                f"error={counts['error']}"
            )
            if (
                counts["ok"] != args.runs
                or counts["fallo"]
                or counts["inconcluso"]
                or counts["error"]
            ):
                all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
