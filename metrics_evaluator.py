#!/usr/bin/env python3
"""Evalua hallazgos de weak-page contra ground_truth.json.

Uso: python metrics_evaluator.py resultado.json
La unidad de evaluacion es el flag, no cada instancia reportada.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


GROUND_TRUTH_PATH = Path(__file__).resolve().with_name("ground_truth.json")

# IDs emitidos por los validadores del proyecto.
ID_ALIASES = {
    "BAC-IDOR-001": "IDOR_ORDERS",
    "BAC-AUTH-ME-001": "MISSING_AUTH_ME",
    "BAC-FILE-EXPOSED-001": "EXPOSED_SENSITIVE_FILES",
    "BAC-ROLE-ADMIN-001": "MISSING_ROLE_CHECK_ADMIN",
    "BAC-MASS-ASSIGN-001": "MASS_ASSIGNMENT_REGISTER",
    "CRYPTO-RESET-ACTIVE-001": "PREDICTABLE_RESET_TOKEN",
    "CRYPTO-B64-ACTIVE-001": "BASE64_FAKE_ENCRYPTION",
}


def load_json(path):
    try:
        with path.open(encoding="utf-8-sig") as file:
            return json.load(file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"No se pudo leer {path}: {exc}") from exc


def validate_ground_truth(data):
    if not isinstance(data, dict) or not data:
        raise ValueError("El ground truth debe ser un objeto de categorias no vacio.")
    seen = set()
    for category, flags in data.items():
        if not isinstance(category, str) or not category.strip():
            raise ValueError("Cada categoria debe tener un nombre no vacio.")
        if not isinstance(flags, list) or not flags:
            raise ValueError(f"La categoria {category} debe contener una lista de flags.")
        for flag in flags:
            if not isinstance(flag, str) or not re.fullmatch(r"[A-Z0-9_]+", flag):
                raise ValueError(f"Flag invalido en {category}: {flag!r}")
            if flag in seen:
                raise ValueError(f"Flag duplicado en el ground truth: {flag}")
            seen.add(flag)
    return seen


def validate_findings(data):
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("El resultado debe contener una lista 'vulnerabilities'.")
    for index, finding in enumerate(data["vulnerabilities"], 1):
        if not isinstance(finding, dict):
            raise ValueError(f"El hallazgo {index} debe ser un objeto.")
        for field in ("finding_id", "type", "endpoint", "parameter"):
            if finding.get(field) is not None and not isinstance(finding[field], str):
                raise ValueError(f"El campo {field} del hallazgo {index} debe ser texto o null.")
        if not (finding.get("finding_id", "") or finding.get("type", "")):
            raise ValueError(f"El hallazgo {index} necesita finding_id o type.")
    return data["vulnerabilities"]


def match_flag(finding, expected):
    finding_id = (finding.get("finding_id") or "").strip().upper()
    finding_type = (finding.get("type") or "").strip()
    flag = ID_ALIASES.get(finding_id)
    if flag in expected:
        return flag
    if finding_id.startswith("CRYPTO-FLAG-"):
        flag = finding_id.removeprefix("CRYPTO-FLAG-")
        return flag if flag in expected else None
    if finding_id in expected:
        return finding_id

    # Se aceptan flags completos en el tipo, no coincidencias parciales.
    mentioned = {
        flag for flag in expected
        if re.search(r"(?<![A-Z0-9_])" + re.escape(flag) + r"(?![A-Z0-9_])",
                     finding_type.upper())
    }
    if len(mentioned) == 1:
        return mentioned.pop()
    if mentioned:
        return None

    parsed = urlsplit(finding.get("endpoint") or "")
    path = parsed.path.rstrip("/").lower()
    parameter = (finding.get("parameter") or "").strip().lower()
    kind = finding_type.casefold()
    if "sql injection" in kind or "sqli" in kind:
        if path == "/api/auth/login":
            return "SQLI_LOGIN" if "SQLI_LOGIN" in expected else None
        if path == "/api/products":
            parameters = {parameter} if parameter else set(parse_qs(parsed.query))
            candidates = {
                flag for key, flag in (("q", "SQLI_SEARCH"), ("category", "UNION_SQLI_DUMP"))
                if key in parameters and flag in expected
            }
            if len(candidates) == 1:
                return candidates.pop()
    if "xss" in kind or "cross-site scripting" in kind:
        if "stored" in kind and (path == "/api/contact" or path.startswith("/api/contact/")):
            return "XSS_STORED_CONTACT" if "XSS_STORED_CONTACT" in expected else None
        if "reflected" in kind and path == "/api/products":
            parameters = {parameter} if parameter else set(parse_qs(parsed.query))
            if "q" in parameters and "XSS_REFLECTED_SEARCH" in expected:
                return "XSS_REFLECTED_SEARCH"
    return None


def evaluate(ground_truth, findings):
    expected = validate_ground_truth(ground_truth)
    detected = set()
    unmatched = {}
    for finding in findings:
        flag = match_flag(finding, expected)
        if flag:
            detected.add(flag)
        else:
            # Hallazgos identicos no aumentan el denominador de precision.
            key = tuple((finding.get(field) or "").strip().casefold()
                        for field in ("finding_id", "type", "endpoint", "parameter"))
            unmatched.setdefault(key, finding)
    return detected, expected - detected, list(unmatched.values())


def print_table(headers, rows):
    rows = [[str(value) for value in row] for row in rows]
    widths = [max(len(str(header)), *(len(row[i]) for row in rows))
              for i, header in enumerate(headers)] if rows else [len(str(h)) for h in headers]
    separator = "-+-".join("-" * width for width in widths)
    print(" | ".join(str(value).ljust(widths[i]) for i, value in enumerate(headers)))
    print(separator)
    for row in rows:
        print(" | ".join(value.ljust(widths[i]) for i, value in enumerate(row)))


def print_report(ground_truth, detected, missing, unmatched):
    tp, fp, fn = len(detected), len(unmatched), len(missing)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    print("\nMETRICAS GLOBALES")
    print_table(("TP", "FP", "FN", "Precision", "Recall", "F1"),
                [(tp, fp, fn, f"{precision:.2%}", f"{recall:.2%}", f"{f1:.2%}")])
    print("\nRECALL POR CATEGORIA")
    print_table(("Categoria", "Detectadas", "Esperadas", "Recall"), [
        (category, len(detected.intersection(flags)), len(flags),
         f"{len(detected.intersection(flags)) / len(flags):.2%}")
        for category, flags in ground_truth.items()
    ])
    print("\nFALSOS NEGATIVOS")
    for category, flags in ground_truth.items():
        for flag in flags:
            if flag in missing:
                print(f"  {category}: {flag}")
    if not missing:
        print("  Ninguno")
    print("\nFALSOS POSITIVOS RESPECTO AL GROUND TRUTH")
    for finding in unmatched:
        print(f"  ID: {finding.get('finding_id') or '(sin ID)'} | "
              f"Tipo: {finding.get('type') or '(sin tipo)'} | "
              f"Endpoint: {finding.get('endpoint') or '(sin endpoint)'} | "
              f"Parametro: {finding.get('parameter') or '(sin parametro)'}")
    if not unmatched:
        print("  Ninguno")
    print("\nNota: un hallazgo sin correspondencia puede ser real pero estar fuera "
          "del alcance de este ground truth.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("resultado", type=Path, help="JSON de salida del sistema")
    args = parser.parse_args(argv)
    try:
        ground_truth = load_json(GROUND_TRUTH_PATH)
        findings = validate_findings(load_json(args.resultado))
        detected, missing, unmatched = evaluate(ground_truth, findings)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print_report(ground_truth, detected, missing, unmatched)
    return 0


if __name__ == "__main__":
    sys.exit(main())
