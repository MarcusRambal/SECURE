import argparse
import base64
import codecs
import json
import math
import re
import socket
import ssl
import requests
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import hashlib
import itertools

# Dependencias opcionales
try:
    import zmq
    HAS_ZMQ = True
except ImportError:
    HAS_ZMQ = False

try:
    import jwt as pyjwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False


# Diccionario base (simula rockyou.txt o SecLists)
BASE_WORDLIST = [
    "admin", "password", "123456", "juice", "shop", "test", "demo", 
    "root", "user", "guest", "qwerty", "secret", "admin123", "welcome","jim", "bender", "admin123"
]

# ==========================================
# 1. ENTROPÍA DE SHANNON
# ==========================================
def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    length = len(data)
    frequency = {}
    for char in data:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


# ==========================================
# 2. PATRONES REGEX Y REGISTRADOR
# ==========================================
SHA1_STRICT_REGEX = r"^[a-fA-F0-9]{40}$"
MD5_STRICT_REGEX = r"^[a-fA-F0-9]{32}$"
SHA256_STRICT_REGEX = r"^[a-fA-F0-9]{64}$"

CRYPTO_PATTERNS = {
    "MD5 Hash": r"\b[a-fA-F0-9]{32}\b",
    "SHA1 Hash": r"\b[a-fA-F0-9]{40}\b",
    "SHA256 Hash": r"\b[a-fA-F0-9]{64}\b",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Base64 String": r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    "RSA/Generic Private Key": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
    "Generic Secret Key": r"(?i)(api[_-]?key|secret|token|password|auth)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']"
}

SECRET_PATTERNS = {
    "AWS Access Key": r"(AKIA[0-9A-Z]{16})",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]+",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "JWT Secret (assignment)": r"(?:jwt[_-]?secret|jwtSecret)\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    "Private Key Inline": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{100,}?-----END",
    "Generic Hardcoded Password": r"(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]",
    "Firebase Config": r"apiKey\s*:\s*['\"]AIza[^'\"]+['\"]",
}


# ==========================================
# 3. CLASIFICADOR DE CONTEXTO
# ==========================================
SECURITY_CONTEXT_SIGNALS = [
    "password", "passwd", "pwd", "secret", "token", "session",
    "auth", "login", "credential", "signature", "reset",
    "verification", "otp", "2fa", "mfa", "remember", "cookie"
]

BENIGN_CONTEXT_SIGNALS = [
    "checksum", "csaf", "advisory", "integrity", "etag", "md5sum",
    "sha1sum", "fingerprint", "cache", "dedup", "version", "build",
    "static", "asset", "manifest", "sri", "digest_url", "challenge"
]

COMMON_HASH_DB = {
    # MD5
    "0192023a7bbd73250516f069df18b500": "admin123",
    "21232f297a57a5a743894a0e4a801fc3": "admin",
    "5f4dcc3b5aa765d61d8327deb882cf99": "password",
    "e10adc3949ba59abbe56e057f20f883e": "123456",
    "25d55ad283aa400af464c76d713c07ad": "12345678",
    "d8578edf8458ce06fbc5bb76a58c5ca4": "qwerty",
    "482c811da5d5b4bc6d497ffa98491e38": "password123",
    # SHA1
    "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password",
    "f7c3bc1d808e04732adf679965ccc34ca7ae3441": "admin",
    "d033e22ae348aeb5660fc2140aec35850c4da997": "admin",
    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3": "test",
     "9283f1b2e9669749081963be0462e466": "admin123",
    "6edd9d726cbdc873c539e41ae8757b8c": "demo",
    "2c17c6393771ee3048ae34d6b380c5ec": "test",
    "00479e957b6b42c459ee5746478e4d45": "bender",
    "402f1c4a75e316afec5a6ea63147f739": "jim",
    
}

COMMON_JWT_SECRETS = [
    "secret", "juice", "password", "admin", "key", "jwt", "supersecret",
    "mysecret", "test", "1234", "changeme", "default", "juice-shop",
    "your-256-bit-secret", "secretkey"
]


def classify_context(path: str, key: str, endpoint: str = "") -> Dict[str, Any]:
    haystack = f"{path} {key} {endpoint}".lower()
    is_security = any(sig in haystack for sig in SECURITY_CONTEXT_SIGNALS)
    is_benign = any(sig in haystack for sig in BENIGN_CONTEXT_SIGNALS)

    if is_security and not is_benign:
        return {
            "role": "authentication_material",
            "participates_in_security_decision": True,
            "impact_if_broken": "token_forgery_or_auth_bypass",
            "severity_floor": "HIGH",
            "recommended_action": "attempt_precomputation_or_jwt_attack",
        }
    if is_benign and not is_security:
        return {
            "role": "static_checksum",
            "participates_in_security_decision": False,
            "impact_if_broken": "none_demonstrable_in_this_context",
            "severity_floor": "LOW",
            "recommended_action": "defense_in_depth_migration_only",
        }
    return {
        "role": "unclassified",
        "participates_in_security_decision": None,
        "impact_if_broken": "unknown_needs_manual_review",
        "severity_floor": "MEDIUM",
        "recommended_action": "manual_review",
    }


def looks_like_password_field(path: str, key: str) -> bool:
    haystack = f"{path} {key}".lower()
    password_signals = ["password", "passwd", "pwd", "secret", "credential",
                        "user", "account", "email"]
    return any(sig in haystack for sig in password_signals)


def attempt_precomputation(hash_value: str) -> Optional[str]:
    return COMMON_HASH_DB.get(hash_value.lower())


# ==========================================
# 4. ANÁLISIS REAL DE JWT
# ==========================================
def analyze_jwt(token: str) -> Dict[str, Any]:
    result = {
        "algorithm": None, "header": None, "payload": None,
        "weaknesses": [], "cracked_secret": None,
    }
    if not HAS_JWT:
        result["error"] = "pyjwt no instalado"
        return result

    try:
        header = pyjwt.get_unverified_header(token)
        payload = pyjwt.decode(token, options={"verify_signature": False})
        result["header"] = header
        result["payload"] = payload
        result["algorithm"] = header.get("alg")

        if str(header.get("alg", "")).lower() == "none":
            result["weaknesses"].append({
                "type": "alg_none", "severity": "CRITICAL",
                "description": "JWT acepta alg=none → firma no verificada",
            })

        if header.get("alg") in ("HS256", "HS384", "HS512"):
            for secret in COMMON_JWT_SECRETS:
                try:
                    pyjwt.decode(token, secret, algorithms=[header["alg"]])
                    result["cracked_secret"] = secret
                    result["weaknesses"].append({
                        "type": "weak_secret", "severity": "CRITICAL",
                        "description": f"Secreto JWT débil encontrado: '{secret}'",
                    })
                    break
                except pyjwt.InvalidSignatureError:
                    continue
                except Exception:
                    break

        if "exp" not in (payload or {}):
            result["weaknesses"].append({
                "type": "no_expiration", "severity": "MEDIUM",
                "description": "Token sin claim 'exp' → no expira",
            })

        sensitive_claims = ["password", "secret", "key", "ssn", "credit", "apikey"]
        for claim in (payload or {}):
            if any(s in claim.lower() for s in sensitive_claims):
                result["weaknesses"].append({
                    "type": "sensitive_claim", "severity": "HIGH",
                    "description": f"Claim sensible en payload: {claim}",
                })
    except Exception as e:
        result["error"] = str(e)
    return result


# ==========================================
# 5. DETECCIÓN DE EXPOSICIÓN DE ENDPOINT ADMIN
# ==========================================
ADMIN_PATHS = ["/rest/admin/", "/admin/", "/internal/", "/debug/", "/config/", "/application-config"]


def check_endpoint_exposure(url: str, status: int, body: str) -> Optional[Dict[str, Any]]:
    path = urlparse(url).path.lower()
    if any(p in path for p in ADMIN_PATHS) and status == 200 and body:
        return {
            "id": "CRYPTO-EXPOSURE",
            "title": "Unauthenticated Admin Endpoint Exposure",
            "severity": "HIGH",
            "exploitable": True,
            "context": {"role": "information_disclosure", "participates_in_security_decision": True},
            "evidence": f"{url} devuelve HTTP {status} sin credenciales",
            "cwe": "CWE-306",
            "owasp": "A01:2021 - Broken Access Control",
            "attack_chain": [
                f"1. Petición GET a {url} sin cabecera Authorization",
                "2. Servidor devuelve HTTP 200 con contenido interno",
                "3. Atacante accede a configuración, claves y metadatos del sistema",
            ],
        }
    return None


# ==========================================
# 6. DETECCIÓN TLS DÉBIL
# ==========================================
def check_tls(target_url: str) -> Optional[Dict[str, Any]]:
    parsed = urlparse(target_url)
    if not parsed.hostname:
        return None

    if parsed.scheme != "https":
        return {
            "id": "CRYPTO-TLS-001",
            "title": "Tráfico HTTP sin cifrar",
            "severity": "HIGH",
            "exploitable": True,
            "context": {"role": "transport_security", "participates_in_security_decision": True},
            "cwe": "CWE-319",
            "owasp": "A02:2021 - Cryptographic Failures",
            "evidence": f"{target_url} usa HTTP plano; interceptable en tránsito.",
            "attack_chain": [
                f"1. Interceptar tráfico a {target_url} en la red local (ARP spoofing, MITM)",
                "2. Leer credenciales, tokens y datos sensibles en texto plano",
            ],
        }

    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()

        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            return {
                "id": "CRYPTO-TLS-002",
                "title": f"Versión TLS obsoleta: {version}",
                "severity": "HIGH",
                "exploitable": True,
                "context": {"role": "transport_security", "participates_in_security_decision": True},
                "cwe": "CWE-326",
                "evidence": f"El servidor negocia {version}, vulnerable a downgrade/ataques conocidos.",
            }
        if cipher and cipher[0] in ("RC4-SHA", "DES-CBC3-SHA", "NULL"):
            return {
                "id": "CRYPTO-TLS-003",
                "title": f"Cifrado TLS débil: {cipher[0]}",
                "severity": "HIGH",
                "exploitable": True,
                "context": {"role": "transport_security", "participates_in_security_decision": True},
                "cwe": "CWE-327",
                "evidence": f"El cifrado negociado es {cipher[0]}, considerado obsoleto.",
            }
    except Exception:
        return None
    return None


# ==========================================
# 7. EXTRACCIÓN DE SECRETOS EN HTML/JS
# ==========================================
def extract_from_html_js(raw_content: str) -> List[Dict[str, Any]]:
    findings = []
    for name, regex in SECRET_PATTERNS.items():
        for m in re.findall(regex, raw_content):
            val = m if isinstance(m, str) else m[0]
            findings.append({
                "id": f"CRYPTO-SECRET-{len(findings)+1:03d}",
                "title": f"Hardcoded Secret: {name}",
                "value": val,
                "severity": "CRITICAL",
                "exploitable": True,
                "context": {"role": "hardcoded_secret", "participates_in_security_decision": True},
                "cwe": "CWE-798",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "attack_demonstrated": "extraction",
                "evidence": f"Secreto hardcodeado detectado: {name}",
                "attack_chain": [
                    f"1. Obtener el HTML/JS público donde aparece el secreto",
                    f"2. Extraer el valor de {name} del código",
                    "3. Usar el secreto para acceder a APIs/servicios de terceros",
                ],
            })
    return findings


# ==========================================
# 8. VERIFICACIÓN DE LOGIN CON HASH ROTO
# ==========================================
def verify_login_with_cracked_hash(
    login_url: str, username: str, password: str
) -> Dict[str, Any]:
    """Intenta hacer login real con la contraseña rota. Retorna status y evidencia."""
    try:
        r = requests.post(
            login_url,
            json={"email": username, "password": password},
            timeout=5,
        )
        success = r.status_code == 200 and "token" in r.text.lower()
        return {
            "verified": success,
            "status_code": r.status_code,
            "evidence": (
                f"Login exitoso con {username}:{password} → HTTP 200"
                if success else
                f"Login falló con {username}:{password} → HTTP {r.status_code}"
            ),
        }
    except Exception as e:
        return {"verified": False, "error": str(e)}


# ==========================================
# 9. DECODIFICACIÓN MULTINIVEL
# ==========================================
def decode_rot13(text: str) -> str:
    return codecs.decode(text, "rot_13")


def decode_hex(text: str) -> Optional[str]:
    clean = text.strip()
    if len(clean) % 2 != 0:
        return None
    try:
        return bytes.fromhex(clean).decode("utf-8", errors="ignore")
    except ValueError:
        return None


def decode_base64(text: str) -> Optional[str]:
    clean = text.strip()
    missing = len(clean) % 4
    if missing:
        clean += "=" * (4 - missing)
    try:
        return base64.b64decode(clean, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return None


def decode_z85(text: str) -> Optional[str]:
    clean = text.strip()
    if HAS_ZMQ:
        try:
            return zmq.utils.z85.decode(clean.encode("ascii")).decode("utf-8", errors="ignore")
        except Exception:
            pass
    try:
        return base64.b85decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        return None


def is_printable_ascii(text: str) -> bool:
    if not text or len(text) < 3:
        return False
    return all(32 <= ord(c) <= 126 or c in "\n\r\t" for c in text)


INTERESTING_KEYWORDS = ["flag", "secret", "token", "admin", "password",
                        "api_key", "private", "begin", "akia", "ghp_", "sk_"]


def score_decoded_content(text: str) -> int:
    score = 0
    lower = text.lower()
    for kw in INTERESTING_KEYWORDS:
        if kw in lower:
            score += 2
    if re.search(r"-----BEGIN .* KEY-----", text):
        score += 5
    if re.search(r"(AKIA|ghp_|sk_live_)[A-Za-z0-9]{16,}", text):
        score += 5
    return score


def decode_multilevel(candidate: str, max_depth: int = 5) -> List[Dict[str, Any]]:
    history = [candidate]
    steps = []
    current = candidate.strip()

    for depth in range(1, max_depth + 1):
        decoded = None
        method_used = None

        res_b64 = decode_base64(current)
        if res_b64 and is_printable_ascii(res_b64) and res_b64 != current:
            decoded, method_used = res_b64, "Base64"

        if not decoded:
            res_z85 = decode_z85(current)
            if res_z85 and is_printable_ascii(res_z85) and res_z85 != current:
                decoded, method_used = res_z85, "Z85/Base85"

        if not decoded:
            res_hex = decode_hex(current)
            if res_hex and is_printable_ascii(res_hex) and res_hex != current:
                decoded, method_used = res_hex, "Hexadecimal"

        if not decoded:
            res_rot13 = decode_rot13(current)
            if is_printable_ascii(res_rot13) and res_rot13 != current and res_rot13 != candidate:
                if any(k in res_rot13.lower() for k in ["/bin", "easter", "flag", "secret", "http", "admin"]):
                    decoded, method_used = res_rot13, "ROT13"

        if decoded:
            steps.append({
                "step": depth, "method": method_used,
                "input": current, "output": decoded,
            })
            current = decoded
            if current in history:
                break
            history.append(current)
        else:
            break
    return steps


# ==========================================
# 10. CADENA DE EXPLOTACIÓN
# ==========================================
def build_attack_chain(finding: Dict[str, Any], endpoint: str = "") -> List[str]:
    """Construye una cadena lógica de explotación para el finding."""
    chain = []
    alg = finding.get("algorithm_detected", "")
    ctx = finding.get("context", {})
    role = ctx.get("role", "")
    cracked = finding.get("attack_result")
    path = finding.get("path", "")

    if role == "authentication_material" and cracked:
        chain = [
            f"1. Acceder al endpoint {endpoint or '(desconocido)'} sin autenticación",
            f"2. Extraer el hash {alg} del campo '{path}'",
            f"3. Precomputar el hash: {finding['value']} → '{cracked}'",
            f"4. Hacer login con la contraseña recuperada",
            "5. Acceder a recursos protegidos como el usuario suplantado",
        ]
    elif role == "authentication_material" and not cracked:
        chain = [
            f"1. Acceder al endpoint {endpoint or '(desconocido)'}",
            f"2. Extraer el hash {alg} del campo '{path}'",
            "3. Precomputar con hashcat/john + wordlist (no en tabla local, pero factible)",
            "4. Suplantar identidad con la contraseña recuperada",
        ]
    elif role == "static_checksum":
        chain = [
            f"1. El hash {alg} está en '{path}' pero es un checksum de recurso estático",
            "2. Una colisión aquí NO otorga privilegios adicionales al atacante",
            "3. Riesgo real: nulo en este contexto. Solo defensa en profundidad.",
        ]
    elif role == "hardcoded_secret":
        chain = [
            "1. Acceder al recurso público (HTML/JS) que contiene el secreto",
            f"2. Extraer el valor del secreto '{finding.get('title','')}'",
            "3. Usar el secreto para acceder a servicios de terceros (AWS, GitHub, etc.)",
        ]
    elif role == "information_disclosure":
        chain = [
            f"1. GET a {endpoint} sin autenticación",
            "2. Servidor devuelve configuración interna",
            "3. Extraer claves, rutas y metadatos para ataques posteriores",
        ]
    return chain


# ==========================================
# 11. PARSER RECURSIVO CON CONTEXTO
# ==========================================
def inspect_json_keys(
    data: Any, path: str = "", endpoint_hint: str = ""
) -> List[Dict[str, Any]]:
    findings = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            if any(k in key.lower() for k in ["crypto", "hash", "algorithm", "secret", "showcrypto"]):
                ctx = classify_context(current_path, key, endpoint_hint)
                findings.append({
                    "id": f"CRYPTO-KEY-{len(findings)+1:03d}",
                    "title": "Cryptographic Configuration Key",
                    "path": current_path, "key": key, "value": str(value),
                    "severity": ctx["severity_floor"],
                    "exploitable": ctx["participates_in_security_decision"],
                    "context": ctx,
                    "attack_demonstrated": "none",
                })

            if isinstance(value, str):
                stripped = value.strip()
                alg = None
                if re.match(SHA1_STRICT_REGEX, stripped):
                    alg = "SHA1"
                elif re.match(MD5_STRICT_REGEX, stripped):
                    alg = "MD5"
                elif re.match(SHA256_STRICT_REGEX, stripped):
                    alg = "SHA256"

                if alg:
                    ctx = classify_context(current_path, key, endpoint_hint)
                    finding = {
                        "id": f"CRYPTO-HASH-{len(findings)+1:03d}",
                        "title": f"Exposed {alg} Hash",
                        "path": current_path, "key": key, "value": stripped,
                        "algorithm_detected": alg,
                        "severity": ctx["severity_floor"],
                        "exploitable": ctx["participates_in_security_decision"],
                        "context": ctx,
                        "cwe": "CWE-327" if alg in ("MD5", "SHA1") else "CWE-328",
                        "owasp": "A02:2021 - Cryptographic Failures",
                        "attack_demonstrated": "none",
                        "attack_result": None,
                    }

                    if ctx["participates_in_security_decision"] and alg in ("MD5", "SHA1"):
                        # 1. Intentar con tabla estática rápida
                        cracked = attempt_precomputation(stripped)
                        
                        # 2. Si falla, lanzar el ataque de diccionario con mutaciones
                        if not cracked:
                            cracked = attempt_dictionary_attack(stripped, alg)

                        if cracked:
                            finding["severity"] = "CRITICAL"
                            finding["attack_demonstrated"] = "dictionary_attack"
                            finding["attack_result"] = cracked
                            finding["evidence"] = f"Hash roto por fuerza bruta de diccionario: {stripped} → '{cracked}'"
                            finding["attack_chain"] = [
                                f"1. Acceder al endpoint {endpoint_hint}",
                                f"2. Extraer el hash {alg} del campo '{current_path}'",
                                f"3. Ejecutar ataque de diccionario con reglas (hashcat/john)",
                                f"4. Contraseña encontrada: '{cracked}'",
                                "5. Suplantar identidad con las credenciales recuperadas"
                            ]
                        elif looks_like_password_field(current_path, key):
                            finding["attack_demonstrated"] = "dictionary_attack_failed"
                            finding["evidence"] = (
                                "Hash de contraseña con algoritmo débil. No está en el diccionario local, "
                                "pero es atacable con hashcat + rockyou.txt."
                            )
                    elif ctx["role"] == "static_checksum":
                        finding["evidence"] = (
                            "Checksum de recurso estático. Una colisión aquí no otorga "
                            "privilegios adicionales al atacante."
                        )

                    finding["attack_chain"] = build_attack_chain(finding, endpoint_hint)
                    findings.append(finding)

            elif isinstance(value, (dict, list)):
                findings.extend(inspect_json_keys(value, current_path, endpoint_hint))

    elif isinstance(data, list):
        for index, item in enumerate(data):
            current_path = f"{path}[{index}]"
            findings.extend(inspect_json_keys(item, current_path, endpoint_hint))

    return findings


# ==========================================
# 12. ORQUESTADOR PRINCIPAL
# ==========================================
def inspect_crypto_payload(
    raw_content: str,
    endpoint_hint: str = "",
    http_status: int = 0,
    headers: Optional[Dict[str, str]] = None,
    verify_login: bool = False,
    login_url: str = "",
) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    # 1. Parser JSON
    try:
        parsed_json = json.loads(raw_content)
        findings.extend(inspect_json_keys(parsed_json, endpoint_hint=endpoint_hint))
    except Exception:
        pass

    # 2. Secretos hardcodeados en HTML/JS
    findings.extend(extract_from_html_js(raw_content))

    # 3. Regex genéricos (JWT se trata aparte)
    regex_findings = []
    for pattern_name, pattern_regex in CRYPTO_PATTERNS.items():
        matches = re.findall(pattern_regex, raw_content)
        if not matches:
            continue
        unique_matches = list(set([m[1] if isinstance(m, tuple) else m for m in matches]))

        if pattern_name == "JWT Token":
            for tok in unique_matches[:5]:
                jwt_analysis = analyze_jwt(tok)
                sev = "HIGH"
                for w in jwt_analysis.get("weaknesses", []):
                    if w["severity"] == "CRITICAL":
                        sev = "CRITICAL"
                        break
                findings.append({
                    "id": f"CRYPTO-JWT-{len(findings)+1:03d}",
                    "title": "JWT Token Detected",
                    "value": tok[:40] + "..." if len(tok) > 40 else tok,
                    "algorithm_detected": jwt_analysis.get("algorithm"),
                    "severity": sev,
                    "exploitable": bool(jwt_analysis.get("weaknesses")),
                    "context": {"role": "authentication_material", "participates_in_security_decision": True},
                    "jwt_analysis": jwt_analysis,
                    "cwe": "CWE-347",
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "attack_demonstrated": "jwt_analysis",
                    "attack_result": jwt_analysis.get("cracked_secret"),
                })
        else:
            regex_findings.append({
                "pattern": pattern_name,
                "count": len(unique_matches),
                "samples": unique_matches[:5],
            })

    # 4. Exposición de endpoint
    if endpoint_hint and http_status:
        exp = check_endpoint_exposure(endpoint_hint, http_status, raw_content)
        if exp:
            findings.append(exp)

    # 5. TLS débil
    if endpoint_hint:
        tls = check_tls(endpoint_hint)
        if tls:
            findings.append(tls)

    # 6. Entropía + decodificación multinivel
    high_entropy_tokens = []
    multilevel_findings = []
    tokens = set(re.findall(r"[A-Za-z0-9+/=_%-]{12,}", raw_content))

    for token in tokens:
        entropy = calculate_shannon_entropy(token)
        if entropy >= 4.2:
            high_entropy_tokens.append({
                "token": token[:30] + "..." if len(token) > 30 else token,
                "entropy": entropy,
                "classification": (
                    "High Entropy (Ciphertext/Key)" if entropy > 4.8
                    else "Medium-High Entropy (Hash/Encoded)"
                ),
            })

        cascade = decode_multilevel(token)
        if cascade:
            final = cascade[-1]["output"]
            score = score_decoded_content(final)
            if score >= 2 or len(cascade) >= 3:
                multilevel_findings.append({
                    "original_token": token,
                    "depth_reached": len(cascade),
                    "transformations": cascade,
                    "final_decoded_value": final,
                    "interest_score": score,
                })

    # 7. Verificación de login con hash roto (opcional)
    if verify_login and login_url:
        for f in findings:
            if (
                f.get("attack_demonstrated") == "precomputation"
                and f.get("attack_result")
                and f.get("context", {}).get("role") == "authentication_material"
            ):
                # Inferir usuario del path (ej: data[0].user)
                user_field = f.get("path", "").replace("password", "user").replace("pwd", "user")
                username = f.get("username_hint") or "admin@juice-sh.op"
                verification = verify_login_with_cracked_hash(
                    login_url, username, f["attack_result"]
                )
                f["login_verification"] = verification
                if verification.get("verified"):
                    f["severity"] = "CRITICAL"
                    f["evidence"] = (
                        f"{f.get('evidence','')} + Login confirmado con {username}:{f['attack_result']}"
                    )
                    f["attack_chain"].append(
                        f"✓ Login verificado: sesión obtenida como {username}"
                    )

    # 8. Deduplicar
    seen = set()
    deduped = []
    for f in findings:
        key = (f.get("path"), f.get("algorithm_detected"), f.get("value"), f.get("title"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    findings = deduped

    # 9. Resumen
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in by_severity:
            by_severity[sev] += 1

    exploitable_count = sum(1 for f in findings if f.get("exploitable") is True)
    non_exploitable_count = sum(1 for f in findings if f.get("exploitable") is False)

    return {
        "tool": "crypto_inspector",
        "finding_type": "Cryptographic Failure / Insecure Data Exposure",
        "endpoint": endpoint_hint,
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "exploitable_findings": exploitable_count,
            "non_exploitable_findings": non_exploitable_count,
            "regex_patterns_detected": len(regex_findings),
            "high_entropy_tokens_count": len(high_entropy_tokens),
            "multilevel_decodings_found": len(multilevel_findings),
        },
        "findings": findings,
        "regex_matches": regex_findings,
        "high_entropy_tokens": sorted(high_entropy_tokens, key=lambda x: x["entropy"], reverse=True)[:10],
        "multilevel_decodings": multilevel_findings,
    }


# ==========================================
# 13. RESOLUCIÓN DE INPUT
# ==========================================
def _resolve_input_data(
    target_url: str, jwt_token: str, auth_header: str = ""
) -> Dict[str, Any]:
    if jwt_token:
        return {"content": jwt_token, "status": 0, "endpoint": "jwt://inline", "headers": {}}

    if target_url:
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header
        try:
            response = requests.get(target_url, headers=headers, timeout=10)
            return {
                "content": response.text,
                "status": response.status_code,
                "endpoint": target_url,
                "headers": dict(response.headers),
            }
        except Exception as e:
            return {
                "content": json.dumps({"error": f"No se pudo obtener contenido: {e}"}),
                "status": 0,
                "endpoint": target_url,
                "headers": {},
            }

    return {
        "content": json.dumps({
            "config": {"showCryptoExtraScore": "19c01cb7157e4645e9e2c863062a85a8cbfbdcda"},
            "secret_token": "L012LzM0T3BlblNvdXJjZQ==",
        }),
        "status": 0,
        "endpoint": "fixture://default",
        "headers": {},
    }

def apply_mutations(word: str) -> List[str]:
    """Aplica mutaciones comunes a una palabra (simula las reglas de hashcat)."""
    mutations = {word, word.lower(), word.upper(), word.capitalize()}
    
    # Añadir números al final (admin -> admin1, admin123)
    for num in ["1", "12", "123", "1234", "2024", "2025", "2026", "!"]:
        mutations.add(f"{word}{num}")
        
    # Reemplazos leetspeak (password -> p@ssw0rd)
    leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}
    leet_word = "".join(leet_map.get(c.lower(), c) for c in word)
    mutations.add(leet_word)
    
    return list(mutations)

def attempt_dictionary_attack(hash_value: str, algorithm: str) -> Optional[str]:
    """Ataque de diccionario con reglas de mutación."""
    hash_value = hash_value.lower()
    
    # Generar todas las combinaciones posibles de antemano
    candidates = set()
    for base_word in BASE_WORDLIST:
        for mutation in apply_mutations(base_word):
            candidates.add(mutation)
            
    # Probar cada candidato calculando su hash
    for candidate in candidates:
        if algorithm == "MD5":
            h = hashlib.md5(candidate.encode()).hexdigest()
        elif algorithm == "SHA1":
            h = hashlib.sha1(candidate.encode()).hexdigest()
        else:
            continue
            
        if h == hash_value:
            return candidate  # ¡Contraseña encontrada!
            
    return None



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crypto Inspector - OWASP A02")
    parser.add_argument("--url", default="", help="URL objetivo")
    parser.add_argument("--jwt", default="", help="Token JWT directo")
    parser.add_argument("--auth-header", default="", help="Header Authorization")
    parser.add_argument("--verify-login", action="store_true",
                        help="Intentar login real con hash roto (requiere --login-url)")
    parser.add_argument("--login-url", default="",
                        help="Endpoint de login (ej: http://juice-shop:3000/rest/user/login)")
    cli_args = parser.parse_args()

    resolved = _resolve_input_data(cli_args.url, cli_args.jwt, cli_args.auth_header)
    report = inspect_crypto_payload(
        resolved["content"],
        endpoint_hint=resolved["endpoint"],
        http_status=resolved["status"],
        headers=resolved["headers"],
        verify_login=cli_args.verify_login,
        login_url=cli_args.login_url,
    )
    print(json.dumps(report, indent=2))