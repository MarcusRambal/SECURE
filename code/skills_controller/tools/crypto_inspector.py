import base64
import codecs
import json
import math
import re
import sys
from typing import Any, Dict, List, Optional

# Intentar importación de zmq para soporte nativo Z85
try:
    import zmq
    HAS_ZMQ = True
except ImportError:
    HAS_ZMQ = False

# ==========================================
# 1. ENTROPÍA DE SHANNON
# ==========================================
def calculate_shannon_entropy(data: str) -> float:
    """Calcula la entropía de Shannon (H) para medir aleatoriedad/cifrado."""
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

CRYPTO_PATTERNS = {
    "MD5 Hash": r"\b[a-fA-F0-9]{32}\b",
    "SHA1 Hash": r"\b[a-fA-F0-9]{40}\b",
    "SHA256 Hash": r"\b[a-fA-F0-9]{64}\b",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "Base64 String": r"(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
    "RSA/Generic Private Key": r"-----BEGIN (?:RSA )?PRIVATE KEY-----",
    "Generic Secret Key": r"(?i)(api[_-]?key|secret|token|password|auth)\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']"
}

# ==========================================
# 3. DECODIFICACIÓN MULTINIVEL (Z85/B64/Hex/ROT13)
# ==========================================
def decode_rot13(text: str) -> str:
    return codecs.decode(text, 'rot_13')

def decode_hex(text: str) -> Optional[str]:
    clean_text = text.strip()
    if len(clean_text) % 2 != 0:
        return None
    try:
        return bytes.fromhex(clean_text).decode('utf-8', errors='ignore')
    except ValueError:
        return None

def decode_base64(text: str) -> Optional[str]:
    clean_text = text.strip()
    missing_padding = len(clean_text) % 4
    if missing_padding:
        clean_text += '=' * (4 - missing_padding)
    try:
        return base64.b64decode(clean_text, validate=True).decode('utf-8', errors='ignore')
    except Exception:
        return None

def decode_z85(text: str) -> Optional[str]:
    clean_text = text.strip()
    if HAS_ZMQ:
        try:
            return zmq.utils.z85.decode(clean_text.encode('ascii')).decode('utf-8', errors='ignore')
        except Exception:
            pass
    try:
        return base64.b85decode(clean_text).decode('utf-8', errors='ignore')
    except Exception:
        return None

def is_printable_ascii(text: str) -> bool:
    if not text or len(text) < 3:
        return False
    return all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in text)

def decode_multilevel(candidate: str, max_depth: int = 5) -> List[Dict[str, Any]]:
    history = [candidate]
    steps = []
    current = candidate.strip()

    for depth in range(1, max_depth + 1):
        decoded = None
        method_used = None

        res_b64 = decode_base64(current)
        if res_b64 and is_printable_ascii(res_b64) and res_b64 != current:
            decoded = res_b64
            method_used = "Base64"

        if not decoded:
            res_z85 = decode_z85(current)
            if res_z85 and is_printable_ascii(res_z85) and res_z85 != current:
                decoded = res_z85
                method_used = "Z85/Base85"

        if not decoded:
            res_hex = decode_hex(current)
            if res_hex and is_printable_ascii(res_hex) and res_hex != current:
                decoded = res_hex
                method_used = "Hexadecimal"

        if not decoded:
            res_rot13 = decode_rot13(current)
            if is_printable_ascii(res_rot13) and res_rot13 != current and res_rot13 != candidate:
                if any(k in res_rot13.lower() for k in ["/bin", "easter", "flag", "secret", "http", "admin"]):
                    decoded = res_rot13
                    method_used = "ROT13"

        if decoded:
            steps.append({
                "step": depth,
                "method": method_used,
                "input": current,
                "output": decoded
            })
            current = decoded
            if current in history:
                break
            history.append(current)
        else:
            break

    return steps

# ==========================================
# 4. PARSER RECURSIVO PARA JSON REST
# ==========================================
def inspect_json_keys(data: Any, path: str = "") -> List[Dict[str, Any]]:
    """Recorre la estructura JSON para mapear claves criptográficas y hashes SHA1 expuestos."""
    findings = []

    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            # Detectar claves con nombres sospechosos
            if any(k in key.lower() for k in ["crypto", "hash", "algorithm", "secret", "showcrypto"]):
                findings.append({
                    "path": current_path,
                    "key": key,
                    "value": str(value),
                    "finding": "Cryptographic Configuration Key"
                })

            # Detectar valores con formato hash SHA1
            if isinstance(value, str) and re.match(SHA1_STRICT_REGEX, value.strip()):
                findings.append({
                    "path": current_path,
                    "key": key,
                    "value": value,
                    "finding": "Exposed SHA1 Hash",
                    "algorithm_detected": "SHA1"
                })

            elif isinstance(value, (dict, list)):
                findings.extend(inspect_json_keys(value, current_path))

    elif isinstance(data, list):
        for index, item in enumerate(data):
            current_path = f"{path}[{index}]"
            findings.extend(inspect_json_keys(item, current_path))

    return findings

# ==========================================
# 5. ORQUESTADOR PRINCIPAL
# ==========================================
def inspect_crypto_payload(raw_content: str) -> Dict[str, Any]:
    json_structure_findings = []
    regex_findings = []
    high_entropy_tokens = []
    multilevel_findings = []

    # 1. Parsing JSON y recorrido recursivo de claves
    try:
        parsed_json = json.loads(raw_content)
        json_structure_findings = inspect_json_keys(parsed_json)
    except Exception:
        pass  # No es un JSON válido, se procede como texto plano

    # 2. Análisis por Expresiones Regulares
    for pattern_name, pattern_regex in CRYPTO_PATTERNS.items():
        matches = re.findall(pattern_regex, raw_content)
        if matches:
            unique_matches = list(set([m[1] if isinstance(m, tuple) else m for m in matches]))
            regex_findings.append({
                "pattern": pattern_name,
                "count": len(unique_matches),
                "samples": unique_matches[:5]
            })

    # 3. Extracción de tokens, entropía y desofuscación multinivel
    tokens = set(re.findall(r'[A-Za-z0-9+/=_%-]{12,}', raw_content))
    
    for token in tokens:
        entropy = calculate_shannon_entropy(token)
        
        if entropy >= 4.2:
            high_entropy_tokens.append({
                "token": token[:30] + "..." if len(token) > 30 else token,
                "entropy": entropy,
                "classification": "High Entropy (Ciphertext/Key)" if entropy > 4.8 else "Medium-High Entropy (Hash/Encoded)"
            })
            
        cascade = decode_multilevel(token)
        if len(cascade) >= 2 or (cascade and any(k in cascade[-1]["output"].lower() for k in ["easter", "flag", "secret", "admin"])):
            multilevel_findings.append({
                "original_token": token,
                "depth_reached": len(cascade),
                "transformations": cascade,
                "final_decoded_value": cascade[-1]["output"]
            })

    return {
        "tool": "crypto_inspector",
        "finding_type": "Cryptographic Failure / Insecure Data Exposure",
        "summary": {
            "json_keys_detected": len(json_structure_findings),
            "regex_patterns_detected": len(regex_findings),
            "high_entropy_tokens_count": len(high_entropy_tokens),
            "multilevel_decodings_found": len(multilevel_findings)
        },
        "json_structure_findings": json_structure_findings,
        "regex_matches": regex_findings,
        "high_entropy_tokens": sorted(high_entropy_tokens, key=lambda x: x["entropy"], reverse=True)[:10],
        "multilevel_decodings": multilevel_findings
    }

if __name__ == "__main__":
    input_data = sys.stdin.read() if not sys.stdin.isatty() else (sys.argv[1] if len(sys.argv) > 1 else "")
    if not input_data:
        # Payload de prueba por defecto
        input_data = json.dumps({
            "config": {"showCryptoExtraScore": "19c01cb7157e4645e9e2c863062a85a8cbfbdcda"},
            "secret_token": "L012LzM0T3BlblNvdXJjZQ=="
        })
    
    report = inspect_crypto_payload(input_data)
    print(json.dumps(report, indent=2))