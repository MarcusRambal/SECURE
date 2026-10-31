SQLI_ATTACK_TYPE = "sqli"
XSS_ATTACK_TYPE = "xss"
CRYPTOGRAPHIC_FAILURES = "crypto_inspector"
CRYPTO_ATTACK_TYPES = {CRYPTOGRAPHIC_FAILURES, "crypto", "crypto_default"}
ACCESS_CONTROL_ATTACK_TYPE = "access_control"
ACCESS_CONTROL_ATTACK_TYPES = {
    ACCESS_CONTROL_ATTACK_TYPE,
    "access-control",
    "broken_access_control",
    "broken-access-control",
    "idor",
    # Identificadores usados por el frontend para la categoria
    # "Broken Access Control" (BAC). Se normalizan a "access_control".
    "bac",
    "bac_default",
}


def normalize_attack_type(attack_type_filter: str) -> str:
    normalized = (attack_type_filter or "").casefold()
    if normalized in CRYPTO_ATTACK_TYPES:
        return CRYPTOGRAPHIC_FAILURES
    if normalized in ACCESS_CONTROL_ATTACK_TYPES:
        return ACCESS_CONTROL_ATTACK_TYPE
    return normalized


def is_sqli_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == SQLI_ATTACK_TYPE


def is_xss_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == XSS_ATTACK_TYPE


def is_crypto_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == CRYPTOGRAPHIC_FAILURES


def is_access_control_attack(attack_type_filter: str) -> bool:
    if not attack_type_filter:
        return False
    filters = {
        part.strip().casefold()
        for part in str(attack_type_filter).split(",")
        if part.strip()
    }
    return bool(filters & ACCESS_CONTROL_ATTACK_TYPES)
