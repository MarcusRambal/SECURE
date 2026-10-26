SQLI_ATTACK_TYPE = "sqli"
XSS_ATTACK_TYPE = "xss"
CRYPTOGRAPHIC_FAILURES = "crypto_inspector"
CRYPTO_ATTACK_TYPES = {CRYPTOGRAPHIC_FAILURES, "crypto", "crypto_default"}


def normalize_attack_type(attack_type_filter: str) -> str:
    normalized = (attack_type_filter or "").casefold()
    if normalized in CRYPTO_ATTACK_TYPES:
        return CRYPTOGRAPHIC_FAILURES
    return normalized


def is_sqli_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == SQLI_ATTACK_TYPE


def is_xss_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == XSS_ATTACK_TYPE


def is_crypto_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == CRYPTOGRAPHIC_FAILURES
