SQLI_ATTACK_TYPE = "sqli"
JWT_ATTACK_TYPE = "jwt"
XSS_ATTACK_TYPE = "xss"


def normalize_attack_type(attack_type_filter: str) -> str:
    return attack_type_filter.casefold()


def is_sqli_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == SQLI_ATTACK_TYPE


def is_jwt_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == JWT_ATTACK_TYPE


def is_xss_attack(attack_type_filter: str) -> bool:
    return normalize_attack_type(attack_type_filter) == XSS_ATTACK_TYPE